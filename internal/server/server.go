// Package server runs the DNS listeners and the query pipeline:
// parse -> rate limit -> filter -> cache -> upstream -> CNAME check -> cache.
package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/takobas/vartadns/internal/cache"
	"github.com/takobas/vartadns/internal/dnsmsg"
	"github.com/takobas/vartadns/internal/filter"
	"github.com/takobas/vartadns/internal/policy"
	"github.com/takobas/vartadns/internal/stats"
	"github.com/takobas/vartadns/internal/upstream"
)

// Options configure the resolver pipeline.
type Options struct {
	BlockMode       dnsmsg.BlockMode
	BlockedTTL      uint32
	RateLimitQPS    int
	RateLimitBurst  int
	RateLimitExempt []netip.Prefix
	BypassClients   []netip.Prefix // clients that are never filtered
	AllowedClients  []netip.Prefix // if non-empty, only these may query (ACL)
	BlockDoHCanary  bool           // answer use-application-dns.net with NXDOMAIN
	Conditional     map[string]*upstream.Group
	MaxConcurrent   int
}

// Resolver is the query pipeline shared by all listeners.
type Resolver struct {
	opts     Options
	Filter   *filter.Engine
	Cache    *cache.Cache
	Upstream *upstream.Group
	Stats    *stats.Stats

	limiter       *limiter
	blockingOn    atomic.Bool
	disabledUntil atomic.Int64 // unix seconds; 0 = not scheduled
	sf            flightGroup
	sem           chan struct{}
	tcpSem        chan struct{}
	pol           atomic.Pointer[policyState]
	bypass        atomic.Pointer[[]netip.Prefix] // panel "do not filter" list (+ config)
	defaultMask   atomic.Uint32                  // list classes for clients outside groups
	local         atomic.Pointer[LocalName]
	lastLog       atomic.Int64

	// OnEntry, if set before serving, may enrich a finished entry (device
	// name, list kind) and hand it to the disk log and notifiers. It runs on
	// the query path and must not block.
	OnEntry func(*stats.Entry)
}

// logLimit allows at most one upstream-error log line per 5 seconds so a
// dead upstream cannot flood a router's small log buffer.
func (r *Resolver) logLimit() bool {
	now := time.Now().Unix()
	last := r.lastLog.Load()
	return now-last >= 5 && r.lastLog.CompareAndSwap(last, now)
}

// NewResolver wires the pipeline.
func NewResolver(o Options, f *filter.Engine, c *cache.Cache, u *upstream.Group, s *stats.Stats) *Resolver {
	if o.MaxConcurrent <= 0 {
		o.MaxConcurrent = 20000
	}
	r := &Resolver{opts: o, Filter: f, Cache: c, Upstream: u, Stats: s,
		limiter: newLimiter(o.RateLimitQPS, o.RateLimitBurst),
		sem:     make(chan struct{}, o.MaxConcurrent),
		tcpSem:  make(chan struct{}, 512)}
	r.blockingOn.Store(true)
	r.defaultMask.Store(uint32(filter.ClassAll))
	return r
}

// BlockingEnabled reports whether filtering is active (re-enabling it when a
// temporary pause has expired).
func (r *Resolver) BlockingEnabled() bool {
	if r.blockingOn.Load() {
		return true
	}
	if until := r.disabledUntil.Load(); until > 0 && time.Now().Unix() >= until {
		r.blockingOn.Store(true)
		r.disabledUntil.Store(0)
		return true
	}
	return false
}

// SetBlocking enables or disables filtering; a positive pause re-enables it
// automatically after that duration.
func (r *Resolver) SetBlocking(on bool, pause time.Duration) {
	r.blockingOn.Store(on)
	if !on && pause > 0 {
		r.disabledUntil.Store(time.Now().Add(pause).Unix())
	} else {
		r.disabledUntil.Store(0)
	}
}

// DisabledUntil returns when a pause ends (zero time if none).
func (r *Resolver) DisabledUntil() time.Time {
	if u := r.disabledUntil.Load(); u > 0 {
		return time.Unix(u, 0)
	}
	return time.Time{}
}

func inPrefixes(ip netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Resolve handles one query and returns the wire response (nil = drop).
func (r *Resolver) Resolve(ctx context.Context, msg []byte, client netip.Addr, proto string) []byte {
	return r.resolve(ctx, msg, client, proto, false)
}

// ResolveTrusted is Resolve for clients identified by a personal DoH/DoT
// address: the client ACL is skipped and client is the device's identity.
func (r *Resolver) ResolveTrusted(ctx context.Context, msg []byte, client netip.Addr, proto string) []byte {
	return r.resolve(ctx, msg, client, proto, true)
}

// LocalName makes VartaDNS answer host and *.host itself (the hostname of
// its own DoH/DoT service).
type LocalName struct {
	Host string
	IP4  []byte
	IP6  []byte
}

// SetBypass sets extra clients that are never filtered (from the panel).
func (r *Resolver) SetBypass(p []netip.Prefix) { r.bypass.Store(&p) }

// SetDefaultClasses sets the list classes for clients outside any group.
func (r *Resolver) SetDefaultClasses(mask uint8) { r.defaultMask.Store(uint32(mask)) }

// SetLocalName installs (or with nil removes) the local name.
func (r *Resolver) SetLocalName(l *LocalName) { r.local.Store(l) }

func (r *Resolver) resolve(ctx context.Context, msg []byte, client netip.Addr, proto string, trusted bool) []byte {
	start := time.Now()
	ent := stats.Entry{Time: start, Client: client.String(), Proto: proto}
	finish := func(resp []byte, status string) []byte {
		ent.Status = status
		ent.Micros = time.Since(start).Microseconds()
		if len(resp) >= 4 {
			ent.Rcode = dnsmsg.Rcode(resp)
		}
		if r.OnEntry != nil {
			r.OnEntry(&ent)
		}
		r.Stats.Record(ent)
		return resp
	}

	if !trusted && len(r.opts.AllowedClients) > 0 && !inPrefixes(client, r.opts.AllowedClients) {
		return nil // not our client: silently drop (no amplification)
	}

	q, err := dnsmsg.ParseQuery(msg)
	if err != nil {
		if len(msg) < 12 {
			return nil
		}
		return finish(dnsmsg.BuildError(msg, nil, dnsmsg.RcodeFormErr), stats.StatusError)
	}
	ent.Name = q.Name
	ent.Type = dnsmsg.TypeString(q.Type)

	if q.Opcode != 0 {
		return finish(dnsmsg.BuildError(msg, &q, dnsmsg.RcodeNotImp), stats.StatusError)
	}
	if !inPrefixes(client, r.opts.RateLimitExempt) && !r.limiter.allow(client, start) {
		return finish(dnsmsg.BuildError(msg, &q, dnsmsg.RcodeRefused), stats.StatusRefused)
	}
	if l := r.local.Load(); l != nil && l.Host != "" && (q.Name == l.Host || strings.HasSuffix(q.Name, "."+l.Host)) {
		ip := l.IP4
		if q.Type == dnsmsg.TypeAAAA {
			ip = l.IP6
		}
		return finish(dnsmsg.BuildAddress(msg, q, ip, 300), stats.StatusLocal)
	}
	if q.Type == dnsmsg.TypeANY {
		// ANY is a classic amplification vector; refuse it (RFC 8482 spirit).
		return finish(dnsmsg.BuildError(msg, &q, dnsmsg.RcodeNotImp), stats.StatusRefused)
	}

	now := start
	bypass := inPrefixes(client, r.opts.BypassClients)
	if bp := r.bypass.Load(); !bypass && bp != nil {
		bypass = inPrefixes(client, *bp)
	}
	globalOn := r.BlockingEnabled() && !bypass
	var gp *policy.GroupPolicy
	pol := r.pol.Load()
	if !bypass && pol != nil {
		// Groups (parental control) keep working while global filtering is paused.
		gp = pol.p.Lookup(client)
	}
	mask := uint8(r.defaultMask.Load())
	if gp != nil {
		ent.Group = gp.Name
		mask = gp.ListMask
	}

	// decide applies group rules first, then the global rules.
	decide := func(name string) (blocked, allowed bool, rule, src string) {
		if gp != nil {
			switch d := gp.Check(name, now, pol.cats); d.Verdict {
			case policy.Block:
				return true, false, d.Rule, d.Source
			case policy.Allow:
				return false, true, d.Rule, d.Source
			}
		}
		if globalOn {
			switch m := r.Filter.CheckClasses(name, mask); m.Verdict {
			case filter.Blocked:
				return true, false, m.Rule, m.Source
			case filter.Allowed:
				return false, true, m.Rule, m.Source
			}
		}
		return false, false, "", ""
	}
	blockedResp := func() []byte {
		return finish(dnsmsg.BuildBlocked(msg, q, r.opts.BlockMode, r.opts.BlockedTTL), stats.StatusBlocked)
	}

	if r.opts.BlockDoHCanary && q.Name == "use-application-dns.net" {
		ent.Rule, ent.Source = q.Name, "doh-canary"
		return finish(dnsmsg.BuildError(msg, &q, dnsmsg.RcodeNXDomain), stats.StatusBlocked)
	}

	status := stats.StatusForwarded
	blocked, allowed, rule, src := decide(q.Name)
	switch {
	case blocked:
		ent.Rule, ent.Source = rule, src
		return blockedResp()
	case allowed:
		ent.Rule, ent.Source = rule, src
		status = stats.StatusAllowed
	}

	// SafeSearch: answer with a CNAME to the provider's safe hostname.
	if gp != nil && gp.SafeSearch {
		if target := policy.SafeSearchTarget(q.Name); target != "" {
			return finish(r.safeSearch(ctx, msg, q, target, &ent), stats.StatusSafeSearch)
		}
	}

	// checkCNAMEs blocks answers that alias into a blocked domain (CNAME cloaking).
	checkCNAMEs := func(cnames []string) bool {
		if status == stats.StatusAllowed {
			return false
		}
		for _, cn := range cnames {
			if b, _, rule, src := decide(cn); b {
				ent.Rule, ent.Source = rule+" (CNAME)", src
				return true
			}
		}
		return false
	}

	key := cache.Key(q)
	if resp := r.Cache.Get(key, dnsmsg.ID(msg)); resp != nil {
		resp = dnsmsg.AdaptResponse(resp, msg, q)
		if info, err := dnsmsg.Inspect(resp); err == nil && checkCNAMEs(info.CNAMEs) {
			return blockedResp()
		}
		return finish(r.fit(resp, q, proto), stats.StatusCached)
	}

	res, err := r.fetch(ctx, q, key)
	if err != nil {
		if !errors.Is(err, context.Canceled) && r.logLimit() {
			log.Printf("upstream error for %s: %v", q.Name, err)
		}
		return finish(dnsmsg.BuildError(msg, &q, dnsmsg.RcodeServFail), stats.StatusError)
	}
	ent.Upstream = res.upstream
	resp := dnsmsg.AdaptResponse(append([]byte(nil), res.resp...), msg, q)
	if checkCNAMEs(res.info.CNAMEs) {
		return blockedResp()
	}
	return finish(r.fit(resp, q, proto), status)
}

type policyState struct {
	p    *policy.Policy
	cats policy.CategoryChecker
}

// SetPolicy installs compiled groups and the category checker (nil = none).
func (r *Resolver) SetPolicy(p *policy.Policy, cats policy.CategoryChecker) {
	r.pol.Store(&policyState{p: p, cats: cats})
}

// PolicyState returns the active compiled groups (nil if none).
func (r *Resolver) PolicyState() *policy.Policy {
	if st := r.pol.Load(); st != nil {
		return st.p
	}
	return nil
}

// fetch resolves a question through the upstreams, deduplicating identical
// in-flight queries and storing the answer in the cache.
func (r *Resolver) fetch(ctx context.Context, q dnsmsg.Query, key string) (flightResult, error) {
	return r.sf.do(key, func() (flightResult, error) {
		grp := r.Upstream
		if g := r.conditionalFor(q.Name); g != nil {
			grp = g
		}
		resp, name, err := grp.Exchange(ctx, dnsmsg.BuildUpstreamQuery(q))
		if err != nil {
			return flightResult{}, err
		}
		info, ierr := dnsmsg.Inspect(resp)
		if ierr == nil {
			r.Cache.Put(key, resp, info)
		}
		return flightResult{resp: resp, info: info, upstream: name}, nil
	})
}

// safeSearch answers "name CNAME target" plus the target's addresses.
func (r *Resolver) safeSearch(ctx context.Context, msg []byte, q dnsmsg.Query, target string, ent *stats.Entry) []byte {
	ent.Rule, ent.Source = target, "safesearch"
	if q.Type != dnsmsg.TypeA && q.Type != dnsmsg.TypeAAAA {
		// Other types (HTTPS/SVCB hints could bypass): CNAME only.
		return dnsmsg.BuildCNAME(msg, q, target, 300, nil)
	}
	tq := dnsmsg.Query{Name: target, Type: q.Type, Class: q.Class, UDPSize: 512}
	key := cache.Key(tq)
	var resp []byte
	if c := r.Cache.Get(key, 0); c != nil {
		resp = c
	} else {
		res, err := r.fetch(ctx, tq, key)
		if err != nil {
			return dnsmsg.BuildError(msg, &q, dnsmsg.RcodeServFail)
		}
		resp = res.resp
	}
	info, err := dnsmsg.Inspect(resp)
	if err != nil {
		return dnsmsg.BuildError(msg, &q, dnsmsg.RcodeServFail)
	}
	want := 4
	if q.Type == dnsmsg.TypeAAAA {
		want = 16
	}
	var ips [][]byte
	for _, a := range info.AnswerIPs {
		if len(a) == want {
			ips = append(ips, a)
		}
	}
	ttl := uint32(300)
	if info.HasTTL && info.MinTTL < ttl {
		ttl = info.MinTTL
	}
	return dnsmsg.BuildCNAME(msg, q, target, ttl, ips)
}

// fit truncates UDP responses that exceed what the client can receive.
func (r *Resolver) fit(resp []byte, q dnsmsg.Query, proto string) []byte {
	if proto == "udp" && len(resp) > q.UDPSize {
		return dnsmsg.Truncate(resp, q)
	}
	return resp
}

func (r *Resolver) conditionalFor(name string) *upstream.Group {
	if len(r.opts.Conditional) == 0 {
		return nil
	}
	for n := name; ; {
		if g, ok := r.opts.Conditional[n]; ok {
			return g
		}
		dot := strings.IndexByte(n, '.')
		if dot < 0 {
			return nil
		}
		n = n[dot+1:]
	}
}

// ---- singleflight -------------------------------------------------------------------

type flightResult struct {
	resp     []byte
	info     dnsmsg.RRInfo
	upstream string
}

type call struct {
	wg  sync.WaitGroup
	res flightResult
	err error
}

type flightGroup struct {
	mu sync.Mutex
	m  map[string]*call
}

func (g *flightGroup) do(key string, fn func() (flightResult, error)) (flightResult, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = map[string]*call{}
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.res, c.err
	}
	c := &call{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.res, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	return c.res, c.err
}

// ---- listeners -------------------------------------------------------------------------

var bufPool = sync.Pool{New: func() any { b := make([]byte, 65535); return &b }}

// ServeUDP answers queries on a UDP socket until ctx is cancelled.
func (r *Resolver) ServeUDP(ctx context.Context, conn *net.UDPConn, workers int) {
	if workers <= 0 {
		workers = 4
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				bp := bufPool.Get().(*[]byte)
				n, addr, err := conn.ReadFromUDPAddrPort(*bp)
				if err != nil {
					bufPool.Put(bp)
					if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
						return
					}
					continue
				}
				msg := append([]byte(nil), (*bp)[:n]...)
				bufPool.Put(bp)
				select {
				case r.sem <- struct{}{}:
				default:
					continue // overloaded: drop, the client will retry
				}
				go func() {
					defer func() { <-r.sem }()
					qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
					if resp := r.Resolve(qctx, msg, addr.Addr().Unmap(), "udp"); resp != nil {
						_, _ = conn.WriteToUDPAddrPort(resp, addr)
					}
				}()
			}
		}()
	}
	<-ctx.Done()
	_ = conn.Close()
	wg.Wait()
}

// ServeTCP answers length-prefixed queries on a TCP listener.
func (r *Resolver) ServeTCP(ctx context.Context, ln net.Listener) {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
		if len(r.opts.AllowedClients) > 0 && !inPrefixes(ap.Addr().Unmap(), r.opts.AllowedClients) {
			_ = c.Close() // ACL before reading anything
			continue
		}
		select {
		case r.tcpSem <- struct{}{}:
		default:
			_ = c.Close() // too many open TCP connections
			continue
		}
		go func() {
			defer func() { <-r.tcpSem }()
			r.handleTCP(ctx, c)
		}()
	}
}

func (r *Resolver) handleTCP(ctx context.Context, c net.Conn) {
	defer c.Close()
	ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	client := ap.Addr().Unmap()
	var l [2]byte
	for {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(l[:])
		if n < 12 {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		resp := r.Resolve(qctx, msg, client, "tcp")
		cancel()
		if resp == nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

// Maintenance runs periodic housekeeping until ctx is cancelled.
func (r *Resolver) Maintenance(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			r.limiter.gc(now)
			r.BlockingEnabled() // re-enable after an expired pause
		}
	}
}
