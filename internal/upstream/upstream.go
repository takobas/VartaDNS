// Package upstream forwards queries to upstream resolvers over UDP, TCP or
// DNS-over-HTTPS, with failover between several servers.
package upstream

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/takobas/vartadns/internal/dnsmsg"
)

// Upstream is a single resolver.
type Upstream interface {
	Exchange(ctx context.Context, query []byte) ([]byte, error)
	String() string
}

// New parses an upstream spec:
//
//	9.9.9.9 | 9.9.9.9:53 | udp://9.9.9.9:53 | tcp://9.9.9.9:53 | https://dns.quad9.net/dns-query
func New(spec string, resolver *net.Resolver) (Upstream, error) {
	switch {
	case strings.HasPrefix(spec, "https://"):
		return newDoH(spec, resolver)
	case strings.HasPrefix(spec, "tcp://"):
		return &plain{addr: withPort(strings.TrimPrefix(spec, "tcp://")), tcpOnly: true}, nil
	case strings.HasPrefix(spec, "udp://"):
		return &plain{addr: withPort(strings.TrimPrefix(spec, "udp://"))}, nil
	case strings.Contains(spec, "://"):
		return nil, fmt.Errorf("unsupported upstream scheme: %s", spec)
	default:
		return &plain{addr: withPort(spec)}, nil
	}
}

func withPort(a string) string {
	if _, _, err := net.SplitHostPort(a); err == nil {
		return a
	}
	return net.JoinHostPort(strings.Trim(a, "[]"), "53")
}

func randomID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// ---- plain DNS (UDP with TCP fallback) -------------------------------------------

var udpBufPool = sync.Pool{New: func() any { b := make([]byte, 65535); return &b }}

type plain struct {
	addr    string
	tcpOnly bool
}

func (p *plain) String() string {
	if p.tcpOnly {
		return "tcp://" + p.addr
	}
	return p.addr
}

func (p *plain) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	if !p.tcpOnly {
		resp, err := p.exchangeUDP(ctx, query)
		if err != nil || !dnsmsg.Truncated(resp) {
			return resp, err
		}
	}
	return p.exchangeTCP(ctx, query)
}

func (p *plain) exchangeUDP(ctx context.Context, query []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", p.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	// Use a random ID towards the upstream to resist spoofing; restore later.
	origID := dnsmsg.ID(query)
	q := append([]byte(nil), query...)
	id := randomID()
	dnsmsg.SetID(q, id)
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	bp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bp)
	buf := *bp
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 12 || dnsmsg.ID(buf[:n]) != id || !dnsmsg.IsResponse(buf[:n]) {
			continue // stray or spoofed packet
		}
		// The question must match what we asked.
		if !dnsmsg.SameQuestion(q, buf[:n]) {
			continue
		}
		resp := append([]byte(nil), buf[:n]...)
		dnsmsg.SetID(resp, origID)
		return resp, nil
	}
}

func (p *plain) exchangeTCP(ctx context.Context, query []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", p.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	origID := dnsmsg.ID(query)
	q := append([]byte(nil), query...)
	dnsmsg.SetID(q, randomID())
	resp, err := ExchangeStream(conn, q)
	if err != nil {
		return nil, err
	}
	dnsmsg.SetID(resp, origID)
	return resp, nil
}

// ExchangeStream sends one length-prefixed query on a stream and reads the reply.
func ExchangeStream(conn io.ReadWriter, query []byte) ([]byte, error) {
	msg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(msg, uint16(len(query)))
	copy(msg[2:], query)
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if len(resp) < 12 || dnsmsg.ID(resp) != dnsmsg.ID(query) || !dnsmsg.SameQuestion(query, resp) {
		return nil, errors.New("upstream: mismatched TCP response")
	}
	return resp, nil
}

// ---- DNS over HTTPS (RFC 8484) -----------------------------------------------------

type doh struct {
	url    string
	client *http.Client
}

func newDoH(spec string, resolver *net.Resolver) (*doh, error) {
	u, err := url.Parse(spec)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, Resolver: resolver}
	tr := &http.Transport{
		Proxy:               nil, // a router talks to the resolver directly
		DialContext:         dialer.DialContext,
		TLSClientConfig:     &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &doh{url: spec, client: &http.Client{Transport: tr}}, nil
}

func (d *doh) String() string { return d.url }

func (d *doh) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	origID := dnsmsg.ID(query)
	q := append([]byte(nil), query...)
	dnsmsg.SetID(q, 0) // RFC 8484 recommends ID 0 for cache friendliness
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if len(body) < 12 || !dnsmsg.IsResponse(body) || !dnsmsg.SameQuestion(q, body) {
		return nil, errors.New("doh: invalid response")
	}
	dnsmsg.SetID(body, origID)
	return body, nil
}

// ---- group with failover ------------------------------------------------------------

type member struct {
	u         Upstream
	encrypted bool         // DNS-over-HTTPS
	latency   atomic.Int64 // EWMA in microseconds
	fails     atomic.Int64 // consecutive failures
}

// record updates health and latency after one exchange.
func (m *member) record(ok bool, d time.Duration) {
	if !ok {
		m.fails.Add(1)
		return
	}
	us := d.Microseconds()
	if old := m.latency.Load(); old == 0 {
		m.latency.Store(us)
	} else {
		m.latency.Store((old*7 + us) / 8)
	}
	m.fails.Store(0)
}

func (m *member) healthy() bool { return m.fails.Load() <= 2 }

// Strategy selects how upstreams are ordered.
type Strategy int32

const (
	// EncryptedFirst uses healthy DoH upstreams before plain DNS; plain
	// DNS is only a fallback. Within each kind the fastest goes first.
	EncryptedFirst Strategy = iota
	// Fastest uses the healthy upstream with the lowest latency.
	Fastest
)

// ParseStrategy converts "encrypted-first" / "fastest".
func ParseStrategy(s string) (Strategy, error) {
	switch s {
	case "", "encrypted-first":
		return EncryptedFirst, nil
	case "fastest":
		return Fastest, nil
	}
	return EncryptedFirst, fmt.Errorf("unknown upstream strategy %q (use encrypted-first or fastest)", s)
}

func (s Strategy) String() string {
	if s == Fastest {
		return "fastest"
	}
	return "encrypted-first"
}

// Group tries upstreams ordered by health and latency.
type Group struct {
	ms       atomic.Pointer[[]*member] // replaced atomically by SetSpecs
	timeout  time.Duration
	strategy atomic.Int32
	resolver *net.Resolver
}

func (g *Group) list() []*member {
	if p := g.ms.Load(); p != nil {
		return *p
	}
	return nil
}

// SetStrategy switches the ordering at runtime.
func (g *Group) SetStrategy(s Strategy) { g.strategy.Store(int32(s)) }

// Strategy returns the current ordering strategy.
func (g *Group) Strategy() Strategy { return Strategy(g.strategy.Load()) }

// NewGroup builds a group from specs.
func NewGroup(specs []string, timeout time.Duration, resolver *net.Resolver) (*Group, error) {
	if len(specs) == 0 {
		return nil, errors.New("upstream: no upstreams configured")
	}
	g := &Group{timeout: timeout, resolver: resolver}
	if err := g.SetSpecs(specs); err != nil {
		return nil, err
	}
	return g, nil
}

// MaxUpstreams limits how many servers a group may hold.
const MaxUpstreams = 8

// Validate parses specs without using them.
func Validate(specs []string) error {
	n := 0
	for _, s := range specs {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if _, err := New(s, nil); err != nil {
			return err
		}
		n++
	}
	if n == 0 {
		return errors.New("upstream: at least one server is required")
	}
	if n > MaxUpstreams {
		return fmt.Errorf("upstream: at most %d servers", MaxUpstreams)
	}
	return nil
}

// SetSpecs replaces the servers at runtime. Health and latency of servers
// that stay in the list are kept.
func (g *Group) SetSpecs(specs []string) error {
	if err := Validate(specs); err != nil {
		return err
	}
	old := map[string]*member{}
	for _, m := range g.list() {
		old[m.u.String()] = m
	}
	var next []*member
	for _, s := range specs {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		u, _ := New(s, g.resolver)
		if m, ok := old[u.String()]; ok {
			next = append(next, m)
			continue
		}
		_, isDoH := u.(*doh)
		next = append(next, &member{u: u, encrypted: isDoH})
	}
	g.ms.Store(&next)
	return nil
}

// Specs returns the current server list.
func (g *Group) Specs() []string {
	var out []string
	for _, m := range g.list() {
		out = append(out, m.u.String())
	}
	return out
}

func (g *Group) ordered() []*member {
	cur := g.list()
	ms := make([]*member, len(cur))
	copy(ms, cur)
	encFirst := g.Strategy() == EncryptedFirst
	sort.SliceStable(ms, func(i, j int) bool {
		hi, hj := ms[i].healthy(), ms[j].healthy()
		if hi != hj {
			return hi // healthy first
		}
		if encFirst && ms[i].encrypted != ms[j].encrypted {
			return ms[i].encrypted // DoH before plain DNS
		}
		return ms[i].latency.Load() < ms[j].latency.Load()
	})
	return ms
}

// Exchange forwards the query, trying the next upstream on failure.
// It returns the response and the name of the upstream that answered.
func (g *Group) Exchange(ctx context.Context, query []byte) ([]byte, string, error) {
	var lastErr error
	for _, m := range g.ordered() {
		cctx, cancel := context.WithTimeout(ctx, g.timeout)
		start := time.Now()
		resp, err := m.u.Exchange(cctx, query)
		cancel()
		if err == nil && dnsmsg.Rcode(resp) != dnsmsg.RcodeServFail {
			m.record(true, time.Since(start))
			return resp, m.u.String(), nil
		}
		if err == nil {
			err = errors.New("SERVFAIL from " + m.u.String())
		}
		m.record(false, 0)
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, "", lastErr
}

// Status describes an upstream for the web panel.
type Status struct {
	Name      string  `json:"name"`
	LatencyMs float64 `json:"latency_ms"`
	Fails     int64   `json:"fails"`
	Healthy   bool    `json:"healthy"`
	Encrypted bool    `json:"encrypted"`
	Primary   bool    `json:"primary"` // tried first for the next query
}

// Statuses reports per-upstream health.
func (g *Group) Statuses() []Status {
	cur := g.list()
	out := make([]Status, 0, len(cur))
	if len(cur) == 0 {
		return out
	}
	first := g.ordered()[0]
	for _, m := range cur {
		f := m.fails.Load()
		out = append(out, Status{Name: m.u.String(), LatencyMs: float64(m.latency.Load()) / 1000,
			Fails: f, Healthy: f <= 2, Encrypted: m.encrypted, Primary: m == first})
	}
	return out
}

// HealthLoop probes every upstream periodically with a tiny query (root
// NS). It keeps DoH connections warm, keeps latency figures current and
// lets an upstream that failed earlier come back into use.
func (g *Group) HealthLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	var id uint16
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, m := range g.list() {
			id++
			cctx, cancel := context.WithTimeout(ctx, g.timeout)
			start := time.Now()
			resp, err := m.u.Exchange(cctx, dnsmsg.BuildQuery(id, "", dnsmsg.TypeNS))
			cancel()
			m.record(err == nil && dnsmsg.Rcode(resp) != dnsmsg.RcodeServFail, time.Since(start))
		}
	}
}

// BootstrapResolver returns a resolver that uses the given plain DNS servers,
// so DoH hostnames and list URLs resolve without depending on ourselves.
func BootstrapResolver(servers []string) *net.Resolver {
	return NewBootstrap(servers).Resolver()
}

// Bootstrap is a set of plain DNS servers that can be changed at runtime.
// With an empty set the system resolver is used.
type Bootstrap struct {
	servers atomic.Pointer[[]string]
	next    atomic.Uint32
	res     *net.Resolver
}

// NewBootstrap creates a bootstrap with the given servers.
func NewBootstrap(servers []string) *Bootstrap {
	b := &Bootstrap{}
	b.Set(servers)
	b.res = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			list := b.Servers()
			if len(list) == 0 {
				return d.DialContext(ctx, network, address) // system resolver
			}
			return d.DialContext(ctx, network, withPort(list[int(b.next.Add(1))%len(list)]))
		},
	}
	return b
}

// Set replaces the servers.
func (b *Bootstrap) Set(servers []string) {
	var clean []string
	for _, s := range servers {
		if s = strings.TrimSpace(s); s != "" {
			clean = append(clean, s)
		}
	}
	b.servers.Store(&clean)
}

// Servers returns the current list.
func (b *Bootstrap) Servers() []string { return *b.servers.Load() }

// Resolver returns a resolver that always uses the current servers.
func (b *Bootstrap) Resolver() *net.Resolver { return b.res }

// ValidateBootstrap accepts plain IP addresses with optional port only:
// bootstrap servers must not need DNS themselves.
func ValidateBootstrap(servers []string) error {
	for _, s := range servers {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		host := s
		if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		}
		if net.ParseIP(strings.Trim(host, "[]")) == nil {
			return fmt.Errorf("bootstrap %q: must be an IP address", s)
		}
	}
	return nil
}

// Result is the outcome of testing one server.
type Result struct {
	Server string  `json:"server"`
	OK     bool    `json:"ok"`
	Ms     float64 `json:"ms"`
	Error  string  `json:"error,omitempty"`
}

// Test sends one small query (root NS) to every spec and reports results.
func Test(ctx context.Context, specs []string, resolver *net.Resolver, timeout time.Duration) []Result {
	var out []Result
	for i, s := range specs {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		r := Result{Server: s}
		u, err := New(s, resolver)
		if err != nil {
			r.Error = err.Error()
			out = append(out, r)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		resp, err := u.Exchange(cctx, dnsmsg.BuildQuery(uint16(i+1), "", dnsmsg.TypeNS))
		cancel()
		r.Ms = float64(time.Since(start).Microseconds()) / 1000
		switch {
		case err != nil:
			r.Error = err.Error()
		case dnsmsg.Rcode(resp) == dnsmsg.RcodeServFail:
			r.Error = "SERVFAIL"
		default:
			r.OK = true
		}
		if d, ok := u.(*doh); ok {
			d.client.CloseIdleConnections()
		}
		out = append(out, r)
	}
	return out
}
