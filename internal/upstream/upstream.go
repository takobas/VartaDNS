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
	u       Upstream
	latency atomic.Int64 // EWMA in microseconds
	fails   atomic.Int64 // consecutive failures
}

// Group tries upstreams ordered by health and latency.
type Group struct {
	members []*member
	timeout time.Duration
}

// NewGroup builds a group from specs.
func NewGroup(specs []string, timeout time.Duration, resolver *net.Resolver) (*Group, error) {
	if len(specs) == 0 {
		return nil, errors.New("upstream: no upstreams configured")
	}
	g := &Group{timeout: timeout}
	for _, s := range specs {
		u, err := New(strings.TrimSpace(s), resolver)
		if err != nil {
			return nil, err
		}
		g.members = append(g.members, &member{u: u})
	}
	return g, nil
}

func (g *Group) ordered() []*member {
	ms := make([]*member, len(g.members))
	copy(ms, g.members)
	sort.SliceStable(ms, func(i, j int) bool {
		fi, fj := ms[i].fails.Load() > 2, ms[j].fails.Load() > 2
		if fi != fj {
			return !fi // healthy first
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
			us := time.Since(start).Microseconds()
			old := m.latency.Load()
			if old == 0 {
				m.latency.Store(us)
			} else {
				m.latency.Store((old*7 + us) / 8)
			}
			m.fails.Store(0)
			return resp, m.u.String(), nil
		}
		if err == nil {
			err = errors.New("SERVFAIL from " + m.u.String())
		}
		m.fails.Add(1)
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
}

// Statuses reports per-upstream health.
func (g *Group) Statuses() []Status {
	out := make([]Status, 0, len(g.members))
	for _, m := range g.members {
		f := m.fails.Load()
		out = append(out, Status{Name: m.u.String(), LatencyMs: float64(m.latency.Load()) / 1000,
			Fails: f, Healthy: f <= 2})
	}
	return out
}

// BootstrapResolver returns a resolver that uses the given plain DNS servers,
// so DoH hostnames and list URLs resolve without depending on ourselves.
func BootstrapResolver(servers []string) *net.Resolver {
	if len(servers) == 0 {
		return net.DefaultResolver
	}
	var i atomic.Uint32
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			s := withPort(servers[int(i.Add(1))%len(servers)])
			var d net.Dialer
			return d.DialContext(ctx, network, s)
		},
	}
}
