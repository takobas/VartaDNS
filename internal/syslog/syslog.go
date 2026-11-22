// Package syslog forwards query and audit events to a SIEM (Graylog, Wazuh,
// rsyslog...) as RFC 5424 messages with a JSON body, over UDP, TCP or TLS.
package syslog

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/takobas/vartadns/internal/stats"
)

// Settings are edited from the panel.
type Settings struct {
	Enabled  bool   `json:"enabled"`
	Address  string `json:"address"`  // host:port
	Protocol string `json:"protocol"` // udp, tcp, tls
	Mode     string `json:"mode"`     // threats, blocked, all
	Audit    bool   `json:"audit"`    // also send panel audit events
	Insecure bool   `json:"insecure"` // TLS without certificate check (lab only)
}

// Validate checks the settings.
func (s *Settings) Validate() error {
	if s.Protocol == "" {
		s.Protocol = "udp"
	}
	if s.Mode == "" {
		s.Mode = "threats"
	}
	switch s.Protocol {
	case "udp", "tcp", "tls":
	default:
		return errors.New("protocol must be udp, tcp or tls")
	}
	switch s.Mode {
	case "threats", "blocked", "all":
	default:
		return errors.New("mode must be threats, blocked or all")
	}
	if !s.Enabled {
		return nil
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(s.Address))
	if err != nil || host == "" {
		return errors.New("address must be host:port, e.g. 192.168.11.20:514")
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return errors.New("bad port")
	}
	return nil
}

// Event is one message.
type event struct {
	sev   int // RFC 5424 severity
	msgid string
	body  []byte
	ts    time.Time
}

// Sender is safe for concurrent use; Query/Audit never block.
type Sender struct {
	set     atomic.Pointer[Settings]
	ch      chan event
	host    string
	sent    atomic.Uint64
	dropped atomic.Uint64
	lastErr atomic.Pointer[string]
	gen     atomic.Uint64 // bumps on settings change: reconnect
}

// New creates a sender.
func New(s Settings) *Sender {
	h, _ := os.Hostname()
	if h == "" {
		h = "vartadns"
	}
	x := &Sender{ch: make(chan event, 10000), host: h}
	x.set.Store(&s)
	return x
}

// Settings returns the active settings.
func (x *Sender) Settings() Settings { return *x.set.Load() }

// SetSettings replaces the settings (reconnects).
func (x *Sender) SetSettings(s Settings) {
	x.set.Store(&s)
	x.gen.Add(1)
}

func isThreat(kind string) bool { return kind == "malware" || kind == "phishing" }

// Query queues a DNS query event if it matches the mode.
func (x *Sender) Query(e *stats.Entry) {
	s := x.set.Load()
	if !s.Enabled {
		return
	}
	blocked := e.Status == stats.StatusBlocked
	sev := 6 // informational
	switch {
	case blocked && isThreat(e.Kind):
		sev = 4 // warning
	case blocked:
		sev = 5 // notice
	}
	switch s.Mode {
	case "threats":
		if sev != 4 {
			return
		}
	case "blocked":
		if !blocked {
			return
		}
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	x.push(event{sev: sev, msgid: "QUERY", body: b, ts: e.Time})
}

// Audit queues a panel audit event (any JSON-able value).
func (x *Sender) Audit(v any) {
	s := x.set.Load()
	if !s.Enabled || !s.Audit {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	x.push(event{sev: 5, msgid: "AUDIT", body: b, ts: time.Now()})
}

func (x *Sender) push(ev event) {
	select {
	case x.ch <- ev:
	default:
		x.dropped.Add(1)
	}
}

// Format builds an RFC 5424 line (facility local0).
func (x *Sender) Format(ev event) []byte {
	pri := 16*8 + ev.sev
	return []byte(fmt.Sprintf("<%d>1 %s %s vartadns - %s - %s", pri,
		ev.ts.UTC().Format("2006-01-02T15:04:05.000000Z"), x.host, ev.msgid, ev.body))
}

// Run sends queued events until ctx ends, reconnecting with backoff.
func (x *Sender) Run(ctx context.Context) {
	var conn net.Conn
	var w *bufio.Writer
	var connGen uint64
	backoff := time.Second
	closeConn := func() {
		if conn != nil {
			conn.Close()
			conn, w = nil, nil
		}
	}
	defer closeConn()
	flushT := time.NewTicker(time.Second)
	defer flushT.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-flushT.C:
			if w != nil {
				if err := w.Flush(); err != nil {
					x.fail(err)
					closeConn()
				}
			}
			continue
		case ev := <-x.ch:
			s := x.set.Load()
			if !s.Enabled {
				closeConn()
				continue
			}
			if conn != nil && connGen != x.gen.Load() {
				closeConn()
			}
			if conn == nil {
				c, err := dial(ctx, s)
				if err != nil {
					x.fail(err)
					x.dropped.Add(1)
					select {
					case <-ctx.Done():
						return
					case <-time.After(backoff):
					}
					if backoff < time.Minute {
						backoff *= 2
					}
					continue
				}
				conn, connGen, backoff = c, x.gen.Load(), time.Second
				w = bufio.NewWriterSize(conn, 32<<10)
				x.lastErr.Store(nil)
			}
			line := x.Format(ev)
			var err error
			if s.Protocol == "udp" {
				if len(line) > 8000 {
					line = line[:8000]
				}
				_, err = conn.Write(line)
			} else {
				// RFC 6587 octet counting
				_, err = fmt.Fprintf(w, "%d %s", len(line), line)
			}
			if err != nil {
				x.fail(err)
				x.dropped.Add(1)
				closeConn()
				continue
			}
			x.sent.Add(1)
		}
	}
}

func (x *Sender) fail(err error) {
	m := err.Error()
	x.lastErr.Store(&m)
}

func dial(ctx context.Context, s *Settings) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	switch s.Protocol {
	case "udp":
		return d.DialContext(ctx, "udp", s.Address)
	case "tcp":
		return d.DialContext(ctx, "tcp", s.Address)
	}
	host, _, _ := net.SplitHostPort(s.Address)
	td := &tls.Dialer{NetDialer: d, Config: &tls.Config{ServerName: host, InsecureSkipVerify: s.Insecure, MinVersion: tls.VersionTLS12}}
	return td.DialContext(ctx, "tcp", s.Address)
}

// Status for the panel.
type Status struct {
	Sent    uint64 `json:"sent"`
	Dropped uint64 `json:"dropped"`
	Error   string `json:"error,omitempty"`
}

// Status returns counters.
func (x *Sender) Status() Status {
	st := Status{Sent: x.sent.Load(), Dropped: x.dropped.Load()}
	if e := x.lastErr.Load(); e != nil {
		st.Error = *e
	}
	return st
}
