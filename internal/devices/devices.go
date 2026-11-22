// Package devices remembers the clients seen on the network and gives them
// names: manual names from the panel first, then reverse DNS (PTR) answers
// from the router, which knows DHCP host names.
package devices

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/takobas/vartadns/internal/dnsmsg"
)

// Device is one client address.
type Device struct {
	IP        string    `json:"ip"`
	Auto      string    `json:"auto,omitempty"`   // name from reverse DNS
	Manual    string    `json:"manual,omitempty"` // name set in the panel (filled on read)
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Name returns the display name ("" = unknown).
func (d *Device) Name() string {
	if d.Manual != "" {
		return d.Manual
	}
	return d.Auto
}

type ptrInfo struct {
	name string
	exp  time.Time
}

// Limits.
const (
	MaxDevices  = 4096
	ptrTTL      = 5 * time.Minute
	ptrNegTTL   = time.Minute
	learnPeriod = time.Hour // no "new device" alerts right after the first start
	saveEvery   = 5 * time.Minute
)

// Tracker is safe for concurrent use.
type Tracker struct {
	path    string
	created time.Time

	mu    sync.Mutex
	m     map[string]*Device
	ptr   map[string]ptrInfo
	dirty bool

	manual  atomic.Pointer[map[string]string]
	server  atomic.Pointer[string] // "host:53" or ""
	lookups chan lookupReq

	// OnNew is called (from the lookup goroutine) for a device seen for
	// the first time, after its name lookup.
	OnNew func(ip, name string)

	now      func() time.Time
	resolve  func(ctx context.Context, server, ip string) (string, error)
	inflight map[string]bool
}

type lookupReq struct {
	ip    string
	isNew bool
}

type fileFormat struct {
	Created time.Time `json:"created"`
	Devices []*Device `json:"devices"`
}

// Open loads <dir>/devices.json (a missing file starts empty).
func Open(dir string) *Tracker {
	t := &Tracker{path: filepath.Join(dir, "devices.json"), m: map[string]*Device{},
		ptr: map[string]ptrInfo{}, lookups: make(chan lookupReq, 256),
		inflight: map[string]bool{}, now: time.Now}
	t.resolve = queryPTR
	empty := map[string]string{}
	t.manual.Store(&empty)
	srv := ""
	t.server.Store(&srv)
	var f fileFormat
	if b, err := os.ReadFile(t.path); err == nil && json.Unmarshal(b, &f) == nil {
		t.created = f.Created
		for _, d := range f.Devices {
			if d != nil && d.IP != "" {
				d.Manual = ""
				t.m[d.IP] = d
			}
		}
	}
	if t.created.IsZero() {
		t.created = time.Now()
		t.dirty = true
	}
	return t
}

// SetManual replaces the manual names (ip -> name).
func (t *Tracker) SetManual(m map[string]string) {
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	t.manual.Store(&cp)
}

// SetServer sets the DNS server asked for PTR names ("" = off). A bare
// address gets port 53.
func (t *Tracker) SetServer(s string) error {
	s = strings.TrimSpace(s)
	if s != "" {
		if _, err := netip.ParseAddr(s); err == nil {
			s = net.JoinHostPort(s, "53")
		} else if _, err := netip.ParseAddrPort(s); err != nil {
			return fmt.Errorf("names server must be an IP address, e.g. 192.168.11.1")
		}
	}
	t.server.Store(&s)
	t.mu.Lock()
	t.ptr = map[string]ptrInfo{} // ask the new server
	t.mu.Unlock()
	return nil
}

// Server returns the configured PTR server address.
func (t *Tracker) Server() string { return *t.server.Load() }

// CleanName keeps a printable, short host label (first label of a FQDN).
func CleanName(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	return cleanText(s, 40)
}

func cleanText(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			break
		}
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// CleanManual sanitizes a name typed in the panel.
func CleanManual(s string) string { return cleanText(s, 40) }

// Observe records a query from ip and returns its display name. It runs on
// the query path: no I/O, lookups are queued.
func (t *Tracker) Observe(ip string, now time.Time) string {
	manual := (*t.manual.Load())[ip]
	t.mu.Lock()
	d, ok := t.m[ip]
	isNew := false
	if !ok {
		if len(t.m) >= MaxDevices {
			t.evictLocked()
		}
		d = &Device{IP: ip, FirstSeen: now}
		t.m[ip] = d
		isNew = true
	}
	if now.Sub(d.LastSeen) > time.Minute {
		d.LastSeen = now
		t.dirty = true
	}
	auto := d.Auto
	p, cached := t.ptr[ip]
	needLookup := *t.server.Load() != "" && (!cached || now.After(p.exp)) && !t.inflight[ip]
	if cached {
		auto = p.name
	}
	if needLookup || isNew {
		t.inflight[ip] = needLookup
	}
	t.mu.Unlock()
	if needLookup || isNew {
		select {
		case t.lookups <- lookupReq{ip: ip, isNew: isNew}:
		default:
			t.mu.Lock()
			delete(t.inflight, ip)
			t.mu.Unlock()
		}
	}
	if manual != "" {
		return manual
	}
	return auto
}

func (t *Tracker) evictLocked() {
	var oldest *Device
	for _, d := range t.m {
		if oldest == nil || d.LastSeen.Before(oldest.LastSeen) {
			oldest = d
		}
	}
	if oldest != nil {
		delete(t.m, oldest.IP)
		delete(t.ptr, oldest.IP)
	}
}

// Run serves name lookups and saves the device list until ctx ends.
func (t *Tracker) Run(ctx context.Context) {
	save := time.NewTicker(saveEvery)
	defer save.Stop()
	defer t.Save()
	for {
		select {
		case <-ctx.Done():
			return
		case <-save.C:
			t.Save()
		case req := <-t.lookups:
			t.lookup(ctx, req)
		}
	}
}

func (t *Tracker) lookup(ctx context.Context, req lookupReq) {
	srv := *t.server.Load()
	name := ""
	ok := false
	if srv != "" {
		lctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		n, err := t.resolve(lctx, srv, req.ip)
		cancel()
		name, ok = CleanName(n), err == nil
	}
	now := t.now()
	t.mu.Lock()
	delete(t.inflight, req.ip)
	if srv != "" {
		ttl := ptrTTL
		if !ok || name == "" {
			ttl = ptrNegTTL
		}
		prev := t.ptr[req.ip]
		if !ok && prev.name != "" {
			name = prev.name // keep the last good name on timeouts
		}
		t.ptr[req.ip] = ptrInfo{name: name, exp: now.Add(ttl)}
		if d := t.m[req.ip]; d != nil && name != "" && d.Auto != name {
			d.Auto = name
			t.dirty = true
		}
	}
	learning := now.Sub(t.created) < learnPeriod
	t.mu.Unlock()
	if req.isNew && !learning && t.OnNew != nil {
		display := (*t.manual.Load())[req.ip]
		if display == "" {
			display = name
		}
		t.OnNew(req.ip, display)
	}
}

// List returns all devices, most recently seen first.
func (t *Tracker) List() []Device {
	manual := *t.manual.Load()
	t.mu.Lock()
	out := make([]Device, 0, len(t.m)+len(manual))
	seen := map[string]bool{}
	for ip, d := range t.m {
		c := *d
		c.Manual = manual[ip]
		if p, ok := t.ptr[ip]; ok && p.name != "" {
			c.Auto = p.name
		}
		out = append(out, c)
		seen[ip] = true
	}
	t.mu.Unlock()
	for ip, n := range manual { // named but not seen yet
		if !seen[ip] {
			out = append(out, Device{IP: ip, Manual: n})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// Names returns ip -> display name for every named device.
func (t *Tracker) Names() map[string]string {
	out := map[string]string{}
	for _, d := range t.List() {
		if n := d.Name(); n != "" {
			out[d.IP] = n
		}
	}
	return out
}

// Forget removes a device from the list (its manual name stays in state).
func (t *Tracker) Forget(ip string) {
	t.mu.Lock()
	delete(t.m, ip)
	delete(t.ptr, ip)
	t.dirty = true
	t.mu.Unlock()
}

// Save writes devices.json if something changed.
func (t *Tracker) Save() error {
	t.mu.Lock()
	if !t.dirty {
		t.mu.Unlock()
		return nil
	}
	f := fileFormat{Created: t.created}
	for _, d := range t.m {
		c := *d
		c.Manual = ""
		f.Devices = append(f.Devices, &c)
	}
	t.dirty = false
	t.mu.Unlock()
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, t.path)
}

// ReverseName returns the in-addr.arpa / ip6.arpa name of an address.
func ReverseName(ip string) (string, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", err
	}
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0]), nil
	}
	b := a.As16()
	var sb strings.Builder
	const hex = "0123456789abcdef"
	for i := 15; i >= 0; i-- {
		sb.WriteByte(hex[b[i]&0x0f])
		sb.WriteByte('.')
		sb.WriteByte(hex[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa")
	return sb.String(), nil
}

// queryPTR asks server for the PTR name of ip over UDP.
func queryPTR(ctx context.Context, server, ip string) (string, error) {
	rev, err := ReverseName(ip)
	if err != nil {
		return "", err
	}
	id := uint16(rand.Uint32())
	q := dnsmsg.BuildQuery(id, rev, dnsmsg.TypePTR)
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write(q); err != nil {
		return "", err
	}
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return "", err
		}
		resp := buf[:n]
		if n < 12 || dnsmsg.ID(resp) != id || !dnsmsg.IsResponse(resp) || !dnsmsg.SameQuestion(q, resp) {
			continue // not our answer
		}
		if dnsmsg.Rcode(resp) != 0 {
			return "", nil // NXDOMAIN etc.: no name
		}
		return dnsmsg.AnswerPTR(resp)
	}
}
