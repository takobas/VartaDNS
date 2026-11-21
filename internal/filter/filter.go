// Package filter holds the domain block/allow rules and matches names
// against them. Matching is suffix-based: a rule for "example.com" also
// covers "ads.example.com".
package filter

import (
	"bufio"
	"hash/maphash"
	"io"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Verdict is the result of a lookup.
type Verdict int

const (
	Pass    Verdict = iota // no rule matched
	Blocked                // a block rule matched
	Allowed                // an allow rule matched (overrides block)
)

// Match explains a verdict.
type Match struct {
	Verdict Verdict
	Rule    string // the matching rule (domain suffix)
	Source  string // list name or "custom"
}

// set is an immutable, compact rule set: sorted 64-bit hashes of every
// domain plus a parallel slice of source indexes (~10 bytes per rule).
type set struct {
	seed    maphash.Seed
	hashes  []uint64
	src     []uint16
	sources []string
}

func (s *set) has(name string) (int, bool) {
	h := maphash.String(s.seed, name)
	i, ok := slices.BinarySearch(s.hashes, h)
	return i, ok
}

func (s *set) lookup(name string) (string, string, bool) {
	if s == nil || len(s.hashes) == 0 {
		return "", "", false
	}
	// Walk from the full name towards the TLD: a.b.example.com, b.example.com, ...
	for {
		if i, ok := s.has(name); ok {
			return name, s.sources[s.src[i]], true
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			return "", "", false
		}
		name = name[dot+1:]
	}
}

// Engine combines list-based rules (rebuilt on reload) and custom rules
// (edited live from the web panel).
type Engine struct {
	block atomic.Pointer[set]
	allow atomic.Pointer[set]

	mu          sync.RWMutex
	customBlock map[string]struct{}
	customAllow map[string]struct{}
}

// New returns an empty engine.
func New() *Engine {
	return &Engine{
		customBlock: map[string]struct{}{},
		customAllow: map[string]struct{}{},
	}
}

// Check returns the verdict for a lower-cased name without trailing dot.
// Priority: custom allow > custom block > list allow > list block.
func (e *Engine) Check(name string) Match {
	if name == "" {
		return Match{}
	}
	e.mu.RLock()
	if r, ok := lookupMap(e.customAllow, name); ok {
		e.mu.RUnlock()
		return Match{Verdict: Allowed, Rule: r, Source: "custom"}
	}
	if r, ok := lookupMap(e.customBlock, name); ok {
		e.mu.RUnlock()
		return Match{Verdict: Blocked, Rule: r, Source: "custom"}
	}
	e.mu.RUnlock()
	if r, src, ok := e.allow.Load().lookup(name); ok {
		return Match{Verdict: Allowed, Rule: r, Source: src}
	}
	if r, src, ok := e.block.Load().lookup(name); ok {
		return Match{Verdict: Blocked, Rule: r, Source: src}
	}
	return Match{}
}

func lookupMap(m map[string]struct{}, name string) (string, bool) {
	if len(m) == 0 {
		return "", false
	}
	for {
		if _, ok := m[name]; ok {
			return name, true
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			return "", false
		}
		name = name[dot+1:]
	}
}

// ---- custom rules -------------------------------------------------------------

// SetCustom replaces the custom rule sets.
func (e *Engine) SetCustom(block, allow []string) {
	b := make(map[string]struct{}, len(block))
	for _, d := range block {
		if d = Normalize(d); d != "" {
			b[d] = struct{}{}
		}
	}
	a := make(map[string]struct{}, len(allow))
	for _, d := range allow {
		if d = Normalize(d); d != "" {
			a[d] = struct{}{}
		}
	}
	e.mu.Lock()
	e.customBlock, e.customAllow = b, a
	e.mu.Unlock()
}

// Custom returns sorted copies of the custom rules.
func (e *Engine) Custom() (block, allow []string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for d := range e.customBlock {
		block = append(block, d)
	}
	for d := range e.customAllow {
		allow = append(allow, d)
	}
	sort.Strings(block)
	sort.Strings(allow)
	return
}

// ---- list loading -----------------------------------------------------------------

type pair struct {
	h   uint64
	src uint16
}

// Builder accumulates rules from several lists and swaps them in atomically.
type Builder struct {
	seed    maphash.Seed
	block   []pair
	allow   []pair
	sources []string
	nBlock  int
	nAllow  int
}

// NewBuilder creates a builder; sizeHint pre-allocates the block slice.
func NewBuilder(sizeHint int) *Builder {
	return &Builder{seed: maphash.MakeSeed(), block: make([]pair, 0, sizeHint)}
}

// Add parses one list. If allowList is true every entry is an allow rule;
// otherwise "@@" adblock exceptions inside the list become allow rules.
// It returns the number of rules read from this list.
func (b *Builder) Add(name string, r io.Reader, allowList bool) (int, error) {
	idx := uint16(len(b.sources))
	b.sources = append(b.sources, name)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		dom, exception := ParseLine(sc.Text())
		if dom == "" {
			continue
		}
		p := pair{h: maphash.String(b.seed, dom), src: idx}
		if allowList || exception {
			b.allow = append(b.allow, p)
		} else {
			b.block = append(b.block, p)
		}
		n++
	}
	return n, sc.Err()
}

// finish sorts and de-duplicates pairs (keeping the first list's source).
func finish(seed maphash.Seed, ps []pair, sources []string) (*set, int) {
	slices.SortStableFunc(ps, func(a, b pair) int {
		switch {
		case a.h < b.h:
			return -1
		case a.h > b.h:
			return 1
		}
		return 0
	})
	s := &set{seed: seed, sources: sources}
	s.hashes = make([]uint64, 0, len(ps))
	s.src = make([]uint16, 0, len(ps))
	for i, p := range ps {
		if i > 0 && p.h == ps[i-1].h {
			continue
		}
		s.hashes = append(s.hashes, p.h)
		s.src = append(s.src, p.src)
	}
	return s, len(s.hashes)
}

// Apply swaps the collected rules into the engine and releases the builder.
func (b *Builder) Apply(e *Engine) {
	bs, nb := finish(b.seed, b.block, b.sources)
	as, na := finish(b.seed, b.allow, b.sources)
	b.block, b.allow = nil, nil
	b.nBlock, b.nAllow = nb, na
	e.block.Store(bs)
	e.allow.Store(as)
}

// Counts returns the number of unique block and allow rules after Apply.
func (b *Builder) Counts() (int, int) { return b.nBlock, b.nAllow }

// RuleCounts returns the active list-based rule counts.
func (e *Engine) RuleCounts() (block, allow int) {
	if s := e.block.Load(); s != nil {
		block = len(s.hashes)
	}
	if s := e.allow.Load(); s != nil {
		allow = len(s.hashes)
	}
	return
}

// ParseLine extracts a domain from one line of a hosts file, a plain domain
// list or an Adblock-style list. exception reports an "@@" allow rule.
func ParseLine(line string) (domain string, exception bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	switch line[0] {
	case '#', '!', '[':
		return "", false
	}
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}

	if strings.HasPrefix(line, "@@") {
		exception = true
		line = line[2:]
	}
	if strings.HasPrefix(line, "||") {
		// Adblock syntax: ||example.com^ or ||example.com^$important
		line = line[2:]
		end := strings.IndexAny(line, "^$/")
		if end < 0 {
			end = len(line)
		}
		rest := line[end:]
		line = line[:end]
		// Rules with modifiers other than $important are page-level: skip them.
		if i := strings.IndexByte(rest, '$'); i >= 0 {
			mods := rest[i+1:]
			if mods != "important" && mods != "" {
				return "", false
			}
		}
		return Normalize(line), exception
	}
	if exception {
		return "", false // unsupported exception syntax
	}

	fields := strings.Fields(line)
	switch len(fields) {
	case 0:
		return "", false
	case 1:
		return Normalize(fields[0]), false
	default:
		// hosts format: "0.0.0.0 domain [domain...]" (only the first is used)
		if _, err := netip.ParseAddr(fields[0]); err == nil {
			d := Normalize(fields[1])
			switch d {
			case "localhost", "localhost.localdomain", "local", "broadcasthost",
				"ip6-localhost", "ip6-loopback", "0.0.0.0":
				return "", false
			}
			return d, false
		}
		return "", false
	}
}

// Normalize lower-cases a domain, strips wildcard prefixes and the trailing
// dot, and rejects anything that is not a plausible hostname.
func Normalize(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimPrefix(d, ".")
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return ""
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return ""
		}
	}
	if strings.Contains(d, "..") {
		return ""
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "" // bare IPs are not domain rules
	}
	return d
}
