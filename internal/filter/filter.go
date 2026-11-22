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

// Kind classes of lists. A client can be given only some of them (e.g.
// malware and phishing but no ad blocking).
const (
	ClassMalware  uint8 = 1 << iota
	ClassPhishing       // 2
	ClassAds            // 4
	ClassOther          // 8
	ClassAll      = ClassMalware | ClassPhishing | ClassAds | ClassOther
)

// KindClass maps a list kind name to its class bit (unknown = other).
func KindClass(kind string) uint8 {
	switch kind {
	case "malware":
		return ClassMalware
	case "phishing":
		return ClassPhishing
	case "ads":
		return ClassAds
	}
	return ClassOther
}

// set is an immutable, compact rule set: sorted 64-bit hashes of every
// domain plus a parallel slice of source indexes (~10 bytes per rule).
// A domain present in lists of different classes is kept once per class
// (adjacent entries), so a lookup restricted to some classes still finds
// the right list.
type set struct {
	seed     maphash.Seed
	hashes   []uint64
	src      []uint16
	sources  []string
	classes  []uint8 // class of each source
	classAll uint8   // union of classes present
	unique   int     // distinct domains
}

// has returns the index of an entry for name whose source class is in mask.
func (s *set) has(name string, mask uint8) (int, bool) {
	h := maphash.String(s.seed, name)
	i, ok := slices.BinarySearch(s.hashes, h)
	if !ok {
		return 0, false
	}
	for ; i < len(s.hashes) && s.hashes[i] == h; i++ {
		if s.classes[s.src[i]]&mask != 0 {
			return i, true
		}
	}
	return 0, false
}

func (s *set) lookup(name string, mask uint8) (string, string, bool) {
	if s == nil || len(s.hashes) == 0 || s.classAll&mask == 0 {
		return "", "", false
	}
	// Walk from the full name towards the TLD: a.b.example.com, b.example.com, ...
	for {
		if i, ok := s.has(name, mask); ok {
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
func (e *Engine) Check(name string) Match { return e.CheckClasses(name, ClassAll) }

// CheckClasses is Check using only block lists of the given classes (allow
// lists and custom rules always apply).
func (e *Engine) CheckClasses(name string, mask uint8) Match {
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
	if r, src, ok := e.allow.Load().lookup(name, ClassAll); ok {
		return Match{Verdict: Allowed, Rule: r, Source: src}
	}
	if r, src, ok := e.block.Load().lookup(name, mask); ok {
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
	classes []uint8
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
	return b.AddClass(name, r, allowList, ClassOther)
}

// AddClass is Add for a list of the given class (see KindClass).
func (b *Builder) AddClass(name string, r io.Reader, allowList bool, class uint8) (int, error) {
	idx := uint16(len(b.sources))
	b.sources = append(b.sources, name)
	b.classes = append(b.classes, class)
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

// finish sorts and de-duplicates pairs: one entry per hash and class,
// keeping the first list's source of each class.
func finish(seed maphash.Seed, ps []pair, sources []string, classes []uint8) (*set, int) {
	slices.SortStableFunc(ps, func(a, b pair) int {
		switch {
		case a.h < b.h:
			return -1
		case a.h > b.h:
			return 1
		}
		return 0
	})
	s := &set{seed: seed, sources: sources, classes: classes}
	s.hashes = make([]uint64, 0, len(ps))
	s.src = make([]uint16, 0, len(ps))
	unique := 0
	var seen uint8 // classes already stored for the current hash
	for i, p := range ps {
		c := classes[p.src]
		if i == 0 || p.h != ps[i-1].h {
			seen = 0
			unique++
		}
		if seen&c != 0 {
			continue
		}
		seen |= c
		s.classAll |= c
		s.hashes = append(s.hashes, p.h)
		s.src = append(s.src, p.src)
	}
	s.unique = unique
	return s, unique
}

// Apply swaps the collected rules into the engine and releases the builder.
func (b *Builder) Apply(e *Engine) {
	bs, nb := finish(b.seed, b.block, b.sources, b.classes)
	as, na := finish(b.seed, b.allow, b.sources, b.classes)
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
		block = s.unique
	}
	if s := e.allow.Load(); s != nil {
		allow = s.unique
	}
	return
}

// ParseLine extracts a domain from one line of a hosts file, a plain domain
// list, an Adblock-style list or an RPZ zone. exception reports an allow
// rule ("@@" in Adblock, rpz-passthru in RPZ).
func ParseLine(line string) (domain string, exception bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	switch line[0] {
	case '#', '!', '[', ';', '$':
		return "", false
	}
	if d, exc, ok := parseRPZ(line); ok {
		return d, exc
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

// parseRPZ handles one RPZ (Response Policy Zone) record, as published for
// BIND, PowerDNS Recursor, Knot Resolver and Unbound:
//
//	example.com CNAME .               block (NXDOMAIN)
//	*.example.com CNAME .             block (subdomains; suffix match covers both)
//	example.com 300 IN CNAME *.       block (NODATA)
//	example.com CNAME rpz-drop.       block (drop)
//	example.com CNAME rpz-passthru.   allow (exception)
//
// Other targets (redirects to a walled garden) are treated as blocks.
// SOA/NS/A records and IP-based triggers (rpz-ip, rpz-nsdname...) are
// skipped. ok=false: not an RPZ line.
func parseRPZ(line string) (domain string, exception, ok bool) {
	if i := strings.IndexByte(line, ';'); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	ci := -1
	for i, x := range f {
		if strings.EqualFold(x, "CNAME") {
			ci = i
			break
		}
	}
	if ci < 1 || ci != len(f)-2 {
		for _, x := range f {
			switch strings.ToUpper(x) {
			case "SOA", "NS":
				return "", false, true // zone header
			}
		}
		return "", false, false
	}
	name, target := f[0], strings.ToLower(f[len(f)-1])
	if name == "@" {
		return "", false, true
	}
	for _, l := range strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".") {
		switch l {
		case "rpz-ip", "rpz-nsip", "rpz-nsdname", "rpz-client-ip":
			return "", false, true // IP/NS triggers are not domain rules
		}
	}
	d := Normalize(name)
	if d == "" {
		return "", false, true
	}
	return d, target == "rpz-passthru.", true
}
