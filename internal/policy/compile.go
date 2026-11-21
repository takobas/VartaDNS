package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/takobas/vartadns/internal/filter"
)

// Verdict of a group check.
type Verdict int

const (
	Pass  Verdict = iota // no group rule matched: continue with global rules
	Block                // blocked by the group
	Allow                // allowed by the group (overrides global blocks)
)

// Decision explains a group check.
type Decision struct {
	Verdict Verdict
	Rule    string
	Source  string // e.g. "group:Kids/TikTok", "group:Kids/internet-off"
}

// CategoryChecker reports whether a name is in a loaded category list.
type CategoryChecker func(category, name string) (rule string, ok bool)

// GroupPolicy is a compiled, immutable group.
type GroupPolicy struct {
	Group
	ranges  []ipRange
	block   map[string]string // domain -> label (service name or "custom")
	allow   map[string]struct{}
	windows []window
}

// Policy is the compiled set of groups in priority order.
type Policy struct {
	groups []*GroupPolicy
}

// Normalize cleans a group in place (trims, lower-cases and de-duplicates
// domains, validates members, services, categories and schedule).
func Normalize(g *Group) error {
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" {
		return fmt.Errorf("group name is required")
	}
	var members []string
	for _, m := range g.Members {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if _, _, err := ParseMember(m); err != nil {
			return fmt.Errorf("group %q: %w", g.Name, err)
		}
		members = append(members, m)
	}
	g.Members = members
	for _, s := range g.Services {
		if serviceByID(s) == nil {
			return fmt.Errorf("group %q: unknown service %q", g.Name, s)
		}
	}
	for _, c := range g.Categories {
		if !categoryKnown(c) {
			return fmt.Errorf("group %q: unknown category %q", g.Name, c)
		}
	}
	g.Block = cleanDomains(g.Block)
	g.Allow = cleanDomains(g.Allow)
	if g.Schedule.Enabled {
		if len(g.Schedule.Windows) == 0 {
			return fmt.Errorf("group %q: schedule is enabled but has no time windows", g.Name)
		}
		if _, err := compileWindows(g.Schedule.Windows); err != nil {
			return fmt.Errorf("group %q: %w", g.Name, err)
		}
	}
	return nil
}

func cleanDomains(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, d := range in {
		if d = filter.Normalize(d); d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// Compile validates and compiles groups. Order is priority: the first group
// that contains a client's IP wins.
func Compile(groups []Group) (*Policy, error) {
	p := &Policy{}
	for _, g := range groups {
		if err := Normalize(&g); err != nil {
			return nil, err
		}
		gp := &GroupPolicy{Group: g, block: map[string]string{}, allow: map[string]struct{}{}}
		for _, m := range g.Members {
			from, to, _ := ParseMember(m)
			gp.ranges = append(gp.ranges, ipRange{from, to})
		}
		for _, sid := range g.Services {
			svc := serviceByID(sid)
			for _, d := range svc.Domains {
				gp.block[d] = svc.Name
			}
		}
		for _, d := range g.Block {
			gp.block[d] = "custom"
		}
		for _, d := range g.Allow {
			gp.allow[d] = struct{}{}
		}
		if g.Schedule.Enabled {
			gp.windows, _ = compileWindows(g.Schedule.Windows)
		}
		p.groups = append(p.groups, gp)
	}
	return p, nil
}

// Groups returns the compiled groups in priority order.
func (p *Policy) Groups() []*GroupPolicy {
	if p == nil {
		return nil
	}
	return p.groups
}

// Lookup returns the first group containing ip, or nil.
func (p *Policy) Lookup(ip netip.Addr) *GroupPolicy {
	if p == nil {
		return nil
	}
	ip = ip.Unmap()
	for _, g := range p.groups {
		for _, r := range g.ranges {
			if r.contains(ip) {
				return g
			}
		}
	}
	return nil
}

// UsedCategories lists categories enabled by at least one group.
func (p *Policy) UsedCategories() []string {
	if p == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range p.groups {
		for _, c := range g.Categories {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// InWindow reports whether a schedule window is active now.
func (g *GroupPolicy) InWindow(now time.Time) bool {
	for _, w := range g.windows {
		if w.active(now) {
			return true
		}
	}
	return false
}

// RestrictionsActive: without a schedule restrictions always apply; with a
// schedule only inside its windows.
func (g *GroupPolicy) RestrictionsActive(now time.Time) bool {
	return !g.Schedule.Enabled || g.InWindow(now)
}

// InternetOff reports whether the group has no internet right now and why.
func (g *GroupPolicy) InternetOff(now time.Time) (bool, string) {
	if g.Group.InternetOff && (g.OffUntil.IsZero() || now.Before(g.OffUntil)) {
		return true, "internet-off"
	}
	if g.Schedule.Enabled && g.Schedule.BlockAll && g.InWindow(now) {
		return true, "schedule"
	}
	return false, ""
}

func suffixLookup[V any](m map[string]V, name string) (string, V, bool) {
	var zero V
	if len(m) == 0 {
		return "", zero, false
	}
	for {
		if v, ok := m[name]; ok {
			return name, v, true
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			return "", zero, false
		}
		name = name[dot+1:]
	}
}

// Check applies the group's rules to a name.
func (g *GroupPolicy) Check(name string, now time.Time, cats CategoryChecker) Decision {
	src := "group:" + g.Name
	if off, why := g.InternetOff(now); off {
		return Decision{Verdict: Block, Rule: name, Source: src + "/" + why}
	}
	if rule, _, ok := suffixLookup(g.allow, name); ok {
		return Decision{Verdict: Allow, Rule: rule, Source: src}
	}
	if !g.RestrictionsActive(now) {
		return Decision{}
	}
	if rule, label, ok := suffixLookup(g.block, name); ok {
		return Decision{Verdict: Block, Rule: rule, Source: src + "/" + label}
	}
	if cats != nil {
		for _, c := range g.Categories {
			if rule, ok := cats(c, name); ok {
				return Decision{Verdict: Block, Rule: rule, Source: src + "/" + c}
			}
		}
	}
	return Decision{}
}

// ---- SafeSearch ---------------------------------------------------------------------

// SafeSearchTarget returns the provider's enforced-safe hostname for a
// search/video host, or "" if the name is not a search host. The targets
// are the providers' documented SafeSearch mechanisms (DNS CNAME).
func SafeSearchTarget(name string) string {
	switch name {
	case "www.youtube.com", "m.youtube.com", "youtube.com", "youtubei.googleapis.com",
		"youtube.googleapis.com", "www.youtube-nocookie.com":
		return "restrict.youtube.com"
	case "www.bing.com", "bing.com":
		return "strict.bing.com"
	case "duckduckgo.com", "www.duckduckgo.com", "start.duckduckgo.com":
		return "safe.duckduckgo.com"
	}
	if isGoogleSearch(name) {
		return "forcesafesearch.google.com"
	}
	return ""
}

// isGoogleSearch matches google.<tld>, google.com.<cc>, google.co.<cc>
// with or without "www.".
func isGoogleSearch(name string) bool {
	name = strings.TrimPrefix(name, "www.")
	rest, ok := strings.CutPrefix(name, "google.")
	if !ok || rest == "" {
		return false
	}
	labels := strings.Split(rest, ".")
	switch len(labels) {
	case 1:
		return len(labels[0]) >= 2 && len(labels[0]) <= 3
	case 2:
		return (labels[0] == "com" || labels[0] == "co") && len(labels[1]) == 2
	}
	return false
}
