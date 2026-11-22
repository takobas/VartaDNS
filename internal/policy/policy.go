// Package policy implements per-client groups: membership by IP, range or
// subnet, per-group blocking (custom domains, built-in services, category
// lists), allow rules, SafeSearch, an internet kill-switch and schedules.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Window is one schedule interval. Days uses Go's time.Weekday numbering
// (0 = Sunday ... 6 = Saturday). If From > To the window crosses midnight
// and belongs to the day it starts on (22:00-07:00 on Friday covers Friday
// 22:00 to Saturday 07:00).
type Window struct {
	Days []int  `json:"days"`
	From string `json:"from"` // "HH:MM"
	To   string `json:"to"`   // "HH:MM"
}

// Schedule limits when restrictions apply. Disabled = restrictions always on.
type Schedule struct {
	Enabled  bool     `json:"enabled"`
	BlockAll bool     `json:"block_all"` // no internet at all inside the windows
	Windows  []Window `json:"windows"`
}

// Group is a persisted client group.
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Members     []string  `json:"members"`    // "192.168.11.50", "192.168.11.50-192.168.11.69", "192.168.11.64/27"
	Services    []string  `json:"services"`   // service IDs from the catalog
	Categories  []string  `json:"categories"` // category IDs
	Block       []string  `json:"block"`      // custom domains to block
	Allow       []string  `json:"allow"`      // custom domains always allowed for this group
	SafeSearch  bool      `json:"safe_search"`
	InternetOff bool      `json:"internet_off"`
	OffUntil    time.Time `json:"off_until"` // zero = until switched on manually
	Schedule    Schedule  `json:"schedule"`
	// SkipKinds lists the kinds of general blocklists NOT applied to this
	// group (e.g. ["ads"] = protection without ad blocking). Empty = all.
	SkipKinds []string `json:"skip_kinds,omitempty"`
}

// ---- membership -------------------------------------------------------------------

type ipRange struct{ from, to netip.Addr }

func (r ipRange) contains(ip netip.Addr) bool {
	return ip.BitLen() == r.from.BitLen() && r.from.Compare(ip) <= 0 && ip.Compare(r.to) <= 0
}

// ParseMember parses an IP, an "a-b" range or a CIDR prefix.
func ParseMember(s string) (from, to netip.Addr, err error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return from, to, errors.New("empty member")
	case strings.Contains(s, "/"):
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return from, to, fmt.Errorf("bad subnet %q", s)
		}
		p = p.Masked()
		return p.Addr(), lastAddr(p), nil
	case strings.Contains(s, "-"):
		a, b, _ := strings.Cut(s, "-")
		from, err1 := netip.ParseAddr(strings.TrimSpace(a))
		to, err2 := netip.ParseAddr(strings.TrimSpace(b))
		if err1 != nil || err2 != nil {
			return from, to, fmt.Errorf("bad range %q", s)
		}
		from, to = from.Unmap(), to.Unmap()
		if from.BitLen() != to.BitLen() || from.Compare(to) > 0 {
			return from, to, fmt.Errorf("bad range %q (start must be <= end, same family)", s)
		}
		return from, to, nil
	default:
		a, err := netip.ParseAddr(s)
		if err != nil {
			return from, to, fmt.Errorf("bad address %q", s)
		}
		a = a.Unmap()
		return a, a, nil
	}
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		for j := 0; j < 8; j++ {
			if i*8+j >= bits {
				b[i] |= 0x80 >> j
			}
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// ---- schedule ------------------------------------------------------------------------

func parseHHMM(s string) (int, error) {
	h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, fmt.Errorf("bad time %q (use HH:MM)", s)
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 24 || mm < 0 || mm > 59 || (hh == 24 && mm != 0) {
		return 0, fmt.Errorf("bad time %q (use HH:MM)", s)
	}
	return hh*60 + mm, nil
}

type window struct {
	days     [7]bool
	from, to int // minutes since midnight
}

func (w window) active(t time.Time) bool {
	day := int(t.Weekday())
	now := t.Hour()*60 + t.Minute()
	if w.from == w.to {
		return w.days[day] // whole day
	}
	if w.from < w.to {
		return w.days[day] && now >= w.from && now < w.to
	}
	// Crosses midnight: evening part belongs to today, morning part to yesterday.
	if w.days[day] && now >= w.from {
		return true
	}
	prev := (day + 6) % 7
	return w.days[prev] && now < w.to
}

func compileWindows(ws []Window) ([]window, error) {
	out := make([]window, 0, len(ws))
	for _, w := range ws {
		var cw window
		if len(w.Days) == 0 {
			return nil, errors.New("schedule window has no days")
		}
		for _, d := range w.Days {
			if d < 0 || d > 6 {
				return nil, fmt.Errorf("bad weekday %d", d)
			}
			cw.days[d] = true
		}
		var err error
		if cw.from, err = parseHHMM(w.From); err != nil {
			return nil, err
		}
		if cw.to, err = parseHHMM(w.To); err != nil {
			return nil, err
		}
		if cw.to == 24*60 {
			cw.to = 0 // "24:00" == midnight
			if cw.from == 0 {
				cw.to = 0
			}
		}
		out = append(out, cw)
	}
	return out, nil
}
