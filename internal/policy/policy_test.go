package policy

import (
	"net/netip"
	"testing"
	"time"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestMembership(t *testing.T) {
	p, err := Compile([]Group{
		{ID: "1", Name: "Kids", Members: []string{"192.168.11.50", "192.168.11.100-192.168.11.110", "192.168.11.64/30"}},
		{ID: "2", Name: "All", Members: []string{"192.168.11.0/24"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"192.168.11.50": "Kids", "192.168.11.100": "Kids", "192.168.11.110": "Kids",
		"192.168.11.111": "All", "192.168.11.67": "Kids", "192.168.11.68": "All",
		"10.0.0.1": "",
	}
	for a, want := range cases {
		g := p.Lookup(ip(a))
		got := ""
		if g != nil {
			got = g.Name
		}
		if got != want {
			t.Errorf("%s -> %q, want %q", a, got, want)
		}
	}
	if g := p.Lookup(ip("::ffff:192.168.11.50")); g == nil || g.Name != "Kids" {
		t.Error("IPv4-mapped address not matched")
	}
}

func TestBadMembers(t *testing.T) {
	for _, m := range []string{"192.168.11.300", "192.168.11.20-192.168.11.10", "10.0.0.0/33", "abc", "10.0.0.1-::1"} {
		if _, err := Compile([]Group{{Name: "x", Members: []string{m}}}); err == nil {
			t.Errorf("member %q accepted", m)
		}
	}
	if _, err := Compile([]Group{{Name: "x", Services: []string{"nope"}}}); err == nil {
		t.Error("unknown service accepted")
	}
}

// Kyiv-independent fixed times: 2026-11-20 is a Friday.
func at(day int, hh, mm int) time.Time {
	return time.Date(2026, 11, 16+day, hh, mm, 0, 0, time.UTC) // 16 = Monday
}

func TestScheduleWindows(t *testing.T) {
	ws, err := compileWindows([]Window{
		{Days: []int{1, 2, 3, 4, 5}, From: "08:00", To: "14:00"}, // weekdays school time
		{Days: []int{5}, From: "22:00", To: "07:00"},             // Friday night
	})
	if err != nil {
		t.Fatal(err)
	}
	g := &GroupPolicy{Group: Group{Schedule: Schedule{Enabled: true}}, windows: ws}
	check := func(tm time.Time, want bool) {
		t.Helper()
		if got := g.InWindow(tm); got != want {
			t.Errorf("%s %02d:%02d -> %v, want %v", tm.Weekday(), tm.Hour(), tm.Minute(), got, want)
		}
	}
	check(at(0, 9, 0), true)   // Monday 09:00
	check(at(0, 14, 0), false) // end is exclusive
	check(at(5, 9, 0), false)  // Saturday
	check(at(4, 23, 0), true)  // Friday 23:00
	check(at(5, 6, 59), true)  // Saturday 06:59 (Friday's window)
	check(at(5, 7, 0), false)  // Saturday 07:00
	check(at(3, 23, 0), false) // Thursday 23:00
	check(at(0, 3, 0), false)  // Monday 03:00 (Sunday has no window)

	ws, _ = compileWindows([]Window{{Days: []int{6}, From: "00:00", To: "24:00"}})
	g.windows = ws
	check(at(5, 12, 0), true) // Saturday all day
	check(at(6, 0, 1), false) // Sunday
}

func TestGroupCheck(t *testing.T) {
	cats := func(c, name string) (string, bool) {
		if c == "adult" && name == "bad.example" {
			return "bad.example", true
		}
		return "", false
	}
	p, err := Compile([]Group{{Name: "Kids", Members: []string{"192.168.11.50"},
		Services: []string{"tiktok"}, Categories: []string{"adult"},
		Block: []string{"Games.example.COM"}, Allow: []string{"edu.tiktok.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	g := p.Lookup(ip("192.168.11.50"))
	now := at(0, 12, 0)
	expect := func(name string, v Verdict) {
		t.Helper()
		if d := g.Check(name, now, cats); d.Verdict != v {
			t.Errorf("%s -> %+v, want %v", name, d, v)
		}
	}
	expect("www.tiktok.com", Block)
	expect("v16.tiktokcdn.com", Block)
	expect("edu.tiktok.com", Allow)
	expect("play.games.example.com", Block)
	expect("bad.example", Block)
	expect("wikipedia.org", Pass)

	// Schedule: restrictions only inside the window.
	g.Schedule = Schedule{Enabled: true}
	g.windows, _ = compileWindows([]Window{{Days: []int{0, 1, 2, 3, 4, 5, 6}, From: "20:00", To: "22:00"}})
	expect("www.tiktok.com", Pass) // 12:00 is outside
	if d := g.Check("www.tiktok.com", at(0, 21, 0), cats); d.Verdict != Block {
		t.Error("schedule window not applied")
	}
	// Block-all schedule.
	g.Schedule.BlockAll = true
	if d := g.Check("wikipedia.org", at(0, 21, 0), cats); d.Verdict != Block {
		t.Error("block_all schedule not applied")
	}
	// Internet kill switch with expiry.
	g.Schedule = Schedule{}
	g.Group.InternetOff = true
	g.OffUntil = now.Add(time.Hour)
	expect("wikipedia.org", Block)
	if d := g.Check("wikipedia.org", now.Add(2*time.Hour), cats); d.Verdict == Block {
		t.Error("expired internet-off still blocks")
	}
}

func TestSafeSearch(t *testing.T) {
	cases := map[string]string{
		"www.google.com": "forcesafesearch.google.com", "google.com.ua": "forcesafesearch.google.com",
		"www.google.co.uk": "forcesafesearch.google.com", "google.de": "forcesafesearch.google.com",
		"accounts.google.com": "", "google.example.org": "",
		"www.youtube.com": "restrict.youtube.com", "m.youtube.com": "restrict.youtube.com",
		"www.bing.com": "strict.bing.com", "duckduckgo.com": "safe.duckduckgo.com",
		"example.com": "",
	}
	for in, want := range cases {
		if got := SafeSearchTarget(in); got != want {
			t.Errorf("%s -> %q want %q", in, got, want)
		}
	}
}
