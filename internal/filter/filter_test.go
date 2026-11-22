package filter

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseLine(t *testing.T) {
	cases := []struct {
		in   string
		want string
		exc  bool
	}{
		{"0.0.0.0 ads.example.com", "ads.example.com", false},
		{"127.0.0.1\tTracker.Example.com  # comment", "tracker.example.com", false},
		{"0.0.0.0 localhost", "", false},
		{"::1 ip6-localhost", "", false},
		{"example.org", "example.org", false},
		{"*.wild.example.net", "wild.example.net", false},
		{"||doubleclick.net^", "doubleclick.net", false},
		{"||ads.site.com^$important", "ads.site.com", false},
		{"||site.com^$third-party", "", false},
		{"@@||good.example.com^", "good.example.com", true},
		{"# comment", "", false},
		{"! adblock comment", "", false},
		{"[Adblock Plus 2.0]", "", false},
		{"localhost", "", false},
		{"1.2.3.4", "", false},
		{"bad_domain!.com", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, exc := ParseLine(c.in)
		if got != c.want || exc != c.exc {
			t.Errorf("ParseLine(%q) = %q,%v want %q,%v", c.in, got, exc, c.want, c.exc)
		}
	}
}

func TestEngine(t *testing.T) {
	e := New()
	b := NewBuilder(0)
	_, _ = b.Add("ads", strings.NewReader("example.com\n0.0.0.0 tracker.net\n@@||ok.example.com^\n"), false)
	_, _ = b.Add("allow", strings.NewReader("safe.tracker.net\n"), true)
	b.Apply(e)

	check := func(name string, want Verdict, rule string) {
		t.Helper()
		m := e.Check(name)
		if m.Verdict != want || m.Rule != rule {
			t.Errorf("Check(%q) = %+v, want verdict %v rule %q", name, m, want, rule)
		}
	}
	check("example.com", Blocked, "example.com")
	check("a.b.example.com", Blocked, "example.com")
	check("notexample.com", Pass, "")
	check("ok.example.com", Allowed, "ok.example.com")
	check("x.ok.example.com", Allowed, "ok.example.com")
	check("safe.tracker.net", Allowed, "safe.tracker.net")
	check("evil.tracker.net", Blocked, "tracker.net")
	check("com", Pass, "")

	// Custom rules take priority over lists.
	e.SetCustom([]string{"safe.tracker.net", "facebook.com"}, []string{"example.com"})
	check("www.example.com", Allowed, "example.com")
	check("m.facebook.com", Blocked, "facebook.com")
	check("safe.tracker.net", Blocked, "safe.tracker.net")
}

func BenchmarkCheck(b *testing.B) {
	e := New()
	bl := NewBuilder(1000000)
	var sb strings.Builder
	for i := 0; i < 1000000; i++ {
		fmt.Fprintf(&sb, "host%d.blocked%d.com\n", i, i%5000)
	}
	_, _ = bl.Add("big", strings.NewReader(sb.String()), false)
	bl.Apply(e)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Check("cdn.static.www.some-normal-site.example.org")
	}
}

func TestClassesAndRPZ(t *testing.T) {
	b := NewBuilder(0)
	b.AddClass("Ads", strings.NewReader("tracker.example\nboth.example\n"), false, ClassAds)
	b.AddClass("Malware", strings.NewReader("evil.example\nboth.example\n"), false, ClassMalware)
	rpz := `$TTL 300
@ SOA localhost. root.localhost. 1 3600 600 86400 300
  NS localhost.
; comment
rpz-blocked.example CNAME .
*.rpz-blocked.example CNAME .
nodata.example 300 IN CNAME *.
ok.rpz-blocked.example CNAME rpz-passthru.
32.1.0.0.10.rpz-ip CNAME .
`
	n, err := b.AddClass("RPZ", strings.NewReader(rpz), false, ClassOther)
	if err != nil || n != 4 {
		t.Fatalf("rpz rules: %d %v", n, err)
	}
	e := New()
	b.Apply(e)
	if blk, alw := e.RuleCounts(); blk != 5 || alw != 1 {
		t.Fatalf("counts %d %d", blk, alw)
	}
	// "both.example" is in ads and malware: a malware-only client still
	// gets it blocked and sees the malware list as source.
	if m := e.CheckClasses("both.example", ClassMalware); m.Verdict != Blocked || m.Source != "Malware" {
		t.Fatalf("both/malware: %+v", m)
	}
	if m := e.CheckClasses("both.example", ClassAds); m.Verdict != Blocked || m.Source != "Ads" {
		t.Fatalf("both/ads: %+v", m)
	}
	if m := e.CheckClasses("tracker.example", ClassMalware|ClassPhishing); m.Verdict != Pass {
		t.Fatalf("ads must pass for a malware-only client: %+v", m)
	}
	if m := e.Check("x.rpz-blocked.example"); m.Verdict != Blocked {
		t.Fatalf("rpz block: %+v", m)
	}
	if m := e.Check("ok.rpz-blocked.example"); m.Verdict != Allowed {
		t.Fatalf("rpz passthru: %+v", m)
	}
	if m := e.Check("nodata.example"); m.Verdict != Blocked {
		t.Fatalf("rpz nodata: %+v", m)
	}
}
