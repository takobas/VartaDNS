package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/takobas/vartadns/internal/dnsmsg"
	"github.com/takobas/vartadns/internal/policy"
	"github.com/takobas/vartadns/internal/stats"
)

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{{"0.3.0", "v0.3.1", true}, {"0.3.0", "v0.3.0", false}, {"0.10.0", "v0.9.9", false},
		{"0.2.3", "v1.0.0-rc1", true}, {"dev", "v9.9.9", false}}
	for _, c := range cases {
		if got := newerVersion(c.a, c.b); got != c.want {
			t.Errorf("newer(%s,%s)=%v", c.a, c.b, got)
		}
	}
}

func TestBotCommands(t *testing.T) {
	a, _, _ := newTestApp(t)
	err := a.state.update(func(s *State) {
		s.Groups = []policy.Group{{ID: "g1", Name: "Діти", Members: []string{"192.168.11.45"}}}
	})
	if err != nil {
		t.Fatal(err)
	}
	a.applyPolicy(context.Background(), false)
	ctx := context.Background()

	if r := a.botCommand(ctx, "internet", []string{"діти", "off", "30"}); !strings.Contains(r, "🔴") {
		t.Fatalf("internet off: %s", r)
	}
	g := a.state.get().Groups[0]
	if !g.InternetOff || time.Until(g.OffUntil) < 29*time.Minute {
		t.Fatalf("group not switched off: %+v", g)
	}
	q := dnsmsg.BuildQuery(7, "example.com", dnsmsg.TypeA)
	a.Resolver.Resolve(ctx, q, netip.MustParseAddr("192.168.11.45"), "udp")
	if l := a.Stats.Log(statsFilterOne()); l[0].Status != "blocked" {
		t.Fatalf("kid must be offline, got %s", l[0].Status)
	}
	if r := a.botCommand(ctx, "internet", []string{"Діти", "on"}); !strings.Contains(r, "🟢") {
		t.Fatalf("internet on: %s", r)
	}
	if r := a.botCommand(ctx, "internet", []string{"Нема", "off"}); !strings.Contains(r, "Нема") {
		t.Fatalf("unknown group: %s", r)
	}
	if r := a.botCommand(ctx, "pause", []string{"10"}); !strings.Contains(r, "10") || a.Resolver.BlockingEnabled() {
		t.Fatalf("pause: %s", r)
	}
	a.botCommand(ctx, "resume", nil)
	if !a.Resolver.BlockingEnabled() {
		t.Fatal("resume")
	}
	if r := a.botCommand(ctx, "status", nil); !strings.Contains(r, "VartaDNS") {
		t.Fatal(r)
	}
	if r := a.reportText(time.Now(), false); !strings.Contains(r, "📊") {
		t.Fatal(r)
	}
}

func TestUpdateCheck(t *testing.T) {
	a, _, _ := newTestApp(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name":"v9.0.0","html_url":"https://github.com/takobas/VartaDNS/releases/tag/v9.0.0"}`))
	}))
	defer srv.Close()
	old, oldV := ReleaseAPI, Version
	ReleaseAPI, Version = srv.URL, "0.3.0"
	defer func() { ReleaseAPI, Version = old, oldV }()
	a.checkUpdate(context.Background())
	if lv := a.latestVersion(); lv == nil || lv["tag"] != "v9.0.0" {
		t.Fatalf("latest: %v", lv)
	}
}

func statsFilterOne() stats.Filter { return stats.Filter{Limit: 1} }
