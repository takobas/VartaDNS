package app

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/takobas/vartadns/internal/dnsmsg"
	"github.com/takobas/vartadns/internal/policy"
	"github.com/takobas/vartadns/internal/stats"
)

func TestListKindsPerGroupAndBypass(t *testing.T) {
	a, h, tok := newTestApp(t)
	ads := filepath.Join(a.cfg.DataDir, "ads.txt")
	os.WriteFile(ads, []byte("tracker.example\n"), 0o644)
	a.state.update(func(s *State) {
		s.Lists = append(s.Lists, ListSpec{Name: "Ads", URL: ads, Enabled: true, Kind: KindAds})
		s.Groups = []policy.Group{{ID: "acc", Name: "Бухгалтерія", Members: []string{"192.168.11.10"}, SkipKinds: []string{"ads"}}}
	})
	a.RebuildLists(context.Background(), false)
	a.applyPolicy(context.Background(), false)
	ctx := context.Background()
	status := func(ip, name string) string {
		a.Resolver.Resolve(ctx, dnsmsg.BuildQuery(1, name, dnsmsg.TypeA), netip.MustParseAddr(ip), "udp")
		return a.Stats.Log(stats.Filter{Limit: 1})[0].Status
	}
	if s := status("192.168.11.10", "tracker.example"); s == stats.StatusBlocked {
		t.Fatal("accounting must not get ad blocking")
	}
	if s := status("192.168.11.10", "evil.example"); s != stats.StatusBlocked {
		t.Fatal("accounting must keep malware blocking")
	}
	if s := status("192.168.11.50", "tracker.example"); s != stats.StatusBlocked {
		t.Fatal("others get ad blocking by default")
	}
	// default for clients outside groups: no ads
	if w := call(t, h, tok, "PUT", "/api/filtering", []byte(`{"default_skip_kinds":["ads"],"bypass_clients":["192.168.11.200"]}`)); w.Code != 200 {
		t.Fatalf("filtering: %d %s", w.Code, w.Body)
	}
	if s := status("192.168.11.50", "tracker.example"); s == stats.StatusBlocked {
		t.Fatal("default skip ads not applied")
	}
	if s := status("192.168.11.200", "evil.example"); s == stats.StatusBlocked {
		t.Fatal("bypass client must not be filtered")
	}
	if w := call(t, h, tok, "PUT", "/api/filtering", []byte(`{"default_skip_kinds":["nope"]}`)); w.Code != 400 {
		t.Fatalf("bad kind must fail: %d", w.Code)
	}
}
