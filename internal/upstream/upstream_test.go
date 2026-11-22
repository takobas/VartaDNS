package upstream

import (
	"context"
	"testing"
	"time"
)

type fakeUp struct{ name string }

func (f fakeUp) Exchange(context.Context, []byte) ([]byte, error) { return nil, nil }
func (f fakeUp) String() string                                   { return f.name }

func newTestGroup() *Group {
	doh := &member{u: fakeUp{"doh"}, encrypted: true}
	fast := &member{u: fakeUp{"udp-fast"}}
	slow := &member{u: fakeUp{"udp-slow"}}
	doh.latency.Store(int64(250 * time.Millisecond / time.Microsecond))
	fast.latency.Store(int64(19 * time.Millisecond / time.Microsecond))
	slow.latency.Store(int64(62 * time.Millisecond / time.Microsecond))
	g := &Group{timeout: time.Second}
	list := []*member{doh, slow, fast}
	g.ms.Store(&list)
	return g
}

func names(ms []*member) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.u.String()
	}
	return out
}

func TestOrderingStrategies(t *testing.T) {
	g := newTestGroup()
	g.SetStrategy(EncryptedFirst)
	if got := names(g.ordered()); got[0] != "doh" || got[1] != "udp-fast" {
		t.Fatalf("encrypted-first order = %v", got)
	}
	g.SetStrategy(Fastest)
	if got := names(g.ordered()); got[0] != "udp-fast" || got[2] != "doh" {
		t.Fatalf("fastest order = %v", got)
	}
	// An unhealthy DoH falls back to plain DNS even in encrypted-first.
	g.SetStrategy(EncryptedFirst)
	g.list()[0].fails.Store(3)
	if got := names(g.ordered()); got[0] != "udp-fast" {
		t.Fatalf("unhealthy DoH still first: %v", got)
	}
	// A successful probe/exchange brings it back.
	g.list()[0].record(true, 30*time.Millisecond)
	if got := names(g.ordered()); got[0] != "doh" {
		t.Fatalf("recovered DoH not first: %v", got)
	}
	st := g.Statuses()
	if !st[0].Primary || !st[0].Encrypted || st[1].Primary {
		t.Fatalf("statuses wrong: %+v", st)
	}
}

func TestParseStrategy(t *testing.T) {
	for in, want := range map[string]Strategy{"": EncryptedFirst, "encrypted-first": EncryptedFirst, "fastest": Fastest} {
		if got, err := ParseStrategy(in); err != nil || got != want {
			t.Errorf("%q -> %v %v", in, got, err)
		}
	}
	if _, err := ParseStrategy("x"); err == nil {
		t.Error("bad strategy accepted")
	}
}
