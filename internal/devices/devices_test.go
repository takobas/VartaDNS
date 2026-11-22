package devices

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestReverseName(t *testing.T) {
	if r, _ := ReverseName("192.168.11.45"); r != "45.11.168.192.in-addr.arpa" {
		t.Fatal(r)
	}
	if r, _ := ReverseName("2001:db8::1"); r != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" {
		t.Fatal(r)
	}
}

func TestObserveNamesAndNew(t *testing.T) {
	tr := Open(t.TempDir())
	tr.created = time.Now().Add(-2 * time.Hour) // past the learning period
	tr.SetServer("192.168.11.1")
	tr.resolve = func(ctx context.Context, srv, ip string) (string, error) {
		if srv != "192.168.11.1:53" {
			t.Errorf("server %s", srv)
		}
		return "iPhone-Maksym.lan", nil
	}
	var mu sync.Mutex
	var news []string
	tr.OnNew = func(ip, name string) { mu.Lock(); news = append(news, ip+"="+name); mu.Unlock() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	if n := tr.Observe("192.168.11.45", time.Now()); n != "" {
		t.Fatalf("first observe has no name yet, got %q", n)
	}
	deadline := time.Now().Add(2 * time.Second)
	for tr.Observe("192.168.11.45", time.Now()) != "iPhone-Maksym" {
		if time.Now().After(deadline) {
			t.Fatal("PTR name not applied")
		}
		time.Sleep(10 * time.Millisecond)
	}
	tr.SetManual(map[string]string{"192.168.11.45": "Телефон Максима"})
	if n := tr.Observe("192.168.11.45", time.Now()); n != "Телефон Максима" {
		t.Fatalf("manual name must win, got %q", n)
	}
	mu.Lock()
	if len(news) != 1 || news[0] != "192.168.11.45=iPhone-Maksym" {
		t.Fatalf("new device events: %v", news)
	}
	mu.Unlock()
	if err := tr.Save(); err != nil {
		t.Fatal(err)
	}
	tr2 := Open(tr.path[:len(tr.path)-len("/devices.json")])
	if l := tr2.List(); len(l) != 1 || l[0].Auto != "iPhone-Maksym" {
		t.Fatalf("reload: %+v", l)
	}
}

func TestLearningPeriod(t *testing.T) {
	tr := Open(t.TempDir())
	called := false
	tr.OnNew = func(string, string) { called = true }
	tr.lookup(context.Background(), lookupReq{ip: "10.0.0.5", isNew: true})
	if called {
		t.Fatal("no new-device alerts during the learning period")
	}
	if CleanName("host\x07name.home.arpa") != "hostname" {
		t.Fatal("clean name")
	}
}
