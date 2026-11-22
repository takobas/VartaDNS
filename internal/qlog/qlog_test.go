package qlog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/takobas/vartadns/internal/stats"
)

func ent(t time.Time, client, name, status, kind string) stats.Entry {
	return stats.Entry{Time: t, Client: client, Name: name, Status: status, Kind: kind, Type: "A"}
}

func newTestLog(t *testing.T, s Settings) (*Log, *time.Time) {
	t.Helper()
	l, err := New(t.TempDir(), s, Events{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.Local)
	l.now = func() time.Time { return now }
	l.freeFn = func(string) int64 { return -1 }
	return l, &now
}

func TestModes(t *testing.T) {
	l, _ := newTestLog(t, DefaultSettings())
	blk := ent(time.Now(), "1.1.1.1", "ads.example", stats.StatusBlocked, "ads")
	mal := ent(time.Now(), "1.1.1.1", "evil.example", stats.StatusBlocked, "malware")
	fwd := ent(time.Now(), "1.1.1.1", "ok.example", stats.StatusForwarded, "")
	cases := []struct {
		mode          string
		blk, mal, fwd bool
	}{
		{ModeOff, false, false, false},
		{ModeThreats, false, true, false},
		{ModeBlocked, true, true, false},
		{ModeAll, true, true, true},
	}
	for _, c := range cases {
		s := DefaultSettings()
		s.Mode = c.mode
		l.SetSettings(s)
		if l.Wants(&blk) != c.blk || l.Wants(&mal) != c.mal || l.Wants(&fwd) != c.fwd {
			t.Errorf("mode %s: wrong selection", c.mode)
		}
	}
}

func TestWriteCompressPageExport(t *testing.T) {
	s := DefaultSettings()
	s.Mode = ModeAll
	l, now := newTestLog(t, s)
	var batch []stats.Entry
	for d := 2; d >= 0; d-- {
		day := now.AddDate(0, 0, -d)
		for i := 0; i < 50; i++ {
			c := "192.168.11.10"
			if i%2 == 1 {
				c = "192.168.11.20"
			}
			batch = append(batch, ent(day.Add(time.Duration(i)*time.Second), c,
				fmt.Sprintf("d%d-%d.example", d, i), stats.StatusBlocked, "ads"))
		}
	}
	l.writeBatch(batch[:70]) // two batches: the second reuses the open file
	l.writeBatch(batch[70:])
	l.Cleanup()
	files := l.Files()
	if len(files) != 3 {
		t.Fatalf("want 3 day files, got %+v", files)
	}
	if !files[0].Gz || !files[1].Gz || files[2].Gz {
		t.Fatalf("old days must be gzipped, today plain: %+v", files)
	}

	ctx := context.Background()

	q := Query{Clients: map[string]bool{"192.168.11.20": true}}
	page, more, err := l.Page(ctx, q, 0, 10)
	if err != nil || len(page) != 10 || !more {
		t.Fatalf("page: %d more=%v err=%v", len(page), more, err)
	}
	if page[0].Name != "d0-49.example" || page[1].Name != "d0-47.example" {
		t.Fatalf("newest first expected, got %s, %s", page[0].Name, page[1].Name)
	}
	// page crossing a day boundary
	page, _, _ = l.Page(context.Background(), q, 20, 10)
	if len(page) != 10 || page[0].Name != "d0-9.example" || page[5].Name != "d1-49.example" {
		t.Fatalf("cross-day page wrong: %s .. %s", page[0].Name, page[5].Name)
	}

	day1 := now.AddDate(0, 0, -1).Format(dayLayout)
	n := 0
	err = l.Each(context.Background(), Query{From: day1, To: day1}, func(e *stats.Entry) error {
		if !strings.HasPrefix(e.Name, "d1-") {
			t.Errorf("out of range entry %s", e.Name)
		}
		n++
		return nil
	})
	if err != nil || n != 50 {
		t.Fatalf("each: n=%d err=%v", n, err)
	}
}

func TestRetentionSizeFree(t *testing.T) {
	s := DefaultSettings()
	s.RetentionDays = 5
	l, now := newTestLog(t, s)
	var mu sync.Mutex
	var events []CleanupEvent
	full := make(chan int64, 1)
	l.ev = Events{
		OnCleanup: func(e CleanupEvent) { mu.Lock(); events = append(events, e); mu.Unlock() },
		OnFull:    func(f int64) { full <- f },
	}
	big := strings.Repeat("x", 1<<20)
	for d := 0; d < 10; d++ {
		day := now.AddDate(0, 0, -d).Format(dayLayout)
		os.WriteFile(filepath.Join(l.dir, day+".log.gz"), []byte(big), 0o640)
	}
	os.WriteFile(filepath.Join(l.dir, "state.json"), []byte("{}"), 0o640) // must survive
	l.Cleanup()
	if got := len(l.Files()); got != 6 { // today + 5 days
		t.Fatalf("retention: want 6 days, got %d", got)
	}

	s.MaxMB = 10
	l.set.Store(&s)
	os.WriteFile(filepath.Join(l.dir, now.Format(dayLayout)+".log"), []byte(strings.Repeat("y", 8<<20)), 0o640)
	l.Cleanup()
	var total int64
	for _, f := range l.Files() {
		total += f.Size
	}
	if total > 10<<20 {
		t.Fatalf("size rule: %d bytes left", total)
	}

	// free space: pretend the disk is full; everything but today goes,
	// then logging pauses.
	l.freeFn = func(string) int64 { return 100 << 20 }
	l.Cleanup()
	files := l.Files()
	if len(files) != 1 || files[0].Day != now.Format(dayLayout) {
		t.Fatalf("free rule: %+v", files)
	}
	select {
	case <-full:
	case <-time.After(time.Second):
		t.Fatal("OnFull not called")
	}
	if !l.paused.Load() {
		t.Fatal("log must be paused")
	}
	if _, err := os.Stat(filepath.Join(l.dir, "state.json")); err != nil {
		t.Fatal("foreign file deleted")
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	reasons := map[string]bool{}
	for _, e := range events {
		reasons[e.Reason] = true
	}
	mu.Unlock()
	if !reasons[ReasonRetention] || !reasons[ReasonSize] || !reasons[ReasonFree] {
		t.Fatalf("missing cleanup events: %v", reasons)
	}
	l.freeFn = func(string) int64 { return 10 << 30 }
	l.Cleanup()
	if l.paused.Load() {
		t.Fatal("log must resume when space is back")
	}
}

func TestRunFlush(t *testing.T) {
	s := DefaultSettings()
	l, _ := newTestLog(t, s)
	l.now = time.Now
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.Run(ctx); close(done) }()
	for !l.running.Load() {
		time.Sleep(time.Millisecond)
	}
	e := ent(time.Now(), "10.0.0.1", "evil.example", stats.StatusBlocked, "malware")
	l.Add(&e)
	got, _, err := l.Page(context.Background(), Query{Status: "threats"}, 0, 10)
	if err != nil || len(got) != 1 {
		t.Fatalf("flush before read failed: %v %v", got, err)
	}
	cancel()
	<-done
}
