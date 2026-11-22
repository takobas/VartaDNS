package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/takobas/vartadns/internal/stats"
)

const testToken = "123456789:AAEhBOweik6ad9r_QXMENQjcrGbqCr4K-ra"

type fakeAPI struct {
	mu    sync.Mutex
	texts []string
	fail  bool
}

func (f *fakeAPI) handler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		w.Write([]byte(`{"ok":false,"description":"Bad Gateway"}`))
		return
	}
	if strings.HasSuffix(r.URL.Path, "/getUpdates") {
		w.Write([]byte(`{"ok":true,"result":[{"message":{"chat":{"id":42,"type":"private","first_name":"Alex","username":"alex"}}},{"message":{"chat":{"id":42,"type":"private"}}}]}`))
		return
	}
	f.texts = append(f.texts, r.Form.Get("text"))
	w.Write([]byte(`{"ok":true,"result":{}}`))
}

func newTest(t *testing.T, ev map[string]bool) (*Telegram, *fakeAPI, *time.Time) {
	f := &fakeAPI{}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	tg := New(Settings{Token: testToken, ChatID: "42", Events: ev}, srv.Client())
	tg.api = srv.URL
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.Local)
	tg.now = func() time.Time { return now }
	return tg, f, &now
}

func blocked(client, name, kind string, ts time.Time) *stats.Entry {
	return &stats.Entry{Time: ts, Client: client, Name: name, Status: stats.StatusBlocked, Kind: kind, Source: "URLhaus", Device: "iPhone-Maksym"}
}

func drain(tg *Telegram) {
	for {
		select {
		case it := <-tg.in:
			tg.accept(it)
		default:
			return
		}
	}
}

func TestDefaultsOnlyMalware(t *testing.T) {
	tg, f, now := newTest(t, nil)
	tg.Blocked(blocked("192.168.11.45", "ads.example", "ads", *now))
	tg.Blocked(blocked("192.168.11.45", "phish.example", "phishing", *now))
	tg.Blocked(blocked("192.168.11.45", "evil.example", "malware", *now))
	tg.Blocked(blocked("192.168.11.45", "evil.example", "malware", *now)) // dedup
	drain(tg)
	tg.maybeSend(context.Background())
	if len(f.texts) != 1 {
		t.Fatalf("want 1 message, got %d", len(f.texts))
	}
	msg := f.texts[0]
	for _, want := range []string{"🦠", "iPhone-Maksym · 192.168.11.45", "evil[.]example", "URLhaus"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "evil.example") {
		t.Error("domain must be defanged")
	}
}

func TestRateLimitSummaryAndRetry(t *testing.T) {
	tg, f, now := newTest(t, map[string]bool{EvMalware: true})
	tg.Blocked(blocked("10.0.0.1", "a.example", "malware", *now))
	drain(tg)
	tg.maybeSend(context.Background())
	for i := 0; i < 30; i++ {
		tg.Blocked(blocked("10.0.0.1", "x"+string(rune('a'+i%26))+strings.Repeat("y", i/26)+".example", "malware", *now))
	}
	drain(tg)
	*now = now.Add(30 * time.Second)
	tg.maybeSend(context.Background())
	if len(f.texts) != 1 {
		t.Fatal("second message must wait a minute")
	}
	f.fail = true
	*now = now.Add(31 * time.Second)
	tg.maybeSend(context.Background())
	if tg.Status().Pending != 30 || tg.Status().LastError == "" {
		t.Fatalf("failed send must keep events: %+v", tg.Status())
	}
	f.fail = false
	*now = now.Add(2 * time.Minute)
	tg.maybeSend(context.Background())
	if len(f.texts) != 2 || !strings.Contains(f.texts[1], "30") || !strings.Contains(f.texts[1], "…") {
		t.Fatalf("want one summary of 30 events, got %q", f.texts)
	}
	if strings.Contains(tg.Status().LastError, testToken) {
		t.Fatal("token leaked into error")
	}
}

func TestInfected(t *testing.T) {
	tg, f, now := newTest(t, map[string]bool{EvInfected: true})
	for i := 0; i < 5; i++ {
		tg.Blocked(blocked("10.0.0.9", "m"+string(rune('a'+i))+".example", "malware", *now))
	}
	drain(tg)
	tg.maybeSend(context.Background())
	if len(f.texts) != 1 || !strings.Contains(f.texts[0], "🚨") || !strings.Contains(f.texts[0], "5") {
		t.Fatalf("infection alert expected, got %q", f.texts)
	}
}

func TestDetectAndValidate(t *testing.T) {
	tg, _, _ := newTest(t, nil)
	chats, err := tg.DetectChats(context.Background(), testToken)
	if err != nil || len(chats) != 1 || chats[0].ID != 42 {
		t.Fatalf("detect: %+v %v", chats, err)
	}
	if !ValidToken(testToken) || ValidToken("bad") || !ValidChat("-1001234") || !ValidChat("@my_channel") || ValidChat("x y") {
		t.Fatal("validation")
	}
	if m := MaskToken(testToken); strings.Contains(m, "AAEh") || !strings.HasSuffix(m, "K-ra") {
		t.Fatalf("mask: %s", m)
	}
}

func TestParseCommand(t *testing.T) {
	c, a, ok := ParseCommand("/Internet@VartaBot Діти off 30")
	if !ok || c != "internet" || len(a) != 3 || a[0] != "Діти" {
		t.Fatalf("%q %q %v", c, a, ok)
	}
	if _, _, ok := ParseCommand("hello"); ok {
		t.Fatal("plain text is not a command")
	}
}

func TestPollOnlyOwnChat(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		mu.Lock()
		defer mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/sendMessage") {
			sent = append(sent, r.Form.Get("chat_id")+":"+r.Form.Get("text"))
			w.Write([]byte(`{"ok":true,"result":{}}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/setMyCommands") {
			w.Write([]byte(`{"ok":true,"result":true}`))
			return
		}
		calls++
		switch {
		case r.Form.Get("offset") == "-1":
			w.Write([]byte(`{"ok":true,"result":[{"update_id":5,"message":{"chat":{"id":42},"text":"/pause"}}]}`))
		case calls == 2 && r.Form.Get("offset") == "6":
			w.Write([]byte(`{"ok":true,"result":[{"update_id":6,"message":{"chat":{"id":42},"text":"/status"}},{"update_id":7,"message":{"chat":{"id":99},"text":"/status"}}]}`))
		default:
			time.Sleep(20 * time.Millisecond)
			w.Write([]byte(`{"ok":true,"result":[]}`))
		}
	}))
	defer srv.Close()
	tg := New(Settings{Token: testToken, ChatID: "42", Commands: true}, srv.Client())
	tg.api = srv.URL
	var got []string
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tg.Poll(ctx, func(_ context.Context, cmd string, _ []string) string {
			mu.Lock()
			got = append(got, cmd)
			mu.Unlock()
			return "ok " + cmd
		})
		close(done)
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "status" {
		t.Fatalf("handled %v (backlog /pause must be skipped, chat 99 ignored)", got)
	}
	if len(sent) != 1 || sent[0] != "42:ok status" {
		t.Fatalf("replies %v", sent)
	}
}
