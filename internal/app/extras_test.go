package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/takobas/vartadns/internal/dnsmsg"
	"github.com/takobas/vartadns/internal/stats"
)

func newTestApp(t *testing.T) (*App, http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	list := filepath.Join(dir, "mal.txt")
	os.WriteFile(list, []byte("0.0.0.0 evil.example\n"), 0o644)
	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.Upstreams = []string{"127.0.0.1:9"}
	cfg.Bootstrap = []string{"127.0.0.1"}
	cfg.WebTLSListen = "127.0.0.1:0"
	cfg.DoHListen = "127.0.0.1:0"
	cfg.DoTListen = "127.0.0.1:0"
	cfg.DefaultLists = []ListSpec{{Name: "Test malware", URL: list, Enabled: true, Kind: KindMalware}}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.RebuildLists(context.Background(), false)
	a.handler = a.redirectHTTPS(a.routes())
	return a, a.handler, a.sessions.create("admin", RoleAdmin, "127.0.0.1")
}

func call(t *testing.T, h http.Handler, tok, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://192.168.11.1:8080"+path, bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
	req.Header.Set("X-Varta", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestDiskLogExportBackupRestore(t *testing.T) {
	a, h, tok := newTestApp(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.QLog.Run(ctx)
	time.Sleep(50 * time.Millisecond) // let the log writer start

	// manual device name, then a malware query from that device
	if w := call(t, h, tok, "PUT", "/api/devices/name", []byte(`{"ip":"192.168.11.45","name":"Телефон Максима"}`)); w.Code != 200 {
		t.Fatalf("name: %d %s", w.Code, w.Body)
	}
	q := dnsmsg.BuildQuery(1, "evil.example", dnsmsg.TypeA)
	if resp := a.Resolver.Resolve(ctx, q, netip.MustParseAddr("192.168.11.45"), "udp"); resp == nil {
		t.Fatal("no response")
	}
	live := a.Stats.Log(stats.Filter{Limit: 1})
	if len(live) != 1 || live[0].Kind != KindMalware || live[0].Device != "Телефон Максима" || live[0].Status != stats.StatusBlocked {
		t.Fatalf("live entry not enriched: %+v", live)
	}

	w := call(t, h, tok, "GET", "/api/qlog/entries?status=threats&clients=192.168.11.45", nil)
	var page struct {
		Entries []stats.Entry `json:"entries"`
	}
	json.Unmarshal(w.Body.Bytes(), &page)
	if w.Code != 200 || len(page.Entries) != 1 || page.Entries[0].Name != "evil.example" {
		t.Fatalf("disk page: %d %s", w.Code, w.Body)
	}
	w = call(t, h, tok, "GET", "/api/qlog/export?format=csv&clients=192.168.11.45", nil)
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "evil.example") || !strings.Contains(body, "Телефон Максима") ||
		!strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("export: %d %q", w.Code, body)
	}
	if w = call(t, h, tok, "GET", "/api/qlog/export?clients=not-an-ip", nil); w.Code != 400 {
		t.Fatalf("bad IP must be rejected, got %d", w.Code)
	}

	// Telegram token is never returned in clear text and is stripped from
	// backups without secrets.
	const token = "123456789:AAEhBOweik6ad9r_QXMENQjcrGbqCr4K-ra"
	w = call(t, h, tok, "PUT", "/api/telegram", []byte(`{"token":"`+token+`","chat_id":"42","events":{"malware":true}}`))
	if w.Code != 200 || strings.Contains(w.Body.String(), "AAEh") {
		t.Fatalf("telegram save: %d %s", w.Code, w.Body)
	}
	w = call(t, h, tok, "GET", "/api/backup", nil)
	backup := w.Body.Bytes()
	if strings.Contains(string(backup), token) || strings.Contains(string(backup), a.state.get().PasswordHash) {
		t.Fatal("secrets leaked into a backup without secrets")
	}
	// change something, then restore: the change is undone, secrets kept
	call(t, h, tok, "PUT", "/api/devices/name", []byte(`{"ip":"192.168.11.45","name":"Інше"}`))
	w = call(t, h, tok, "POST", "/api/restore", backup)
	if w.Code != 200 {
		t.Fatalf("restore: %d %s", w.Code, w.Body)
	}
	st := a.state.get()
	if st.DeviceNames["192.168.11.45"] != "Телефон Максима" || st.Telegram.Token != token || st.PasswordHash == "" {
		t.Fatalf("restore result wrong: names=%v", st.DeviceNames)
	}
	if w = call(t, h, tok, "POST", "/api/restore", []byte(`{"hello":1}`)); w.Code != 400 {
		t.Fatalf("foreign file must be rejected, got %d", w.Code)
	}
}
