package app

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/takobas/vartadns/internal/dnsmsg"
	"github.com/takobas/vartadns/internal/stats"
)

func TestEncryptedDNSWithLocalCA(t *testing.T) {
	a, h, tok := newTestApp(t)
	defer a.stopEnc()
	w := call(t, h, tok, "PUT", "/api/encdns", []byte(`{"enabled":true,"hostname":"dns.home.test","address":"127.0.0.1","doh":true,"dot":true,"cert_source":"ca"}`))
	if w.Code != 200 {
		t.Fatalf("enable: %d %s", w.Code, w.Body)
	}
	w = call(t, h, tok, "POST", "/api/encdns/devices", []byte(`{"name":"Телефон Максима","ip":"192.168.11.45"}`))
	var v struct {
		Devices []encDeviceView `json:"devices"`
	}
	json.Unmarshal(w.Body.Bytes(), &v)
	if len(v.Devices) != 1 || len(v.Devices[0].Token) != 16 {
		t.Fatalf("device: %s", w.Body)
	}
	token := v.Devices[0].Token

	caPEM, _ := os.ReadFile(filepath.Join(a.tlsDir(), "ca.crt"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	tcfg := &tls.Config{RootCAs: pool, ServerName: "dns.home.test"}
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tcfg}}

	// DoH with a personal address: identified as 192.168.11.45, blocked list works
	q := dnsmsg.BuildQuery(0, "evil.example", dnsmsg.TypeA)
	resp, err := hc.Post("https://"+a.enc.dohAddr+"/dns-query/"+token, "application/dns-message", bytes.NewReader(q))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(body) < 12 || resp.Header.Get("Content-Type") != "application/dns-message" {
		t.Fatalf("doh: %d %q", resp.StatusCode, body)
	}
	e := a.Stats.Log(stats.Filter{Limit: 1})[0]
	if e.Client != "192.168.11.45" || e.Proto != "doh" || e.Status != stats.StatusBlocked {
		t.Fatalf("doh entry: %+v", e)
	}
	// unknown token: 404
	resp, _ = hc.Post("https://"+a.enc.dohAddr+"/dns-query/nope", "application/dns-message", bytes.NewReader(q))
	if resp.StatusCode != 404 {
		t.Fatalf("unknown token: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// DoT with SNI <token>.dns.home.test
	c, err := tls.Dial("tcp", a.enc.dotAddr, &tls.Config{RootCAs: pool, ServerName: token + ".dns.home.test"})
	if err != nil {
		t.Fatal(err)
	}
	q2 := dnsmsg.BuildQuery(9, "dns.home.test", dnsmsg.TypeA) // local name of the service
	out := binary.BigEndian.AppendUint16(nil, uint16(len(q2)))
	c.Write(append(out, q2...))
	var l [2]byte
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, l[:]); err != nil {
		t.Fatal(err)
	}
	r2 := make([]byte, binary.BigEndian.Uint16(l[:]))
	io.ReadFull(c, r2)
	c.Close()
	info, _ := dnsmsg.Inspect(r2)
	if len(info.AnswerIPs) != 1 || !bytes.Equal(info.AnswerIPs[0], []byte{127, 0, 0, 1}) {
		t.Fatalf("local name answer: %v", info.AnswerIPs)
	}
	e = a.Stats.Log(stats.Filter{Limit: 1})[0]
	if e.Client != "192.168.11.45" || e.Proto != "dot" || e.Status != stats.StatusLocal {
		t.Fatalf("dot entry: %+v", e)
	}

	// Apple profile
	w = call(t, h, tok, "GET", "/api/encdns/mobileconfig?token="+token, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "/dns-query/"+token) || !strings.Contains(w.Body.String(), "com.apple.security.root") {
		t.Fatalf("mobileconfig: %d", w.Code)
	}
	// backup without secrets hides the personal tokens
	w = call(t, h, tok, "GET", "/api/backup", nil)
	if strings.Contains(w.Body.String(), token) {
		t.Fatal("token in backup without secrets")
	}
	// disable stops the listeners and the local name
	call(t, h, tok, "PUT", "/api/encdns", []byte(`{"enabled":false,"hostname":"dns.home.test","cert_source":"ca"}`))
	if _, err := tls.Dial("tcp", a.enc.dotAddr, &tls.Config{RootCAs: pool, ServerName: "dns.home.test"}); err == nil {
		t.Fatal("DoT must be stopped")
	}
}
