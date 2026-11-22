package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeACME is a tiny ACME server: it checks every JWS signature, the nonce
// and that the DNS-01 TXT value is "published" in txt before validating.
type fakeACME struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	nonces map[string]bool
	acct   *ecdsa.PublicKey
	txt    map[string]string // fqdn -> value (filled by the test solver)
	tokens map[string]string // authz id -> token
	names  map[string]string // authz id -> identifier
	valid  map[string]bool
	order  []string
	ca     *CA
	cert   []byte
}

func b64d(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(s); return b }

func (f *fakeACME) nonce(w http.ResponseWriter) {
	n := fmt.Sprint(time.Now().UnixNano())
	f.nonces[n] = true
	w.Header().Set("Replay-Nonce", n)
}

func (f *fakeACME) verify(r *http.Request) (map[string]any, []byte) {
	var jws struct{ Protected, Payload, Signature string }
	json.NewDecoder(r.Body).Decode(&jws)
	var prot map[string]any
	json.Unmarshal(b64d(jws.Protected), &prot)
	if !f.nonces[fmt.Sprint(prot["nonce"])] {
		f.t.Errorf("bad nonce")
	}
	delete(f.nonces, fmt.Sprint(prot["nonce"]))
	pub := f.acct
	if j, ok := prot["jwk"].(map[string]any); ok {
		x := new(big.Int).SetBytes(b64d(j["x"].(string)))
		y := new(big.Int).SetBytes(b64d(j["y"].(string)))
		pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		f.acct = pub
	} else if prot["kid"] != f.srv.URL+"/acct/1" {
		f.t.Errorf("bad kid %v", prot["kid"])
	}
	sig := b64d(jws.Signature)
	h := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
	if len(sig) != 64 || !ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		f.t.Errorf("bad signature on %s", r.URL.Path)
	}
	if prot["url"] != f.srv.URL+r.URL.Path {
		f.t.Errorf("url mismatch %v", prot["url"])
	}
	return prot, b64d(jws.Payload)
}

func (f *fakeACME) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.srv.URL
	f.nonce(w)
	if r.URL.Path == "/dir" {
		json.NewEncoder(w).Encode(map[string]string{"newNonce": u + "/nonce", "newAccount": u + "/acct", "newOrder": u + "/order"})
		return
	}
	if r.URL.Path == "/nonce" {
		return
	}
	_, payload := f.verify(r)
	switch {
	case r.URL.Path == "/acct":
		var p map[string]any
		json.Unmarshal(payload, &p)
		if p["termsOfServiceAgreed"] != true {
			f.t.Error("terms not agreed")
		}
		w.Header().Set("Location", u+"/acct/1")
		w.WriteHeader(201)
		w.Write([]byte(`{"status":"valid"}`))
	case r.URL.Path == "/order":
		var p struct{ Identifiers []struct{ Value string } }
		json.Unmarshal(payload, &p)
		var authz []string
		for i, id := range p.Identifiers {
			aid := fmt.Sprint(i)
			f.names[aid] = id.Value
			f.tokens[aid] = "tok" + aid
			f.order = append(f.order, id.Value)
			authz = append(authz, u+"/authz/"+aid)
		}
		w.Header().Set("Location", u+"/order/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"status": "pending", "authorizations": authz, "finalize": u + "/finalize"})
	case strings.HasPrefix(r.URL.Path, "/authz/"):
		aid := strings.TrimPrefix(r.URL.Path, "/authz/")
		name := f.names[aid]
		st := "pending"
		if f.valid[aid] {
			st = "valid"
		}
		wild := strings.HasPrefix(name, "*.")
		json.NewEncoder(w).Encode(map[string]any{"status": st, "wildcard": wild,
			"identifier": map[string]string{"type": "dns", "value": strings.TrimPrefix(name, "*.")},
			"challenges": []map[string]string{{"type": "http-01", "url": u + "/x", "token": "no"},
				{"type": "dns-01", "url": u + "/chall/" + aid, "token": f.tokens[aid]}}})
	case strings.HasPrefix(r.URL.Path, "/chall/"):
		aid := strings.TrimPrefix(r.URL.Path, "/chall/")
		fqdn := "_acme-challenge." + strings.TrimPrefix(f.names[aid], "*.")
		thumb := (&ACME{Key: &ecdsa.PrivateKey{PublicKey: *f.acct}}).Thumbprint()
		h := sha256.Sum256([]byte(f.tokens[aid] + "." + thumb))
		if f.txt[fqdn] == base64.RawURLEncoding.EncodeToString(h[:]) {
			f.valid[aid] = true
		} else {
			f.t.Errorf("TXT for %s not published", fqdn)
		}
		w.Write([]byte(`{"status":"processing"}`))
	case r.URL.Path == "/order/1":
		st := "ready"
		if f.cert != nil {
			st = "valid"
		}
		json.NewEncoder(w).Encode(map[string]any{"status": st, "finalize": u + "/finalize", "certificate": u + "/cert"})
	case r.URL.Path == "/finalize":
		var p struct{ CSR string }
		json.Unmarshal(payload, &p)
		csr, err := x509.ParseCertificateRequest(b64d(p.CSR))
		if err != nil {
			f.t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: csr.DNSNames[0]},
			DNSNames: csr.DNSNames, NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, f.ca.Cert, csr.PublicKey, f.ca.key)
		f.cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		json.NewEncoder(w).Encode(map[string]any{"status": "valid", "certificate": u + "/cert"})
	case r.URL.Path == "/cert":
		w.Write(f.cert)
	default:
		w.WriteHeader(404)
	}
}

type mapSolver struct {
	mu  sync.Mutex
	txt map[string]string
	f   *fakeACME
	log []string
}

func (s *mapSolver) Present(_ context.Context, fqdn, v string) error {
	s.f.mu.Lock()
	s.f.txt[fqdn] = v
	s.f.mu.Unlock()
	s.log = append(s.log, "add "+fqdn)
	return nil
}
func (s *mapSolver) CleanUp(_ context.Context, fqdn, v string) error {
	s.f.mu.Lock()
	delete(s.f.txt, fqdn)
	s.f.mu.Unlock()
	s.log = append(s.log, "del "+fqdn)
	return nil
}
func (s *mapSolver) Wait() time.Duration { return 0 }

func TestACMEObtainWildcard(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeACME{t: t, nonces: map[string]bool{}, txt: map[string]string{}, tokens: map[string]string{},
		names: map[string]string{}, valid: map[string]bool{}, ca: ca}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handler))
	defer f.srv.Close()
	key, _ := LoadOrCreateKey(filepath.Join(t.TempDir(), "acct.key"))
	c := &ACME{Directory: f.srv.URL + "/dir", HTTP: f.srv.Client(), Key: key}
	if err := c.Register(context.Background(), "a@example.com", false); err == nil {
		t.Fatal("registration without agreement must fail")
	}
	if err := c.Register(context.Background(), "a@example.com", true); err != nil {
		t.Fatal(err)
	}
	s := &mapSolver{f: f}
	chain, keyPEM, err := c.Obtain(context.Background(), []string{"dns.home.example", "*.dns.home.example"}, s)
	if err != nil {
		t.Fatal(err)
	}
	// challenges are solved one after another (DuckDNS has one TXT slot)
	if strings.Join(s.log, ",") != "add _acme-challenge.dns.home.example,del _acme-challenge.dns.home.example,add _acme-challenge.dns.home.example,del _acme-challenge.dns.home.example" {
		t.Fatalf("solver order: %v", s.log)
	}
	blk, _ := pem.Decode(chain)
	cert, _ := x509.ParseCertificate(blk.Bytes)
	if cert.VerifyHostname("k7f3x9.dns.home.example") != nil || cert.VerifyHostname("dns.home.example") != nil {
		t.Fatal("wildcard certificate names")
	}
	if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
		t.Fatal("key")
	}
}

func TestLocalCAIssue(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	ca2, _ := LoadOrCreateCA(dir)
	if string(ca.CertPEM) != string(ca2.CertPEM) {
		t.Fatal("CA must be reused")
	}
	certPEM, _, err := ca.Issue([]string{"dns.home", "*.dns.home"}, []net.IP{net.ParseIP("172.17.53.2")})
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(blk.Bytes)
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "abc.dns.home"}); err != nil {
		t.Fatal(err)
	}
	if cert.VerifyHostname("172.17.53.2") != nil {
		t.Fatal("ip SAN")
	}
}

func TestDuckSub(t *testing.T) {
	if s, _ := duckSub("_acme-challenge.alex.duckdns.org"); s != "alex" {
		t.Fatal(s)
	}
	if _, err := duckSub("_acme-challenge.example.com"); err == nil {
		t.Fatal("non-duckdns name")
	}
	_ = io.EOF
}
