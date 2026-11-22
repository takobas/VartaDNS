package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TLS modes for the panel.
const (
	TLSOff    = "off"
	TLSAuto   = "auto"   // self-signed certificate made by VartaDNS
	TLSCustom = "custom" // certificate and key uploaded in the panel
)

// TLSSettings are stored in state.json; KeyPEM is a secret.
type TLSSettings struct {
	Mode     string `json:"mode"`
	Redirect bool   `json:"redirect,omitempty"` // send http:// visitors to https://
	CertPEM  string `json:"cert_pem,omitempty"`
	KeyPEM   string `json:"key_pem,omitempty"`
}

type tlsState struct {
	mu      sync.Mutex
	cert    atomic.Pointer[tls.Certificate]
	srv     *http.Server
	running atomic.Bool
	lastErr atomic.Pointer[string]
	addr    string // actual listen address (tests use port 0)
}

func (s State) tlsSettings() TLSSettings {
	if s.TLS != nil {
		return *s.TLS
	}
	return TLSSettings{Mode: TLSOff}
}

// localIPs lists the addresses of this host (container) interfaces.
func localIPs() []net.IP {
	var out []net.IP
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLinkLocalUnicast() {
			out = append(out, n.IP)
		}
	}
	return out
}

// autoCert loads or (re)creates the self-signed certificate. It is renewed
// when it expires within 30 days or does not cover the current addresses.
func (a *App) autoCert() (*tls.Certificate, error) {
	dir := filepath.Join(a.cfg.DataDir, "tls")
	cp, kp := filepath.Join(dir, "auto.crt"), filepath.Join(dir, "auto.key")
	ips := localIPs()
	names := append([]string{"localhost"}, a.cfg.WebHosts...)
	if c, err := tls.LoadX509KeyPair(cp, kp); err == nil && c.Leaf != nil {
		ok := time.Until(c.Leaf.NotAfter) > 30*24*time.Hour
		for _, ip := range ips {
			if c.Leaf.VerifyHostname(ip.String()) != nil {
				ok = false
			}
		}
		for _, n := range names {
			if c.Leaf.VerifyHostname(n) != nil {
				ok = false
			}
		}
		if ok {
			return &c, nil
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "VartaDNS panel", Organization: []string{"VartaDNS"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	if err := os.WriteFile(kp, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(cp, certPEM, 0o644); err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	log.Printf("panel HTTPS: new self-signed certificate, SHA-256 %s", fingerprint(c.Leaf))
	return &c, nil
}

func parsePair(certPEM, keyPEM string) (*tls.Certificate, error) {
	c, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("certificate/key: %w", err)
	}
	if c.Leaf == nil {
		return nil, errors.New("certificate: cannot parse")
	}
	if time.Now().After(c.Leaf.NotAfter) {
		return nil, errors.New("certificate has expired")
	}
	return &c, nil
}

func fingerprint(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	h := sha256.Sum256(c.Raw)
	parts := make([]string, len(h))
	for i, b := range h {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	return strings.Join(parts, ":")
}

// applyTLS loads the certificate for the saved mode and starts or stops
// the HTTPS listener. The HTTP panel always keeps running.
func (a *App) applyTLS() error {
	st := a.state.get().tlsSettings()
	t := a.tls
	t.mu.Lock()
	defer t.mu.Unlock()
	var cert *tls.Certificate
	var err error
	switch st.Mode {
	case TLSOff, "":
		if t.srv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			t.srv.Shutdown(ctx)
			cancel()
			t.srv = nil
			t.running.Store(false)
		}
		t.cert.Store(nil)
		return nil
	case TLSAuto:
		cert, err = a.autoCert()
	case TLSCustom:
		cert, err = parsePair(st.CertPEM, st.KeyPEM)
	default:
		err = fmt.Errorf("unknown TLS mode %q", st.Mode)
	}
	if err != nil {
		msg := err.Error()
		t.lastErr.Store(&msg)
		return err
	}
	t.lastErr.Store(nil)
	t.cert.Store(cert) // a running listener picks it up at the next handshake
	if t.srv != nil {
		return nil
	}
	ln, err := net.Listen("tcp", a.cfg.WebTLSListen)
	if err != nil {
		msg := err.Error()
		t.lastErr.Store(&msg)
		return fmt.Errorf("listen %s: %w", a.cfg.WebTLSListen, err)
	}
	srv := &http.Server{
		Handler:           a.handler,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				if c := t.cert.Load(); c != nil {
					return c, nil
				}
				return nil, errors.New("no certificate")
			},
		},
	}
	t.srv, t.addr = srv, ln.Addr().String()
	t.running.Store(true)
	go func() {
		log.Printf("Web panel (HTTPS) listening on %s", a.cfg.WebTLSListen)
		if err := srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			msg := err.Error()
			t.lastErr.Store(&msg)
			t.running.Store(false)
		}
	}()
	return nil
}

func (a *App) stopTLS() {
	t := a.tls
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		t.srv.Shutdown(ctx)
		cancel()
		t.srv = nil
	}
}

// redirectHTTPS sends plain-HTTP panel visitors to HTTPS when enabled and
// the HTTPS listener is up (never redirect into a dead port).
func (a *App) redirectHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil && a.tls.running.Load() && a.state.get().tlsSettings().Redirect {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			_, port, _ := net.SplitHostPort(a.cfg.WebTLSListen)
			if port != "" && port != "443" {
				host = net.JoinHostPort(strings.Trim(host, "[]"), port)
			}
			http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusTemporaryRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type tlsView struct {
	Mode        string   `json:"mode"`
	Redirect    bool     `json:"redirect"`
	Listen      string   `json:"listen"`
	Running     bool     `json:"running"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	Names       []string `json:"names,omitempty"`
	Error       string   `json:"error,omitempty"`
	HasCustom   bool     `json:"has_custom"`
}

func (a *App) hTLSGet(w http.ResponseWriter, r *http.Request) {
	st := a.state.get().tlsSettings()
	v := tlsView{Mode: st.Mode, Redirect: st.Redirect, Listen: a.cfg.WebTLSListen, Running: a.tls.running.Load(),
		HasCustom: st.CertPEM != ""}
	if v.Mode == "" {
		v.Mode = TLSOff
	}
	if c := a.tls.cert.Load(); c != nil && c.Leaf != nil {
		v.Fingerprint = fingerprint(c.Leaf)
		v.NotAfter = c.Leaf.NotAfter.Format(time.RFC3339)
		v.Subject = c.Leaf.Subject.CommonName
		for _, ip := range c.Leaf.IPAddresses {
			v.Names = append(v.Names, ip.String())
		}
		v.Names = append(v.Names, c.Leaf.DNSNames...)
		sort.Strings(v.Names)
	}
	if e := a.tls.lastErr.Load(); e != nil {
		v.Error = *e
	}
	writeJSON(w, v)
}

func (a *App) hTLSSave(w http.ResponseWriter, r *http.Request) {
	var req TLSSettings
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	cur := a.state.get().tlsSettings()
	switch req.Mode {
	case TLSOff, TLSAuto:
		req.CertPEM, req.KeyPEM = cur.CertPEM, cur.KeyPEM // keep an uploaded pair for later
	case TLSCustom:
		if strings.TrimSpace(req.CertPEM) == "" && strings.TrimSpace(req.KeyPEM) == "" {
			req.CertPEM, req.KeyPEM = cur.CertPEM, cur.KeyPEM // switch back to the saved pair
		}
		if _, err := parsePair(req.CertPEM, req.KeyPEM); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
	default:
		jsonErr(w, http.StatusBadRequest, "mode must be off, auto or custom")
		return
	}
	if err := a.state.update(func(s *State) { s.TLS = &req }); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.applyTLS(); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.hTLSGet(w, r)
}
