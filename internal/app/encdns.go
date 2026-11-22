package app

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/takobas/vartadns/internal/certs"
	"github.com/takobas/vartadns/internal/devices"
	"github.com/takobas/vartadns/internal/server"
	"github.com/takobas/vartadns/internal/stats"
	"github.com/takobas/vartadns/internal/syslog"
)

// Certificate sources for encrypted DNS.
const (
	CertCA     = "ca"     // VartaDNS's own CA (installed on devices once)
	CertACME   = "acme"   // Let's Encrypt via DNS-01
	CertCustom = "custom" // uploaded certificate and key
)

// PersonalDevice has its own DoH path / DoT hostname. Queries over it are
// treated as coming from IP (groups, logs), wherever the device is.
type PersonalDevice struct {
	Token   string    `json:"token"`
	Name    string    `json:"name"`
	IP      string    `json:"ip"`
	Created time.Time `json:"created"`
}

// EncDNSSettings configure DoH/DoT for clients. ACMEToken and KeyPEM are secrets.
type EncDNSSettings struct {
	Enabled      bool             `json:"enabled"`
	Hostname     string           `json:"hostname"`
	Address      string           `json:"address"` // IP clients connect to (answered for Hostname)
	DoH          bool             `json:"doh"`
	DoT          bool             `json:"dot"`
	CertSource   string           `json:"cert_source"`
	ACMEProvider string           `json:"acme_provider,omitempty"`
	ACMEToken    string           `json:"acme_token,omitempty"`
	ACMEEmail    string           `json:"acme_email,omitempty"`
	ACMEAgree    bool             `json:"acme_agree,omitempty"`
	ACMEStaging  bool             `json:"acme_staging,omitempty"`
	CertPEM      string           `json:"cert_pem,omitempty"`
	KeyPEM       string           `json:"key_pem,omitempty"`
	Devices      []PersonalDevice `json:"devices,omitempty"`
}

type encState struct {
	mu      sync.Mutex
	cert    atomic.Pointer[tls.Certificate]
	doh     *http.Server
	dot     net.Listener
	dotStop context.CancelFunc
	host    atomic.Pointer[string]
	tokens  atomic.Pointer[map[string]netip.Addr]
	lastErr atomic.Pointer[string]
	acme    atomic.Pointer[string] // ACME progress / result text
	issuing atomic.Bool
	dohAddr string
	dotAddr string
}

func (s State) encDNS() EncDNSSettings {
	if s.EncDNS != nil {
		e := *s.EncDNS
		e.Devices = append([]PersonalDevice(nil), s.EncDNS.Devices...)
		return e
	}
	return EncDNSSettings{CertSource: CertCA, DoH: true, DoT: true}
}

var hostRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

func validHost(h string) bool { return len(h) <= 200 && hostRE.MatchString(h) }

func (e *encState) setErr(err error) {
	if err == nil {
		e.lastErr.Store(nil)
		return
	}
	m := err.Error()
	e.lastErr.Store(&m)
}

func (e *encState) setACME(msg string) { e.acme.Store(&msg) }

func (a *App) identify(token string) (netip.Addr, bool) {
	m := a.enc.tokens.Load()
	if m == nil {
		return netip.Addr{}, false
	}
	ip, ok := (*m)[token]
	return ip, ok
}

func (a *App) encHost() string {
	if h := a.enc.host.Load(); h != nil {
		return *h
	}
	return ""
}

func (a *App) tlsDir() string { return filepath.Join(a.cfg.DataDir, "tls") }

func firstLocalIPv4() string {
	for _, ip := range localIPs() {
		if v4 := ip.To4(); v4 != nil && !v4.IsLoopback() {
			return v4.String()
		}
	}
	return ""
}

// encCert returns the certificate for the current source, issuing a local
// CA certificate when needed. For ACME it only loads what was obtained.
func (a *App) encCert(s EncDNSSettings) (*tls.Certificate, error) {
	names := []string{s.Hostname, "*." + s.Hostname}
	switch s.CertSource {
	case CertCustom:
		return parsePair(s.CertPEM, s.KeyPEM)
	case CertACME:
		c, err := tls.LoadX509KeyPair(filepath.Join(a.tlsDir(), "dns-acme.crt"), filepath.Join(a.tlsDir(), "dns-acme.key"))
		if err != nil || c.Leaf == nil || c.Leaf.VerifyHostname(s.Hostname) != nil {
			return nil, errors.New("no Let's Encrypt certificate yet: press \"Get certificate\"")
		}
		return &c, nil
	}
	cp, kp := filepath.Join(a.tlsDir(), "dns-ca.crt"), filepath.Join(a.tlsDir(), "dns-ca.key")
	if c, err := tls.LoadX509KeyPair(cp, kp); err == nil && c.Leaf != nil &&
		time.Until(c.Leaf.NotAfter) > 60*24*time.Hour && c.Leaf.VerifyHostname(s.Hostname) == nil &&
		(s.Address == "" || c.Leaf.VerifyHostname(s.Address) == nil) {
		return &c, nil
	}
	ca, err := certs.LoadOrCreateCA(a.tlsDir())
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	if ip := net.ParseIP(s.Address); ip != nil {
		ips = append(ips, ip)
	}
	certPEM, keyPEM, err := ca.Issue(names, ips)
	if err != nil {
		return nil, err
	}
	if err := certs.Save(a.tlsDir(), "dns-ca", certPEM, keyPEM); err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	return &c, err
}

// applyEnc starts, reconfigures or stops DoH/DoT from the saved settings.
func (a *App) applyEnc() error {
	s := a.state.get().encDNS()
	e := a.enc
	e.mu.Lock()
	defer e.mu.Unlock()
	tokens := map[string]netip.Addr{}
	for _, d := range s.Devices {
		if ip, err := netip.ParseAddr(d.IP); err == nil {
			tokens[d.Token] = ip
		}
	}
	e.tokens.Store(&tokens)
	host := s.Hostname
	e.host.Store(&host)
	if !s.Enabled {
		e.stopLocked()
		a.Resolver.SetLocalName(nil)
		e.setErr(nil)
		return nil
	}
	ln := &server.LocalName{Host: s.Hostname}
	if ip, err := netip.ParseAddr(s.Address); err == nil && ip.Is4() {
		b := ip.As4()
		ln.IP4 = b[:]
	}
	a.Resolver.SetLocalName(ln)
	cert, err := a.encCert(s)
	if err != nil {
		e.setErr(err)
		e.stopLocked()
		if s.CertSource == CertACME {
			return nil // waiting for the first certificate is not an error
		}
		return err
	}
	e.cert.Store(cert)
	tcfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := e.cert.Load(); c != nil {
				return c, nil
			}
			return nil, errors.New("no certificate")
		},
	}
	var errs []string
	if s.DoH && e.doh == nil {
		l, err := net.Listen("tcp", a.cfg.DoHListen)
		if err != nil {
			errs = append(errs, fmt.Sprintf("DoH %s: %v", a.cfg.DoHListen, err))
		} else {
			mux := http.NewServeMux()
			mux.Handle("/dns-query", a.Resolver.DoHHandler(a.identify))
			mux.Handle("/dns-query/", a.Resolver.DoHHandler(a.identify))
			srv := &http.Server{Handler: mux, TLSConfig: tcfg.Clone(),
				ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
			e.doh, e.dohAddr = srv, l.Addr().String()
			go func() {
				log.Printf("DoH listening on %s", a.cfg.DoHListen)
				if err := srv.ServeTLS(l, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
					e.setErr(err)
				}
			}()
		}
	} else if !s.DoH && e.doh != nil {
		e.doh.Close()
		e.doh = nil
	}
	if s.DoT && e.dot == nil {
		l, err := net.Listen("tcp", a.cfg.DoTListen)
		if err != nil {
			errs = append(errs, fmt.Sprintf("DoT %s: %v", a.cfg.DoTListen, err))
		} else {
			ctx, cancel := context.WithCancel(context.Background())
			e.dot, e.dotStop, e.dotAddr = l, cancel, l.Addr().String()
			log.Printf("DoT listening on %s", a.cfg.DoTListen)
			go a.Resolver.ServeDoT(ctx, tls.NewListener(l, tcfg.Clone()), a.encHost, a.identify)
		}
	} else if !s.DoT && e.dot != nil {
		e.dotStop()
		e.dot = nil
	}
	if len(errs) > 0 {
		err := errors.New(strings.Join(errs, "; "))
		e.setErr(err)
		return err
	}
	e.setErr(nil)
	return nil
}

func (e *encState) stopLocked() {
	if e.doh != nil {
		e.doh.Close()
		e.doh = nil
	}
	if e.dot != nil {
		e.dotStop()
		e.dot = nil
	}
}

func (a *App) stopEnc() {
	a.enc.mu.Lock()
	a.enc.stopLocked()
	a.enc.mu.Unlock()
}

// issueACME obtains a Let's Encrypt certificate in the background.
func (a *App) issueACME() error {
	s := a.state.get().encDNS()
	if s.CertSource != CertACME || !validHost(s.Hostname) {
		return errors.New("choose Let's Encrypt and a hostname first")
	}
	if !s.ACMEAgree {
		return errors.New("accept the Let's Encrypt subscriber agreement first")
	}
	solver, err := certs.NewSolver(s.ACMEProvider, s.ACMEToken, a.http)
	if err != nil {
		return err
	}
	if !a.enc.issuing.CompareAndSwap(false, true) {
		return errors.New("a certificate request is already running")
	}
	go func() {
		defer a.enc.issuing.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		a.enc.setACME("running")
		key, err := certs.LoadOrCreateKey(filepath.Join(a.tlsDir(), "acme-account.key"))
		if err == nil {
			dir := certs.LetsEncrypt
			if s.ACMEStaging {
				dir = certs.LetsEncryptStaging
			}
			c := &certs.ACME{Directory: dir, HTTP: a.http, Key: key, Log: func(m string) { a.enc.setACME("running: " + m) }}
			if err = c.Register(ctx, s.ACMEEmail, s.ACMEAgree); err == nil {
				var chain, keyPEM []byte
				chain, keyPEM, err = c.Obtain(ctx, []string{s.Hostname, "*." + s.Hostname}, solver)
				if err == nil {
					err = certs.Save(a.tlsDir(), "dns-acme", chain, keyPEM)
				}
			}
		}
		if err != nil {
			msg := strings.ReplaceAll(err.Error(), s.ACMEToken, "***")
			a.enc.setACME("error: " + msg)
			log.Printf("Let's Encrypt: %s", msg)
			return
		}
		a.enc.setACME("ok " + time.Now().Format(time.RFC3339))
		log.Printf("Let's Encrypt: certificate for %s obtained", s.Hostname)
		if err := a.applyEnc(); err != nil {
			log.Printf("encrypted DNS: %v", err)
		}
	}()
	return nil
}

// encLoop renews certificates: Let's Encrypt 30 days before expiry, the
// local CA certificate through applyEnc.
func (a *App) encLoop(ctx context.Context) {
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			a.stopEnc()
			return
		case <-t.C:
		}
		s := a.state.get().encDNS()
		if !s.Enabled {
			continue
		}
		if s.CertSource == CertACME {
			c := a.enc.cert.Load()
			if c == nil || c.Leaf == nil || time.Until(c.Leaf.NotAfter) < 30*24*time.Hour {
				if err := a.issueACME(); err != nil {
					log.Printf("Let's Encrypt renewal: %v", err)
				}
			}
			continue
		}
		if err := a.applyEnc(); err != nil {
			log.Printf("encrypted DNS: %v", err)
		}
	}
}

// ---- API ---------------------------------------------------------------------------------------

type encDeviceView struct {
	PersonalDevice
	DoH string `json:"doh"`
	DoT string `json:"dot"`
}

func (a *App) dohURL(s EncDNSSettings, token string) string {
	host := s.Hostname
	if _, port, _ := net.SplitHostPort(a.cfg.DoHListen); port != "" && port != "443" {
		host = net.JoinHostPort(host, port)
	}
	u := "https://" + host + "/dns-query"
	if token != "" {
		u += "/" + token
	}
	return u
}

func (a *App) hEncGet(w http.ResponseWriter, r *http.Request) {
	s := a.state.get().encDNS()
	v := map[string]any{
		"enabled": s.Enabled, "hostname": s.Hostname, "address": s.Address, "doh": s.DoH, "dot": s.DoT,
		"cert_source": s.CertSource, "acme_provider": s.ACMEProvider, "acme_token_set": s.ACMEToken != "",
		"acme_email": s.ACMEEmail, "acme_agree": s.ACMEAgree, "acme_staging": s.ACMEStaging,
		"has_custom": s.CertPEM != "", "suggested_address": firstLocalIPv4(),
		"doh_listen": a.cfg.DoHListen, "dot_listen": a.cfg.DoTListen,
		"issuing": a.enc.issuing.Load(),
	}
	a.enc.mu.Lock()
	v["doh_running"], v["dot_running"] = a.enc.doh != nil, a.enc.dot != nil
	a.enc.mu.Unlock()
	if s.Hostname != "" {
		v["doh_url"] = a.dohURL(s, "")
	}
	if c := a.enc.cert.Load(); c != nil && c.Leaf != nil {
		v["cert_not_after"] = c.Leaf.NotAfter
		v["cert_issuer"] = c.Leaf.Issuer.CommonName
		v["cert_fingerprint"] = fingerprint(c.Leaf)
	}
	if e := a.enc.lastErr.Load(); e != nil {
		v["error"] = *e
	}
	if m := a.enc.acme.Load(); m != nil {
		v["acme_status"] = *m
	}
	devs := []encDeviceView{}
	for _, d := range s.Devices {
		dv := encDeviceView{PersonalDevice: d}
		if s.Hostname != "" {
			dv.DoH = a.dohURL(s, d.Token)
			dv.DoT = d.Token + "." + s.Hostname
		}
		devs = append(devs, dv)
	}
	v["devices"] = devs
	writeJSON(w, v)
}

func (a *App) hEncSave(w http.ResponseWriter, r *http.Request) {
	var req EncDNSSettings
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	cur := a.state.get().encDNS()
	req.Hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Hostname), "."))
	req.Address = strings.TrimSpace(req.Address)
	req.ACMEEmail = strings.TrimSpace(req.ACMEEmail)
	if req.Hostname != "" && !validHost(req.Hostname) {
		jsonErr(w, http.StatusBadRequest, "hostname must look like dns.example.com")
		return
	}
	if req.Enabled && req.Hostname == "" {
		jsonErr(w, http.StatusBadRequest, "a hostname is required")
		return
	}
	if req.Address != "" {
		if ip, err := netip.ParseAddr(req.Address); err != nil || !ip.Is4() {
			jsonErr(w, http.StatusBadRequest, "address must be an IPv4 address")
			return
		}
	}
	switch req.CertSource {
	case CertCA, CertCustom:
	case CertACME:
		if req.ACMEProvider != certs.ProviderCloudflare && req.ACMEProvider != certs.ProviderDuckDNS && req.ACMEProvider != certs.ProviderDeSEC {
			jsonErr(w, http.StatusBadRequest, "choose a DNS provider")
			return
		}
		if req.ACMEProvider == certs.ProviderDuckDNS && req.Hostname != "" && !strings.HasSuffix(req.Hostname, ".duckdns.org") {
			jsonErr(w, http.StatusBadRequest, "with DuckDNS the hostname must end with .duckdns.org")
			return
		}
	default:
		jsonErr(w, http.StatusBadRequest, "certificate source must be ca, acme or custom")
		return
	}
	if req.ACMEToken == "" {
		req.ACMEToken = cur.ACMEToken
	}
	if req.CertSource == CertCustom {
		if req.CertPEM == "" && req.KeyPEM == "" {
			req.CertPEM, req.KeyPEM = cur.CertPEM, cur.KeyPEM
		}
		if _, err := parsePair(req.CertPEM, req.KeyPEM); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		req.CertPEM, req.KeyPEM = cur.CertPEM, cur.KeyPEM
	}
	req.Devices = cur.Devices // managed by the device endpoints
	if err := a.state.update(func(s *State) { s.EncDNS = &req }); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.applyEnc(); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.hEncGet(w, r)
}

func (a *App) hEncIssue(w http.ResponseWriter, r *http.Request) {
	if err := a.issueACME(); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.hEncGet(w, r)
}

func newDeviceToken() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, 16)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func (a *App) hEncDeviceAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		IP   string `json:"ip"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(req.IP))
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "IP: the address this device counts as (e.g. its static LAN IP)")
		return
	}
	name := devices.CleanManual(req.Name)
	if name == "" {
		jsonErr(w, http.StatusBadRequest, "name is required")
		return
	}
	err = a.state.update(func(s *State) {
		e := s.encDNS()
		if len(e.Devices) >= 500 {
			return
		}
		e.Devices = append(e.Devices, PersonalDevice{Token: newDeviceToken(), Name: name, IP: ip.String(), Created: time.Now()})
		s.EncDNS = &e
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.applyEnc()
	a.hEncGet(w, r)
}

func (a *App) hEncDeviceDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	err := a.state.update(func(s *State) {
		e := s.encDNS()
		out := e.Devices[:0:0]
		for _, d := range e.Devices {
			if d.Token != req.Token {
				out = append(out, d)
			}
		}
		e.Devices = out
		s.EncDNS = &e
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.applyEnc()
	a.hEncGet(w, r)
}

func (a *App) hEncCA(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(filepath.Join(a.tlsDir(), "ca.crt"))
	if err != nil {
		jsonErr(w, http.StatusNotFound, "no local CA yet (choose \"VartaDNS certificate\" and save)")
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="vartadns-ca.crt"`)
	w.Write(b)
}

func uuid() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// hEncMobileconfig builds an Apple configuration profile (DoH + the local CA
// when that source is used) for one personal device.
func (a *App) hEncMobileconfig(w http.ResponseWriter, r *http.Request) {
	s := a.state.get().encDNS()
	tok := r.URL.Query().Get("token")
	var dev *PersonalDevice
	for i := range s.Devices {
		if s.Devices[i].Token == tok {
			dev = &s.Devices[i]
		}
	}
	if dev == nil || !s.Enabled || !s.DoH {
		jsonErr(w, http.StatusNotFound, "device not found or DoH is off")
		return
	}
	x := html.EscapeString
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
`)
	if s.CertSource == CertCA {
		if p, err := os.ReadFile(filepath.Join(a.tlsDir(), "ca.crt")); err == nil {
			if blk, _ := pem.Decode(p); blk != nil {
				id := uuid()
				fmt.Fprintf(&b, `<dict>
<key>PayloadType</key><string>com.apple.security.root</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>ua.vartadns.ca.%s</string>
<key>PayloadUUID</key><string>%s</string>
<key>PayloadDisplayName</key><string>VartaDNS local CA</string>
<key>PayloadContent</key><data>%s</data>
</dict>
`, id, id, base64.StdEncoding.EncodeToString(blk.Bytes))
			}
		}
	}
	id := uuid()
	fmt.Fprintf(&b, `<dict>
<key>DNSSettings</key>
<dict>
<key>DNSProtocol</key><string>HTTPS</string>
<key>ServerURL</key><string>%s</string>
`, x(a.dohURL(s, dev.Token)))
	if s.Address != "" {
		fmt.Fprintf(&b, "<key>ServerAddresses</key><array><string>%s</string></array>\n", x(s.Address))
	}
	fmt.Fprintf(&b, `</dict>
<key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>ua.vartadns.dns.%s</string>
<key>PayloadUUID</key><string>%s</string>
<key>PayloadDisplayName</key><string>VartaDNS</string>
</dict>
</array>
<key>PayloadDisplayName</key><string>VartaDNS — %s</string>
<key>PayloadIdentifier</key><string>ua.vartadns.profile.%s</string>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>%s</string>
<key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
`, id, id, x(dev.Name), x(dev.Token), uuid())
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="vartadns-`+dev.Token[:6]+`.mobileconfig"`)
	w.Write([]byte(b.String()))
}

// ---- syslog API ------------------------------------------------------------------------------

func (a *App) hSyslogGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"settings": a.Syslog.Settings(), "status": a.Syslog.Status()})
}

func (a *App) hSyslogSave(w http.ResponseWriter, r *http.Request) {
	var s syslog.Settings
	if err := readJSON(r, &s); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := s.Validate(); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.state.update(func(st *State) { st.Syslog = &s }); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.Syslog.SetSettings(s)
	a.hSyslogGet(w, r)
}

func (a *App) hSyslogTest(w http.ResponseWriter, r *http.Request) {
	if !a.Syslog.Settings().Enabled {
		jsonErr(w, http.StatusBadRequest, "enable syslog and save first")
		return
	}
	a.Syslog.Query(&stats.Entry{Time: time.Now(), Client: "127.0.0.1", Device: "VartaDNS test",
		Name: "test.vartadns.invalid", Type: "A", Status: stats.StatusBlocked, Kind: "malware",
		Source: "test", Rule: "test.vartadns.invalid", Proto: "test"})
	writeJSON(w, map[string]bool{"ok": true})
}
