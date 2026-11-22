package certs

import (
	"bytes"
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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Let's Encrypt directories.
const (
	LetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Solver publishes and removes the DNS-01 TXT record.
type Solver interface {
	Present(ctx context.Context, fqdn, value string) error
	CleanUp(ctx context.Context, fqdn, value string) error
	Wait() time.Duration // how long to wait for the record to be visible
}

// ACME is a minimal RFC 8555 client (ES256 account key, DNS-01 only).
type ACME struct {
	Directory string
	HTTP      *http.Client
	Key       *ecdsa.PrivateKey
	Log       func(string)

	dir   struct{ NewNonce, NewAccount, NewOrder string }
	kid   string
	nonce string
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// LoadOrCreateKey loads an EC key from path or creates it (0600).
func LoadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
				return k, nil
			}
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	p, err := EncodeKey(k)
	if err != nil {
		return nil, err
	}
	return k, os.WriteFile(path, p, 0o600)
}

func (c *ACME) logf(f string, a ...any) {
	if c.Log != nil {
		c.Log(fmt.Sprintf(f, a...))
	}
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func (c *ACME) jwk() map[string]string {
	return map[string]string{"crv": "P-256", "kty": "EC",
		"x": b64(pad32(c.Key.X.Bytes())), "y": b64(pad32(c.Key.Y.Bytes()))}
}

// Thumbprint is the RFC 7638 JWK thumbprint of the account key.
func (c *ACME) Thumbprint() string {
	j := c.jwk()
	s := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, j["x"], j["y"])
	h := sha256.Sum256([]byte(s))
	return b64(h[:])
}

// DNS01Value is the TXT value for a challenge token.
func (c *ACME) DNS01Value(token string) string {
	h := sha256.Sum256([]byte(token + "." + c.Thumbprint()))
	return b64(h[:])
}

type problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

func (c *ACME) init(ctx context.Context) error {
	if c.dir.NewNonce != "" {
		return nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.Directory, nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("acme directory: HTTP %d", resp.StatusCode)
	}
	var d struct{ NewNonce, NewAccount, NewOrder string }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return err
	}
	if d.NewNonce == "" || d.NewAccount == "" || d.NewOrder == "" {
		return errors.New("acme directory: missing endpoints")
	}
	c.dir = d
	return nil
}

func (c *ACME) newNonce(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, c.dir.NewNonce, nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	c.nonce = resp.Header.Get("Replay-Nonce")
	if c.nonce == "" {
		return errors.New("acme: no nonce")
	}
	return nil
}

// post sends a JWS-signed request; payload nil = POST-as-GET.
func (c *ACME) post(ctx context.Context, url string, payload any, out any) (*http.Response, []byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		if c.nonce == "" {
			if err := c.newNonce(ctx); err != nil {
				return nil, nil, err
			}
		}
		prot := map[string]any{"alg": "ES256", "nonce": c.nonce, "url": url}
		if c.kid != "" {
			prot["kid"] = c.kid
		} else {
			prot["jwk"] = c.jwk()
		}
		c.nonce = ""
		pb, _ := json.Marshal(prot)
		var plb []byte
		if payload != nil {
			plb, _ = json.Marshal(payload)
		}
		signing := b64(pb) + "." + b64(plb)
		if payload == nil {
			signing = b64(pb) + "."
		}
		h := sha256.Sum256([]byte(signing))
		r, s, err := ecdsa.Sign(rand.Reader, c.Key, h[:])
		if err != nil {
			return nil, nil, err
		}
		sig := append(pad32(r.Bytes()), pad32(s.Bytes())...)
		body, _ := json.Marshal(map[string]string{"protected": b64(pb), "payload": strings.TrimPrefix(signing, b64(pb)+"."), "signature": b64(sig)})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/jose+json")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, nil, err
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		c.nonce = resp.Header.Get("Replay-Nonce")
		if resp.StatusCode >= 400 {
			var p problem
			json.Unmarshal(data, &p)
			if strings.HasSuffix(p.Type, ":badNonce") {
				continue
			}
			if p.Detail == "" {
				p.Detail = http.StatusText(resp.StatusCode)
			}
			return resp, data, fmt.Errorf("acme: %s", p.Detail)
		}
		if out != nil {
			if err := json.Unmarshal(data, out); err != nil {
				return resp, data, fmt.Errorf("acme: bad response: %w", err)
			}
		}
		return resp, data, nil
	}
	return nil, nil, errors.New("acme: too many bad nonces")
}

// Register creates (or finds) the account. agree must reflect the user's
// explicit acceptance of the CA's subscriber agreement.
func (c *ACME) Register(ctx context.Context, email string, agree bool) error {
	if !agree {
		return errors.New("the Let's Encrypt subscriber agreement must be accepted")
	}
	if err := c.init(ctx); err != nil {
		return err
	}
	p := map[string]any{"termsOfServiceAgreed": true}
	if email != "" {
		p["contact"] = []string{"mailto:" + email}
	}
	resp, _, err := c.post(ctx, c.dir.NewAccount, p, nil)
	if err != nil {
		return err
	}
	c.kid = resp.Header.Get("Location")
	if c.kid == "" {
		return errors.New("acme: no account URL")
	}
	return nil
}

type order struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
	url            string
}

type authz struct {
	Status     string `json:"status"`
	Identifier struct {
		Value string `json:"value"`
	} `json:"identifier"`
	Wildcard   bool `json:"wildcard"`
	Challenges []struct {
		Type   string `json:"type"`
		URL    string `json:"url"`
		Token  string `json:"token"`
		Status string `json:"status"`
	} `json:"challenges"`
}

func (c *ACME) poll(ctx context.Context, url string, out any, status func() string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, _, err := c.post(ctx, url, nil, out); err != nil {
			return err
		}
		switch status() {
		case "valid", "ready":
			return nil
		case "invalid":
			return errors.New("acme: validation failed (the TXT record was not visible to Let's Encrypt)")
		}
		if time.Now().After(deadline) {
			return errors.New("acme: timed out waiting for validation")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// Obtain orders a certificate for domains (a "*.x" wildcard is allowed),
// solving the DNS-01 challenges one by one. It returns the chain and key.
func (c *ACME) Obtain(ctx context.Context, domains []string, solver Solver) (certPEM, keyPEM []byte, err error) {
	if c.kid == "" {
		return nil, nil, errors.New("acme: not registered")
	}
	ids := make([]map[string]string, 0, len(domains))
	for _, d := range domains {
		ids = append(ids, map[string]string{"type": "dns", "value": d})
	}
	var o order
	resp, _, err := c.post(ctx, c.dir.NewOrder, map[string]any{"identifiers": ids}, &o)
	if err != nil {
		return nil, nil, err
	}
	o.url = resp.Header.Get("Location")
	for _, au := range o.Authorizations {
		var a authz
		if _, _, err := c.post(ctx, au, nil, &a); err != nil {
			return nil, nil, err
		}
		if a.Status == "valid" {
			continue
		}
		ci := -1
		for i, ch := range a.Challenges {
			if ch.Type == "dns-01" {
				ci = i
			}
		}
		if ci < 0 {
			return nil, nil, errors.New("acme: no dns-01 challenge offered")
		}
		ch := a.Challenges[ci]
		fqdn := "_acme-challenge." + a.Identifier.Value
		val := c.DNS01Value(ch.Token)
		c.logf("publishing TXT %s", fqdn)
		if err := solver.Present(ctx, fqdn, val); err != nil {
			return nil, nil, fmt.Errorf("dns provider: %w", err)
		}
		select {
		case <-ctx.Done():
			solver.CleanUp(context.Background(), fqdn, val)
			return nil, nil, ctx.Err()
		case <-time.After(solver.Wait()):
		}
		if _, _, err := c.post(ctx, ch.URL, map[string]any{}, nil); err != nil {
			solver.CleanUp(context.Background(), fqdn, val)
			return nil, nil, err
		}
		err := c.poll(ctx, au, &a, func() string { return a.Status }, 3*time.Minute)
		solver.CleanUp(context.Background(), fqdn, val)
		if err != nil {
			return nil, nil, err
		}
		c.logf("validated %s", a.Identifier.Value)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains}, key)
	if err != nil {
		return nil, nil, err
	}
	if err := c.poll(ctx, o.url, &o, func() string { return o.Status }, time.Minute); err != nil {
		return nil, nil, err
	}
	if _, _, err := c.post(ctx, o.Finalize, map[string]string{"csr": b64(csr)}, &o); err != nil {
		return nil, nil, err
	}
	if o.Status != "valid" {
		if err := c.poll(ctx, o.url, &o, func() string {
			if o.Status == "valid" && o.Certificate == "" {
				return "processing"
			}
			return o.Status
		}, 2*time.Minute); err != nil {
			return nil, nil, err
		}
	}
	_, chain, err := c.post(ctx, o.Certificate, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	if blk, _ := pem.Decode(chain); blk == nil || blk.Type != "CERTIFICATE" {
		return nil, nil, errors.New("acme: certificate download is not PEM")
	}
	keyPEM, err = EncodeKey(key)
	return chain, keyPEM, err
}
