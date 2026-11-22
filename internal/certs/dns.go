package certs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DNS providers for DNS-01.
const (
	ProviderCloudflare = "cloudflare"
	ProviderDuckDNS    = "duckdns"
	ProviderDeSEC      = "desec"
)

// NewSolver returns the solver for a provider and its API token.
func NewSolver(provider, token string, hc *http.Client) (Solver, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("DNS provider API token is required")
	}
	switch provider {
	case ProviderCloudflare:
		return &cloudflare{token: token, hc: hc, base: "https://api.cloudflare.com/client/v4", ids: map[string][2]string{}}, nil
	case ProviderDuckDNS:
		return &duckdns{token: token, hc: hc, base: "https://www.duckdns.org"}, nil
	case ProviderDeSEC:
		return &desec{token: token, hc: hc, base: "https://desec.io/api/v1"}, nil
	}
	return nil, fmt.Errorf("unknown DNS provider %q", provider)
}

func doJSON(ctx context.Context, hc *http.Client, method, u string, hdr map[string]string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return 0, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if out != nil && len(data) > 0 {
		_ = json.Unmarshal(data, out)
	}
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}
	return resp.StatusCode, nil
}

// ---- Cloudflare -------------------------------------------------------------------------

type cloudflare struct {
	token, base string
	hc          *http.Client
	ids         map[string][2]string // fqdn|value -> zone id, record id
}

func (c *cloudflare) Wait() time.Duration { return 20 * time.Second }

func (c *cloudflare) hdr() map[string]string {
	return map[string]string{"Authorization": "Bearer " + c.token}
}

func (c *cloudflare) zone(ctx context.Context, fqdn string) (string, error) {
	labels := strings.Split(fqdn, ".")
	for i := 0; i < len(labels)-1; i++ {
		name := strings.Join(labels[i:], ".")
		var r struct {
			Result []struct {
				ID string `json:"id"`
			} `json:"result"`
		}
		if _, err := doJSON(ctx, c.hc, http.MethodGet, c.base+"/zones?name="+url.QueryEscape(name), c.hdr(), nil, &r); err != nil {
			return "", fmt.Errorf("cloudflare: %w", err)
		}
		if len(r.Result) > 0 {
			return r.Result[0].ID, nil
		}
	}
	return "", errors.New("cloudflare: zone not found for " + fqdn + " (does the token have access to it?)")
}

func (c *cloudflare) Present(ctx context.Context, fqdn, value string) error {
	z, err := c.zone(ctx, fqdn)
	if err != nil {
		return err
	}
	var r struct {
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	_, err = doJSON(ctx, c.hc, http.MethodPost, c.base+"/zones/"+z+"/dns_records", c.hdr(),
		map[string]any{"type": "TXT", "name": fqdn, "content": value, "ttl": 120}, &r)
	if err != nil {
		return fmt.Errorf("cloudflare: %w", err)
	}
	c.ids[fqdn+"|"+value] = [2]string{z, r.Result.ID}
	return nil
}

func (c *cloudflare) CleanUp(ctx context.Context, fqdn, value string) error {
	id, ok := c.ids[fqdn+"|"+value]
	if !ok {
		return nil
	}
	delete(c.ids, fqdn+"|"+value)
	_, err := doJSON(ctx, c.hc, http.MethodDelete, c.base+"/zones/"+id[0]+"/dns_records/"+id[1], c.hdr(), nil, nil)
	return err
}

// ---- DuckDNS ------------------------------------------------------------------------------

// duckdns keeps one TXT value per subdomain (challenges are solved one by one).
type duckdns struct {
	token, base string
	hc          *http.Client
}

func (d *duckdns) Wait() time.Duration { return 60 * time.Second }

func duckSub(fqdn string) (string, error) {
	n := strings.TrimSuffix(strings.TrimPrefix(fqdn, "_acme-challenge."), ".")
	if !strings.HasSuffix(n, ".duckdns.org") {
		return "", errors.New("duckdns: the hostname must end with .duckdns.org")
	}
	n = strings.TrimSuffix(n, ".duckdns.org")
	if i := strings.LastIndexByte(n, '.'); i >= 0 {
		n = n[i+1:] // a.b.duckdns.org -> b
	}
	return n, nil
}

func (d *duckdns) set(ctx context.Context, fqdn, value string, clear bool) error {
	sub, err := duckSub(fqdn)
	if err != nil {
		return err
	}
	q := url.Values{"domains": {sub}, "token": {d.token}, "txt": {value}, "verbose": {"true"}}
	if clear {
		q.Set("clear", "true")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, d.base+"/update?"+q.Encode(), nil)
	resp, err := d.hc.Do(req)
	if err != nil {
		return errors.New("duckdns: request failed") // the URL contains the token
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if !strings.HasPrefix(string(b), "OK") {
		return errors.New("duckdns: update rejected (check the token and subdomain)")
	}
	return nil
}

func (d *duckdns) Present(ctx context.Context, fqdn, value string) error {
	return d.set(ctx, fqdn, value, false)
}
func (d *duckdns) CleanUp(ctx context.Context, fqdn, value string) error {
	return d.set(ctx, fqdn, "", true)
}

// ---- deSEC ---------------------------------------------------------------------------------

type desec struct {
	token, base string
	hc          *http.Client
}

func (d *desec) Wait() time.Duration { return 90 * time.Second }

func (d *desec) hdr() map[string]string {
	return map[string]string{"Authorization": "Token " + d.token}
}

func (d *desec) split(ctx context.Context, fqdn string) (domain, sub string, err error) {
	var r []struct {
		Name string `json:"name"`
	}
	if _, err := doJSON(ctx, d.hc, http.MethodGet, d.base+"/domains/?owns_qname="+url.QueryEscape(fqdn), d.hdr(), nil, &r); err != nil {
		return "", "", fmt.Errorf("desec: %w", err)
	}
	if len(r) == 0 {
		return "", "", errors.New("desec: no domain in this account owns " + fqdn)
	}
	return r[0].Name, strings.TrimSuffix(fqdn, "."+r[0].Name), nil
}

func (d *desec) Present(ctx context.Context, fqdn, value string) error {
	dom, sub, err := d.split(ctx, fqdn)
	if err != nil {
		return err
	}
	rec := map[string]any{"subname": sub, "type": "TXT", "ttl": 3600, "records": []string{`"` + value + `"`}}
	// PUT on the rrset collection creates or replaces it.
	if _, err := doJSON(ctx, d.hc, http.MethodPut, d.base+"/domains/"+dom+"/rrsets/", d.hdr(), []any{rec}, nil); err != nil {
		return fmt.Errorf("desec: %w", err)
	}
	return nil
}

func (d *desec) CleanUp(ctx context.Context, fqdn, value string) error {
	dom, sub, err := d.split(ctx, fqdn)
	if err != nil {
		return err
	}
	_, err = doJSON(ctx, d.hc, http.MethodDelete, d.base+"/domains/"+dom+"/rrsets/"+url.PathEscape(sub)+"/TXT/", d.hdr(), nil, nil)
	return err
}
