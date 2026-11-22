package app

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/takobas/vartadns/internal/upstream"
)

// Preset is a ready-made upstream set offered in the panel.
type Preset struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Upstreams []string `json:"upstreams"`
	Bootstrap []string `json:"bootstrap"`
	Note      string   `json:"note"` // i18n key
}

// Presets: DoH first, then plain DNS of the same provider as fallback.
var Presets = []Preset{
	{ID: "quad9", Name: "Quad9", Note: "preset_quad9",
		Upstreams: []string{"https://dns.quad9.net/dns-query", "9.9.9.9", "149.112.112.112"},
		Bootstrap: []string{"9.9.9.9", "149.112.112.112"}},
	{ID: "cloudflare", Name: "Cloudflare", Note: "preset_cloudflare",
		Upstreams: []string{"https://cloudflare-dns.com/dns-query", "1.1.1.1", "1.0.0.1"},
		Bootstrap: []string{"1.1.1.1", "1.0.0.1"}},
	{ID: "cloudflare-security", Name: "Cloudflare Security", Note: "preset_cf_security",
		Upstreams: []string{"https://security.cloudflare-dns.com/dns-query", "1.1.1.2", "1.0.0.2"},
		Bootstrap: []string{"1.1.1.2", "1.0.0.2"}},
	{ID: "cloudflare-family", Name: "Cloudflare Family", Note: "preset_cf_family",
		Upstreams: []string{"https://family.cloudflare-dns.com/dns-query", "1.1.1.3", "1.0.0.3"},
		Bootstrap: []string{"1.1.1.3", "1.0.0.3"}},
	{ID: "google", Name: "Google", Note: "preset_google",
		Upstreams: []string{"https://dns.google/dns-query", "8.8.8.8", "8.8.4.4"},
		Bootstrap: []string{"8.8.8.8", "8.8.4.4"}},
	{ID: "adguard", Name: "AdGuard DNS", Note: "preset_adguard",
		Upstreams: []string{"https://dns.adguard-dns.com/dns-query", "94.140.14.14", "94.140.15.15"},
		Bootstrap: []string{"94.140.14.14", "94.140.15.15"}},
}

func cleanList(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (a *App) hUpstreamsGet(w http.ResponseWriter, r *http.Request) {
	s := a.state.get()
	writeJSON(w, map[string]any{
		"upstreams":  nz(a.Group.Specs()),
		"bootstrap":  nz(a.Boot.Servers()),
		"custom":     len(s.Upstreams) > 0,
		"defaults":   map[string][]string{"upstreams": nz(a.cfg.Upstreams), "bootstrap": nz(a.cfg.Bootstrap)},
		"presets":    Presets,
		"status":     a.Group.Statuses(),
		"strategy":   a.Group.Strategy().String(),
		"max":        upstream.MaxUpstreams,
		"timeout_ms": a.timeout.Milliseconds(),
	})
}

type upstreamsReq struct {
	Upstreams []string `json:"upstreams"`
	Bootstrap []string `json:"bootstrap"`
}

func (r *upstreamsReq) clean() error {
	r.Upstreams, r.Bootstrap = cleanList(r.Upstreams), cleanList(r.Bootstrap)
	if err := upstream.Validate(r.Upstreams); err != nil {
		return err
	}
	return upstream.ValidateBootstrap(r.Bootstrap)
}

// testSet checks every server, resolving DoH hostnames through the
// bootstrap servers being tested (not the active ones).
func (a *App) testSet(ctx context.Context, req upstreamsReq) []upstream.Result {
	boot := upstream.NewBootstrap(req.Bootstrap)
	return upstream.Test(ctx, req.Upstreams, boot.Resolver(), a.timeout+time.Second)
}

func (a *App) hUpstreamsTest(w http.ResponseWriter, r *http.Request) {
	var req upstreamsReq
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := req.clean(); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]any{"results": a.testSet(r.Context(), req)})
}

// apply switches the live servers and stores (or clears) the override.
func (a *App) applyUpstreams(req upstreamsReq, save bool) error {
	a.Boot.Set(req.Bootstrap)
	if err := a.Group.SetSpecs(req.Upstreams); err != nil {
		return err
	}
	a.Cache.Flush()
	return a.state.update(func(s *State) {
		if save {
			s.Upstreams, s.Bootstrap = req.Upstreams, req.Bootstrap
		} else {
			s.Upstreams, s.Bootstrap = nil, nil
		}
	})
}

func (a *App) hUpstreamsSave(w http.ResponseWriter, r *http.Request) {
	var req upstreamsReq
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := req.clean(); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Refuse a set where nothing answers: it would leave the network
	// without working DNS (the router fallback only covers a dead container).
	results := a.testSet(r.Context(), req)
	ok := false
	for _, res := range results {
		ok = ok || res.OK
	}
	if !ok {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnprocessableEntity)
		writeJSON(w, map[string]any{"error": "none of the servers answered", "results": results})
		return
	}
	if err := a.applyUpstreams(req, true); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"results": results, "status": a.Group.Statuses()})
}

func (a *App) hUpstreamsReset(w http.ResponseWriter, r *http.Request) {
	req := upstreamsReq{Upstreams: a.cfg.Upstreams, Bootstrap: a.cfg.Bootstrap}
	if err := req.clean(); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.applyUpstreams(req, false); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.hUpstreamsGet(w, r)
}
