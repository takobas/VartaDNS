package app

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/takobas/vartadns/internal/filter"
	"github.com/takobas/vartadns/internal/stats"
)

//go:embed static
var staticFS embed.FS

const cookieName = "varta_session"

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))

	mux.HandleFunc("POST /api/login", a.hLogin)
	mux.HandleFunc("POST /api/logout", a.hLogout)

	api := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, a.auth(h)) }
	api("GET /api/status", a.hStatus)
	api("GET /api/series", a.hSeries)
	api("GET /api/top", a.hTop)
	api("GET /api/querylog", a.hQueryLog)
	api("GET /api/check", a.hCheck)
	api("POST /api/blocking", a.hBlocking)
	api("GET /api/rules", a.hRulesGet)
	api("POST /api/rules", a.hRulesAdd)
	api("DELETE /api/rules", a.hRulesDelete)
	api("GET /api/lists", a.hListsGet)
	api("POST /api/lists", a.hListsAdd)
	api("PUT /api/lists", a.hListsUpdate)
	api("DELETE /api/lists", a.hListsDelete)
	api("POST /api/lists/refresh", a.hListsRefresh)
	api("POST /api/cache/flush", a.hCacheFlush)
	api("POST /api/password", a.hPassword)
	api("GET /metrics", a.hMetrics)
	api("GET /api/groups", a.hGroupsGet)
	api("POST /api/groups", a.hGroupsCreate)
	api("PUT /api/groups", a.hGroupsUpdate)
	api("DELETE /api/groups", a.hGroupsDelete)
	api("POST /api/groups/move", a.hGroupsMove)
	api("POST /api/groups/internet", a.hGroupsInternet)
	api("POST /api/groups/rule", a.hGroupsRule)
	return a.hostCheck(securityHeaders(mux))
}

// hostCheck rejects requests whose Host header is a hostname we were not
// told about. Blocks DNS-rebinding attacks from web pages in the LAN; the
// panel is still reachable by IP address and by names in "web_hosts".
func (a *App) hostCheck(next http.Handler) http.Handler {
	allowed := map[string]bool{"localhost": true}
	for _, h := range a.cfg.WebHosts {
		allowed[strings.ToLower(strings.TrimSpace(h))] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(strings.Trim(host, "[]"))
		if _, err := netip.ParseAddr(host); err != nil && !allowed[host] {
			http.Error(w, "unknown host; add it to web_hosts in config.json", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}

// auth requires a valid session cookie; state-changing requests must also
// carry the X-Varta header (blocks cross-site form posts).
func (a *App) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || !a.sessions.valid(c.Value) {
			jsonErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Varta") != "1" {
			jsonErr(w, http.StatusForbidden, "missing X-Varta header")
			return
		}
		next(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	return dec.Decode(v)
}

// ---- auth handlers ------------------------------------------------------------------

func (a *App) hLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if a.sessions.lockedOut(ip) {
		jsonErr(w, http.StatusTooManyRequests, "too many failed logins, wait 10 minutes")
		return
	}
	var req struct{ User, Password string }
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if !a.checkPassword(req.User, req.Password) {
		a.sessions.fail(ip)
		time.Sleep(500 * time.Millisecond)
		jsonErr(w, http.StatusUnauthorized, "wrong user or password")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: a.sessions.create(), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
		MaxAge: int(sessionTTL / time.Second),
	})
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) hLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.sessions.drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) hPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if !a.checkPassword(a.state.get().AdminUser, req.Old) {
		jsonErr(w, http.StatusForbidden, "current password is wrong")
		return
	}
	if err := a.SetPassword(req.New); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.sessions.dropAll()
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- status & stats -------------------------------------------------------------------

func (a *App) hStatus(w http.ResponseWriter, r *http.Request) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	blk, alw := a.Engine.RuleCounts()
	cb, ca := a.Engine.Custom()
	hits, misses := a.Cache.Stats()
	s := a.Stats
	a.statusMu.RLock()
	last := a.lastUpdate
	a.statusMu.RUnlock()
	writeJSON(w, map[string]any{
		"version":          Version,
		"uptime_sec":       int64(s.Uptime().Seconds()),
		"blocking":         a.Resolver.BlockingEnabled(),
		"disabled_until":   a.Resolver.DisabledUntil(),
		"total":            s.Total.Load(),
		"blocked":          s.Blocked.Load(),
		"cached":           s.Cached.Load(),
		"errors":           s.Errors.Load(),
		"refused":          s.Refused.Load(),
		"qps":              s.QPS(),
		"rules_block":      blk,
		"rules_allow":      alw,
		"custom_block":     len(cb),
		"custom_allow":     len(ca),
		"cache_entries":    a.Cache.Len(),
		"cache_hits":       hits,
		"cache_misses":     misses,
		"mem_alloc_mb":     float64(ms.Alloc) / (1 << 20),
		"mem_sys_mb":       float64(ms.Sys) / (1 << 20),
		"goroutines":       runtime.NumGoroutine(),
		"upstreams":        a.Group.Statuses(),
		"lists_updated_at": last,
		"admin_user":       a.state.get().AdminUser,
	})
}

func (a *App) hSeries(w http.ResponseWriter, r *http.Request) {
	m, _ := strconv.Atoi(r.URL.Query().Get("minutes"))
	writeJSON(w, a.Stats.Series(m))
}

func (a *App) hTop(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 || n > 100 {
		n = 10
	}
	d, b, c, since := a.Stats.Tops(n)
	writeJSON(w, map[string]any{"domains": d, "blocked": b, "clients": c, "since": since})
}

func (a *App) hQueryLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	writeJSON(w, a.Stats.Log(stats.Filter{
		Search: q.Get("q"), Status: q.Get("status"), Client: q.Get("client"), Group: q.Get("group"), Limit: limit,
	}))
}

func (a *App) hCheck(w http.ResponseWriter, r *http.Request) {
	d := filter.Normalize(r.URL.Query().Get("domain"))
	if d == "" {
		jsonErr(w, http.StatusBadRequest, "invalid domain")
		return
	}
	m := a.Engine.Check(d)
	verdict := map[filter.Verdict]string{filter.Pass: "pass", filter.Blocked: "blocked", filter.Allowed: "allowed"}[m.Verdict]
	writeJSON(w, map[string]string{"domain": d, "verdict": verdict, "rule": m.Rule, "source": m.Source})
}

func (a *App) hBlocking(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
		Minutes int  `json:"minutes"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	a.Resolver.SetBlocking(req.Enabled, time.Duration(req.Minutes)*time.Minute)
	writeJSON(w, map[string]any{"blocking": a.Resolver.BlockingEnabled(), "disabled_until": a.Resolver.DisabledUntil()})
}

// ---- custom rules --------------------------------------------------------------------------

func (a *App) hRulesGet(w http.ResponseWriter, r *http.Request) {
	b, al := a.Engine.Custom()
	writeJSON(w, map[string][]string{"block": nz(b), "allow": nz(al)})
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type ruleReq struct {
	Kind   string `json:"kind"` // "block" | "allow"
	Domain string `json:"domain"`
}

func (a *App) editRules(w http.ResponseWriter, r *http.Request, add bool) {
	var req ruleReq
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	d := filter.Normalize(req.Domain)
	if d == "" || (req.Kind != "block" && req.Kind != "allow") {
		jsonErr(w, http.StatusBadRequest, "invalid domain or kind")
		return
	}
	err := a.state.update(func(s *State) {
		list := &s.CustomBlock
		if req.Kind == "allow" {
			list = &s.CustomAllow
		}
		*list = editList(*list, d, add)
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s := a.state.get()
	a.Engine.SetCustom(s.CustomBlock, s.CustomAllow)
	a.Cache.Flush() // cached answers may now be wrong
	a.hRulesGet(w, r)
}

func editList(list []string, d string, add bool) []string {
	out := list[:0:0]
	for _, x := range list {
		if x != d {
			out = append(out, x)
		}
	}
	if add {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func (a *App) hRulesAdd(w http.ResponseWriter, r *http.Request)    { a.editRules(w, r, true) }
func (a *App) hRulesDelete(w http.ResponseWriter, r *http.Request) { a.editRules(w, r, false) }

// ---- lists -------------------------------------------------------------------------------------

func (a *App) hListsGet(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.ListStatuses()) }

func validListURL(u string) bool {
	return strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")
}

func (a *App) hListsAdd(w http.ResponseWriter, r *http.Request) {
	var spec ListSpec
	if err := readJSON(r, &spec); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	spec.Name = strings.TrimSpace(spec.Name)
	spec.URL = strings.TrimSpace(spec.URL)
	if spec.Name == "" || !validListURL(spec.URL) {
		jsonErr(w, http.StatusBadRequest, "name and http(s) URL are required")
		return
	}
	spec.Enabled = true
	var dup bool
	err := a.state.update(func(s *State) {
		for _, l := range s.Lists {
			if l.URL == spec.URL {
				dup = true
				return
			}
		}
		s.Lists = append(s.Lists, spec)
	})
	if dup {
		jsonErr(w, http.StatusConflict, "list already exists")
		return
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.refreshAsync()
	writeJSON(w, a.ListStatuses())
}

func (a *App) hListsUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL     string `json:"url"`
		Enabled bool   `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	found := false
	err := a.state.update(func(s *State) {
		for i := range s.Lists {
			if s.Lists[i].URL == req.URL {
				s.Lists[i].Enabled = req.Enabled
				found = true
			}
		}
	})
	if !found {
		jsonErr(w, http.StatusNotFound, "list not found")
		return
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	go func() { a.RebuildLists(context.Background(), false); a.Cache.Flush() }()
	writeJSON(w, a.ListStatuses())
}

func (a *App) hListsDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	err := a.state.update(func(s *State) {
		out := s.Lists[:0:0]
		for _, l := range s.Lists {
			if l.URL != req.URL {
				out = append(out, l)
			}
		}
		s.Lists = out
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	go func() { a.RebuildLists(context.Background(), false); a.Cache.Flush() }()
	writeJSON(w, a.ListStatuses())
}

func (a *App) refreshAsync() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		a.RebuildLists(ctx, true)
		a.Cache.Flush()
	}()
}

func (a *App) hListsRefresh(w http.ResponseWriter, r *http.Request) {
	a.refreshAsync()
	writeJSON(w, map[string]bool{"started": true})
}

func (a *App) hCacheFlush(w http.ResponseWriter, r *http.Request) {
	a.Cache.Flush()
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- Prometheus ---------------------------------------------------------------------------------

func (a *App) hMetrics(w http.ResponseWriter, r *http.Request) {
	s := a.Stats
	blk, alw := a.Engine.RuleCounts()
	hits, misses := a.Cache.Stats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	p := func(name, help, typ string, v any) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", name, help, name, typ, name, v)
	}
	p("varta_queries_total", "Total DNS queries.", "counter", s.Total.Load())
	p("varta_blocked_total", "Blocked queries.", "counter", s.Blocked.Load())
	p("varta_cached_total", "Queries answered from cache.", "counter", s.Cached.Load())
	p("varta_errors_total", "Queries that failed.", "counter", s.Errors.Load())
	p("varta_refused_total", "Queries refused (rate limit, ANY).", "counter", s.Refused.Load())
	p("varta_cache_hits_total", "Cache hits.", "counter", hits)
	p("varta_cache_misses_total", "Cache misses.", "counter", misses)
	p("varta_cache_entries", "Entries in cache.", "gauge", a.Cache.Len())
	p("varta_rules_block", "Active block rules.", "gauge", blk)
	p("varta_rules_allow", "Active allow rules.", "gauge", alw)
	on := 0
	if a.Resolver.BlockingEnabled() {
		on = 1
	}
	p("varta_blocking_enabled", "1 if filtering is enabled.", "gauge", on)
	fmt.Fprintf(w, "# HELP varta_upstream_latency_ms Upstream EWMA latency.\n# TYPE varta_upstream_latency_ms gauge\n")
	for _, u := range a.Group.Statuses() {
		fmt.Fprintf(w, "varta_upstream_latency_ms{upstream=%q} %.3f\n", u.Name, u.LatencyMs)
	}
}
