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
	"github.com/takobas/vartadns/internal/upstream"
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

	// Minimum role per route: viewer < operator < admin.
	api := func(role, pattern string, h http.HandlerFunc) { mux.Handle(pattern, a.auth(role, h)) }
	api(RoleViewer, "GET /api/status", a.hStatus)
	api(RoleViewer, "GET /api/series", a.hSeries)
	api(RoleViewer, "GET /api/top", a.hTop)
	api(RoleViewer, "GET /api/querylog", a.hQueryLog)
	api(RoleViewer, "GET /api/check", a.hCheck)
	api(RoleAdmin, "POST /api/blocking", a.hBlocking)
	api(RoleViewer, "GET /api/rules", a.hRulesGet)
	api(RoleAdmin, "POST /api/rules", a.hRulesAdd)
	api(RoleAdmin, "DELETE /api/rules", a.hRulesDelete)
	api(RoleViewer, "GET /api/lists", a.hListsGet)
	api(RoleAdmin, "POST /api/lists", a.hListsAdd)
	api(RoleAdmin, "PUT /api/lists", a.hListsUpdate)
	api(RoleAdmin, "DELETE /api/lists", a.hListsDelete)
	api(RoleAdmin, "POST /api/lists/refresh", a.hListsRefresh)
	api(RoleAdmin, "POST /api/cache/flush", a.hCacheFlush)
	api(RoleViewer, "POST /api/password", a.hPassword)
	api(RoleViewer, "GET /metrics", a.hMetrics)
	api(RoleAdmin, "POST /api/upstream/strategy", a.hUpstreamStrategy)
	api(RoleViewer, "GET /api/upstreams", a.hUpstreamsGet)
	api(RoleAdmin, "POST /api/upstreams/test", a.hUpstreamsTest)
	api(RoleAdmin, "PUT /api/upstreams", a.hUpstreamsSave)
	api(RoleAdmin, "POST /api/upstreams/reset", a.hUpstreamsReset)
	api(RoleViewer, "GET /api/groups", a.hGroupsGet)
	api(RoleAdmin, "POST /api/groups", a.hGroupsCreate)
	api(RoleOperator, "PUT /api/groups", a.hGroupsUpdate)
	api(RoleAdmin, "DELETE /api/groups", a.hGroupsDelete)
	api(RoleAdmin, "POST /api/groups/move", a.hGroupsMove)
	api(RoleOperator, "POST /api/groups/internet", a.hGroupsInternet)
	api(RoleOperator, "POST /api/groups/rule", a.hGroupsRule)
	api(RoleViewer, "GET /api/qlog", a.hQLogStatus)
	api(RoleAdmin, "PUT /api/qlog", a.hQLogSettings)
	api(RoleViewer, "GET /api/qlog/entries", a.hQLogDisk)
	api(RoleViewer, "GET /api/qlog/export", a.hQLogExport)
	api(RoleAdmin, "GET /api/telegram", a.hTelegramGet)
	api(RoleAdmin, "PUT /api/telegram", a.hTelegramSave)
	api(RoleAdmin, "POST /api/telegram/test", a.hTelegramTest)
	api(RoleAdmin, "POST /api/telegram/chats", a.hTelegramChats)
	api(RoleViewer, "GET /api/devices", a.hDevicesGet)
	api(RoleAdmin, "PUT /api/devices/name", a.hDeviceName)
	api(RoleAdmin, "POST /api/devices/forget", a.hDeviceForget)
	api(RoleAdmin, "PUT /api/devices/server", a.hNamesServer)
	api(RoleAdmin, "GET /api/backup", a.hBackup)
	api(RoleAdmin, "POST /api/restore", a.hRestore)
	api(RoleViewer, "GET /api/me", a.hMe)
	api(RoleAdmin, "GET /api/users", a.hUsersGet)
	api(RoleAdmin, "PUT /api/users", a.hUsersSave)
	api(RoleAdmin, "DELETE /api/users", a.hUsersDelete)
	api(RoleAdmin, "GET /api/audit", a.hAudit)
	api(RoleAdmin, "GET /api/tls", a.hTLSGet)
	api(RoleAdmin, "PUT /api/tls", a.hTLSSave)
	api(RoleAdmin, "GET /api/filtering", a.hFilteringGet)
	api(RoleAdmin, "PUT /api/filtering", a.hFilteringSave)
	api(RoleAdmin, "GET /api/syslog", a.hSyslogGet)
	api(RoleAdmin, "PUT /api/syslog", a.hSyslogSave)
	api(RoleAdmin, "POST /api/syslog/test", a.hSyslogTest)
	api(RoleAdmin, "GET /api/encdns", a.hEncGet)
	api(RoleAdmin, "PUT /api/encdns", a.hEncSave)
	api(RoleAdmin, "POST /api/encdns/issue", a.hEncIssue)
	api(RoleAdmin, "POST /api/encdns/devices", a.hEncDeviceAdd)
	api(RoleAdmin, "DELETE /api/encdns/devices", a.hEncDeviceDelete)
	api(RoleAdmin, "GET /api/encdns/ca.crt", a.hEncCA)
	api(RoleAdmin, "GET /api/encdns/mobileconfig", a.hEncMobileconfig)
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

// auth requires a valid session with at least the given role; state-changing
// requests must also carry the X-Varta header (blocks cross-site form posts)
// and are written to the audit log.
func (a *App) auth(role string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			jsonErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ss, ok := a.sessions.get(c.Value)
		if !ok {
			jsonErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if roleRank(ss.Role) < roleRank(role) {
			jsonErr(w, http.StatusForbidden, "your role does not allow this")
			return
		}
		if r.Method == http.MethodGet {
			next(w, withSession(r, ss))
			return
		}
		if r.Header.Get("X-Varta") != "1" {
			jsonErr(w, http.StatusForbidden, "missing X-Varta header")
			return
		}
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		next(rec, withSession(r, ss))
		a.auditAdd(AuditEntry{Time: time.Now(), User: ss.User, IP: clientIP(r),
			Action: r.Method + " " + r.URL.Path, Status: rec.code})
	})
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

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
	var req struct{ User, Password string }
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	req.User = strings.TrimSpace(req.User)
	if a.sessions.lockedOut(ip) || a.sessions.lockedOut("user:"+req.User) {
		jsonErr(w, http.StatusTooManyRequests, "too many failed logins, wait 10 minutes")
		return
	}
	u, ok := a.checkLogin(req.User, req.Password)
	if !ok {
		a.sessions.fail(ip, "user:"+req.User)
		a.auditAdd(AuditEntry{Time: time.Now(), User: auditName(req.User), IP: ip, Action: "login", Status: 401})
		time.Sleep(500 * time.Millisecond)
		jsonErr(w, http.StatusUnauthorized, "wrong user or password")
		return
	}
	a.auditAdd(AuditEntry{Time: time.Now(), User: u.Name, IP: ip, Action: "login", Status: 200})
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: a.sessions.create(u.Name, u.Role, ip), Path: "/",
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
	me := sessionOf(r).User
	if _, ok := a.checkLogin(me, req.Old); !ok {
		jsonErr(w, http.StatusForbidden, "current password is wrong")
		return
	}
	if err := a.SetUserPassword(me, req.New, ""); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.sessions.dropUser(me)
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
		"version":           Version,
		"uptime_sec":        int64(s.Uptime().Seconds()),
		"blocking":          a.Resolver.BlockingEnabled(),
		"disabled_until":    a.Resolver.DisabledUntil(),
		"total":             s.Total.Load(),
		"blocked":           s.Blocked.Load(),
		"cached":            s.Cached.Load(),
		"errors":            s.Errors.Load(),
		"refused":           s.Refused.Load(),
		"qps":               s.QPS(),
		"rules_block":       blk,
		"rules_allow":       alw,
		"custom_block":      len(cb),
		"custom_allow":      len(ca),
		"cache_entries":     a.Cache.Len(),
		"cache_hits":        hits,
		"cache_misses":      misses,
		"mem_alloc_mb":      float64(ms.Alloc) / (1 << 20),
		"mem_sys_mb":        float64(ms.Sys) / (1 << 20),
		"goroutines":        runtime.NumGoroutine(),
		"upstreams":         a.Group.Statuses(),
		"upstream_strategy": a.Group.Strategy().String(),
		"lists_updated_at":  last,
		"user":              sessionOf(r).User,
		"role":              sessionOf(r).Role,
		"profile":           profileName(a.cfg.Profile),
		"latest_version":    a.latestVersion(),
	})
}

// auditName keeps junk typed into the login form out of the audit log.
func auditName(s string) string {
	if userNameRE.MatchString(s) {
		return s
	}
	return "?"
}

func profileName(p string) string {
	if p == "" {
		return "standard"
	}
	return p
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
	if spec.Kind == "" {
		spec.Kind = guessKind(spec)
	} else if !validKind(spec.Kind) {
		jsonErr(w, http.StatusBadRequest, "kind must be malware, phishing, ads or other")
		return
	}
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
		Kind    string `json:"kind"` // "" = unchanged
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if req.Kind != "" && !validKind(req.Kind) {
		jsonErr(w, http.StatusBadRequest, "kind must be malware, phishing, ads or other")
		return
	}
	found := false
	err := a.state.update(func(s *State) {
		for i := range s.Lists {
			if s.Lists[i].URL == req.URL {
				s.Lists[i].Enabled = req.Enabled
				if req.Kind != "" {
					s.Lists[i].Kind = req.Kind
				}
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

func (a *App) hUpstreamStrategy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Strategy string `json:"strategy"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	st, err := upstream.ParseStrategy(req.Strategy)
	if err != nil || req.Strategy == "" {
		jsonErr(w, http.StatusBadRequest, "strategy must be encrypted-first or fastest")
		return
	}
	if err := a.state.update(func(s *State) { s.UpstreamStrategy = st.String() }); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.Group.SetStrategy(st)
	writeJSON(w, map[string]any{"upstream_strategy": st.String(), "upstreams": a.Group.Statuses()})
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
