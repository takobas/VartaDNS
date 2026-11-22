package app

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/takobas/vartadns/internal/devices"
	"github.com/takobas/vartadns/internal/notify"
	"github.com/takobas/vartadns/internal/policy"
	"github.com/takobas/vartadns/internal/qlog"
	"github.com/takobas/vartadns/internal/stats"
	"github.com/takobas/vartadns/internal/syslog"
	"github.com/takobas/vartadns/internal/upstream"
)

// initExtras creates the disk log, Telegram notifier and device tracker.
func (a *App) initExtras(s State) error {
	a.daily = openCounters(a.cfg.DataDir)
	sl := syslog.Settings{}
	if s.Syslog != nil {
		sl = *s.Syslog
	}
	a.Syslog = syslog.New(sl)
	a.Devices = devices.Open(a.cfg.DataDir)
	a.Devices.SetManual(s.DeviceNames)
	if err := a.Devices.SetServer(s.NamesServer); err != nil {
		return err
	}
	a.TG = notify.New(s.telegram(), a.http)
	a.Devices.OnNew = func(ip, name string) {
		a.TG.System(notify.EvNewDevice, a.TG.NewDeviceText(ip, name))
	}
	qs := s.queryLog()
	if err := qs.Validate(); err != nil {
		qs = qlog.DefaultSettings()
	}
	var err error
	a.QLog, err = qlog.New(filepath.Join(a.cfg.DataDir, "logs"), qs, qlog.Events{
		OnCleanup: func(ev qlog.CleanupEvent) {
			kind := notify.EvLogCleanup
			if ev.Reason == qlog.ReasonRetention {
				kind = notify.EvLogRetention
			}
			a.TG.System(kind, a.TG.CleanupText(ev, a.QLog.Settings()))
		},
		OnFull: func(free int64) {
			a.TG.System(notify.EvDiskFull, a.TG.DiskFullText(free, a.QLog.Settings()))
		},
		OnResume: func() { a.TG.System(notify.EvDiskFull, a.TG.DiskResumedText()) },
	})
	if err != nil {
		return err
	}
	empty := map[string]string{}
	a.kinds.Store(&empty)
	if err := a.applyFiltering(s); err != nil {
		log.Printf("filtering settings: %v (ignored)", err)
	}
	a.Resolver.OnEntry = a.onEntry
	return nil
}

// kindOf maps a rule source to its kind.
func (a *App) kindOf(src string) string {
	switch {
	case src == "":
		return ""
	case src == "custom":
		return "custom"
	case strings.HasPrefix(src, "group:"), src == "safesearch":
		return "parental"
	case src == "doh-canary":
		return KindOther
	}
	if k := (*a.kinds.Load())[src]; k != "" {
		return k
	}
	return KindOther
}

// onEntry runs on the query path for every finished query.
func (a *App) onEntry(e *stats.Entry) {
	if e.Client != "" {
		e.Device = a.Devices.Observe(e.Client, e.Time)
	}
	e.Kind = a.kindOf(e.Source)
	a.daily.add(e)
	a.QLog.Add(e)
	a.Syslog.Query(e)
	a.TG.Blocked(e)
}

// watchUpstreams reports when every upstream is down (two checks in a row)
// and when they recover.
func (a *App) watchUpstreams(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	bad, down := 0, false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		st := a.Group.Statuses()
		all := len(st) > 0
		for _, s := range st {
			if s.Healthy {
				all = false
				break
			}
		}
		if all {
			bad++
		} else {
			bad = 0
		}
		switch {
		case bad >= 2 && !down:
			down = true
			a.TG.System(notify.EvUpstreamsDown, a.TG.UpstreamsText(true))
		case bad == 0 && down:
			down = false
			a.TG.System(notify.EvUpstreamsDown, a.TG.UpstreamsText(false))
		}
	}
}

// ---- disk query log -----------------------------------------------------------------

func (a *App) hQLogStatus(w http.ResponseWriter, r *http.Request) {
	a.QLog.Flush(r.Context()) // show today's file even before the 30 s batch
	writeJSON(w, a.QLog.Status())
}

func (a *App) hQLogSettings(w http.ResponseWriter, r *http.Request) {
	var s qlog.Settings
	if err := readJSON(r, &s); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := s.Validate(); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.state.update(func(st *State) { st.QueryLog = &s }); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.QLog.SetSettings(s)
	writeJSON(w, a.QLog.Status())
}

func parseDay(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return "", fmt.Errorf("bad date %q (use YYYY-MM-DD)", s)
	}
	return s, nil
}

// parseQuery reads from/to/clients/status/kind/q from the URL.
func parseQuery(r *http.Request) (qlog.Query, error) {
	v := r.URL.Query()
	var q qlog.Query
	var err error
	if q.From, err = parseDay(v.Get("from")); err != nil {
		return q, err
	}
	if q.To, err = parseDay(v.Get("to")); err != nil {
		return q, err
	}
	if q.From != "" && q.To != "" && q.From > q.To {
		q.From, q.To = q.To, q.From
	}
	for _, c := range strings.FieldsFunc(v.Get("clients"), func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		ip, err := netip.ParseAddr(c)
		if err != nil {
			return q, fmt.Errorf("bad IP address %q", c)
		}
		if q.Clients == nil {
			q.Clients = map[string]bool{}
		}
		q.Clients[ip.String()] = true
	}
	q.Status = v.Get("status")
	q.Kind = v.Get("kind")
	q.Search = strings.ToLower(strings.TrimSpace(v.Get("q")))
	return q, nil
}

func (a *App) hQLogDisk(w http.ResponseWriter, r *http.Request) {
	q, err := parseQuery(r)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	lim, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	ents, more, err := a.QLog.Page(r.Context(), q, off, lim)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]any{"entries": ents, "more": more})
}

var csvHeader = []string{"time", "client", "device", "name", "type", "status", "kind", "source", "rule", "group", "upstream", "rcode", "ms", "proto"}

func csvRow(e *stats.Entry) []string {
	return []string{e.Time.In(time.Local).Format("2006-01-02 15:04:05"), e.Client, e.Device, e.Name, e.Type,
		e.Status, e.Kind, e.Source, e.Rule, e.Group, e.Upstream, strconv.Itoa(e.Rcode),
		strconv.FormatFloat(float64(e.Micros)/1000, 'f', 1, 64), e.Proto}
}

// csvSafe stops spreadsheet formula injection from domain names.
func csvSafe(row []string) []string {
	for i, c := range row {
		if c != "" && strings.ContainsRune("=+-@\t\r", rune(c[0])) {
			row[i] = "'" + c
		}
	}
	return row
}

func (a *App) hQLogExport(w http.ResponseWriter, r *http.Request) {
	q, err := parseQuery(r)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "csv-comma" && format != "json" {
		jsonErr(w, http.StatusBadRequest, "format must be csv, csv-comma or json")
		return
	}
	// Exports of many days can take longer than the server's write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Minute))
	name := "vartadns-log"
	if q.From != "" {
		name += "-" + q.From
	}
	if q.To != "" && q.To != q.From {
		name += "_" + q.To
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	n := 0
	if format == "json" {
		h.Set("Content-Type", "application/json; charset=utf-8")
		h.Set("Content-Disposition", `attachment; filename="`+name+`.json"`)
		w.Write([]byte("[\n"))
		enc := json.NewEncoder(w)
		err = a.QLog.Each(r.Context(), q, func(e *stats.Entry) error {
			if n > 0 {
				w.Write([]byte(","))
			}
			n++
			return enc.Encode(e)
		})
		w.Write([]byte("]\n"))
		return
	}
	h.Set("Content-Type", "text/csv; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
	w.Write([]byte("\ufeff")) // UTF-8 BOM so Excel shows Cyrillic device names
	cw := csv.NewWriter(w)
	if format == "csv" {
		cw.Comma = ';' // Excel default in Ukrainian/European locales
	}
	cw.Write(csvHeader)
	err = a.QLog.Each(r.Context(), q, func(e *stats.Entry) error {
		n++
		if err := cw.Write(csvSafe(csvRow(e))); err != nil {
			return err
		}
		if n%1000 == 0 {
			cw.Flush()
			return cw.Error()
		}
		return nil
	})
	cw.Flush()
}

// ---- Telegram ------------------------------------------------------------------------

type tgView struct {
	Configured      bool            `json:"configured"`
	TokenMasked     string          `json:"token_masked"`
	ChatID          string          `json:"chat_id"`
	Events          map[string]bool `json:"events"`
	AllEvents       []string        `json:"all_events"`
	InfectThreshold int             `json:"infect_threshold"`
	Lang            string          `json:"lang"`
	Commands        bool            `json:"commands"`
	Report          string          `json:"report"`
	ReportHour      int             `json:"report_hour"`
	Status          notify.Status   `json:"status"`
}

func (a *App) tgView() tgView {
	s := a.TG.Settings()
	return tgView{Configured: s.Configured(), TokenMasked: notify.MaskToken(s.Token), ChatID: s.ChatID,
		Events: s.Events, AllEvents: notify.AllEvents, InfectThreshold: s.InfectThreshold, Lang: s.Lang,
		Commands: s.Commands, Report: s.Report, ReportHour: s.ReportHour, Status: a.TG.Status()}
}

func (a *App) hTelegramGet(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.tgView()) }

type tgReq struct {
	Token           string          `json:"token"` // "" = keep the saved token
	ClearToken      bool            `json:"clear_token"`
	ChatID          string          `json:"chat_id"`
	Events          map[string]bool `json:"events"`
	InfectThreshold int             `json:"infect_threshold"`
	Lang            string          `json:"lang"`
	Commands        *bool           `json:"commands"`
	Report          string          `json:"report"`
	ReportHour      *int            `json:"report_hour"`
}

// merge builds new settings from the saved ones and the request.
func (a *App) tgMerge(req tgReq) (notify.Settings, error) {
	s := a.TG.Settings()
	req.Token = strings.TrimSpace(req.Token)
	req.ChatID = strings.TrimSpace(req.ChatID)
	switch {
	case req.ClearToken:
		s.Token = ""
	case req.Token != "":
		if !notify.ValidToken(req.Token) {
			return s, errors.New("this does not look like a bot token (123456789:AA...)")
		}
		s.Token = req.Token
	}
	if req.ChatID != "" && !notify.ValidChat(req.ChatID) {
		return s, errors.New("chat ID must be a number (e.g. 123456789 or -100...) or @channel")
	}
	s.ChatID = req.ChatID
	if req.Events != nil {
		ev := map[string]bool{}
		for _, k := range notify.AllEvents {
			if req.Events[k] {
				ev[k] = true
			}
		}
		s.Events = ev
	}
	if req.InfectThreshold != 0 {
		if req.InfectThreshold < 2 || req.InfectThreshold > 1000 {
			return s, errors.New("infection threshold must be 2-1000 domains per hour")
		}
		s.InfectThreshold = req.InfectThreshold
	}
	if req.Lang != "" {
		s.Lang = req.Lang
	}
	if req.Commands != nil {
		s.Commands = *req.Commands
	}
	if req.Report != "" {
		if req.Report != "off" && req.Report != "daily" && req.Report != "weekly" {
			return s, errors.New("report must be off, daily or weekly")
		}
		s.Report = req.Report
	}
	if req.ReportHour != nil {
		if *req.ReportHour < 0 || *req.ReportHour > 23 {
			return s, errors.New("report hour must be 0-23")
		}
		s.ReportHour = *req.ReportHour
	}
	if s.Commands && strings.HasPrefix(s.ChatID, "@") {
		return s, errors.New("commands need a numeric chat ID (use \"Find chat ID\")")
	}
	s.Normalize()
	return s, nil
}

func (a *App) hTelegramSave(w http.ResponseWriter, r *http.Request) {
	var req tgReq
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	s, err := a.tgMerge(req)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.state.update(func(st *State) { st.Telegram = &s }); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.TG.SetSettings(s)
	writeJSON(w, a.tgView())
}

func (a *App) hTelegramTest(w http.ResponseWriter, r *http.Request) {
	var req tgReq
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	s, err := a.tgMerge(req)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := a.TG.Test(ctx, s); err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) hTelegramChats(w http.ResponseWriter, r *http.Request) {
	var req tgReq
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	s, err := a.tgMerge(req)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.Token == "" {
		jsonErr(w, http.StatusBadRequest, "enter the bot token first")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	chats, err := a.TG.DetectChats(ctx, s.Token)
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, chats)
}

// ---- devices ---------------------------------------------------------------------------

func (a *App) hDevicesGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"devices": a.Devices.List(), "names_server": a.state.get().NamesServer})
}

func (a *App) hDeviceName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP   string `json:"ip"`
		Name string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(req.IP))
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "bad IP address")
		return
	}
	name := devices.CleanManual(req.Name)
	var names map[string]string
	err = a.state.update(func(s *State) {
		if s.DeviceNames == nil {
			s.DeviceNames = map[string]string{}
		}
		if name == "" {
			delete(s.DeviceNames, ip.String())
		} else {
			if len(s.DeviceNames) >= devices.MaxDevices {
				return
			}
			s.DeviceNames[ip.String()] = name
		}
		names = s.DeviceNames
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.Devices.SetManual(names)
	a.hDevicesGet(w, r)
}

func (a *App) hDeviceForget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	a.Devices.Forget(strings.TrimSpace(req.IP))
	a.hDevicesGet(w, r)
}

func (a *App) hNamesServer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server string `json:"server"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := a.Devices.SetServer(req.Server); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.state.update(func(s *State) { s.NamesServer = strings.TrimSpace(req.Server) }); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.hDevicesGet(w, r)
}

// ---- backup / restore ------------------------------------------------------------------

type backupFile struct {
	Format  string    `json:"vartadns_backup"`
	Version string    `json:"version"`
	Created time.Time `json:"created"`
	Secrets bool      `json:"secrets"`
	State   State     `json:"state"`
}

func (a *App) hBackup(w http.ResponseWriter, r *http.Request) {
	secrets := r.URL.Query().Get("secrets") == "1"
	s := a.state.get()
	if !secrets {
		s.PasswordHash = ""
		if s.Telegram != nil {
			s.Telegram.Token = ""
		}
		for i := range s.Users {
			s.Users[i].Hash = ""
		}
		if s.TLS != nil {
			s.TLS.KeyPEM = ""
		}
		if s.EncDNS != nil {
			s.EncDNS.ACMEToken, s.EncDNS.KeyPEM = "", ""
			s.EncDNS.Devices = nil // personal addresses work like passwords
		}
	}
	b := backupFile{Format: "1", Version: Version, Created: time.Now(), Secrets: secrets, State: s}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition",
		`attachment; filename="vartadns-backup-`+time.Now().Format("2006-01-02")+`.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(b)
}

// validateState checks a restored state before it replaces the live one.
func validateState(s *State) error {
	for i := range s.Lists {
		l := &s.Lists[i]
		l.Name, l.URL = strings.TrimSpace(l.Name), strings.TrimSpace(l.URL)
		if l.Name == "" || (!validListURL(l.URL) && !filepath.IsAbs(l.URL)) {
			return fmt.Errorf("list %d: name and http(s) URL (or a local file path) are required", i+1)
		}
	}
	if lists, _ := migrateLists(s.Lists); lists != nil {
		s.Lists = lists
	}
	if len(s.Upstreams) > 0 {
		if err := upstream.Validate(s.Upstreams); err != nil {
			return err
		}
		if err := upstream.ValidateBootstrap(s.Bootstrap); err != nil {
			return err
		}
	}
	if s.UpstreamStrategy != "" {
		if _, err := upstream.ParseStrategy(s.UpstreamStrategy); err != nil {
			return err
		}
	}
	if s.QueryLog != nil {
		if err := s.QueryLog.Validate(); err != nil {
			return err
		}
	}
	if s.Telegram != nil {
		if s.Telegram.Token != "" && !notify.ValidToken(s.Telegram.Token) {
			return errors.New("telegram: bad token")
		}
		if s.Telegram.ChatID != "" && !notify.ValidChat(s.Telegram.ChatID) {
			return errors.New("telegram: bad chat ID")
		}
	}
	for ip := range s.DeviceNames {
		if _, err := netip.ParseAddr(ip); err != nil {
			return fmt.Errorf("device names: bad IP %q", ip)
		}
	}
	if s.NamesServer != "" {
		if _, err := netip.ParseAddr(s.NamesServer); err != nil {
			if _, err := netip.ParseAddrPort(s.NamesServer); err != nil {
				return errors.New("names server must be an IP address")
			}
		}
	}
	if _, err := policy.CleanKinds(s.DefaultSkipKinds); err != nil {
		return err
	}
	if _, err := parsePrefixes(s.BypassClients); err != nil {
		return fmt.Errorf("bypass clients: %w", err)
	}
	if s.Syslog != nil {
		if err := s.Syslog.Validate(); err != nil {
			return fmt.Errorf("syslog: %w", err)
		}
	}
	if e := s.EncDNS; e != nil {
		if e.Hostname != "" && !validHost(e.Hostname) {
			return errors.New("encrypted DNS: bad hostname")
		}
		for _, d := range e.Devices {
			if _, err := netip.ParseAddr(d.IP); err != nil || len(d.Token) < 12 {
				return errors.New("encrypted DNS: bad personal device")
			}
		}
	}
	for i := range s.Groups {
		if err := policy.Normalize(&s.Groups[i]); err != nil {
			return fmt.Errorf("groups: %w", err)
		}
	}
	if _, err := policy.Compile(s.Groups); err != nil {
		return fmt.Errorf("groups: %w", err)
	}
	return nil
}

func (a *App) hRestore(w http.ResponseWriter, r *http.Request) {
	var b backupFile
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	if err := dec.Decode(&b); err != nil || b.Format == "" {
		jsonErr(w, http.StatusBadRequest, "not a VartaDNS backup file")
		return
	}
	ns := b.State
	if err := validateState(&ns); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	cur := a.state.get()
	if ns.PasswordHash == "" { // backup without secrets: keep the current login
		ns.PasswordHash = cur.PasswordHash
	}
	if ns.AdminUser == "" {
		ns.AdminUser = cur.AdminUser
	}
	if ns.Telegram != nil && ns.Telegram.Token == "" && cur.Telegram != nil {
		ns.Telegram.Token = cur.Telegram.Token
	}
	ns.Users = mergeUsers(ns.Users, cur.Users)
	if ns.EncDNS != nil && cur.EncDNS != nil {
		if ns.EncDNS.ACMEToken == "" {
			ns.EncDNS.ACMEToken = cur.EncDNS.ACMEToken
		}
		if ns.EncDNS.KeyPEM == "" && ns.EncDNS.CertPEM == cur.EncDNS.CertPEM {
			ns.EncDNS.KeyPEM = cur.EncDNS.KeyPEM
		}
		if len(ns.EncDNS.Devices) == 0 {
			ns.EncDNS.Devices = cur.EncDNS.Devices
		}
	}
	if ns.TLS != nil && ns.TLS.KeyPEM == "" {
		if cur.TLS != nil && cur.TLS.CertPEM == ns.TLS.CertPEM {
			ns.TLS.KeyPEM = cur.TLS.KeyPEM
		}
		if ns.TLS.Mode == TLSCustom && ns.TLS.KeyPEM == "" {
			ns.TLS.Mode = TLSAuto // the key was not in the backup
		}
	}
	syncLegacy(&ns)
	if err := a.state.update(func(s *State) { *s = ns }); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// End sessions of accounts that were removed or got another role.
	newRole := map[string]string{}
	for _, u := range ns.Users {
		newRole[u.Name] = u.Role
	}
	for _, u := range cur.Users {
		if newRole[u.Name] != u.Role {
			a.sessions.dropUser(u.Name)
		}
	}
	if err := a.applyState(r.Context()); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "from_version": b.Version})
}

// mergeUsers restores accounts from a backup. Users without a password
// hash (backup without secrets) keep their current hash or are dropped;
// if no admin would remain, the current accounts are kept.
func mergeUsers(restored, cur []User) []User {
	hash := map[string]string{}
	for _, u := range cur {
		hash[u.Name] = u.Hash
	}
	var out []User
	for _, u := range restored {
		if !userNameRE.MatchString(u.Name) || roleRank(u.Role) == 0 {
			continue
		}
		if u.Hash == "" {
			u.Hash = hash[u.Name]
		}
		if u.Hash != "" {
			out = append(out, u)
		}
	}
	if adminCount(out) == 0 {
		return append([]User(nil), cur...)
	}
	return out
}

// applyState re-applies the whole saved state to the running services.
func (a *App) applyState(ctx context.Context) error {
	s := a.state.get()
	a.Engine.SetCustom(s.CustomBlock, s.CustomAllow)
	up := upstreamsReq{Upstreams: a.cfg.Upstreams, Bootstrap: a.cfg.Bootstrap}
	if len(s.Upstreams) > 0 {
		up = upstreamsReq{Upstreams: s.Upstreams, Bootstrap: s.Bootstrap}
	}
	a.Boot.Set(up.Bootstrap)
	if err := a.Group.SetSpecs(up.Upstreams); err != nil {
		return err
	}
	strategy := a.cfg.UpstreamStrategy
	if s.UpstreamStrategy != "" {
		strategy = s.UpstreamStrategy
	}
	if st, err := upstream.ParseStrategy(strategy); err == nil {
		a.Group.SetStrategy(st)
	}
	a.QLog.SetSettings(s.queryLog())
	a.TG.SetSettings(s.telegram())
	a.Devices.SetManual(s.DeviceNames)
	_ = a.Devices.SetServer(s.NamesServer)
	if err := a.applyFiltering(s); err != nil {
		log.Printf("filtering settings after restore: %v", err)
	}
	if err := a.applyPolicy(ctx, true); err != nil {
		return err
	}
	if err := a.applyTLS(); err != nil {
		log.Printf("panel HTTPS after restore: %v", err)
	}
	if s.Syslog != nil {
		a.Syslog.SetSettings(*s.Syslog)
	}
	if err := a.applyEnc(); err != nil {
		log.Printf("encrypted DNS after restore: %v", err)
	}
	a.refreshAsync()
	return nil
}

// ---- filtering scope (default list kinds, bypass clients) ------------------------------------

func (a *App) applyFiltering(s State) error {
	kinds, err := policy.CleanKinds(s.DefaultSkipKinds)
	if err != nil {
		return err
	}
	bp, err := parsePrefixes(s.BypassClients)
	if err != nil {
		return err
	}
	a.Resolver.SetDefaultClasses(policy.KindsMask(kinds))
	a.Resolver.SetBypass(bp)
	return nil
}

func (a *App) hFilteringGet(w http.ResponseWriter, r *http.Request) {
	s := a.state.get()
	writeJSON(w, map[string]any{"default_skip_kinds": nz(s.DefaultSkipKinds), "bypass_clients": nz(s.BypassClients),
		"config_bypass": nz(a.cfg.BypassClients), "kinds": policy.ListKinds})
}

func (a *App) hFilteringSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DefaultSkipKinds []string `json:"default_skip_kinds"`
		BypassClients    []string `json:"bypass_clients"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonErr(w, http.StatusBadRequest, "bad request")
		return
	}
	kinds, err := policy.CleanKinds(req.DefaultSkipKinds)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var bp []string
	for _, c := range req.BypassClients {
		if c = strings.TrimSpace(c); c != "" {
			bp = append(bp, c)
		}
	}
	if len(bp) > 256 {
		jsonErr(w, http.StatusBadRequest, "too many entries")
		return
	}
	if _, err := parsePrefixes(bp); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.state.update(func(s *State) { s.DefaultSkipKinds, s.BypassClients = kinds, bp }); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.applyFiltering(a.state.get()); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.Cache.Flush()
	a.hFilteringGet(w, r)
}
