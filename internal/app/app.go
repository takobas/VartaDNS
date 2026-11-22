package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/takobas/vartadns/internal/cache"
	"github.com/takobas/vartadns/internal/devices"
	"github.com/takobas/vartadns/internal/dnsmsg"
	"github.com/takobas/vartadns/internal/filter"
	"github.com/takobas/vartadns/internal/notify"
	"github.com/takobas/vartadns/internal/qlog"
	"github.com/takobas/vartadns/internal/server"
	"github.com/takobas/vartadns/internal/stats"
	"github.com/takobas/vartadns/internal/syslog"
	"github.com/takobas/vartadns/internal/upstream"
)

// Version is set at build time with -ldflags "-X .../app.Version=..."
var Version = "dev"

// ListStatus is shown in the web panel.
type ListStatus struct {
	ListSpec
	Rules   int       `json:"rules"`
	Updated time.Time `json:"updated"`
	Error   string    `json:"error,omitempty"`
}

// App owns every service.
type App struct {
	cfg      Config
	state    *stateStore
	Engine   *filter.Engine
	Cache    *cache.Cache
	Group    *upstream.Group
	Boot     *upstream.Bootstrap
	timeout  time.Duration
	Stats    *stats.Stats
	Resolver *server.Resolver
	http     *http.Client

	listMu     sync.Mutex // serialises list rebuilds
	statusMu   sync.RWMutex
	listStatus map[string]ListStatus
	lastUpdate time.Time

	sessions *sessionStore

	catMu      sync.Mutex                           // serialises category loads
	categories atomic.Pointer[map[string]*catState] // loaded category lists

	QLog    *qlog.Log
	TG      *notify.Telegram
	Devices *devices.Tracker
	kinds   atomic.Pointer[map[string]string] // list name -> kind
	daily   *counters
	audit   *auditLog
	tls     *tlsState
	handler http.Handler // panel handler shared by the HTTP and HTTPS listeners
	enc     *encState
	Syslog  *syslog.Sender
}

// New builds the application from a config.
func New(cfg Config) (*App, error) {
	if err := os.MkdirAll(filepath.Join(cfg.DataDir, "lists"), 0o750); err != nil {
		return nil, err
	}
	st, fresh, err := loadState(cfg.DataDir, cfg.DefaultLists)
	if err != nil {
		return nil, err
	}
	// Servers chosen in the panel (state.json) override the config file.
	saved := st.get()
	upSpecs, bsSpecs := cfg.Upstreams, cfg.Bootstrap
	if len(saved.Upstreams) > 0 {
		upSpecs, bsSpecs = saved.Upstreams, saved.Bootstrap
	}
	boot := upstream.NewBootstrap(bsSpecs)
	bootstrap := boot.Resolver()
	timeout := time.Duration(cfg.UpstreamTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	grp, err := upstream.NewGroup(upSpecs, timeout, bootstrap)
	if err != nil {
		return nil, err
	}
	cond := map[string]*upstream.Group{}
	for zone, srv := range cfg.Conditional {
		g, err := upstream.NewGroup(strings.Split(srv, ","), timeout, bootstrap)
		if err != nil {
			return nil, fmt.Errorf("conditional %s: %w", zone, err)
		}
		z := strings.Trim(strings.ToLower(strings.TrimSpace(zone)), ".")
		if z == "" {
			return nil, errors.New("conditional forwarding: empty zone")
		}
		cond[z] = g // e.g. "lan" or "88.168.192.in-addr.arpa"
	}

	exempt, err := parsePrefixes(cfg.RateLimitExempt)
	if err != nil {
		return nil, err
	}
	allowed, err := parsePrefixes(cfg.AllowedClients)
	if err != nil {
		return nil, err
	}
	bypass, err := parsePrefixes(cfg.BypassClients)
	if err != nil {
		return nil, err
	}
	mode := dnsmsg.BlockNullIP
	if cfg.BlockMode == "nxdomain" {
		mode = dnsmsg.BlockNXDomain
	}

	a := &App{
		cfg:        cfg,
		state:      st,
		Engine:     filter.New(),
		Cache:      cache.New(cfg.CacheSize, cfg.CacheMinTTL, cfg.CacheMaxTTL, cfg.CacheNegTTL),
		Group:      grp,
		Boot:       boot,
		timeout:    timeout,
		Stats:      stats.New(cfg.QueryLogSize),
		listStatus: map[string]ListStatus{},
		sessions:   newSessionStore(),
		audit:      newAuditLog(cfg.DataDir),
		tls:        &tlsState{},
		enc:        &encState{},
	}
	a.http = &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			Proxy:       http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{Timeout: 10 * time.Second, Resolver: bootstrap}).DialContext,
		},
	}
	a.Resolver = server.NewResolver(server.Options{
		BlockMode: mode, BlockedTTL: cfg.BlockedTTL,
		RateLimitQPS: cfg.RateLimitQPS, RateLimitBurst: cfg.RateLimitBurst,
		RateLimitExempt: exempt, AllowedClients: allowed, BypassClients: bypass,
		BlockDoHCanary: cfg.BlockDoHCanary, Conditional: cond,
		MaxConcurrent: cfg.MaxConcurrent,
	}, a.Engine, a.Cache, a.Group, a.Stats)

	s := st.get()
	if err := a.initExtras(s); err != nil {
		return nil, err
	}
	a.Engine.SetCustom(s.CustomBlock, s.CustomAllow)
	strategy := cfg.UpstreamStrategy
	if s.UpstreamStrategy != "" {
		strategy = s.UpstreamStrategy // chosen in the panel
	}
	st8, err := upstream.ParseStrategy(strategy)
	if err != nil {
		return nil, err
	}
	a.Group.SetStrategy(st8)
	if err := a.applyPolicy(context.Background(), true); err != nil {
		log.Printf("groups: %v (groups disabled until fixed in the panel)", err)
	}

	if err := a.migrateUsers(); err != nil {
		return nil, err
	}
	if fresh || len(a.state.get().Users) == 0 || os.Getenv("VARTA_RESET_PASSWORD") == "1" {
		pw := randomToken(9)
		name := a.state.get().AdminUser
		if err := a.SetUserPassword(name, pw, RoleAdmin); err != nil {
			return nil, err
		}
		log.Printf("==============================================================")
		log.Printf(" Web panel first-run credentials:  %s / %s", name, pw)
		log.Printf(" Change the password in the panel (Settings).")
		log.Printf("==============================================================")
	}
	return a, nil
}

// Run starts every listener and blocks until ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	// Fast start from cached list copies, then refresh from the network.
	a.RebuildLists(ctx, false)
	go func() {
		a.RebuildLists(ctx, true)
		every := time.Duration(a.cfg.ListUpdateHours) * time.Hour
		if every <= 0 {
			return
		}
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.RebuildLists(ctx, true)
			}
		}
	}()

	stop := make(chan struct{})
	go func() { <-ctx.Done(); close(stop) }()
	go a.Cache.Janitor(time.Minute, stop)
	go a.Resolver.Maintenance(ctx)
	go a.Group.HealthLoop(ctx, 30*time.Second)
	go a.sessions.gcLoop(ctx)
	// Optional features: a failure there must never stop DNS.
	safeGo(ctx, "query log", a.QLog.Run)
	safeGo(ctx, "telegram", a.TG.Run)
	safeGo(ctx, "devices", a.Devices.Run)
	safeGo(ctx, "upstream watch", a.watchUpstreams)
	safeGo(ctx, "scheduler", a.scheduler)
	safeGo(ctx, "syslog", a.Syslog.Run)
	if err := a.applyEnc(); err != nil {
		log.Printf("encrypted DNS: %v", err)
	}
	safeGo(ctx, "encrypted dns", a.encLoop)
	safeGo(ctx, "telegram bot", func(ctx context.Context) { a.TG.Poll(ctx, a.botCommand) })

	udpAddr, err := net.ResolveUDPAddr("udp", a.cfg.DNSListen)
	if err != nil {
		return err
	}
	uconn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", a.cfg.DNSListen, err)
	}
	_ = uconn.SetReadBuffer(4 << 20)
	tln, err := net.Listen("tcp", a.cfg.DNSListen)
	if err != nil {
		uconn.Close()
		return fmt.Errorf("listen tcp %s: %w", a.cfg.DNSListen, err)
	}
	workers := a.cfg.UDPWorkers
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
	}
	go a.Resolver.ServeUDP(ctx, uconn, workers)
	go a.Resolver.ServeTCP(ctx, tln)
	log.Printf("DNS listening on %s (udp/tcp), %d UDP workers", a.cfg.DNSListen, workers)

	a.handler = a.redirectHTTPS(a.routes())
	web := &http.Server{
		Addr:              a.cfg.WebListen,
		Handler:           a.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		log.Printf("Web panel listening on %s", a.cfg.WebListen)
		if err := web.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	if err := a.applyTLS(); err != nil {
		log.Printf("panel HTTPS: %v (HTTP panel keeps working)", err)
	}
	select {
	case <-ctx.Done():
		a.stopTLS()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = web.Shutdown(sctx)
		return nil
	case err := <-errc:
		return err
	}
}

// safeGo runs fn in a goroutine and logs (instead of crashing on) a panic.
func safeGo(ctx context.Context, name string, fn func(context.Context)) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("%s stopped after an internal error: %v", name, r)
			}
		}()
		fn(ctx)
	}()
}

// ---- lists ----------------------------------------------------------------------------

func (a *App) listCachePath(spec ListSpec) string {
	h := sha256.Sum256([]byte(spec.URL))
	return filepath.Join(a.cfg.DataDir, "lists", hex.EncodeToString(h[:8])+".txt")
}

// openList returns a reader for a list: downloads it when network is true
// (saving a local copy), otherwise or on failure uses the saved copy.
func (a *App) openList(ctx context.Context, spec ListSpec, network bool) (io.ReadCloser, error) {
	isURL := strings.HasPrefix(spec.URL, "http://") || strings.HasPrefix(spec.URL, "https://")
	if !isURL {
		return os.Open(spec.URL)
	}
	cachePath := a.listCachePath(spec)
	if network {
		if err := a.download(ctx, spec.URL, cachePath); err != nil {
			log.Printf("list %q: download failed: %v (using cached copy if any)", spec.Name, err)
			f, ferr := os.Open(cachePath)
			if ferr != nil {
				return nil, err
			}
			return f, nil
		}
	}
	return os.Open(cachePath)
}

func (a *App) download(ctx context.Context, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "VartaDNS/"+Version)
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	const maxSize = 128 << 20
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxSize+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxSize {
		err = errors.New("list larger than 128 MiB")
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// RebuildLists reloads every enabled list and swaps the rule set atomically.
func (a *App) RebuildLists(ctx context.Context, network bool) {
	a.listMu.Lock()
	defer a.listMu.Unlock()
	start := time.Now()
	specs := a.state.get().Lists
	// Pre-size the builder from the cached list sizes (~20 bytes per rule)
	// so the rule slice never doubles while loading: lower peak memory on
	// small routers. Lists not downloaded yet simply grow the slice.
	var totalBytes int64
	for _, spec := range specs {
		if !spec.Enabled {
			continue
		}
		path := spec.URL
		if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
			path = a.listCachePath(spec)
		}
		if fi, err := os.Stat(path); err == nil {
			totalBytes += fi.Size()
		}
	}
	kinds := map[string]string{}
	for _, spec := range specs {
		if !spec.Allow {
			kinds[spec.Name] = spec.Kind
		}
	}
	a.kinds.Store(&kinds)
	b := filter.NewBuilder(int(totalBytes / 20))
	status := map[string]ListStatus{}
	for _, spec := range specs {
		ls := ListStatus{ListSpec: spec}
		if !spec.Enabled {
			status[spec.URL] = ls
			continue
		}
		rc, err := a.openList(ctx, spec, network)
		if err != nil {
			if !os.IsNotExist(err) || network {
				ls.Error = err.Error()
			}
		} else {
			n, perr := b.AddClass(spec.Name, rc, spec.Allow, filter.KindClass(spec.Kind))
			rc.Close()
			ls.Rules = n
			if perr != nil {
				ls.Error = perr.Error()
			}
			if fi, err := os.Stat(a.listCachePath(spec)); err == nil {
				ls.Updated = fi.ModTime()
			}
		}
		status[spec.URL] = ls
	}
	b.Apply(a.Engine) // releases the builder's temporary slices
	runtime.GC()      // free them before loading categories (lower peak)
	a.loadCategories(ctx, network)
	runtime.GC()
	blk, alw := b.Counts()
	a.statusMu.Lock()
	a.listStatus = status
	if network {
		a.lastUpdate = time.Now()
	}
	a.statusMu.Unlock()
	log.Printf("lists rebuilt (network=%v): %d block, %d allow rules in %s",
		network, blk, alw, time.Since(start).Round(time.Millisecond))
}

// ListStatuses returns list states in configured order.
func (a *App) ListStatuses() []ListStatus {
	specs := a.state.get().Lists
	a.statusMu.RLock()
	defer a.statusMu.RUnlock()
	out := make([]ListStatus, 0, len(specs))
	for _, s := range specs {
		ls, ok := a.listStatus[s.URL]
		if !ok {
			ls = ListStatus{ListSpec: s}
		}
		ls.ListSpec = s
		out = append(out, ls)
	}
	return out
}

// Authentication, users and sessions live in users.go.
