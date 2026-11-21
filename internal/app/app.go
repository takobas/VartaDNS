package app

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	"github.com/takobas/vartadns/internal/dnsmsg"
	"github.com/takobas/vartadns/internal/filter"
	"github.com/takobas/vartadns/internal/server"
	"github.com/takobas/vartadns/internal/stats"
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
	bootstrap := upstream.BootstrapResolver(cfg.Bootstrap)
	timeout := time.Duration(cfg.UpstreamTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	grp, err := upstream.NewGroup(cfg.Upstreams, timeout, bootstrap)
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
		Stats:      stats.New(cfg.QueryLogSize),
		listStatus: map[string]ListStatus{},
		sessions:   newSessionStore(),
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
	a.Engine.SetCustom(s.CustomBlock, s.CustomAllow)
	if err := a.applyPolicy(context.Background(), true); err != nil {
		log.Printf("groups: %v (groups disabled until fixed in the panel)", err)
	}

	if fresh || s.PasswordHash == "" || os.Getenv("VARTA_RESET_PASSWORD") == "1" {
		pw := randomToken(9)
		if err := a.SetPassword(pw); err != nil {
			return nil, err
		}
		log.Printf("==============================================================")
		log.Printf(" Web panel first-run credentials:  admin / %s", pw)
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
	go a.sessions.gcLoop(ctx)

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

	web := &http.Server{
		Addr:              a.cfg.WebListen,
		Handler:           a.routes(),
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
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = web.Shutdown(sctx)
		return nil
	case err := <-errc:
		return err
	}
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
			n, perr := b.Add(spec.Name, rc, spec.Allow)
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

// ---- auth -------------------------------------------------------------------------------

const pbkdf2Iter = 120000

func hashPassword(pw string, salt []byte) (string, error) {
	k, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(salt) + "$" + hex.EncodeToString(k), nil
}

// SetPassword stores a new admin password hash.
func (a *App) SetPassword(pw string) error {
	if len(pw) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	h, err := hashPassword(pw, salt)
	if err != nil {
		return err
	}
	return a.state.update(func(s *State) { s.PasswordHash = h })
}

func (a *App) checkPassword(user, pw string) bool {
	s := a.state.get()
	parts := strings.SplitN(s.PasswordHash, "$", 2)
	if len(parts) != 2 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	h, err := hashPassword(pw, salt)
	if err != nil {
		return false
	}
	okUser := subtle.ConstantTimeCompare([]byte(user), []byte(s.AdminUser)) == 1
	okPass := subtle.ConstantTimeCompare([]byte(h), []byte(s.PasswordHash)) == 1
	return okUser && okPass
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, n)
	for i, v := range b {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return string(out)
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time
	fails    map[string][]time.Time // login failures per client IP
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]time.Time{}, fails: map[string][]time.Time{}}
}

const sessionTTL = 12 * time.Hour

func (s *sessionStore) create() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[tok] = time.Now().Add(sessionTTL)
	s.mu.Unlock()
	return tok
}

func (s *sessionStore) valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[tok]
	if !ok || time.Now().After(exp) {
		delete(s.sessions, tok)
		return false
	}
	return true
}

func (s *sessionStore) drop(tok string) {
	s.mu.Lock()
	delete(s.sessions, tok)
	s.mu.Unlock()
}

func (s *sessionStore) dropAll() {
	s.mu.Lock()
	s.sessions = map[string]time.Time{}
	s.mu.Unlock()
}

// lockedOut reports whether ip had 5+ failed logins in the last 10 minutes.
func (s *sessionStore) lockedOut(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := time.Now().Add(-10 * time.Minute)
	keep := s.fails[ip][:0]
	for _, t := range s.fails[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	s.fails[ip] = keep
	return len(keep) >= 5
}

func (s *sessionStore) fail(ip string) {
	s.mu.Lock()
	s.fails[ip] = append(s.fails[ip], time.Now())
	s.mu.Unlock()
}

func (s *sessionStore) gcLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			for k, exp := range s.sessions {
				if now.After(exp) {
					delete(s.sessions, k)
				}
			}
			for k, v := range s.fails {
				if len(v) == 0 || now.Sub(v[len(v)-1]) > 10*time.Minute {
					delete(s.fails, k)
				}
			}
			s.mu.Unlock()
		}
	}
}
