// Package app ties configuration, persistent state, list updates and all
// services together.
package app

import (
	"encoding/json"
	"fmt"
	"github.com/takobas/vartadns/internal/policy"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ListSpec is a blocklist or allowlist source.
type ListSpec struct {
	Name    string `json:"name"`
	URL     string `json:"url"`             // http(s) URL or local file path
	Allow   bool   `json:"allow,omitempty"` // true = allowlist
	Enabled bool   `json:"enabled"`
}

// Config is the static configuration file (JSON).
type Config struct {
	Profile           string            `json:"-"` // set by ApplyProfile
	DNSListen         string            `json:"dns_listen"`
	WebListen         string            `json:"web_listen"`
	WebHosts          []string          `json:"web_hosts"` // extra hostnames allowed for the panel (IPs always allowed)
	DataDir           string            `json:"data_dir"`
	Upstreams         []string          `json:"upstreams"`
	Bootstrap         []string          `json:"bootstrap_dns"`
	UpstreamTimeoutMs int               `json:"upstream_timeout_ms"`
	Conditional       map[string]string `json:"conditional_forwarding"`
	BlockMode         string            `json:"block_mode"` // "null" or "nxdomain"
	BlockedTTL        uint32            `json:"blocked_ttl"`
	CacheSize         int               `json:"cache_size"`
	CacheMinTTL       uint32            `json:"cache_min_ttl"`
	CacheMaxTTL       uint32            `json:"cache_max_ttl"`
	CacheNegTTL       uint32            `json:"cache_negative_ttl"`
	RateLimitQPS      int               `json:"rate_limit_qps"`
	RateLimitBurst    int               `json:"rate_limit_burst"`
	RateLimitExempt   []string          `json:"rate_limit_exempt"`
	AllowedClients    []string          `json:"allowed_clients"`
	BypassClients     []string          `json:"bypass_clients"`
	BlockDoHCanary    bool              `json:"block_firefox_doh_canary"`
	QueryLogSize      int               `json:"querylog_size"`
	ListUpdateHours   int               `json:"list_update_hours"`
	UDPWorkers        int               `json:"udp_workers"`
	MaxConcurrent     int               `json:"max_concurrent"`
	DefaultLists      []ListSpec        `json:"default_lists"`
}

// DefaultConfig returns sane defaults for a home/office deployment.
func DefaultConfig() Config {
	return Config{
		DNSListen:         ":53",
		WebListen:         ":8080",
		DataDir:           "./data",
		Upstreams:         []string{"https://dns.quad9.net/dns-query", "9.9.9.9", "149.112.112.112"},
		Bootstrap:         []string{"9.9.9.9", "149.112.112.112"},
		UpstreamTimeoutMs: 2000,
		BlockMode:         "null",
		BlockedTTL:        60,
		CacheSize:         100000,
		CacheMinTTL:       0,
		CacheMaxTTL:       86400,
		CacheNegTTL:       60,
		RateLimitQPS:      200,
		RateLimitBurst:    500,
		RateLimitExempt:   []string{"127.0.0.0/8", "::1/128"},
		AllowedClients: []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12",
			"192.168.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10"},
		BlockDoHCanary:  true,
		QueryLogSize:    5000,
		ListUpdateHours: 24,
		DefaultLists: []ListSpec{
			{Name: "HaGeZi Pro", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt", Enabled: true},
			{Name: "HaGeZi Threat Intelligence", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt", Enabled: true},
			{Name: "URLhaus (malware)", URL: "https://urlhaus.abuse.ch/downloads/hostfile/", Enabled: true},
			{Name: "Phishing Army", URL: "https://phishing.army/download/phishing_army_blocklist.txt", Enabled: true},
		},
	}
}

// LoadConfig reads a JSON config on top of the defaults. A missing file is
// not an error: defaults are used.
// ApplyProfile adjusts the config for a hardware profile.
//
//	"light" - routers with 128-256 MB RAM (hAP ac2/ac3 class): smaller
//	          lists (~300k rules, ~17 MB resident process), smaller cache and log.
//	""/"standard" - no changes.
//
// The profile's lists are only used when state.json does not exist yet
// (first start); afterwards lists are managed from the web panel.
func ApplyProfile(c *Config, profile string) error {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", "standard":
		return nil
	case "light":
		c.Profile = "light"
		c.DefaultLists = []ListSpec{
			{Name: "HaGeZi Light", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt", Enabled: true},
			{Name: "HaGeZi Threat Intelligence Mini", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt", Enabled: true},
			{Name: "URLhaus (malware)", URL: "https://urlhaus.abuse.ch/downloads/hostfile/", Enabled: true},
			{Name: "Phishing Army", URL: "https://phishing.army/download/phishing_army_blocklist.txt", Enabled: true},
		}
		c.CacheSize = 20000
		c.QueryLogSize = 1000
		c.UDPWorkers = 2
		c.MaxConcurrent = 2000
		return nil
	default:
		return fmt.Errorf("unknown profile %q (use \"standard\" or \"light\")", profile)
	}
}

func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

func parsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("bad address %q: %w", s, err)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("bad prefix %q: %w", s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// ---- persistent state (edited from the web panel) -------------------------------

// State is stored in <data_dir>/state.json.
type State struct {
	Lists        []ListSpec     `json:"lists"`
	CustomBlock  []string       `json:"custom_block"`
	CustomAllow  []string       `json:"custom_allow"`
	PasswordHash string         `json:"password_hash"` // salt$sha256hex
	AdminUser    string         `json:"admin_user"`
	Groups       []policy.Group `json:"groups"`
}

type stateStore struct {
	mu   sync.Mutex
	path string
	s    State
}

func loadState(dir string, defaults []ListSpec) (*stateStore, bool, error) {
	st := &stateStore{path: filepath.Join(dir, "state.json")}
	b, err := os.ReadFile(st.path)
	if os.IsNotExist(err) {
		st.s.Lists = append([]ListSpec(nil), defaults...)
		st.s.AdminUser = "admin"
		return st, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := json.Unmarshal(b, &st.s); err != nil {
		return nil, false, fmt.Errorf("state %s: %w", st.path, err)
	}
	if st.s.AdminUser == "" {
		st.s.AdminUser = "admin"
	}
	return st, false, nil
}

func (st *stateStore) get() State {
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.s
	s.Lists = append([]ListSpec(nil), st.s.Lists...)
	s.CustomBlock = append([]string(nil), st.s.CustomBlock...)
	s.CustomAllow = append([]string(nil), st.s.CustomAllow...)
	s.Groups = append([]policy.Group(nil), st.s.Groups...)
	return s
}

// update mutates the state under lock and saves it atomically.
func (st *stateStore) update(fn func(*State)) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	fn(&st.s)
	return st.saveLocked()
}

func (st *stateStore) saveLocked() error {
	b, err := json.MarshalIndent(st.s, "", "  ")
	if err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, st.path)
}
