// Package stats keeps counters, a per-minute time series, top lists and a
// ring buffer of recent queries for the web panel and Prometheus.
package stats

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Status of a resolved query.
const (
	StatusForwarded  = "forwarded"
	StatusCached     = "cached"
	StatusBlocked    = "blocked"
	StatusAllowed    = "allowed"
	StatusError      = "error"
	StatusRefused    = "refused"
	StatusSafeSearch = "safesearch"
)

// Entry is one query log record.
type Entry struct {
	Time     time.Time `json:"time"`
	Client   string    `json:"client"`
	Group    string    `json:"group,omitempty"`
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Status   string    `json:"status"`
	Rule     string    `json:"rule,omitempty"`
	Source   string    `json:"source,omitempty"`
	Upstream string    `json:"upstream,omitempty"`
	Rcode    int       `json:"rcode"`
	Micros   int64     `json:"us"`
	Proto    string    `json:"proto"`
}

const (
	seriesLen   = 24 * 60 // one day of minutes
	topMaxKeys  = 50000
	topResetAge = 24 * time.Hour
)

type bucket struct {
	minute  int64
	total   uint32
	blocked uint32
}

// Stats is safe for concurrent use.
type Stats struct {
	started time.Time

	Total, Blocked, Cached, Errors, Refused atomic.Uint64

	mu       sync.Mutex
	log      []Entry
	logNext  int
	logFull  bool
	series   [seriesLen]bucket
	topDom   map[string]uint64
	topBlk   map[string]uint64
	topCli   map[string]uint64
	topSince time.Time
}

// New creates a Stats with the given query log capacity.
func New(logSize int) *Stats {
	if logSize < 100 {
		logSize = 100
	}
	s := &Stats{started: time.Now(), log: make([]Entry, logSize)}
	s.resetTopLocked()
	return s
}

func (s *Stats) resetTopLocked() {
	s.topDom = map[string]uint64{}
	s.topBlk = map[string]uint64{}
	s.topCli = map[string]uint64{}
	s.topSince = time.Now()
}

func inc(m map[string]uint64, k string) {
	if _, ok := m[k]; ok || len(m) < topMaxKeys {
		m[k]++
	}
}

// Record adds a query to all aggregates.
func (s *Stats) Record(e Entry) {
	s.Total.Add(1)
	switch e.Status {
	case StatusBlocked:
		s.Blocked.Add(1)
	case StatusCached:
		s.Cached.Add(1)
	case StatusError:
		s.Errors.Add(1)
	case StatusRefused:
		s.Refused.Add(1)
	}
	minute := e.Time.Unix() / 60

	s.mu.Lock()
	s.log[s.logNext] = e
	s.logNext++
	if s.logNext == len(s.log) {
		s.logNext = 0
		s.logFull = true
	}
	b := &s.series[minute%seriesLen]
	if b.minute != minute {
		*b = bucket{minute: minute}
	}
	b.total++
	if e.Status == StatusBlocked {
		b.blocked++
	}
	if time.Since(s.topSince) > topResetAge {
		s.resetTopLocked()
	}
	if e.Name != "" {
		inc(s.topDom, e.Name)
		if e.Status == StatusBlocked {
			inc(s.topBlk, e.Name)
		}
	}
	inc(s.topCli, e.Client)
	s.mu.Unlock()
}

// Filter for Log queries.
type Filter struct {
	Search string
	Status string
	Client string
	Group  string
	Limit  int
}

// Log returns recent entries, newest first.
func (s *Stats) Log(f Filter) []Entry {
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 200
	}
	search := strings.ToLower(f.Search)
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.logNext
	if s.logFull {
		n = len(s.log)
	}
	out := make([]Entry, 0, f.Limit)
	for i := 0; i < n && len(out) < f.Limit; i++ {
		idx := (s.logNext - 1 - i + len(s.log)) % len(s.log)
		e := s.log[idx]
		if f.Status != "" && e.Status != f.Status {
			continue
		}
		if f.Client != "" && e.Client != f.Client {
			continue
		}
		if f.Group != "" && e.Group != f.Group {
			continue
		}
		if search != "" && !strings.Contains(e.Name, search) && !strings.Contains(e.Client, search) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Point is one minute of the time series.
type Point struct {
	T       int64  `json:"t"`
	Total   uint32 `json:"total"`
	Blocked uint32 `json:"blocked"`
}

// Series returns the last `minutes` minutes (oldest first).
func (s *Stats) Series(minutes int) []Point {
	if minutes <= 0 || minutes > seriesLen {
		minutes = 60
	}
	now := time.Now().Unix() / 60
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Point, 0, minutes)
	for m := now - int64(minutes) + 1; m <= now; m++ {
		b := s.series[((m%seriesLen)+seriesLen)%seriesLen]
		p := Point{T: m * 60}
		if b.minute == m {
			p.Total, p.Blocked = b.total, b.blocked
		}
		out = append(out, p)
	}
	return out
}

// KV is a top-list item.
type KV struct {
	Key   string `json:"key"`
	Count uint64 `json:"count"`
}

func top(m map[string]uint64, n int) []KV {
	out := make([]KV, 0, len(m))
	for k, v := range m {
		out = append(out, KV{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Tops returns top domains, blocked domains and clients.
func (s *Stats) Tops(n int) (domains, blocked, clients []KV, since time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return top(s.topDom, n), top(s.topBlk, n), top(s.topCli, n), s.topSince
}

// Uptime since start.
func (s *Stats) Uptime() time.Duration { return time.Since(s.started) }

// QPS over the last full minute.
func (s *Stats) QPS() float64 {
	p := s.Series(2)
	return float64(p[0].Total) / 60
}
