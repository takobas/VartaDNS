// Package qlog writes the query log to disk (one JSON Lines file per day),
// compresses old days, keeps the log within retention/size/free-space limits
// and reads it back for the panel and for export.
package qlog

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/takobas/vartadns/internal/stats"
)

// Logging modes.
const (
	ModeOff     = "off"
	ModeThreats = "threats" // blocked malware/phishing only
	ModeBlocked = "blocked" // every blocked query
	ModeAll     = "all"     // every query
)

// Settings are edited from the panel.
type Settings struct {
	Mode          string `json:"mode"`
	RetentionDays int    `json:"retention_days"`
	MaxMB         int    `json:"max_mb"`
	MinFreeMB     int    `json:"min_free_mb"` // 0 = do not watch free space
}

// DefaultSettings: blocked queries, 30 days, 1 GB, keep 500 MB free.
func DefaultSettings() Settings {
	return Settings{Mode: ModeBlocked, RetentionDays: 30, MaxMB: 1024, MinFreeMB: 500}
}

// Validate checks the ranges.
func (s Settings) Validate() error {
	switch s.Mode {
	case ModeOff, ModeThreats, ModeBlocked, ModeAll:
	default:
		return fmt.Errorf("unknown log mode %q", s.Mode)
	}
	if s.RetentionDays < 1 || s.RetentionDays > 3650 {
		return errors.New("retention must be 1-3650 days")
	}
	if s.MaxMB < 10 || s.MaxMB > 1<<20 {
		return errors.New("log size limit must be 10 MB - 1 TB")
	}
	if s.MinFreeMB < 0 || s.MinFreeMB > 1<<20 {
		return errors.New("minimum free space must be 0 MB - 1 TB")
	}
	return nil
}

// IsThreat reports whether a list kind is a security threat.
func IsThreat(kind string) bool { return kind == "malware" || kind == "phishing" }

// Cleanup reasons.
const (
	ReasonRetention = "retention"
	ReasonSize      = "size"
	ReasonFree      = "free"
)

// CleanupEvent describes days deleted by one cleanup pass for one reason.
type CleanupEvent struct {
	Reason    string   `json:"reason"`
	Days      []string `json:"days"`
	Bytes     int64    `json:"bytes"`
	FreeBytes int64    `json:"free_bytes"` // -1 = unknown
	Oldest    string   `json:"oldest"`     // oldest day still kept ("" = none)
}

// Events are called from the log goroutine; they must not block for long.
type Events struct {
	OnCleanup func(CleanupEvent)
	OnFull    func(freeBytes int64) // logging paused: nothing left to delete
	OnResume  func()
}

// Log is the disk query log.
type Log struct {
	dir string
	set atomic.Pointer[Settings]
	ev  Events

	ch       chan stats.Entry
	flushReq chan chan struct{}
	cleanReq chan struct{}

	written atomic.Uint64
	dropped atomic.Uint64
	paused  atomic.Bool
	running atomic.Bool
	lastErr atomic.Pointer[string]

	mu     sync.Mutex // file operations
	cur    *os.File
	curDay string

	freeFn func(dir string) int64 // free bytes, -1 = unknown (tests override)
	now    func() time.Time
}

const dayLayout = "2006-01-02"

// New creates a log in dir (created if missing).
func New(dir string, s Settings, ev Events) (*Log, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	l := &Log{dir: dir, ev: ev,
		ch:       make(chan stats.Entry, 4096),
		flushReq: make(chan chan struct{}),
		cleanReq: make(chan struct{}, 1),
		freeFn:   diskFree, now: time.Now}
	l.set.Store(&s)
	return l, nil
}

// Settings returns the active settings.
func (l *Log) Settings() Settings { return *l.set.Load() }

// SetSettings replaces the settings and triggers a cleanup pass.
func (l *Log) SetSettings(s Settings) {
	l.set.Store(&s)
	select {
	case l.cleanReq <- struct{}{}:
	default:
	}
}

// Wants reports whether the entry is logged in the current mode.
func (l *Log) Wants(e *stats.Entry) bool {
	switch l.set.Load().Mode {
	case ModeAll:
		return true
	case ModeBlocked:
		return e.Status == stats.StatusBlocked
	case ModeThreats:
		return e.Status == stats.StatusBlocked && IsThreat(e.Kind)
	}
	return false
}

// Add queues an entry; it never blocks (a full queue drops the entry).
func (l *Log) Add(e *stats.Entry) {
	if !l.Wants(e) {
		return
	}
	select {
	case l.ch <- *e:
	default:
		l.dropped.Add(1)
	}
}

// Run writes batches every 30 s (or every 1000 entries) and cleans up every
// minute until ctx is cancelled; the remaining batch is flushed on exit.
func (l *Log) Run(ctx context.Context) {
	flushT := time.NewTicker(30 * time.Second)
	cleanT := time.NewTicker(time.Minute)
	defer flushT.Stop()
	defer cleanT.Stop()
	buf := make([]stats.Entry, 0, 1000)
	flush := func() {
		if len(buf) > 0 {
			l.writeBatch(buf)
			buf = buf[:0]
		}
	}
	l.running.Store(true)
	defer l.running.Store(false)
	l.Cleanup()
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case e := <-l.ch:
					buf = append(buf, e)
				default:
					flush()
					l.closeCur()
					return
				}
			}
		case e := <-l.ch:
			buf = append(buf, e)
			if len(buf) >= cap(buf) {
				flush()
			}
		case <-flushT.C:
			flush()
		case done := <-l.flushReq:
			for len(l.ch) > 0 {
				buf = append(buf, <-l.ch)
			}
			flush()
			close(done)
		case <-cleanT.C:
			l.Cleanup()
		case <-l.cleanReq:
			l.Cleanup()
		}
	}
}

// Flush asks the writer to write everything queued (used before reading).
func (l *Log) Flush(ctx context.Context) {
	if !l.running.Load() {
		return
	}
	done := make(chan struct{})
	select {
	case l.flushReq <- done:
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
		return // writer not running
	}
	select {
	case <-done:
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
	}
}

func (l *Log) setErr(err error) {
	if err == nil {
		l.lastErr.Store(nil)
		return
	}
	s := err.Error()
	if old := l.lastErr.Load(); old == nil || *old != s {
		log.Printf("query log: %v", err)
	}
	l.lastErr.Store(&s)
}

func (l *Log) writeBatch(batch []stats.Entry) {
	s := l.Settings()
	if s.Mode == ModeOff {
		return
	}
	// Check free space before writing: a full flash must not break DNS.
	if s.MinFreeMB > 0 {
		if free := l.freeFn(l.dir); free >= 0 && free < int64(s.MinFreeMB)<<20 {
			l.Cleanup()
		}
	}
	if l.paused.Load() {
		l.dropped.Add(uint64(len(batch)))
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// A bug in logging must never take DNS down.
	defer func() {
		if r := recover(); r != nil {
			l.setErr(fmt.Errorf("internal error: %v", r))
			l.closeCurLocked()
		}
	}()
	var w *bufio.Writer
	if l.cur != nil {
		w = bufio.NewWriterSize(l.cur, 32<<10)
	}
	for i := range batch {
		day := batch[i].Time.In(time.Local).Format(dayLayout)
		if day != l.curDay || l.cur == nil {
			if w != nil {
				if err := w.Flush(); err != nil {
					l.setErr(err)
				}
			}
			l.closeCurLocked()
			f, err := os.OpenFile(filepath.Join(l.dir, day+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
			if err != nil {
				l.setErr(err)
				l.dropped.Add(uint64(len(batch) - i))
				return
			}
			l.cur, l.curDay = f, day
			w = bufio.NewWriterSize(f, 32<<10)
		}
		b, err := json.Marshal(&batch[i])
		if err != nil {
			continue
		}
		w.Write(b)
		w.WriteByte('\n')
	}
	if w != nil {
		if err := w.Flush(); err != nil {
			l.setErr(err)
			return
		}
	}
	l.written.Add(uint64(len(batch)))
	l.setErr(nil)
}

func (l *Log) closeCur() {
	l.mu.Lock()
	l.closeCurLocked()
	l.mu.Unlock()
}

func (l *Log) closeCurLocked() {
	if l.cur != nil {
		l.cur.Close()
		l.cur, l.curDay = nil, ""
	}
}

// DayFile is one day of the log on disk.
type DayFile struct {
	Day  string `json:"day"`
	Path string `json:"-"`
	Size int64  `json:"size"`
	Gz   bool   `json:"gz"`
}

// Files lists the day files, oldest first.
func (l *Log) Files() []DayFile {
	ents, err := os.ReadDir(l.dir)
	if err != nil {
		return nil
	}
	byDay := map[string]DayFile{}
	for _, e := range ents {
		name := e.Name()
		gz := strings.HasSuffix(name, ".log.gz")
		if !gz && !strings.HasSuffix(name, ".log") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), ".log")
		if _, err := time.Parse(dayLayout, day); err != nil {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		df := byDay[day]
		df.Day = day
		df.Size += fi.Size()
		if df.Path == "" || !gz { // prefer the plain file while compression is running
			df.Path, df.Gz = filepath.Join(l.dir, name), gz
		}
		byDay[day] = df
	}
	out := make([]DayFile, 0, len(byDay))
	for _, d := range byDay {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Day < out[j].Day })
	return out
}

func (l *Log) today() string { return l.now().In(time.Local).Format(dayLayout) }

func removeDay(d DayFile) {
	base := filepath.Join(filepath.Dir(d.Path), d.Day+".log")
	os.Remove(base)
	os.Remove(base + ".gz")
	os.Remove(base + ".gz.tmp")
}

// Cleanup compresses finished days and applies the retention, size and
// free-space rules. Only this log's own day files are ever deleted.
func (l *Log) Cleanup() {
	s := l.Settings()
	l.mu.Lock()
	defer l.mu.Unlock()
	today := l.today()
	if l.curDay != "" && l.curDay != today {
		l.closeCurLocked()
	}
	for _, d := range l.Files() {
		if !d.Gz && d.Day < today {
			if err := compress(d.Path); err != nil {
				l.setErr(fmt.Errorf("compress %s: %w", d.Day, err))
			}
		}
	}
	files := l.Files()
	events := map[string]*CleanupEvent{}
	del := func(i int, reason string) {
		d := files[i]
		removeDay(d)
		ev := events[reason]
		if ev == nil {
			ev = &CleanupEvent{Reason: reason}
			events[reason] = ev
		}
		ev.Days = append(ev.Days, d.Day)
		ev.Bytes += d.Size
	}
	// 1. retention
	cut := l.now().In(time.Local).AddDate(0, 0, -s.RetentionDays).Format(dayLayout)
	keep := files[:0:0]
	for i, d := range files {
		if d.Day < cut && d.Day != today {
			del(i, ReasonRetention)
		} else {
			keep = append(keep, d)
		}
	}
	files = keep
	// 2. total size
	var total int64
	for _, d := range files {
		total += d.Size
	}
	for len(files) > 0 && total > int64(s.MaxMB)<<20 && files[0].Day != today {
		total -= files[0].Size
		del(0, ReasonSize)
		files = files[1:]
	}
	// 3. free space
	free := int64(-1)
	if s.MinFreeMB > 0 {
		minFree := int64(s.MinFreeMB) << 20
		free = l.freeFn(l.dir)
		for free >= 0 && free < minFree && len(files) > 0 && files[0].Day != today {
			del(0, ReasonFree)
			files = files[1:]
			free = l.freeFn(l.dir)
		}
		if free >= 0 && free < minFree {
			if !l.paused.Swap(true) {
				l.closeCurLocked()
				if l.ev.OnFull != nil {
					go l.ev.OnFull(free)
				}
			}
		} else if l.paused.Swap(false) && l.ev.OnResume != nil {
			go l.ev.OnResume()
		}
	} else if l.paused.Swap(false) && l.ev.OnResume != nil {
		go l.ev.OnResume()
	}
	if free < 0 {
		free = l.freeFn(l.dir)
	}
	oldest := ""
	if len(files) > 0 {
		oldest = files[0].Day
	}
	for _, reason := range []string{ReasonRetention, ReasonSize, ReasonFree} {
		if ev := events[reason]; ev != nil {
			ev.FreeBytes, ev.Oldest = free, oldest
			log.Printf("query log: deleted %d day(s) (%s), %d bytes", len(ev.Days), reason, ev.Bytes)
			if l.ev.OnCleanup != nil {
				go l.ev.OnCleanup(*ev)
			}
		}
	}
}

func compress(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := path + ".gz.tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	zw, _ := gzip.NewWriterLevel(out, gzip.BestCompression)
	_, err = io.Copy(zw, in)
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path+".gz"); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Remove(path)
}

// Status is shown in the panel.
type Status struct {
	Settings  Settings  `json:"settings"`
	Files     []DayFile `json:"files"`
	Bytes     int64     `json:"bytes"`
	FreeBytes int64     `json:"free_bytes"`
	Paused    bool      `json:"paused"`
	Written   uint64    `json:"written"`
	Dropped   uint64    `json:"dropped"`
	Error     string    `json:"error,omitempty"`
}

// Status returns the current state of the disk log.
func (l *Log) Status() Status {
	st := Status{Settings: l.Settings(), Files: l.Files(), FreeBytes: l.freeFn(l.dir),
		Paused: l.paused.Load(), Written: l.written.Load(), Dropped: l.dropped.Load()}
	for _, f := range st.Files {
		st.Bytes += f.Size
	}
	if st.Files == nil {
		st.Files = []DayFile{}
	}
	if e := l.lastErr.Load(); e != nil {
		st.Error = *e
	}
	return st
}

// ---- reading ---------------------------------------------------------------------

// Query selects entries from the disk log.
type Query struct {
	From, To string          // days "YYYY-MM-DD", inclusive; "" = unbounded
	Clients  map[string]bool // empty = all clients
	Status   string          // "", a stats status, or "threats"
	Kind     string          // "" = any
	Search   string          // substring of domain or device name
}

// Match reports whether an entry satisfies the query (except the day range).
func (q *Query) Match(e *stats.Entry) bool {
	if len(q.Clients) > 0 && !q.Clients[e.Client] {
		return false
	}
	switch q.Status {
	case "":
	case "threats":
		if e.Status != stats.StatusBlocked || !IsThreat(e.Kind) {
			return false
		}
	default:
		if e.Status != q.Status {
			return false
		}
	}
	if q.Kind != "" && e.Kind != q.Kind {
		return false
	}
	if q.Search != "" && !strings.Contains(e.Name, q.Search) &&
		!strings.Contains(strings.ToLower(e.Device), q.Search) {
		return false
	}
	return true
}

func (q *Query) days(files []DayFile) []DayFile {
	out := files[:0:0]
	for _, f := range files {
		if (q.From == "" || f.Day >= q.From) && (q.To == "" || f.Day <= q.To) {
			out = append(out, f)
		}
	}
	return out
}

// readDay calls fn for every entry of a day file in order. Broken lines
// (e.g. the line being written right now) are skipped.
func readDay(d DayFile, fn func(*stats.Entry) error) error {
	f, err := os.Open(d.Path)
	if errors.Is(err, os.ErrNotExist) {
		// compressed (or deleted) while we were listing
		alt := filepath.Join(filepath.Dir(d.Path), d.Day+".log.gz")
		if d.Gz {
			alt = filepath.Join(filepath.Dir(d.Path), d.Day+".log")
		}
		if f, err = os.Open(alt); err != nil {
			return nil
		}
		d.Gz = !d.Gz
	} else if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if d.Gz {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil
		}
		defer zr.Close()
		r = zr
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	var e stats.Entry
	for sc.Scan() {
		e = stats.Entry{}
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		if err := fn(&e); err != nil {
			return err
		}
	}
	return nil // a truncated gzip tail is not fatal for reading
}

// Each calls fn for every matching entry, oldest first.
func (l *Log) Each(ctx context.Context, q Query, fn func(*stats.Entry) error) error {
	l.Flush(ctx)
	for _, d := range q.days(l.Files()) {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := readDay(d, func(e *stats.Entry) error {
			if q.Match(e) {
				return fn(e)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// MaxPageDepth limits offset+limit for Page (memory bound).
const MaxPageDepth = 20000

// Page returns matching entries newest first, skipping offset; more reports
// whether older matches exist.
func (l *Log) Page(ctx context.Context, q Query, offset, limit int) (out []stats.Entry, more bool, err error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	need := offset + limit
	if need > MaxPageDepth {
		return nil, false, fmt.Errorf("offset too deep (max %d entries), narrow the date range", MaxPageDepth)
	}
	l.Flush(ctx)
	days := q.days(l.Files())
	var acc []stats.Entry // newest first
	for i := len(days) - 1; i >= 0 && len(acc) <= need; i-- {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		// keep only the last `room` matches of this day in a ring
		room := need + 1 - len(acc)
		ring := make([]stats.Entry, 0, min(room, 1024))
		next := 0
		readDay(days[i], func(e *stats.Entry) error {
			if !q.Match(e) {
				return nil
			}
			if len(ring) < room {
				ring = append(ring, *e)
			} else {
				ring[next] = *e
				next = (next + 1) % room
			}
			return nil
		})
		for j := 0; j < len(ring); j++ { // newest first
			acc = append(acc, ring[(next-1-j+2*len(ring))%len(ring)])
		}
	}
	if len(acc) > need {
		more = true
		acc = acc[:need]
	}
	if offset >= len(acc) {
		return []stats.Entry{}, more, nil
	}
	return acc[offset:], more, nil
}
