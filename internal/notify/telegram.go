// Package notify sends Telegram notifications about blocked threats and
// system events, with de-duplication, rate limiting and retries.
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/takobas/vartadns/internal/stats"
)

// Event types (also the keys of Settings.Events).
const (
	EvMalware       = "malware"
	EvPhishing      = "phishing"
	EvParental      = "parental"
	EvCustom        = "custom"
	EvAds           = "ads"
	EvInfected      = "infected"
	EvNewDevice     = "new_device"
	EvDiskFull      = "disk_full"
	EvLogCleanup    = "log_cleanup"   // logs deleted by the size or free-space rule
	EvLogRetention  = "log_retention" // routine deletion of days past retention
	EvUpstreamsDown = "upstreams_down"
	EvUpdate        = "update" // a new VartaDNS release is out
)

// AllEvents in display order.
var AllEvents = []string{EvMalware, EvPhishing, EvParental, EvCustom, EvAds,
	EvInfected, EvNewDevice, EvDiskFull, EvLogCleanup, EvLogRetention, EvUpstreamsDown, EvUpdate}

// DefaultEvents: only viruses plus the important log events.
func DefaultEvents() map[string]bool {
	return map[string]bool{EvMalware: true, EvDiskFull: true, EvLogCleanup: true}
}

// Settings are stored in state.json. The token is a secret.
type Settings struct {
	Token           string          `json:"token,omitempty"`
	ChatID          string          `json:"chat_id,omitempty"`
	Events          map[string]bool `json:"events,omitempty"`
	InfectThreshold int             `json:"infect_threshold,omitempty"` // distinct threat domains per hour
	Lang            string          `json:"lang,omitempty"`             // "uk" (default) or "en"
	Commands        bool            `json:"commands,omitempty"`         // accept bot commands from ChatID
	Report          string          `json:"report,omitempty"`           // "off" (default), "daily", "weekly"
	ReportHour      int             `json:"report_hour,omitempty"`      // local hour 0-23 (default 20)
}

// Normalize fills defaults.
func (s *Settings) Normalize() {
	if s.Events == nil {
		s.Events = DefaultEvents()
	}
	if s.InfectThreshold <= 0 {
		s.InfectThreshold = 5
	}
	if s.Lang != "en" {
		s.Lang = "uk"
	}
	if s.Report != "daily" && s.Report != "weekly" {
		s.Report = "off"
	}
	if s.ReportHour < 0 || s.ReportHour > 23 || (s.Report == "off" && s.ReportHour == 0) {
		s.ReportHour = 20 // unset; midnight stays possible once a report is on
	}
}

// Configured reports whether a token and chat are set.
func (s *Settings) Configured() bool { return s.Token != "" && s.ChatID != "" }

var tokenRE = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_-]{30,64}$`)
var chatRE = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$`)

// ValidToken checks the BotFather token format.
func ValidToken(t string) bool { return tokenRE.MatchString(t) }

// ValidChat checks a chat ID (number) or a public @channel name.
func ValidChat(c string) bool { return chatRE.MatchString(c) }

// MaskToken shows only the bot id and the last 4 characters.
func MaskToken(t string) string {
	if t == "" {
		return ""
	}
	id, _, _ := strings.Cut(t, ":")
	if len(t) < 8 {
		return "****"
	}
	return id + ":****" + t[len(t)-4:]
}

type item struct {
	ev    string
	text  string // system events: ready text
	e     stats.Entry
	label string // list name for blocks
}

// Telegram is safe for concurrent use.
type Telegram struct {
	set    atomic.Pointer[Settings]
	client *http.Client
	api    string // https://api.telegram.org (tests override)
	in     chan item

	mu      sync.Mutex
	dedup   map[string]time.Time
	infect  map[string]*infState
	pending []item
	last    time.Time // last send attempt that succeeded
	nextTry time.Time
	fails   int

	lastErr atomic.Pointer[string]
	lastOK  atomic.Int64
	sent    atomic.Uint64
	dropped atomic.Uint64
	now     func() time.Time
}

type infState struct {
	domains map[string]time.Time
	alerted time.Time
}

// Limits.
const (
	dedupWindow   = time.Hour
	sendInterval  = time.Minute
	infectWindow  = time.Hour
	infectRepeat  = 6 * time.Hour
	maxTracked    = 10000
	maxPending    = 500
	maxLines      = 25
	maxSendErrors = 5
)

// New creates a notifier using client for HTTPS (it must resolve
// api.telegram.org through the bootstrap resolver).
func New(s Settings, client *http.Client) *Telegram {
	s.Normalize()
	t := &Telegram{client: client, api: "https://api.telegram.org", in: make(chan item, 256),
		dedup: map[string]time.Time{}, infect: map[string]*infState{}, now: time.Now}
	t.set.Store(&s)
	return t
}

// Settings returns a copy of the settings.
func (t *Telegram) Settings() Settings {
	s := *t.set.Load()
	ev := make(map[string]bool, len(s.Events))
	for k, v := range s.Events {
		ev[k] = v
	}
	s.Events = ev
	return s
}

// SetSettings replaces the settings.
func (t *Telegram) SetSettings(s Settings) {
	s.Normalize()
	t.set.Store(&s)
	t.mu.Lock()
	t.fails, t.nextTry = 0, time.Time{}
	t.mu.Unlock()
}

func (t *Telegram) enabled(ev string) bool {
	s := t.set.Load()
	return s.Configured() && s.Events[ev]
}

// KindEvent maps a list kind to its event type ("" = not notifiable).
func KindEvent(kind string) string {
	switch kind {
	case "malware":
		return EvMalware
	case "phishing":
		return EvPhishing
	case "parental":
		return EvParental
	case "custom":
		return EvCustom
	case "ads":
		return EvAds
	}
	return ""
}

func isThreat(kind string) bool { return kind == "malware" || kind == "phishing" }

// Blocked is called for every finished query; it never blocks.
func (t *Telegram) Blocked(e *stats.Entry) {
	if e.Status != stats.StatusBlocked {
		return
	}
	ev := KindEvent(e.Kind)
	if ev == "" {
		return
	}
	if !t.enabled(ev) && !(isThreat(e.Kind) && t.enabled(EvInfected)) {
		return
	}
	select {
	case t.in <- item{ev: ev, e: *e, label: e.Source}:
	default:
		t.dropped.Add(1)
	}
}

// System queues a ready-made system message if its event type is enabled.
func (t *Telegram) System(ev, text string) {
	if !t.enabled(ev) {
		return
	}
	select {
	case t.in <- item{ev: ev, text: text}:
	default:
		t.dropped.Add(1)
	}
}

// Run processes events until ctx is cancelled.
func (t *Telegram) Run(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	gc := time.NewTicker(10 * time.Minute)
	defer tick.Stop()
	defer gc.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case it := <-t.in:
			t.accept(it)
		case <-tick.C:
			t.maybeSend(ctx)
		case <-gc.C:
			t.gc()
		}
	}
}

func (t *Telegram) accept(it item) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if it.text == "" { // a blocked query
		e := it.e
		if isThreat(e.Kind) && t.enabled(EvInfected) {
			t.trackInfection(e, now)
		}
		if !t.enabled(it.ev) {
			return
		}
		key := e.Client + "|" + e.Name
		if last, ok := t.dedup[key]; ok && now.Sub(last) < dedupWindow {
			return
		}
		if len(t.dedup) >= maxTracked {
			return // under a flood keep memory bounded; gc frees old keys
		}
		t.dedup[key] = now
	}
	if len(t.pending) >= maxPending {
		t.dropped.Add(1)
		return
	}
	t.pending = append(t.pending, it)
}

func (t *Telegram) trackInfection(e stats.Entry, now time.Time) {
	st := t.infect[e.Client]
	if st == nil {
		if len(t.infect) >= 1000 {
			return
		}
		st = &infState{domains: map[string]time.Time{}}
		t.infect[e.Client] = st
	}
	if len(st.domains) < 1000 {
		st.domains[e.Name] = now
	}
	n := 0
	for d, ts := range st.domains {
		if now.Sub(ts) > infectWindow {
			delete(st.domains, d)
			continue
		}
		n++
	}
	thr := t.set.Load().InfectThreshold
	if n >= thr && now.Sub(st.alerted) > infectRepeat {
		st.alerted = now
		t.pending = append(t.pending, item{ev: EvInfected, text: t.infectedText(e, n)})
	}
}

func (t *Telegram) gc() {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, ts := range t.dedup {
		if now.Sub(ts) >= dedupWindow {
			delete(t.dedup, k)
		}
	}
	for c, st := range t.infect {
		for d, ts := range st.domains {
			if now.Sub(ts) > infectWindow {
				delete(st.domains, d)
			}
		}
		if len(st.domains) == 0 && now.Sub(st.alerted) > infectRepeat {
			delete(t.infect, c)
		}
	}
}

func (t *Telegram) maybeSend(ctx context.Context) {
	now := t.now()
	t.mu.Lock()
	if len(t.pending) == 0 || now.Sub(t.last) < sendInterval || now.Before(t.nextTry) {
		t.mu.Unlock()
		return
	}
	batch := t.pending
	t.pending = nil
	t.mu.Unlock()

	text := t.compose(batch)
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err := t.send(sctx, text)
	cancel()

	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		t.fails++
		if t.fails >= maxSendErrors {
			t.fails = 0
			t.dropped.Add(uint64(len(batch)))
			t.nextTry = now.Add(10 * time.Minute)
			return
		}
		t.pending = append(batch, t.pending...) // retry with backoff
		if len(t.pending) > maxPending {
			t.pending = t.pending[:maxPending]
		}
		t.nextTry = now.Add(time.Duration(30<<t.fails) * time.Second)
		return
	}
	t.fails, t.nextTry, t.last = 0, time.Time{}, now
}

// ---- texts --------------------------------------------------------------------------

func (t *Telegram) uk() bool { return t.set.Load().Lang != "en" }

func (t *Telegram) tr(uk, en string) string {
	if t.uk() {
		return uk
	}
	return en
}

var evIcon = map[string]string{EvMalware: "🦠", EvPhishing: "🎣", EvParental: "👨‍👧", EvCustom: "✋", EvAds: "📢"}

// Defang makes a domain non-clickable in chat apps: evil.example -> evil[.]example.
func Defang(d string) string { return strings.ReplaceAll(d, ".", "[.]") }

// DeviceLabel returns "name · ip" or just the ip.
func DeviceLabel(name, ip string) string {
	if name == "" {
		return ip
	}
	return name + " · " + ip
}

func (t *Telegram) blockTitle(ev string) string {
	switch ev {
	case EvMalware:
		return t.tr("заблоковано вірусний домен", "blocked a malware domain")
	case EvPhishing:
		return t.tr("заблоковано фішинговий домен", "blocked a phishing domain")
	case EvParental:
		return t.tr("спрацював батьківський контроль", "parental control blocked a site")
	case EvCustom:
		return t.tr("спрацювало власне правило", "a custom rule blocked a site")
	}
	return t.tr("заблоковано рекламу/трекер", "blocked an ad/tracker")
}

func (t *Telegram) fmtTime(ts time.Time) string { return ts.In(time.Local).Format("02.01.2006 15:04") }

func (t *Telegram) blockText(it item) string {
	e := it.e
	var b strings.Builder
	fmt.Fprintf(&b, "%s VartaDNS: %s\n", evIcon[it.ev], t.blockTitle(it.ev))
	dev := DeviceLabel(e.Device, e.Client)
	if e.Group != "" {
		dev += " (" + t.tr("група", "group") + " «" + e.Group + "»)"
	}
	fmt.Fprintf(&b, "%s: %s\n", t.tr("Пристрій", "Device"), dev)
	fmt.Fprintf(&b, "%s: %s\n", t.tr("Домен", "Domain"), Defang(e.Name))
	if it.label != "" {
		fmt.Fprintf(&b, "%s: %s\n", t.tr("Список", "List"), it.label)
	}
	fmt.Fprintf(&b, "%s: %s", t.tr("Час", "Time"), t.fmtTime(e.Time))
	return b.String()
}

func (t *Telegram) compose(batch []item) string {
	if len(batch) == 1 {
		if batch[0].text != "" {
			return batch[0].text
		}
		return t.blockText(batch[0])
	}
	var sys, blocks []item
	for _, it := range batch {
		if it.text != "" {
			sys = append(sys, it)
		} else {
			blocks = append(blocks, it)
		}
	}
	var parts []string
	for _, it := range sys {
		parts = append(parts, it.text)
	}
	if len(blocks) == 1 {
		parts = append(parts, t.blockText(blocks[0]))
	} else if len(blocks) > 1 {
		sort.SliceStable(blocks, func(i, j int) bool { return blocks[i].e.Time.Before(blocks[j].e.Time) })
		var b strings.Builder
		fmt.Fprintf(&b, "🛡 VartaDNS: %s %d\n", t.tr("заблоковано подій:", "blocked events:"), len(blocks))
		for i, it := range blocks {
			if i == maxLines {
				fmt.Fprintf(&b, "… %s %d", t.tr("і ще", "and"), len(blocks)-maxLines)
				break
			}
			e := it.e
			fmt.Fprintf(&b, "%s %s %s → %s", evIcon[it.ev], e.Time.In(time.Local).Format("15:04"),
				DeviceLabel(e.Device, e.Client), Defang(e.Name))
			if it.label != "" {
				fmt.Fprintf(&b, " (%s)", it.label)
			}
			b.WriteByte('\n')
		}
		parts = append(parts, strings.TrimRight(b.String(), "\n"))
	}
	msg := strings.Join(parts, "\n\n")
	if r := []rune(msg); len(r) > 4000 { // Telegram limit is 4096
		msg = string(r[:4000]) + "…"
	}
	return msg
}

func (t *Telegram) infectedText(e stats.Entry, n int) string {
	dev := DeviceLabel(e.Device, e.Client)
	if t.uk() {
		return fmt.Sprintf("🚨 VartaDNS: пристрій, можливо, заражений\nПристрій: %s\n%d різних шкідливих доменів за годину (останній: %s)\nПеревір пристрій антивірусом.",
			dev, n, Defang(e.Name))
	}
	return fmt.Sprintf("🚨 VartaDNS: device may be infected\nDevice: %s\n%d different malicious domains in an hour (last: %s)\nScan the device with an antivirus.",
		dev, n, Defang(e.Name))
}

// ---- Telegram API ---------------------------------------------------------------------

type apiResp struct {
	OK          bool            `json:"ok"`
	Description string          `json:"description"`
	Result      json.RawMessage `json:"result"`
}

// redact removes the token from error texts (URLs contain it).
func redact(err error, token string) error {
	if err == nil || token == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), token, "***"))
}

func (t *Telegram) call(ctx context.Context, token, method string, form url.Values) (json.RawMessage, error) {
	u := t.api + "/bot" + token + "/" + method
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, redact(err, token)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, redact(err, token)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, redact(err, token)
	}
	var ar apiResp
	if err := json.Unmarshal(body, &ar); err != nil {
		return nil, fmt.Errorf("telegram: HTTP %d", resp.StatusCode)
	}
	if !ar.OK {
		return nil, fmt.Errorf("telegram: %s", ar.Description)
	}
	return ar.Result, nil
}

func (t *Telegram) sendWith(ctx context.Context, s *Settings, text string) error {
	_, err := t.call(ctx, s.Token, "sendMessage", url.Values{
		"chat_id": {s.ChatID}, "text": {text}, "disable_web_page_preview": {"true"},
	})
	return err
}

func (t *Telegram) send(ctx context.Context, text string) error {
	s := t.set.Load()
	if !s.Configured() {
		return errors.New("telegram is not configured")
	}
	err := t.sendWith(ctx, s, text)
	if err != nil {
		msg := err.Error()
		t.lastErr.Store(&msg)
		return err
	}
	t.lastErr.Store(nil)
	t.lastOK.Store(t.now().Unix())
	t.sent.Add(1)
	return nil
}

// Test sends a test message right away with the given settings.
func (t *Telegram) Test(ctx context.Context, s Settings) error {
	s.Normalize()
	if !s.Configured() {
		return errors.New("token and chat ID are required")
	}
	text := "✅ VartaDNS: тестове повідомлення. Сповіщення працюють."
	if s.Lang == "en" {
		text = "✅ VartaDNS: test message. Notifications work."
	}
	return t.sendWith(ctx, &s, text)
}

// Chat is a chat that recently wrote to the bot.
type Chat struct {
	ID    int64  `json:"id"`
	Type  string `json:"type"`
	Title string `json:"title"`
}

// DetectChats lists chats from the bot's recent updates, so the user does
// not have to look up the chat ID by hand (write /start to the bot first).
func (t *Telegram) DetectChats(ctx context.Context, token string) ([]Chat, error) {
	res, err := t.call(ctx, token, "getUpdates", url.Values{"limit": {"50"}, "timeout": {"0"}})
	if err != nil {
		return nil, err
	}
	var ups []struct {
		Message *struct {
			Chat struct {
				ID        int64  `json:"id"`
				Type      string `json:"type"`
				Title     string `json:"title"`
				Username  string `json:"username"`
				FirstName string `json:"first_name"`
			} `json:"chat"`
		} `json:"message"`
		ChannelPost *struct {
			Chat struct {
				ID    int64  `json:"id"`
				Type  string `json:"type"`
				Title string `json:"title"`
			} `json:"chat"`
		} `json:"channel_post"`
	}
	if err := json.Unmarshal(res, &ups); err != nil {
		return nil, err
	}
	seen := map[int64]bool{}
	out := []Chat{}
	for _, u := range ups {
		var c Chat
		switch {
		case u.Message != nil:
			m := u.Message.Chat
			c = Chat{ID: m.ID, Type: m.Type, Title: m.Title}
			if c.Title == "" {
				c.Title = strings.TrimSpace(m.FirstName + " @" + m.Username)
			}
		case u.ChannelPost != nil:
			m := u.ChannelPost.Chat
			c = Chat{ID: m.ID, Type: m.Type, Title: m.Title}
		default:
			continue
		}
		if !seen[c.ID] {
			seen[c.ID] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// Status for the panel.
type Status struct {
	LastError string    `json:"last_error,omitempty"`
	LastOK    time.Time `json:"last_ok"`
	Sent      uint64    `json:"sent"`
	Dropped   uint64    `json:"dropped"`
	Pending   int       `json:"pending"`
}

// Status returns delivery counters.
func (t *Telegram) Status() Status {
	st := Status{Sent: t.sent.Load(), Dropped: t.dropped.Load()}
	if e := t.lastErr.Load(); e != nil {
		st.LastError = *e
	}
	if ok := t.lastOK.Load(); ok > 0 {
		st.LastOK = time.Unix(ok, 0)
	}
	t.mu.Lock()
	st.Pending = len(t.pending)
	t.mu.Unlock()
	return st
}
