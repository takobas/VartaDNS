package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/takobas/vartadns/internal/notify"
	"github.com/takobas/vartadns/internal/stats"
)

// ---- per-day counters (for reports and /status) ------------------------------------

type dayStats struct {
	Day       string            `json:"day"`
	Total     uint64            `json:"total"`
	Blocked   uint64            `json:"blocked"`
	Threats   uint64            `json:"threats"`
	ThreatDev map[string]uint64 `json:"threat_devices,omitempty"` // "name · ip" -> count
}

type counters struct {
	mu   sync.Mutex
	path string
	Days []*dayStats `json:"days"` // oldest first, at most 8
	// LastReport is the day a report was last sent; LastVersion the newest
	// release we already told the user about.
	LastReport  string `json:"last_report,omitempty"`
	LastVersion string `json:"last_version,omitempty"`
	Latest      string `json:"latest,omitempty"`
	LatestURL   string `json:"latest_url,omitempty"`
	dirty       bool
	lastMin     int64 // cache: unix minute -> local day (Format is slow on the hot path)
	lastDay     string
}

func openCounters(dir string) *counters {
	c := &counters{path: filepath.Join(dir, "daily.json")}
	if b, err := os.ReadFile(c.path); err == nil {
		_ = json.Unmarshal(b, c)
	}
	return c
}

func dayOf(t time.Time) string { return t.In(time.Local).Format("2006-01-02") }

func (c *counters) dayLocked(day string) *dayStats {
	if n := len(c.Days); n > 0 && c.Days[n-1].Day == day {
		return c.Days[n-1]
	}
	d := &dayStats{Day: day}
	c.Days = append(c.Days, d)
	if len(c.Days) > 8 {
		c.Days = c.Days[len(c.Days)-8:]
	}
	return d
}

func (c *counters) add(e *stats.Entry) {
	min := e.Time.Unix() / 60
	c.mu.Lock()
	if min != c.lastMin || c.lastDay == "" {
		c.lastMin, c.lastDay = min, dayOf(e.Time)
	}
	d := c.dayLocked(c.lastDay)
	d.Total++
	if e.Status == stats.StatusBlocked {
		d.Blocked++
		if e.Kind == KindMalware || e.Kind == KindPhishing {
			d.Threats++
			if d.ThreatDev == nil {
				d.ThreatDev = map[string]uint64{}
			}
			if k := notify.DeviceLabel(e.Device, e.Client); len(d.ThreatDev) < 500 || d.ThreatDev[k] > 0 {
				d.ThreatDev[k]++
			}
		}
	}
	c.dirty = true
	c.mu.Unlock()
}

// sum adds up the last n days ending today.
func (c *counters) sum(now time.Time, n int) dayStats {
	from := now.In(time.Local).AddDate(0, 0, -(n - 1)).Format("2006-01-02")
	out := dayStats{ThreatDev: map[string]uint64{}}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, d := range c.Days {
		if d.Day < from {
			continue
		}
		out.Total += d.Total
		out.Blocked += d.Blocked
		out.Threats += d.Threats
		for k, v := range d.ThreatDev {
			out.ThreatDev[k] += v
		}
	}
	return out
}

func (c *counters) save() {
	c.mu.Lock()
	if !c.dirty {
		c.mu.Unlock()
		return
	}
	b, err := json.Marshal(c)
	c.dirty = false
	c.mu.Unlock()
	if err != nil {
		return
	}
	tmp := c.path + ".tmp"
	if os.WriteFile(tmp, b, 0o640) == nil {
		os.Rename(tmp, c.path)
	}
}

func (c *counters) set(fn func(c *counters)) {
	c.mu.Lock()
	fn(c)
	c.dirty = true
	c.mu.Unlock()
	c.save()
}

// ---- scheduler: reports, update check, saving counters ------------------------------------

func (a *App) scheduler(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	defer a.daily.save()
	nextUpdate := time.Now().Add(2 * time.Minute)
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			n++
			if n%10 == 0 {
				a.daily.save()
			}
			a.maybeReport(ctx, now)
			if now.After(nextUpdate) {
				nextUpdate = now.Add(24 * time.Hour)
				if a.TG.Settings().Events[notify.EvUpdate] {
					a.checkUpdate(ctx)
				}
			}
		}
	}
}

func (a *App) maybeReport(ctx context.Context, now time.Time) {
	s := a.TG.Settings()
	if !s.Configured() || s.Report == "off" {
		return
	}
	local := now.In(time.Local)
	if local.Hour() < s.ReportHour {
		return
	}
	today := dayOf(now)
	if s.Report == "weekly" && local.Weekday() != time.Sunday {
		return
	}
	a.daily.mu.Lock()
	done := a.daily.LastReport == today
	a.daily.mu.Unlock()
	if done {
		return
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := a.TG.SendNow(sctx, a.reportText(now, s.Report == "weekly")); err != nil {
		log.Printf("telegram report: %v", err)
		return // retried next minute
	}
	a.daily.set(func(c *counters) { c.LastReport = today })
}

func pctStr(a, b uint64) string {
	if b == 0 {
		return "0%"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(a)/float64(b))
}

func (a *App) reportText(now time.Time, weekly bool) string {
	tr := a.TG.Tr
	days := 1
	title := tr("звіт за ", "report for ") + now.In(time.Local).Format("02.01.2006")
	if weekly {
		days = 7
		title = tr("звіт за тиждень ", "weekly report ") +
			now.In(time.Local).AddDate(0, 0, -6).Format("02.01") + " – " + now.In(time.Local).Format("02.01.2006")
	}
	d := a.daily.sum(now, days)
	var b strings.Builder
	fmt.Fprintf(&b, "📊 VartaDNS: %s\n", title)
	fmt.Fprintf(&b, "%s: %d\n", tr("Запитів", "Queries"), d.Total)
	fmt.Fprintf(&b, "%s: %d (%s)\n", tr("Заблоковано", "Blocked"), d.Blocked, pctStr(d.Blocked, d.Total))
	fmt.Fprintf(&b, "%s: %d", tr("Загроз (віруси, фішинг)", "Threats (malware, phishing)"), d.Threats)
	if len(d.ThreatDev) > 0 {
		type kv struct {
			k string
			v uint64
		}
		var l []kv
		for k, v := range d.ThreatDev {
			l = append(l, kv{k, v})
		}
		sort.Slice(l, func(i, j int) bool { return l[i].v > l[j].v })
		b.WriteString("\n" + tr("Пристрої із загрозами:", "Devices with threats:"))
		for i, x := range l {
			if i == 5 {
				break
			}
			fmt.Fprintf(&b, "\n  %s — %d", x.k, x.v)
		}
	}
	if !weekly {
		_, blocked, _, _ := a.Stats.Tops(5)
		if len(blocked) > 0 {
			b.WriteString("\n" + tr("Найчастіше заблоковані:", "Most blocked:"))
			for _, x := range blocked {
				fmt.Fprintf(&b, "\n  %s — %d", notify.Defang(x.Key), x.Count)
			}
		}
	}
	return b.String()
}

// ---- update check ------------------------------------------------------------------------------

// ReleaseAPI is the GitHub endpoint for the newest release.
var ReleaseAPI = "https://api.github.com/repos/takobas/VartaDNS/releases/latest"

func parseVer(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		if j := strings.IndexAny(p, "-+"); j >= 0 {
			p = p[:j]
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// newerVersion reports whether b is newer than a.
func newerVersion(a, b string) bool {
	va, ok1 := parseVer(a)
	vb, ok2 := parseVer(b)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if vb[i] != va[i] {
			return vb[i] > va[i]
		}
	}
	return false
}

func (a *App) checkUpdate(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, ReleaseAPI, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "VartaDNS/"+Version)
	resp, err := a.http.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var rel struct {
		Tag string `json:"tag_name"`
		URL string `json:"html_url"`
	}
	if json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&rel) != nil {
		return
	}
	if !strings.HasPrefix(rel.URL, "https://github.com/") {
		rel.URL = ""
	}
	var notifyNow bool
	a.daily.set(func(c *counters) {
		c.Latest, c.LatestURL = rel.Tag, rel.URL
		if newerVersion(Version, rel.Tag) && c.LastVersion != rel.Tag {
			c.LastVersion = rel.Tag
			notifyNow = true
		}
	})
	if notifyNow {
		text := fmt.Sprintf("🆕 VartaDNS: %s %s (%s %s)", a.TG.Tr("вийшла нова версія", "new version available:"),
			rel.Tag, a.TG.Tr("у вас", "you have"), Version)
		if rel.URL != "" {
			text += "\n" + rel.URL
		}
		a.TG.System(notify.EvUpdate, text)
	}
}

// ---- bot commands ------------------------------------------------------------------------------

var errNoGroup = errors.New("group not found")

// setGroupInternet switches a group's internet by name (case-insensitive).
func (a *App) setGroupInternet(name string, off bool, d time.Duration) (string, error) {
	var found string
	err := a.state.update(func(s *State) {
		for i := range s.Groups {
			if strings.EqualFold(strings.TrimSpace(s.Groups[i].Name), strings.TrimSpace(name)) {
				g := &s.Groups[i]
				g.InternetOff, g.OffUntil = off, time.Time{}
				if off && d > 0 {
					g.OffUntil = time.Now().Add(d)
				}
				found = g.Name
				return
			}
		}
	})
	if err != nil {
		return "", err
	}
	if found == "" {
		return "", errNoGroup
	}
	return found, a.applyPolicy(context.Background(), true)
}

func (a *App) botCommand(ctx context.Context, cmd string, args []string) string {
	tr := a.TG.Tr
	switch cmd {
	case "start", "help":
		return tr(`🛡 VartaDNS — команди:
/status — стан захисту
/pause [хв] — пауза фільтрації (типово 15 хв)
/resume — увімкнути фільтрацію
/top — топ заблокованих і клієнтів
/threats — останні загрози
/groups — групи і стан інтернету
/internet <група> off [хв] — вимкнути інтернет групі
/internet <група> on — увімкнути`, `🛡 VartaDNS commands:
/status — protection status
/pause [min] — pause filtering (default 15 min)
/resume — resume filtering
/top — top blocked and clients
/threats — recent threats
/groups — groups and internet state
/internet <group> off [min] — turn a group's internet off
/internet <group> on — turn it on`)
	case "status":
		return a.statusText()
	case "pause":
		min := 15
		if len(args) > 0 {
			if n, err := strconv.Atoi(args[0]); err == nil {
				min = n
			}
		}
		if min < 1 || min > 1440 {
			return tr("Вкажи від 1 до 1440 хвилин.", "Use 1 to 1440 minutes.")
		}
		a.Resolver.SetBlocking(false, time.Duration(min)*time.Minute)
		return fmt.Sprintf("⏸ %s %d %s (%s %s). %s", tr("Фільтрацію призупинено на", "Filtering paused for"), min,
			tr("хв", "min"), tr("до", "until"), a.Resolver.DisabledUntil().In(time.Local).Format("15:04"),
			tr("Групи батьківського контролю працюють далі.", "Parental-control groups keep working."))
	case "resume":
		a.Resolver.SetBlocking(true, 0)
		return "▶️ " + tr("Фільтрацію увімкнено.", "Filtering is on.")
	case "top":
		_, blocked, clients, _ := a.Stats.Tops(5)
		var b strings.Builder
		b.WriteString("🔝 " + tr("Найчастіше заблоковані:", "Most blocked:"))
		for _, x := range blocked {
			fmt.Fprintf(&b, "\n  %s — %d", notify.Defang(x.Key), x.Count)
		}
		b.WriteString("\n\n" + tr("Найактивніші пристрої:", "Most active devices:"))
		names := a.Devices.Names()
		for _, x := range clients {
			fmt.Fprintf(&b, "\n  %s — %d", notify.DeviceLabel(names[x.Key], x.Key), x.Count)
		}
		return b.String()
	case "threats":
		var b strings.Builder
		n := 0
		for _, e := range a.Stats.Log(stats.Filter{Status: stats.StatusBlocked, Limit: 5000}) {
			if e.Kind != KindMalware && e.Kind != KindPhishing {
				continue
			}
			if n == 0 {
				b.WriteString("🦠 " + tr("Останні загрози:", "Recent threats:"))
			}
			fmt.Fprintf(&b, "\n%s %s → %s", e.Time.In(time.Local).Format("02.01 15:04"),
				notify.DeviceLabel(e.Device, e.Client), notify.Defang(e.Name))
			if n++; n == 10 {
				break
			}
		}
		if n == 0 {
			return "✅ " + tr("Загроз серед останніх запитів немає.", "No threats among recent queries.")
		}
		return b.String()
	case "groups":
		gs := a.state.get().Groups
		if len(gs) == 0 {
			return tr("Груп немає.", "No groups.")
		}
		var b strings.Builder
		b.WriteString("👨‍👧 " + tr("Групи:", "Groups:"))
		now := time.Now()
		for _, g := range gs {
			st := "🟢 " + tr("інтернет є", "internet on")
			if g.InternetOff && (g.OffUntil.IsZero() || now.Before(g.OffUntil)) {
				st = "🔴 " + tr("інтернет вимкнено", "internet off")
				if !g.OffUntil.IsZero() {
					st += " " + tr("до", "until") + " " + g.OffUntil.In(time.Local).Format("15:04")
				}
			}
			fmt.Fprintf(&b, "\n• %s — %s", g.Name, st)
		}
		return b.String()
	case "internet":
		// /internet <group name with spaces> on|off [minutes]
		pos := -1
		for i, a := range args {
			if l := strings.ToLower(a); l == "on" || l == "off" {
				pos = i
			}
		}
		if pos < 1 {
			return tr("Формат: /internet <група> off [хв] або /internet <група> on",
				"Usage: /internet <group> off [min] or /internet <group> on")
		}
		name := strings.Join(args[:pos], " ")
		off := strings.ToLower(args[pos]) == "off"
		var d time.Duration
		if off && pos+1 < len(args) {
			if n, err := strconv.Atoi(args[pos+1]); err == nil && n > 0 && n <= 7*1440 {
				d = time.Duration(n) * time.Minute
			}
		}
		g, err := a.setGroupInternet(name, off, d)
		if errors.Is(err, errNoGroup) {
			return tr("Групу не знайдено: ", "Group not found: ") + name + ". /groups"
		}
		if err != nil {
			return "⚠️ " + err.Error()
		}
		if !off {
			return "🟢 " + tr("Інтернет увімкнено для групи «", "Internet on for group “") + g + tr("».", "”.")
		}
		msg := "🔴 " + tr("Інтернет вимкнено для групи «", "Internet off for group “") + g + tr("»", "”")
		if d > 0 {
			msg += " " + tr("до", "until") + " " + time.Now().Add(d).In(time.Local).Format("15:04")
		}
		return msg + "."
	}
	return tr("Невідома команда. /help", "Unknown command. /help")
}

func (a *App) statusText() string {
	tr := a.TG.Tr
	var b strings.Builder
	b.WriteString("🛡 VartaDNS " + Version + "\n")
	if a.Resolver.BlockingEnabled() {
		b.WriteString("✅ " + tr("Захист увімкнено", "Protection on"))
	} else {
		b.WriteString("⏸ " + tr("Захист вимкнено", "Protection off"))
		if u := a.Resolver.DisabledUntil(); !u.IsZero() {
			b.WriteString(" " + tr("до", "until") + " " + u.In(time.Local).Format("15:04"))
		}
	}
	d := a.daily.sum(time.Now(), 1)
	fmt.Fprintf(&b, "\n%s: %d, %s: %d (%s), %s: %d", tr("Сьогодні запитів", "Queries today"), d.Total,
		tr("заблоковано", "blocked"), d.Blocked, pctStr(d.Blocked, d.Total), tr("загроз", "threats"), d.Threats)
	healthy, total, primary := 0, 0, ""
	for _, u := range a.Group.Statuses() {
		total++
		if u.Healthy {
			healthy++
		}
		if u.Primary {
			primary = u.Name
		}
	}
	fmt.Fprintf(&b, "\nUpstream: %d/%d OK, %s %s", healthy, total, tr("основний", "primary"), primary)
	q := a.QLog.Status()
	fmt.Fprintf(&b, "\n%s: %s, %s %s", tr("Журнал на флешці", "Flash log"), notify.MB(q.Bytes),
		tr("вільно", "free"), notify.MB(q.FreeBytes))
	if q.Paused {
		b.WriteString(" ⚠️ " + tr("запис зупинено", "logging stopped"))
	}
	up := a.Stats.Uptime()
	fmt.Fprintf(&b, "\n%s: %d %s %d %s", tr("Працює", "Uptime"), int(up.Hours())/24, tr("дн", "d"),
		int(up.Hours())%24, tr("год", "h"))
	return b.String()
}

// latestVersion returns the newest known release if it is newer than ours.
func (a *App) latestVersion() map[string]string {
	a.daily.mu.Lock()
	defer a.daily.mu.Unlock()
	if a.daily.Latest == "" || !newerVersion(Version, a.daily.Latest) {
		return nil
	}
	return map[string]string{"tag": a.daily.Latest, "url": a.daily.LatestURL}
}
