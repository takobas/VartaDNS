package notify

import (
	"fmt"
	"strings"

	"github.com/takobas/vartadns/internal/qlog"
)

// MB formats bytes as megabytes.
func MB(b int64) string {
	if b < 0 {
		return "?"
	}
	return fmt.Sprintf("%d MB", (b+(1<<19))>>20)
}

func daysRange(days []string) string {
	switch len(days) {
	case 0:
		return ""
	case 1:
		return days[0]
	}
	return days[0] + " … " + days[len(days)-1]
}

// CleanupText describes deleted log days.
func (t *Telegram) CleanupText(ev qlog.CleanupEvent, s qlog.Settings) string {
	var b strings.Builder
	b.WriteString("🗑 VartaDNS: " + t.tr("видалено старі журнали", "old logs deleted") + "\n")
	var reason string
	switch ev.Reason {
	case qlog.ReasonFree:
		reason = t.tr(
			fmt.Sprintf("мало вільного місця на флешці (менше %d MB)", s.MinFreeMB),
			fmt.Sprintf("low free space on the flash drive (below %d MB)", s.MinFreeMB))
	case qlog.ReasonSize:
		reason = t.tr(
			fmt.Sprintf("журнали перевищили ліміт %d MB", s.MaxMB),
			fmt.Sprintf("logs exceeded the %d MB limit", s.MaxMB))
	default:
		reason = t.tr(
			fmt.Sprintf("старші за %d дн.", s.RetentionDays),
			fmt.Sprintf("older than %d days", s.RetentionDays))
	}
	fmt.Fprintf(&b, "%s: %s\n", t.tr("Причина", "Reason"), reason)
	fmt.Fprintf(&b, "%s: %s (%d %s, %s)\n", t.tr("Видалено", "Deleted"), daysRange(ev.Days),
		len(ev.Days), t.tr("дн.", "days"), MB(ev.Bytes))
	if ev.Oldest != "" {
		fmt.Fprintf(&b, "%s: %s\n", t.tr("Зберігаються журнали з", "Logs kept since"), ev.Oldest)
	}
	fmt.Fprintf(&b, "%s: %s", t.tr("Вільно зараз", "Free now"), MB(ev.FreeBytes))
	return b.String()
}

// DiskFullText: logging stopped because nothing is left to delete.
func (t *Telegram) DiskFullText(free int64, s qlog.Settings) string {
	if t.uk() {
		return fmt.Sprintf("💾 VartaDNS: флешка заповнена, запис журналу зупинено\nВільно: %s (потрібно щонайменше %d MB)\nСтарих журналів для видалення немає — місце займають інші файли. DNS і фільтрація працюють далі.",
			MB(free), s.MinFreeMB)
	}
	return fmt.Sprintf("💾 VartaDNS: flash drive full, query logging stopped\nFree: %s (need at least %d MB)\nThere are no old logs left to delete — other files use the space. DNS and filtering keep working.",
		MB(free), s.MinFreeMB)
}

// DiskResumedText: logging resumed.
func (t *Telegram) DiskResumedText() string {
	return "💾 VartaDNS: " + t.tr("місце на флешці звільнилось, запис журналу відновлено",
		"space is available again, query logging resumed")
}

// UpstreamsText reports all upstreams down or recovered.
func (t *Telegram) UpstreamsText(down bool) string {
	if down {
		return "⚠️ VartaDNS: " + t.tr("усі upstream-сервери недоступні. Перевір інтернет; роутер переключить клієнтів на свій DNS.",
			"all upstream servers are unreachable. Check the internet connection; the router falls back to its own DNS.")
	}
	return "✅ VartaDNS: " + t.tr("upstream-сервери знову доступні", "upstream servers are reachable again")
}

// NewDeviceText reports a client seen for the first time.
func (t *Telegram) NewDeviceText(ip, name string) string {
	return fmt.Sprintf("📱 VartaDNS: %s\n%s: %s", t.tr("новий пристрій у мережі", "new device on the network"),
		t.tr("Пристрій", "Device"), DeviceLabel(name, ip))
}
