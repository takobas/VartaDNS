package notify

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// CommandFunc executes a bot command and returns the reply text. cmd is
// lower-case without the leading "/" or "@botname".
type CommandFunc func(ctx context.Context, cmd string, args []string) string

type update struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
		Text string `json:"text"`
	} `json:"message"`
}

// ParseCommand splits "/pause@MyBot 15" into ("pause", ["15"]).
func ParseCommand(text string) (string, []string, bool) {
	f := strings.Fields(strings.TrimSpace(text))
	if len(f) == 0 || !strings.HasPrefix(f[0], "/") {
		return "", nil, false
	}
	cmd := strings.ToLower(strings.TrimPrefix(f[0], "/"))
	if i := strings.IndexByte(cmd, '@'); i >= 0 {
		cmd = cmd[:i]
	}
	return cmd, f[1:], cmd != ""
}

// Poll receives bot commands with long polling while commands are enabled.
// Only messages from the configured chat are executed; old messages that
// arrived while polling was off are skipped.
func (t *Telegram) Poll(ctx context.Context, handle CommandFunc) {
	var offset int64
	synced := "" // token+chat we skipped the backlog for
	var last time.Time
	for ctx.Err() == nil {
		s := t.set.Load()
		if !s.Configured() || !s.Commands {
			synced = ""
			sleepCtx(ctx, 10*time.Second)
			continue
		}
		key := s.Token + "|" + s.ChatID
		if synced != key {
			// Skip the backlog: confirm everything up to the newest update.
			res, err := t.call(ctx, s.Token, "getUpdates", url.Values{"offset": {"-1"}, "timeout": {"0"}})
			if err != nil {
				sleepCtx(ctx, 30*time.Second)
				continue
			}
			var ups []update
			json.Unmarshal(res, &ups)
			offset = 0
			if len(ups) > 0 {
				offset = ups[len(ups)-1].UpdateID + 1
			}
			synced = key
			t.setCommands(ctx, s)
		}
		pctx, cancel := context.WithTimeout(ctx, 70*time.Second)
		res, err := t.call(pctx, s.Token, "getUpdates", url.Values{
			"offset": {strconv.FormatInt(offset, 10)}, "timeout": {"50"}, "allowed_updates": {`["message"]`}})
		cancel()
		if err != nil {
			sleepCtx(ctx, 15*time.Second) // network down or another getUpdates (409)
			continue
		}
		var ups []update
		if json.Unmarshal(res, &ups) != nil {
			continue
		}
		for _, u := range ups {
			offset = u.UpdateID + 1
			if u.Message == nil || strconv.FormatInt(u.Message.Chat.ID, 10) != s.ChatID {
				continue // strangers are ignored silently
			}
			cmd, args, ok := ParseCommand(u.Message.Text)
			if !ok {
				continue
			}
			if time.Since(last) < 2*time.Second {
				continue // simple flood guard
			}
			last = time.Now()
			reply := handle(ctx, cmd, args)
			if reply == "" {
				continue
			}
			sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			_ = t.sendWith(sctx, s, reply)
			cancel()
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// Tr picks the message language of the current settings.
func (t *Telegram) Tr(uk, en string) string { return t.tr(uk, en) }

// SendNow sends a message immediately (reports), bypassing the queue.
func (t *Telegram) SendNow(ctx context.Context, text string) error { return t.send(ctx, text) }

// setCommands fills the bot's "/" menu in Telegram (best effort).
func (t *Telegram) setCommands(ctx context.Context, s *Settings) {
	type bc struct {
		Command     string `json:"command"`
		Description string `json:"description"`
	}
	l := []bc{
		{"status", t.tr("стан захисту", "protection status")},
		{"pause", t.tr("пауза фільтрації: /pause 15", "pause filtering: /pause 15")},
		{"resume", t.tr("увімкнути фільтрацію", "resume filtering")},
		{"top", t.tr("топ заблокованих і пристроїв", "top blocked and devices")},
		{"threats", t.tr("останні загрози", "recent threats")},
		{"groups", t.tr("групи і стан інтернету", "groups and internet state")},
		{"internet", t.tr("/internet <група> off [хв] | on", "/internet <group> off [min] | on")},
		{"help", t.tr("довідка", "help")},
	}
	b, _ := json.Marshal(l)
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, _ = t.call(cctx, s.Token, "setMyCommands", url.Values{"commands": {string(b)}})
}
