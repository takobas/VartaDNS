package policy

// Service is a built-in set of domains that can be blocked with one switch.
type Service struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	Note    string   `json:"note,omitempty"` // shown in the panel (English key)
}

// Services is the catalog of popular apps/sites. Every domain also covers
// its subdomains. Lists include CDNs and API hosts, otherwise apps keep
// partially working. Shared infrastructure (generic Google, Microsoft,
// Akamai, Cloudflare domains) is deliberately excluded.
var Services = []Service{
	{ID: "tiktok", Name: "TikTok", Domains: []string{
		"tiktok.com", "tiktokv.com", "tiktokv.us", "tiktokv.eu", "tiktokcdn.com",
		"tiktokcdn-us.com", "tiktokcdn-eu.com", "ttwstatic.com",
		"byteoversea.com", "ibytedtos.com", "ibyteimg.com", "ipstatp.com",
		"muscdn.com", "musical.ly", "tik-tokapi.com",
	}},
	{ID: "roblox", Name: "Roblox", Domains: []string{
		"roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com",
	}},
	{ID: "minecraft", Name: "Minecraft", Domains: []string{
		"minecraft.net", "mojang.com", "minecraftservices.com", "minecraft-services.net",
	}, Note: "minecraft_note"},
	{ID: "fortnite", Name: "Fortnite / Epic Games", Domains: []string{
		"fortnite.com", "epicgames.com", "epicgames.dev", "unrealengine.com",
	}},
	{ID: "steam", Name: "Steam", Domains: []string{
		"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com",
		"steamserver.net", "steamgames.com", "steamusercontent.com", "steam-chat.com",
		"valvesoftware.com",
	}},
	{ID: "discord", Name: "Discord", Domains: []string{
		"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media",
		"discordcdn.com", "discord.dev", "discord.new", "discordstatus.com",
	}},
	{ID: "youtube", Name: "YouTube", Domains: []string{
		"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com",
		"youtubekids.com", "yt.be", "youtubei.googleapis.com", "youtube.googleapis.com",
	}},
	{ID: "instagram", Name: "Instagram", Domains: []string{
		"instagram.com", "cdninstagram.com", "ig.me", "instagr.am",
	}},
	{ID: "facebook", Name: "Facebook / Messenger", Domains: []string{
		"facebook.com", "fb.com", "fbcdn.net", "facebook.net", "fb.me", "messenger.com",
		"fbsbx.com", "m.me",
	}, Note: "facebook_note"},
	{ID: "snapchat", Name: "Snapchat", Domains: []string{
		"snapchat.com", "sc-cdn.net", "sc-static.net", "snapkit.com", "snap-dev.net",
		"feelinsonice-hrd.appspot.com",
	}},
	{ID: "telegram", Name: "Telegram", Domains: []string{
		"telegram.org", "t.me", "telegram.me", "telesco.pe", "tdesktop.com", "telegra.ph",
		"cdn-telegram.org",
	}, Note: "telegram_note"},
	{ID: "twitch", Name: "Twitch", Domains: []string{
		"twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net",
		"ext-twitch.tv", "twitch.a2z.com",
	}},
}

// Category is a downloadable list blocked per group.
type Category struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`       // standard profile
	LightURL string `json:"light_url"` // smaller variant for 128-256 MB routers
}

// Categories available to groups.
var Categories = []Category{
	{ID: "adult", Name: "Adult content",
		URL:      "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nsfw.txt",
		LightURL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nsfw.txt"},
	{ID: "gambling", Name: "Gambling",
		URL:      "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/gambling.txt",
		LightURL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/gambling.medium.txt"},
}

func serviceByID(id string) *Service {
	for i := range Services {
		if Services[i].ID == id {
			return &Services[i]
		}
	}
	return nil
}

func categoryKnown(id string) bool {
	for _, c := range Categories {
		if c.ID == id {
			return true
		}
	}
	return false
}
