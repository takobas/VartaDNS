package server

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/takobas/vartadns/internal/cache"
	"github.com/takobas/vartadns/internal/dnsmsg"
	"github.com/takobas/vartadns/internal/filter"
	"github.com/takobas/vartadns/internal/policy"
	"github.com/takobas/vartadns/internal/stats"
	"github.com/takobas/vartadns/internal/upstream"
)

// fakeUpstream answers A queries with 1.2.3.4 (TTL 300). Names starting with
// "cname." get a CNAME to tracker.bad.com first.
var lastUpstreamRD, lastUpstreamEDNS atomic.Bool

func fakeUpstream(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	var count atomic.Int64
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			count.Add(1)
			q := buf[:n]
			p, err := dnsmsg.ParseQuery(q)
			if err != nil {
				continue
			}
			lastUpstreamRD.Store(q[2]&0x01 != 0)
			lastUpstreamEDNS.Store(p.HasEDNS)
			r := append([]byte(nil), q[:p.QEnd]...)
			r[2] |= 0x80
			r[3] = 0x80
			binary.BigEndian.PutUint16(r[10:12], 0)
			an := 0
			nameOff := 12
			if strings.HasPrefix(p.Name, "cname.") {
				an++
				r = append(r, 0xC0, 12)
				r = binary.BigEndian.AppendUint16(r, dnsmsg.TypeCNAME)
				r = binary.BigEndian.AppendUint16(r, 1)
				r = binary.BigEndian.AppendUint32(r, 300)
				tgt := []byte{7, 't', 'r', 'a', 'c', 'k', 'e', 'r', 3, 'b', 'a', 'd', 3, 'c', 'o', 'm', 0}
				r = binary.BigEndian.AppendUint16(r, uint16(len(tgt)))
				nameOff = len(r)
				r = append(r, tgt...)
			}
			if p.Type == dnsmsg.TypeA {
				an++
				r = append(r, 0xC0|byte(nameOff>>8), byte(nameOff))
				r = binary.BigEndian.AppendUint16(r, dnsmsg.TypeA)
				r = binary.BigEndian.AppendUint16(r, 1)
				r = binary.BigEndian.AppendUint32(r, 300)
				r = binary.BigEndian.AppendUint16(r, 4)
				r = append(r, 1, 2, 3, 4)
			}
			binary.BigEndian.PutUint16(r[6:8], uint16(an))
			_, _ = pc.WriteTo(r, addr)
		}
	}()
	return pc.LocalAddr().String(), &count
}

func newTestResolver(t *testing.T, opts Options) (*Resolver, *atomic.Int64) {
	addr, count := fakeUpstream(t)
	g, err := upstream.NewGroup([]string{addr}, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := filter.New()
	b := filter.NewBuilder(0)
	_, _ = b.Add("test", strings.NewReader("ads.example.com\nbad.com\n"), false)
	b.Apply(f)
	return NewResolver(opts, f, cache.New(1000, 0, 86400, 60), g, stats.New(100)), count
}

var client = netip.MustParseAddr("192.168.88.10")

func TestPipeline(t *testing.T) {
	r, count := newTestResolver(t, Options{BlockedTTL: 60, BlockDoHCanary: true})
	ctx := context.Background()

	// Blocked by suffix rule.
	resp := r.Resolve(ctx, dnsmsg.BuildQuery(1, "x.ads.example.com", dnsmsg.TypeA), client, "udp")
	info, _ := dnsmsg.Inspect(resp)
	if len(info.AnswerIPs) != 1 || info.AnswerIPs[0][0] != 0 {
		t.Fatal("expected 0.0.0.0 for blocked domain")
	}
	if count.Load() != 0 {
		t.Fatal("blocked query reached upstream")
	}

	// Forwarded, then cached.
	q := dnsmsg.BuildQuery(0x4242, "www.good.org", dnsmsg.TypeA)
	resp = r.Resolve(ctx, q, client, "udp")
	if dnsmsg.ID(resp) != 0x4242 || dnsmsg.Rcode(resp) != 0 {
		t.Fatal("bad forwarded response")
	}
	info, _ = dnsmsg.Inspect(resp)
	if len(info.AnswerIPs) != 1 || info.AnswerIPs[0][0] != 1 {
		t.Fatal("expected 1.2.3.4")
	}
	q2 := dnsmsg.BuildQuery(0x5151, "WWW.GOOD.ORG", dnsmsg.TypeA)
	resp = r.Resolve(ctx, q2, client, "udp")
	if dnsmsg.ID(resp) != 0x5151 {
		t.Fatal("cached response has wrong ID")
	}
	if count.Load() != 1 {
		t.Fatalf("expected 1 upstream query, got %d", count.Load())
	}
	if r.Stats.Cached.Load() != 1 {
		t.Fatal("cache hit not recorded")
	}

	// CNAME pointing into a blocked domain.
	resp = r.Resolve(ctx, dnsmsg.BuildQuery(3, "cname.shop.org", dnsmsg.TypeA), client, "udp")
	info, _ = dnsmsg.Inspect(resp)
	if len(info.AnswerIPs) != 1 || info.AnswerIPs[0][0] != 0 || len(info.CNAMEs) != 0 {
		t.Fatal("CNAME cloaking not blocked")
	}
	// ...and again from cache.
	resp = r.Resolve(ctx, dnsmsg.BuildQuery(4, "cname.shop.org", dnsmsg.TypeA), client, "udp")
	info, _ = dnsmsg.Inspect(resp)
	if len(info.CNAMEs) != 0 {
		t.Fatal("cached CNAME cloaking not blocked")
	}

	// ANY is refused, Firefox canary is NXDOMAIN.
	resp = r.Resolve(ctx, dnsmsg.BuildQuery(5, "good.org", dnsmsg.TypeANY), client, "udp")
	if dnsmsg.Rcode(resp) != dnsmsg.RcodeNotImp {
		t.Fatal("ANY not refused")
	}
	resp = r.Resolve(ctx, dnsmsg.BuildQuery(6, "use-application-dns.net", dnsmsg.TypeA), client, "udp")
	if dnsmsg.Rcode(resp) != dnsmsg.RcodeNXDomain {
		t.Fatal("canary not NXDOMAIN")
	}

	// Pausing filtering lets blocked domains through.
	r.SetBlocking(false, time.Minute)
	resp = r.Resolve(ctx, dnsmsg.BuildQuery(7, "ads.example.com", dnsmsg.TypeA), client, "udp")
	info, _ = dnsmsg.Inspect(resp)
	if info.AnswerIPs[0][0] != 1 {
		t.Fatal("paused filtering still blocked")
	}

	// Garbage gets FORMERR, tiny packets are dropped.
	if resp := r.Resolve(ctx, []byte{1, 2, 3}, client, "udp"); resp != nil {
		t.Fatal("short packet not dropped")
	}
}

func TestACLAndRateLimit(t *testing.T) {
	r, _ := newTestResolver(t, Options{
		RateLimitQPS: 5, RateLimitBurst: 5,
		AllowedClients: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
	})
	ctx := context.Background()
	outsider := netip.MustParseAddr("8.8.8.8")
	if resp := r.Resolve(ctx, dnsmsg.BuildQuery(1, "good.org", dnsmsg.TypeA), outsider, "udp"); resp != nil {
		t.Fatal("ACL did not drop an outside client")
	}
	refused := 0
	for i := 0; i < 20; i++ {
		resp := r.Resolve(ctx, dnsmsg.BuildQuery(uint16(i), "ads.example.com", dnsmsg.TypeA), client, "udp")
		if dnsmsg.Rcode(resp) == dnsmsg.RcodeRefused {
			refused++
		}
	}
	if refused < 14 {
		t.Fatalf("rate limit too weak: %d refused of 20", refused)
	}
}

func TestListenersUDPAndTCP(t *testing.T) {
	r, _ := newTestResolver(t, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go r.ServeUDP(ctx, uc, 2)
	go r.ServeTCP(ctx, ln)

	u, _ := upstream.New(uc.LocalAddr().String(), nil)
	resp, err := u.Exchange(ctx, dnsmsg.BuildQuery(9, "ads.example.com", dnsmsg.TypeA))
	if err != nil || dnsmsg.ID(resp) != 9 {
		t.Fatalf("udp exchange: %v", err)
	}
	tu, _ := upstream.New("tcp://"+ln.Addr().String(), nil)
	resp, err = tu.Exchange(ctx, dnsmsg.BuildQuery(10, "www.good.org", dnsmsg.TypeA))
	if err != nil || dnsmsg.ID(resp) != 10 {
		t.Fatalf("tcp exchange: %v", err)
	}
}

func TestNoClientFlagsLeakUpstream(t *testing.T) {
	r, _ := newTestResolver(t, Options{})
	q := dnsmsg.BuildQuery(77, "NoRecurse.Good.ORG", dnsmsg.TypeA)
	q[2] &^= 0x01 // RD=0 from a misbehaving client
	resp := r.Resolve(context.Background(), q, client, "udp")
	if !lastUpstreamRD.Load() || !lastUpstreamEDNS.Load() {
		t.Fatal("upstream did not get a clean RD=1 EDNS query")
	}
	if string(resp[12:20]) != string(q[12:20]) {
		t.Fatal("question case not preserved")
	}
}

func TestGroups(t *testing.T) {
	r, count := newTestResolver(t, Options{BlockedTTL: 60})
	p, err := policy.Compile([]policy.Group{
		{Name: "Kids", Members: []string{"192.168.88.50-192.168.88.60"},
			Services: []string{"tiktok"}, Allow: []string{"ads.example.com"}, SafeSearch: true},
		{Name: "Off", Members: []string{"192.168.88.70"}, InternetOff: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.SetPolicy(p, nil)
	ctx := context.Background()
	kid := netip.MustParseAddr("192.168.88.55")
	adult := netip.MustParseAddr("192.168.88.10")
	ipOf := func(resp []byte) byte {
		info, _ := dnsmsg.Inspect(resp)
		if len(info.AnswerIPs) == 0 {
			return 255
		}
		return info.AnswerIPs[len(info.AnswerIPs)-1][0]
	}

	// Service block applies only to the group.
	if ipOf(r.Resolve(ctx, dnsmsg.BuildQuery(1, "www.tiktok.com", dnsmsg.TypeA), kid, "udp")) != 0 {
		t.Fatal("TikTok not blocked for kid")
	}
	if ipOf(r.Resolve(ctx, dnsmsg.BuildQuery(2, "www.tiktok.com", dnsmsg.TypeA), adult, "udp")) != 1 {
		t.Fatal("TikTok blocked for non-member")
	}
	// Group allow overrides the global blocklist.
	if ipOf(r.Resolve(ctx, dnsmsg.BuildQuery(3, "ads.example.com", dnsmsg.TypeA), kid, "udp")) != 1 {
		t.Fatal("group allow did not override global block")
	}
	if ipOf(r.Resolve(ctx, dnsmsg.BuildQuery(4, "ads.example.com", dnsmsg.TypeA), adult, "udp")) != 0 {
		t.Fatal("global block lost for others")
	}
	// Pausing global filtering keeps group rules.
	r.SetBlocking(false, time.Minute)
	if ipOf(r.Resolve(ctx, dnsmsg.BuildQuery(5, "m.tiktok.com", dnsmsg.TypeA), kid, "udp")) != 0 {
		t.Fatal("group rule disabled by global pause")
	}
	r.SetBlocking(true, 0)
	// Internet off blocks everything for that group.
	if ipOf(r.Resolve(ctx, dnsmsg.BuildQuery(6, "www.good.org", dnsmsg.TypeA), netip.MustParseAddr("192.168.88.70"), "udp")) != 0 {
		t.Fatal("internet-off group not blocked")
	}
	// SafeSearch: CNAME to forcesafesearch + its address.
	before := count.Load()
	resp := r.Resolve(ctx, dnsmsg.BuildQuery(7, "www.google.com", dnsmsg.TypeA), kid, "udp")
	info, err := dnsmsg.Inspect(resp)
	if err != nil || len(info.CNAMEs) != 1 || info.CNAMEs[0] != "forcesafesearch.google.com" || ipOf(resp) != 1 {
		t.Fatalf("safesearch response wrong: %+v %v", info, err)
	}
	if count.Load() != before+1 {
		t.Fatal("safesearch target not resolved upstream exactly once")
	}
	// Non-members get the normal answer.
	info, _ = dnsmsg.Inspect(r.Resolve(ctx, dnsmsg.BuildQuery(8, "www.google.com", dnsmsg.TypeA), adult, "udp"))
	if len(info.CNAMEs) != 0 {
		t.Fatal("safesearch applied to non-member")
	}
	if r.Stats.Log(stats.Filter{Group: "Kids", Limit: 100})[0].Group != "Kids" {
		t.Fatal("group not recorded in query log")
	}
}
