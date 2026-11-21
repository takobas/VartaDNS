package dnsmsg

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

func TestParseQuery(t *testing.T) {
	q := BuildQuery(0x1234, "WWW.Example.COM", TypeAAAA)
	p, err := ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "www.example.com" || p.Type != TypeAAAA || p.Class != ClassINET || p.UDPSize != 512 {
		t.Fatalf("unexpected parse: %+v", p)
	}
	if p.QEnd != len(q) {
		t.Fatalf("QEnd=%d len=%d", p.QEnd, len(q))
	}
}

func TestParseQueryEDNS(t *testing.T) {
	q := BuildQuery(1, "example.com", TypeA)
	binary.BigEndian.PutUint16(q[10:12], 1) // ARCOUNT=1
	// OPT: root name, type 41, class=udp size 4096, ttl with DO bit, rdlen 0
	q = append(q, 0, 0, 41, 0x10, 0x00, 0, 0, 0x80, 0, 0, 0)
	p, err := ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasEDNS || p.UDPSize != 4096 || !p.DO {
		t.Fatalf("EDNS not parsed: %+v", p)
	}
}

func TestRejectsResponsesAndMultiQuestion(t *testing.T) {
	q := BuildQuery(1, "example.com", TypeA)
	q[2] |= 0x80
	if _, err := ParseQuery(q); err == nil {
		t.Fatal("response accepted as query")
	}
	q = BuildQuery(1, "example.com", TypeA)
	binary.BigEndian.PutUint16(q[4:6], 2)
	if _, err := ParseQuery(q); err == nil {
		t.Fatal("qdcount=2 accepted")
	}
}

func TestCompressionLoop(t *testing.T) {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[4:6], 1)
	q = append(q, 0xC0, 12, 0, 1, 0, 1) // pointer to itself
	if _, err := ParseQuery(q); err == nil {
		t.Fatal("pointer loop not detected")
	}
}

func TestBuildBlocked(t *testing.T) {
	q := BuildQuery(0xBEEF, "ads.example.com", TypeA)
	p, _ := ParseQuery(q)
	r := BuildBlocked(q, p, BlockNullIP, 60)
	if ID(r) != 0xBEEF || !IsResponse(r) || Rcode(r) != RcodeSuccess || ancount(r) != 1 {
		t.Fatalf("bad blocked response header: % x", r[:12])
	}
	info, err := Inspect(r)
	if err != nil || len(info.AnswerIPs) != 1 || len(info.AnswerIPs[0]) != 4 || info.MinTTL != 60 {
		t.Fatalf("bad blocked answer: %+v %v", info, err)
	}
	for _, b := range info.AnswerIPs[0] {
		if b != 0 {
			t.Fatal("expected 0.0.0.0")
		}
	}
	r = BuildBlocked(q, p, BlockNXDomain, 60)
	if Rcode(r) != RcodeNXDomain {
		t.Fatal("expected NXDOMAIN")
	}
	// Non-address types get an empty NOERROR answer.
	q = BuildQuery(2, "ads.example.com", TypeHTTPS)
	p, _ = ParseQuery(q)
	r = BuildBlocked(q, p, BlockNullIP, 60)
	if Rcode(r) != RcodeSuccess || ancount(r) != 0 {
		t.Fatal("expected NODATA for HTTPS")
	}
}

// buildResponse creates "name CNAME target; target A 1.2.3.4" with compression.
func buildResponse(name, target string, ttl1, ttl2 uint32) []byte {
	q := BuildQuery(7, name, TypeA)
	r := append([]byte(nil), q...)
	r[2] |= 0x80
	binary.BigEndian.PutUint16(r[6:8], 2)
	tgtOff := len(r) + 12
	r = append(r, 0xC0, 12)
	r = binary.BigEndian.AppendUint16(r, TypeCNAME)
	r = binary.BigEndian.AppendUint16(r, ClassINET)
	r = binary.BigEndian.AppendUint32(r, ttl1)
	enc := appendName(nil, target)
	r = binary.BigEndian.AppendUint16(r, uint16(len(enc)))
	r = append(r, enc...)
	r = append(r, 0xC0|byte(tgtOff>>8), byte(tgtOff))
	r = binary.BigEndian.AppendUint16(r, TypeA)
	r = binary.BigEndian.AppendUint16(r, ClassINET)
	r = binary.BigEndian.AppendUint32(r, ttl2)
	r = binary.BigEndian.AppendUint16(r, 4)
	return append(r, 1, 2, 3, 4)
}

func TestInspectAndAge(t *testing.T) {
	r := buildResponse("www.shop.com", "Tracker.Bad.com", 300, 120)
	info, err := Inspect(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.CNAMEs) != 1 || info.CNAMEs[0] != "tracker.bad.com" {
		t.Fatalf("CNAMEs = %v", info.CNAMEs)
	}
	if info.MinTTL != 120 || len(info.TTLOffsets) != 2 {
		t.Fatalf("ttl info = %+v", info)
	}
	AgeTTLs(r, info.TTLOffsets, 100, 1)
	info2, _ := Inspect(r)
	if info2.MinTTL != 20 {
		t.Fatalf("aged min TTL = %d", info2.MinTTL)
	}
	AgeTTLs(r, info.TTLOffsets, 1000, 1)
	info3, _ := Inspect(r)
	if info3.MinTTL != 1 {
		t.Fatalf("floor not applied: %d", info3.MinTTL)
	}
}

func TestTruncate(t *testing.T) {
	r := buildResponse("www.shop.com", "x.com", 1, 1)
	q := BuildQuery(7, "www.shop.com", TypeA)
	p, _ := ParseQuery(q)
	tr := Truncate(r, p)
	if !Truncated(tr) || ancount(tr) != 0 || qdcount(tr) != 1 {
		t.Fatal("bad truncated response")
	}
}

// TestNoPanics feeds random garbage to every parser.
func TestNoPanics(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	base := buildResponse("a.b.c.example.com", "d.example.net", 5, 5)
	for i := 0; i < 200000; i++ {
		var m []byte
		if i%2 == 0 {
			m = make([]byte, rng.Intn(80))
			rng.Read(m)
		} else {
			m = append([]byte(nil), base...)
			for j := 0; j < 1+rng.Intn(4); j++ {
				m[rng.Intn(len(m))] = byte(rng.Intn(256))
			}
			m = m[:rng.Intn(len(m)+1)]
		}
		_, _ = ParseQuery(m)
		_, _ = Inspect(m)
	}
}

func BenchmarkParseQuery(b *testing.B) {
	q := BuildQuery(1, "ads.tracker.example.com", TypeA)
	for i := 0; i < b.N; i++ {
		_, _ = ParseQuery(q)
	}
}

func TestUpstreamQueryAndAdapt(t *testing.T) {
	// Client query with RD=0 and mixed case, no EDNS.
	cq := BuildQuery(0x1111, "WwW.ExAmple.com", TypeA)
	cq[2] &^= 0x01
	p, _ := ParseQuery(cq)
	uq := BuildUpstreamQuery(p)
	up, err := ParseQuery(uq)
	if err != nil || uq[2]&0x01 == 0 || !up.HasEDNS || up.UDPSize != UpstreamUDPSize || up.Name != "www.example.com" {
		t.Fatalf("bad upstream query: %+v %v", up, err)
	}
	// Upstream response echoes the lower-case question and carries an OPT.
	resp := buildResponse("www.example.com", "cdn.example.net", 60, 60)
	binary.BigEndian.PutUint16(resp[10:12], 1)
	resp = append(resp, 0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0)
	out := AdaptResponse(append([]byte(nil), resp...), cq, p)
	if ID(out) != 0x1111 || arcount(out) != 0 || len(out) != len(resp)-11 {
		t.Fatalf("OPT not stripped or ID wrong: id=%x ar=%d", ID(out), arcount(out))
	}
	if string(out[12:p.QEnd]) != string(cq[12:p.QEnd]) {
		t.Fatal("client question case not preserved")
	}
	if info, err := Inspect(out); err != nil || len(info.AnswerIPs) != 1 {
		t.Fatalf("adapted response broken: %v", err)
	}
	if !SameQuestion(cq, resp) || SameQuestion(BuildQuery(1, "other.com", TypeA), resp) {
		t.Fatal("SameQuestion wrong")
	}
}
