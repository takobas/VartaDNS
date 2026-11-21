// Package dnsmsg implements the minimal subset of the DNS wire format
// (RFC 1035, RFC 6891) that a filtering forwarder needs: parsing the
// question, walking resource records, rewriting IDs/TTLs and building
// synthetic responses. It is dependency-free and allocation-conscious.
package dnsmsg

import (
	"encoding/binary"
	"errors"
)

// Record types used by the filter.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeOPT   uint16 = 41
	TypeSVCB  uint16 = 64
	TypeHTTPS uint16 = 65
	TypeANY   uint16 = 255

	ClassINET uint16 = 1
)

// Response codes.
const (
	RcodeSuccess  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5
)

const headerLen = 12

var (
	ErrShort  = errors.New("dnsmsg: message too short")
	ErrFormat = errors.New("dnsmsg: malformed message")
)

// Query holds the parsed parts of a client query that matter for filtering.
type Query struct {
	Name    string // lower-case, without trailing dot ("" = root)
	Type    uint16
	Class   uint16
	QEnd    int // offset right after the question section
	Opcode  int
	UDPSize int  // max UDP payload the client accepts (512 without EDNS)
	DO      bool // DNSSEC OK bit
	CD      bool // checking disabled bit
	HasEDNS bool
}

// ---- header helpers -------------------------------------------------------

func ID(m []byte) uint16        { return binary.BigEndian.Uint16(m[0:2]) }
func SetID(m []byte, id uint16) { binary.BigEndian.PutUint16(m[0:2], id) }
func IsResponse(m []byte) bool  { return m[2]&0x80 != 0 }
func Truncated(m []byte) bool   { return m[2]&0x02 != 0 }
func Rcode(m []byte) int        { return int(m[3] & 0x0f) }
func qdcount(m []byte) int      { return int(binary.BigEndian.Uint16(m[4:6])) }
func ancount(m []byte) int      { return int(binary.BigEndian.Uint16(m[6:8])) }
func nscount(m []byte) int      { return int(binary.BigEndian.Uint16(m[8:10])) }
func arcount(m []byte) int      { return int(binary.BigEndian.Uint16(m[10:12])) }

// ---- names ----------------------------------------------------------------

// readName decodes a (possibly compressed) domain name starting at off.
// It returns the lower-cased name without trailing dot and the offset of
// the first byte after the name at its original position.
func readName(m []byte, off int) (string, int, error) {
	var buf [255]byte
	n := 0
	end := -1
	hops := 0
	for {
		if off >= len(m) {
			return "", 0, ErrShort
		}
		c := int(m[off])
		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				off++
				if end < 0 {
					end = off
				}
				return string(buf[:n]), end, nil
			}
			if off+1+c > len(m) {
				return "", 0, ErrShort
			}
			if n > 0 {
				if n >= len(buf) {
					return "", 0, ErrFormat
				}
				buf[n] = '.'
				n++
			}
			if n+c > len(buf) {
				return "", 0, ErrFormat
			}
			for _, b := range m[off+1 : off+1+c] {
				if b >= 'A' && b <= 'Z' {
					b += 'a' - 'A'
				}
				buf[n] = b
				n++
			}
			off += 1 + c
		case 0xC0:
			if off+1 >= len(m) {
				return "", 0, ErrShort
			}
			if end < 0 {
				end = off + 2
			}
			hops++
			if hops > 64 {
				return "", 0, ErrFormat // pointer loop
			}
			off = (c&0x3F)<<8 | int(m[off+1])
		default:
			return "", 0, ErrFormat // 0x40/0x80 label types are obsolete
		}
	}
}

// skipName returns the offset right after the name at off without decoding it.
func skipName(m []byte, off int) (int, error) {
	for {
		if off >= len(m) {
			return 0, ErrShort
		}
		c := int(m[off])
		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				return off + 1, nil
			}
			off += 1 + c
		case 0xC0:
			if off+1 >= len(m) {
				return 0, ErrShort
			}
			return off + 2, nil
		default:
			return 0, ErrFormat
		}
	}
}

// appendName encodes a dotted name in uncompressed wire format.
func appendName(dst []byte, name string) []byte {
	if name == "" {
		return append(dst, 0)
	}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			l := i - start
			if l > 63 {
				l = 63
			}
			if l > 0 {
				dst = append(dst, byte(l))
				dst = append(dst, name[start:start+l]...)
			}
			start = i + 1
		}
	}
	return append(dst, 0)
}

// ---- query parsing ---------------------------------------------------------

// ParseQuery parses a client query. Exactly one question is required.
func ParseQuery(m []byte) (Query, error) {
	var q Query
	if len(m) < headerLen {
		return q, ErrShort
	}
	if IsResponse(m) {
		return q, ErrFormat
	}
	q.Opcode = int(m[2]>>3) & 0x0f
	q.CD = m[3]&0x10 != 0
	if qdcount(m) != 1 {
		return q, ErrFormat
	}
	name, off, err := readName(m, headerLen)
	if err != nil {
		return q, err
	}
	if off+4 > len(m) {
		return q, ErrShort
	}
	q.Name = name
	q.Type = binary.BigEndian.Uint16(m[off:])
	q.Class = binary.BigEndian.Uint16(m[off+2:])
	q.QEnd = off + 4
	q.UDPSize = 512

	// Look for an OPT record in the additional section (skip answer/authority,
	// which are normally empty in queries).
	off = q.QEnd
	total := ancount(m) + nscount(m) + arcount(m)
	for i := 0; i < total; i++ {
		var err error
		if off, err = skipName(m, off); err != nil {
			return q, err
		}
		if off+10 > len(m) {
			return q, ErrShort
		}
		typ := binary.BigEndian.Uint16(m[off:])
		class := binary.BigEndian.Uint16(m[off+2:])
		ttl := binary.BigEndian.Uint32(m[off+4:])
		rdlen := int(binary.BigEndian.Uint16(m[off+8:]))
		if typ == TypeOPT {
			q.HasEDNS = true
			q.UDPSize = int(class)
			if q.UDPSize < 512 {
				q.UDPSize = 512
			}
			q.DO = ttl&0x8000 != 0
		}
		off += 10 + rdlen
		if off > len(m) {
			return q, ErrShort
		}
	}
	return q, nil
}

// ---- response walking --------------------------------------------------------

// RRInfo describes interesting facts about a response.
type RRInfo struct {
	TTLOffsets []int    // offsets of every TTL field except OPT
	MinTTL     uint32   // minimum TTL among answer/authority records
	HasTTL     bool     // at least one TTL seen
	CNAMEs     []string // CNAME targets found in the answer section
	AnswerIPs  [][]byte // raw A/AAAA rdata from the answer section
}

// Inspect walks a response message and collects TTL offsets and CNAME targets.
func Inspect(m []byte) (RRInfo, error) {
	var info RRInfo
	if len(m) < headerLen {
		return info, ErrShort
	}
	off := headerLen
	for i := 0; i < qdcount(m); i++ {
		var err error
		if off, err = skipName(m, off); err != nil {
			return info, err
		}
		off += 4
	}
	an, ns, ar := ancount(m), nscount(m), arcount(m)
	for i := 0; i < an+ns+ar; i++ {
		var err error
		if off, err = skipName(m, off); err != nil {
			return info, err
		}
		if off+10 > len(m) {
			return info, ErrShort
		}
		typ := binary.BigEndian.Uint16(m[off:])
		ttl := binary.BigEndian.Uint32(m[off+4:])
		rdlen := int(binary.BigEndian.Uint16(m[off+8:]))
		rdata := off + 10
		if rdata+rdlen > len(m) {
			return info, ErrShort
		}
		if typ != TypeOPT {
			info.TTLOffsets = append(info.TTLOffsets, off+4)
			if i < an+ns {
				if !info.HasTTL || ttl < info.MinTTL {
					info.MinTTL = ttl
				}
				info.HasTTL = true
			}
		}
		if i < an {
			switch typ {
			case TypeCNAME:
				if target, _, err := readName(m, rdata); err == nil {
					info.CNAMEs = append(info.CNAMEs, target)
				}
			case TypeA, TypeAAAA:
				info.AnswerIPs = append(info.AnswerIPs, m[rdata:rdata+rdlen])
			}
		}
		off = rdata + rdlen
	}
	return info, nil
}

// AgeTTLs subtracts elapsed seconds from every TTL at the given offsets,
// never letting a TTL drop below floor.
func AgeTTLs(m []byte, offsets []int, elapsed, floor uint32) {
	for _, o := range offsets {
		t := binary.BigEndian.Uint32(m[o:])
		if t > elapsed {
			t -= elapsed
		} else {
			t = 0
		}
		if t < floor {
			t = floor
		}
		binary.BigEndian.PutUint32(m[o:], t)
	}
}

// ---- building responses -------------------------------------------------------

// header builds a response header that mirrors the query's ID, opcode and RD.
func header(dst []byte, query []byte, rcode int, an uint16) []byte {
	var h [headerLen]byte
	copy(h[0:2], query[0:2])
	h[2] = 0x80 | (query[2] & 0x79) // QR=1, keep opcode and RD, clear AA/TC
	h[3] = 0x80 | byte(rcode&0x0f)  // RA=1
	if len(query) >= headerLen && qdcount(query) == 1 {
		binary.BigEndian.PutUint16(h[4:6], 1)
	}
	binary.BigEndian.PutUint16(h[6:8], an)
	return append(dst, h[:]...)
}

// appendRawQuestion copies the question exactly as the client sent it (keeps
// the client's letter case), falling back to re-encoding.
func appendRawQuestion(dst, query []byte, q Query) []byte {
	if q.QEnd > headerLen && len(query) >= q.QEnd {
		return append(dst, query[headerLen:q.QEnd]...)
	}
	return appendQuestion(dst, q)
}

func appendQuestion(dst []byte, q Query) []byte {
	dst = appendName(dst, q.Name)
	dst = binary.BigEndian.AppendUint16(dst, q.Type)
	return binary.BigEndian.AppendUint16(dst, q.Class)
}

// BuildError returns a response with the given rcode and the original question.
func BuildError(query []byte, q *Query, rcode int) []byte {
	out := make([]byte, 0, 64)
	if q == nil || len(query) < headerLen {
		// Header-only reply for unparsable queries.
		var h [headerLen]byte
		if len(query) >= 2 {
			copy(h[0:2], query[0:2])
		}
		h[2] = 0x80
		h[3] = 0x80 | byte(rcode&0x0f)
		return append(out, h[:]...)
	}
	out = header(out, query, rcode, 0)
	return appendRawQuestion(out, query, *q)
}

// BlockMode selects how blocked names are answered.
type BlockMode int

const (
	BlockNullIP   BlockMode = iota // A -> 0.0.0.0, AAAA -> ::, others -> NODATA
	BlockNXDomain                  // NXDOMAIN for every type
)

// BuildBlocked returns a synthetic answer for a blocked name.
func BuildBlocked(query []byte, q Query, mode BlockMode, ttl uint32) []byte {
	if mode == BlockNXDomain {
		return BuildError(query, &q, RcodeNXDomain)
	}
	var rdata []byte
	switch q.Type {
	case TypeA:
		rdata = make([]byte, 4)
	case TypeAAAA:
		rdata = make([]byte, 16)
	}
	an := uint16(0)
	if rdata != nil {
		an = 1
	}
	out := make([]byte, 0, 64)
	out = header(out, query, RcodeSuccess, an)
	out = appendRawQuestion(out, query, q)
	if rdata != nil {
		out = append(out, 0xC0, 0x0C) // pointer to the question name
		out = binary.BigEndian.AppendUint16(out, q.Type)
		out = binary.BigEndian.AppendUint16(out, q.Class)
		out = binary.BigEndian.AppendUint32(out, ttl)
		out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
		out = append(out, rdata...)
	}
	return out
}

// Truncate returns a header+question response with the TC bit set, telling
// the client to retry over TCP.
func Truncate(resp []byte, q Query) []byte {
	out := make([]byte, 0, 64)
	out = append(out, resp[:4]...)
	out[2] |= 0x02
	out = binary.BigEndian.AppendUint16(out, 1)
	out = append(out, 0, 0, 0, 0, 0, 0)
	return appendRawQuestion(out, resp, q)
}

// BuildQuery creates a simple recursive query (used by tests and health checks).
func BuildQuery(id uint16, name string, qtype uint16) []byte {
	out := make([]byte, headerLen, 64)
	binary.BigEndian.PutUint16(out[0:2], id)
	out[2] = 0x01 // RD
	binary.BigEndian.PutUint16(out[4:6], 1)
	out = appendName(out, name)
	out = binary.BigEndian.AppendUint16(out, qtype)
	return binary.BigEndian.AppendUint16(out, ClassINET)
}

// UpstreamUDPSize is the EDNS buffer size advertised to upstreams
// (DNS Flag Day 2020 recommendation, avoids IP fragmentation).
const UpstreamUDPSize = 1232

// BuildUpstreamQuery creates a clean query for the upstream from the parsed
// client query: RD=1, the client's CD bit, and our own EDNS OPT (with the
// client's DO bit). Nothing else from the client's packet (RD=0, ECS,
// cookies, extra records) leaks into the shared cache.
func BuildUpstreamQuery(q Query) []byte {
	out := make([]byte, headerLen, 64)
	out[2] = 0x01 // RD
	if q.CD {
		out[3] = 0x10
	}
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[10:12], 1) // ARCOUNT: OPT
	out = appendQuestion(out, q)
	out = append(out, 0) // root name
	out = binary.BigEndian.AppendUint16(out, TypeOPT)
	out = binary.BigEndian.AppendUint16(out, UpstreamUDPSize)
	var flags uint32
	if q.DO {
		flags = 0x8000
	}
	out = binary.BigEndian.AppendUint32(out, flags)
	return binary.BigEndian.AppendUint16(out, 0)
}

// AdaptResponse makes a shared (cached/upstream) response fit one client:
// it sets the client's ID, copies the client's exact question bytes (keeps
// 0x20 case randomisation intact) and removes the OPT record for clients
// that did not use EDNS (RFC 6891). It modifies and returns resp.
func AdaptResponse(resp, clientMsg []byte, q Query) []byte {
	SetID(resp, ID(clientMsg))
	if len(resp) >= q.QEnd && SameQuestion(clientMsg, resp) {
		copy(resp[headerLen:q.QEnd], clientMsg[headerLen:q.QEnd])
	}
	if !q.HasEDNS {
		resp = stripOPT(resp)
	}
	return resp
}

// stripOPT removes OPT records from the additional section.
func stripOPT(m []byte) []byte {
	if len(m) < headerLen || arcount(m) == 0 {
		return m
	}
	off := headerLen
	var err error
	for i := 0; i < qdcount(m); i++ {
		if off, err = skipName(m, off); err != nil {
			return m
		}
		off += 4
	}
	an, ns, ar := ancount(m), nscount(m), arcount(m)
	out := m
	removed := 0
	for i := 0; i < an+ns+ar; i++ {
		start := off
		if off, err = skipName(out, off); err != nil || off+10 > len(out) {
			return m
		}
		typ := binary.BigEndian.Uint16(out[off:])
		end := off + 10 + int(binary.BigEndian.Uint16(out[off+8:]))
		if end > len(out) {
			return m
		}
		if i >= an+ns && typ == TypeOPT {
			out = append(out[:start], out[end:]...)
			removed++
			off = start
			continue
		}
		off = end
	}
	if removed > 0 {
		binary.BigEndian.PutUint16(out[10:12], uint16(ar-removed))
	}
	return out
}

// SameQuestion reports whether a response carries the same question as the
// query (case-insensitive), guarding against mismatched or spoofed replies.
func SameQuestion(query, resp []byte) bool {
	if len(query) < headerLen || len(resp) < headerLen || qdcount(resp) != 1 {
		return false
	}
	qEnd, err := skipName(query, headerLen)
	if err != nil || qEnd+4 > len(query) {
		return false
	}
	qEnd += 4
	if len(resp) < qEnd {
		return false
	}
	return bytesEqualFold(query[headerLen:qEnd], resp[headerLen:qEnd])
}

func bytesEqualFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// TypeString returns a short mnemonic for common record types.
func TypeString(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	case TypeSVCB:
		return "SVCB"
	case TypeHTTPS:
		return "HTTPS"
	case TypeANY:
		return "ANY"
	}
	return "TYPE" + itoa(int(t))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// BuildCNAME answers "qname CNAME target" followed by the given A/AAAA
// rdata (4 or 16 bytes each) owned by target. Used for SafeSearch.
func BuildCNAME(query []byte, q Query, target string, ttl uint32, ips [][]byte) []byte {
	out := make([]byte, 0, 128)
	out = header(out, query, RcodeSuccess, uint16(1+len(ips)))
	out = appendRawQuestion(out, query, q)
	out = append(out, 0xC0, 0x0C)
	out = binary.BigEndian.AppendUint16(out, TypeCNAME)
	out = binary.BigEndian.AppendUint16(out, ClassINET)
	out = binary.BigEndian.AppendUint32(out, ttl)
	enc := appendName(nil, target)
	out = binary.BigEndian.AppendUint16(out, uint16(len(enc)))
	targetOff := len(out)
	out = append(out, enc...)
	for _, ip := range ips {
		typ := TypeA
		if len(ip) == 16 {
			typ = TypeAAAA
		}
		out = append(out, 0xC0|byte(targetOff>>8), byte(targetOff))
		out = binary.BigEndian.AppendUint16(out, typ)
		out = binary.BigEndian.AppendUint16(out, ClassINET)
		out = binary.BigEndian.AppendUint32(out, ttl)
		out = binary.BigEndian.AppendUint16(out, uint16(len(ip)))
		out = append(out, ip...)
	}
	return out
}
