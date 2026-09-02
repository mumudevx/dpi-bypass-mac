// Package resolve is the DNS chain and the single funnel every outbound dial
// must pass through.
//
// MEASUREMENTS.md §5.4 is the reason this package exists as a hard boundary:
// the first run of the compatibility matrix scored every emitter 0/6 because
// the probe dialled by hostname, Go's resolver returned the BTK sinkhole
// 195.175.254.2, and every connection went to a blackhole instead of the
// origin. No packet strategy can survive a poisoned resolution. Every
// constructor here therefore takes an IP literal or an explicit bootstrap set,
// and a hostname can only ever reach the wire as a TLS ServerName — never as
// something the system resolver is asked about.
package resolve

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// headerLen is the fixed DNS message header size (RFC 1035 §4.1.1).
const headerLen = 12

var (
	// ErrShortMessage means the buffer cannot even hold a DNS header, so there
	// is nothing to reply to and nothing to reply with.
	ErrShortMessage = errors.New("resolve: DNS message shorter than a header")
	// ErrNoQuestion means the header claims no question section.
	ErrNoQuestion = errors.New("resolve: DNS message carries no question")
	// ErrMalformed means the question section could not be walked.
	ErrMalformed = errors.New("resolve: malformed DNS message")
)

// Question is the first question of a DNS message.
type Question struct {
	Name  string // lower-case, fully qualified, trailing dot
	Type  uint16
	Class uint16
}

func (q Question) String() string {
	t, ok := dns.TypeToString[q.Type]
	if !ok {
		t = fmt.Sprintf("TYPE%d", q.Type)
	}
	return q.Name + " " + t
}

// MsgID reads the transaction ID.
func MsgID(msg []byte) (uint16, error) {
	if len(msg) < headerLen {
		return 0, ErrShortMessage
	}
	return binary.BigEndian.Uint16(msg[0:2]), nil
}

// SetMsgID rewrites the transaction ID in place. Every answer this package
// returns to a caller carries the caller's own ID, whatever ID went upstream:
// DoH zeroes it per RFC 8484 §4.1 and the UDP resolvers randomise it as an
// anti-spoofing measure, so the two are never the same value by accident.
func SetMsgID(msg []byte, id uint16) error {
	if len(msg) < headerLen {
		return ErrShortMessage
	}
	binary.BigEndian.PutUint16(msg[0:2], id)
	return nil
}

// Truncated reports the TC bit.
func Truncated(msg []byte) bool {
	return len(msg) >= headerLen && msg[2]&0x02 != 0
}

// IsResponse reports the QR bit.
func IsResponse(msg []byte) bool {
	return len(msg) >= headerLen && msg[2]&0x80 != 0
}

// Rcode returns the low four bits of the response code. It ignores the EDNS0
// extended rcode because nothing in this package branches on one.
func Rcode(msg []byte) int {
	if len(msg) < headerLen {
		return -1
	}
	return int(msg[3] & 0x0f)
}

func qdcount(msg []byte) int {
	if len(msg) < headerLen {
		return 0
	}
	return int(binary.BigEndian.Uint16(msg[4:6]))
}

// questionEnd returns the offset just past the first question, so a reply can
// be built by copying the caller's own header and question verbatim rather than
// by re-encoding a name we may have failed to understand.
func questionEnd(msg []byte) (int, error) {
	if len(msg) < headerLen {
		return 0, ErrShortMessage
	}
	if qdcount(msg) == 0 {
		return headerLen, ErrNoQuestion
	}
	_, off, err := dns.UnpackDomainName(msg, headerLen)
	if err != nil {
		return 0, fmt.Errorf("%w: question name: %w", ErrMalformed, err)
	}
	if off+4 > len(msg) {
		return 0, fmt.Errorf("%w: question truncated", ErrMalformed)
	}
	return off + 4, nil
}

// FirstQuestion parses the first question without unpacking the whole message.
func FirstQuestion(msg []byte) (Question, error) {
	if len(msg) < headerLen {
		return Question{}, ErrShortMessage
	}
	if qdcount(msg) == 0 {
		return Question{}, ErrNoQuestion
	}
	name, off, err := dns.UnpackDomainName(msg, headerLen)
	if err != nil {
		return Question{}, fmt.Errorf("%w: question name: %w", ErrMalformed, err)
	}
	if off+4 > len(msg) {
		return Question{}, fmt.Errorf("%w: question truncated", ErrMalformed)
	}
	return Question{
		Name:  strings.ToLower(name),
		Type:  binary.BigEndian.Uint16(msg[off : off+2]),
		Class: binary.BigEndian.Uint16(msg[off+2 : off+4]),
	}, nil
}

// SameQuestion reports whether two messages ask the same thing. An upstream
// answer whose question does not match the query is discarded: on a plaintext
// UDP transport that is the shape of an off-path spoof, and MEASUREMENTS.md §2
// shows plaintext UDP is a first-class rung of this chain.
func SameQuestion(a, b []byte) bool {
	qa, err := FirstQuestion(a)
	if err != nil {
		return false
	}
	qb, err := FirstQuestion(b)
	if err != nil {
		return false
	}
	return qa == qb
}

// unpack is the one place a full message parse happens. A parse failure is
// never fatal to the chain; the caller advances to the next resolver.
func unpack(msg []byte) (*dns.Msg, error) {
	m := new(dns.Msg)
	if err := m.Unpack(msg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return m, nil
}

// AnswerAddrs returns the A and AAAA addresses of the answer section, in
// message order. A message that will not parse yields no addresses rather than
// an error, because "no addresses" is what the caller does with it either way.
func AnswerAddrs(msg []byte) []netip.Addr {
	m, err := unpack(msg)
	if err != nil {
		return nil
	}
	return answerAddrs(m)
}

func answerAddrs(m *dns.Msg) []netip.Addr {
	var out []netip.Addr
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
				out = append(out, a)
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(v.AAAA.To16()); ok {
				out = append(out, a)
			}
		}
	}
	return out
}

// MinTTL is the smallest TTL of the answer section, used to bound the positive
// cache. Zero answers give zero, which the cache reads as "do not cache".
func MinTTL(msg []byte) time.Duration {
	m, err := unpack(msg)
	if err != nil {
		return 0
	}
	return minTTL(m)
}

func minTTL(m *dns.Msg) time.Duration {
	if len(m.Answer) == 0 {
		return 0
	}
	best := ^uint32(0)
	for _, rr := range m.Answer {
		if t := rr.Header().Ttl; t < best {
			best = t
		}
	}
	return time.Duration(best) * time.Second
}

// NewQuery builds a recursion-desired query. It is used by the chain's own
// probes (NAT64 detection, alt-port liveness ranking) and by `dpb dns`.
func NewQuery(name string, qtype uint16) ([]byte, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("resolve: empty query name")
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(strings.ToLower(name)), qtype)
	m.RecursionDesired = true
	b, err := m.Pack()
	if err != nil {
		return nil, fmt.Errorf("resolve: pack query for %s: %w", name, err)
	}
	return b, nil
}

// SynthRcode builds a reply to query carrying the caller's own ID and question
// with every section emptied and the given rcode.
//
// Chain exhaustion must produce one of these rather than silence. A stub
// resolver that gets no answer waits out its own multi-second timeout and then
// usually falls back to TCP/53 — which MEASUREMENTS.md §2 shows is RST-filtered
// at every port on this ISP. Answering SERVFAIL immediately keeps the failure
// fast, attributable, and off the one transport that provably cannot work.
func SynthRcode(query []byte, rcode int) []byte {
	if len(query) < headerLen {
		return nil
	}
	end, err := questionEnd(query)
	if err != nil {
		// The question is unusable, so echo the header alone and declare no
		// question rather than reflecting bytes we could not parse.
		end = headerLen
	}
	out := make([]byte, end)
	copy(out, query[:end])

	// Byte 2: QR(1) Opcode(4) AA(1) TC(1) RD(1). Keep the opcode and RD, set
	// QR, clear AA and TC.
	out[2] = (out[2] & 0x79) | 0x80
	// Byte 3: RA(1) Z(3) RCODE(4). Recursion is available here by definition.
	out[3] = 0x80 | byte(rcode&0x0f)

	if err != nil {
		binary.BigEndian.PutUint16(out[4:6], 0)
	}
	binary.BigEndian.PutUint16(out[6:8], 0)   // ANCOUNT
	binary.BigEndian.PutUint16(out[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(out[10:12], 0) // ARCOUNT
	return out
}

// soaTTL is how long a stub may cache a synthesised empty answer. Short,
// because AAAA suppression is a policy decision that can be revised the moment
// NAT64 detection or the v4 path changes underneath us.
const soaTTL = 60 * time.Second

// SynthEmpty builds a NOERROR reply with an empty answer section and a
// synthetic SOA in the authority section.
//
// It is NEVER NXDOMAIN. NXDOMAIN is cached by every stub as "this name does not
// exist", which would poison the name for other address families and outlive
// the policy decision that produced it. NOERROR with an empty answer means
// "this name has no record of this type", which is exactly what AAAA
// suppression asserts.
func SynthEmpty(query []byte) []byte {
	req, err := unpack(query)
	if err != nil || len(req.Question) == 0 {
		return SynthRcode(query, dns.RcodeSuccess)
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	resp.Ns = []dns.RR{synthSOA(req.Question[0].Name)}
	b, err := resp.Pack()
	if err != nil {
		return SynthRcode(query, dns.RcodeSuccess)
	}
	return b
}

// synthSOA invents an authority record for the closest enclosing zone we can
// name without asking anybody. We do not know the real zone cut and cannot
// learn it without a query we are deliberately not making, so the parent label
// is used when there is one. The record exists to give the stub a negative TTL,
// not to be authoritative about anything.
func synthSOA(qname string) *dns.SOA {
	zone := dns.Fqdn(qname)
	if labels := dns.SplitDomainName(zone); len(labels) > 1 {
		zone = dns.Fqdn(strings.Join(labels[1:], "."))
	}
	ttl := uint32(soaTTL / time.Second)
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      "localhost.",
		Mbox:    "dpb.invalid.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  ttl,
	}
}
