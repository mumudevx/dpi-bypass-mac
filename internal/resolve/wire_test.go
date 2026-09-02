package resolve

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestMsgIDRoundTrip(t *testing.T) {
	q := mustQuery(t, "discord.com", dns.TypeA)
	if err := SetMsgID(q, 0xbeef); err != nil {
		t.Fatalf("SetMsgID: %v", err)
	}
	got, err := MsgID(q)
	if err != nil {
		t.Fatalf("MsgID: %v", err)
	}
	if got != 0xbeef {
		t.Fatalf("MsgID = %#x, want 0xbeef", got)
	}
	if _, err := MsgID([]byte{1, 2, 3}); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("MsgID(short) = %v, want ErrShortMessage", err)
	}
	if err := SetMsgID([]byte{1, 2, 3}, 1); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("SetMsgID(short) = %v, want ErrShortMessage", err)
	}
}

func TestFirstQuestion(t *testing.T) {
	q := mustQuery(t, "DisCord.Com", dns.TypeAAAA)
	fq, err := FirstQuestion(q)
	if err != nil {
		t.Fatalf("FirstQuestion: %v", err)
	}
	if fq.Name != "discord.com." || fq.Type != dns.TypeAAAA || fq.Class != dns.ClassINET {
		t.Fatalf("FirstQuestion = %+v", fq)
	}
	if got := fq.String(); got != "discord.com. AAAA" {
		t.Fatalf("Question.String = %q", got)
	}
	unknown := Question{Name: "x.", Type: 12345}
	if got := unknown.String(); got != "x. TYPE12345" {
		t.Fatalf("unknown type String = %q", got)
	}

	if _, err := FirstQuestion([]byte{0, 1}); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("short: %v", err)
	}
	noQ := make([]byte, headerLen)
	if _, err := FirstQuestion(noQ); !errors.Is(err, ErrNoQuestion) {
		t.Fatalf("qdcount=0: %v", err)
	}
	// A question that claims a name but stops mid-way must not be read past.
	cut := q[:len(q)-3]
	if _, err := FirstQuestion(cut); !errors.Is(err, ErrMalformed) {
		t.Fatalf("truncated question: %v", err)
	}
}

func TestSameQuestion(t *testing.T) {
	a := mustQuery(t, "discord.com", dns.TypeA)
	b := mustQuery(t, "discord.com", dns.TypeA)
	c := mustQuery(t, "discord.gg", dns.TypeA)
	d := mustQuery(t, "discord.com", dns.TypeAAAA)
	if !SameQuestion(a, b) {
		t.Fatal("same name and type must compare equal")
	}
	if SameQuestion(a, c) {
		t.Fatal("different names must not compare equal")
	}
	if SameQuestion(a, d) {
		t.Fatal("different types must not compare equal")
	}
	if SameQuestion(a, []byte{1}) || SameQuestion([]byte{1}, a) {
		t.Fatal("an unparseable message never matches")
	}
}

func TestHeaderBitsAndAddrs(t *testing.T) {
	q := mustQuery(t, "discord.com", dns.TypeA)
	if IsResponse(q) {
		t.Fatal("a query must not read as a response")
	}
	if Truncated(q) {
		t.Fatal("a fresh query is not truncated")
	}
	if Rcode([]byte{1}) != -1 {
		t.Fatal("Rcode of a short message must be -1")
	}
	if Truncated([]byte{1}) || IsResponse([]byte{1}) {
		t.Fatal("short messages have no bits")
	}

	ans := buildAnswer(t, q, 120, genuineAnswer...)
	if !IsResponse(ans) {
		t.Fatal("built answer must have QR set")
	}
	if Rcode(ans) != dns.RcodeSuccess {
		t.Fatalf("rcode = %d", Rcode(ans))
	}
	got := AnswerAddrs(ans)
	if addrStrings(got) != addrStrings(genuineAnswer) {
		t.Fatalf("AnswerAddrs = %s, want %s", addrStrings(got), addrStrings(genuineAnswer))
	}
	if d := MinTTL(ans); d != 120*time.Second {
		t.Fatalf("MinTTL = %s", d)
	}
	if AnswerAddrs([]byte{1, 2, 3}) != nil {
		t.Fatal("garbage yields no addresses")
	}
	if MinTTL([]byte{1, 2, 3}) != 0 {
		t.Fatal("garbage yields no TTL")
	}
	if MinTTL(q) != 0 {
		t.Fatal("an empty answer section yields no TTL")
	}
}

func TestNewQueryRejectsEmptyName(t *testing.T) {
	if _, err := NewQuery("   ", dns.TypeA); err == nil {
		t.Fatal("an empty name must not produce a query")
	}
}

// TestSynthRcodeCarriesCallerIdentity pins the property the local server and the
// chain both depend on: a synthesised failure is still an answer to the caller's
// own question, so a stub accepts it immediately instead of timing out and
// retrying over TCP, which MEASUREMENTS.md §2 measures as reset at every port.
func TestSynthRcodeCarriesCallerIdentity(t *testing.T) {
	q := mustQuery(t, "discord.com", dns.TypeA)
	if err := SetMsgID(q, 0x1234); err != nil {
		t.Fatal(err)
	}
	resp := SynthRcode(q, dns.RcodeServerFailure)

	id, err := MsgID(resp)
	if err != nil {
		t.Fatalf("MsgID: %v", err)
	}
	if id != 0x1234 {
		t.Fatalf("id = %#x, want 0x1234", id)
	}
	if !IsResponse(resp) {
		t.Fatal("QR must be set")
	}
	if Truncated(resp) {
		t.Fatal("TC must be clear")
	}
	if Rcode(resp) != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d", Rcode(resp))
	}
	if resp[3]&0x80 == 0 {
		t.Fatal("RA must be set")
	}
	if !SameQuestion(q, resp) {
		t.Fatal("the caller's question must be echoed verbatim")
	}
	for _, off := range []int{6, 8, 10} {
		if n := binary.BigEndian.Uint16(resp[off : off+2]); n != 0 {
			t.Fatalf("count at offset %d = %d, want 0", off, n)
		}
	}
	var parsed dns.Msg
	if err := parsed.Unpack(resp); err != nil {
		t.Fatalf("a synthesised reply must be well formed: %v", err)
	}
}

func TestSynthRcodeDegradesSafely(t *testing.T) {
	if SynthRcode([]byte{0, 1, 2}, dns.RcodeServerFailure) != nil {
		t.Fatal("a sub-header buffer cannot be replied to")
	}
	// A header claiming one question with nothing behind it: reply with the
	// header alone and no question rather than reflecting unparsed bytes.
	broken := make([]byte, headerLen)
	binary.BigEndian.PutUint16(broken[4:6], 1)
	resp := SynthRcode(broken, dns.RcodeServerFailure)
	if len(resp) != headerLen {
		t.Fatalf("len = %d, want %d", len(resp), headerLen)
	}
	if n := binary.BigEndian.Uint16(resp[4:6]); n != 0 {
		t.Fatalf("qdcount = %d, want 0", n)
	}
}

// TestSynthEmptyIsNeverNXDOMAIN encodes the AAAA-suppression contract: NOERROR
// with an empty answer says "no record of this type", while NXDOMAIN would be
// cached by every stub as "this name does not exist" and would outlive the
// policy decision that produced it.
func TestSynthEmptyIsNeverNXDOMAIN(t *testing.T) {
	q := mustQuery(t, "discord.com", dns.TypeAAAA)
	if err := SetMsgID(q, 0x4242); err != nil {
		t.Fatal(err)
	}
	resp := SynthEmpty(q)

	var m dns.Msg
	if err := m.Unpack(resp); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR (never NXDOMAIN)", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Fatalf("answer section must be empty, got %d records", len(m.Answer))
	}
	if len(m.Ns) != 1 {
		t.Fatalf("authority section must carry one SOA, got %d", len(m.Ns))
	}
	soa, ok := m.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("authority record is %T, want *dns.SOA", m.Ns[0])
	}
	if soa.Hdr.Name != "com." {
		t.Fatalf("SOA owner = %q, want the parent zone", soa.Hdr.Name)
	}
	if m.Id != 0x4242 {
		t.Fatalf("id = %#x", m.Id)
	}
	if !SameQuestion(q, resp) {
		t.Fatal("question must be echoed")
	}
}

func TestSynthEmptyFallsBackOnGarbage(t *testing.T) {
	broken := make([]byte, headerLen)
	binary.BigEndian.PutUint16(broken[4:6], 1)
	resp := SynthEmpty(broken)
	if !IsResponse(resp) || Rcode(resp) != dns.RcodeSuccess {
		t.Fatalf("fallback must still be a NOERROR response, got %v", resp)
	}
	// A single-label name has no parent, so the SOA owner is the name itself.
	q := mustQuery(t, "localhost", dns.TypeAAAA)
	var m dns.Msg
	if err := m.Unpack(SynthEmpty(q)); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if m.Ns[0].Header().Name != "localhost." {
		t.Fatalf("SOA owner = %q", m.Ns[0].Header().Name)
	}
}

func TestQuestionEndReportsNoQuestion(t *testing.T) {
	hdr := make([]byte, headerLen)
	end, err := questionEnd(hdr)
	if !errors.Is(err, ErrNoQuestion) || end != headerLen {
		t.Fatalf("questionEnd = %d, %v", end, err)
	}
	if _, err := questionEnd([]byte{1}); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("questionEnd(short) = %v", err)
	}
}

func TestAnswerAddrsIgnoresOtherTypes(t *testing.T) {
	q := mustQuery(t, "discord.com", dns.TypeA)
	var req dns.Msg
	if err := req.Unpack(q); err != nil {
		t.Fatal(err)
	}
	var resp dns.Msg
	resp.SetReply(&req)
	resp.Answer = []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "discord.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30}, Target: "edge.discord.com."},
		&dns.A{Hdr: dns.RR_Header{Name: "edge.discord.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: []byte{162, 159, 128, 233}},
	}
	b, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got := AnswerAddrs(b)
	if len(got) != 1 || got[0] != netip.MustParseAddr("162.159.128.233") {
		t.Fatalf("AnswerAddrs = %v", got)
	}
	if MinTTL(b) != 30*time.Second {
		t.Fatalf("MinTTL = %s", MinTTL(b))
	}
}

func TestUnpackWrapsMalformed(t *testing.T) {
	if _, err := unpack(bytes.Repeat([]byte{0xff}, 32)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("unpack(garbage) = %v, want ErrMalformed", err)
	}
}
