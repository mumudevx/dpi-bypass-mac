package testcensor

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func newDNS(t *testing.T, role DNSRole) *DNSServer {
	t.Helper()
	s, err := NewDNSServer(DNSCensor(), role)
	if err != nil {
		t.Fatalf("NewDNSServer(%s): %v", role, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func query(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	var m dns.Msg
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return b
}

// ask sends one UDP query and returns the answer addresses, or an error. A
// timeout is the signal for a dropped QNAME.
func ask(t *testing.T, s *DNSServer, name string, qtype uint16) ([]netip.Addr, error) {
	t.Helper()
	c, err := net.Dial("udp", s.UDPAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write(query(t, name, qtype)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	var resp dns.Msg
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	var out []netip.Addr
	for _, rr := range resp.Answer {
		switch a := rr.(type) {
		case *dns.A:
			out = append(out, netip.MustParseAddr(a.A.String()))
		case *dns.AAAA:
			out = append(out, netip.MustParseAddr(a.AAAA.String()))
		}
	}
	return out, nil
}

// TestDNSPublic53DropsBlockedQNAME is MEASUREMENTS.md §2: `dig @8.8.8.8
// discord.com` times out while google.com answers, on all four public resolvers
// tested. It is a per-QNAME drop, not a transparent port-53 redirect, and the
// distinction is what makes an alternate port a working fallback.
func TestDNSPublic53DropsBlockedQNAME(t *testing.T) {
	s := newDNS(t, RolePublic53)

	if _, err := ask(t, s, "discord.com", dns.TypeA); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("blocked QNAME on :53 = %v, want a timeout", err)
	}
	got, err := ask(t, s, "google.com", dns.TypeA)
	if err != nil {
		t.Fatalf("unblocked QNAME on :53: %v", err)
	}
	if len(got) != 1 || got[0].String() != "172.217.18.174" {
		t.Fatalf("google.com = %v, want the genuine §2 answer", got)
	}
	if q := s.Queries(); len(q) != 2 {
		t.Errorf("queries seen = %v, want both to have reached the server", q)
	}
}

// TestDNSAltPortAnswersTruthfully is the working fallback §2 found:
// `dig -p 1253 @77.88.8.8 discord.com` returned the genuine Cloudflare
// addresses. The port, not the resolver, is what censorship keys on.
func TestDNSAltPortAnswersTruthfully(t *testing.T) {
	s := newDNS(t, RoleAltPort)
	got, err := ask(t, s, "discord.com", dns.TypeA)
	if err != nil {
		t.Fatalf("alt-port query: %v", err)
	}
	if len(got) != 2 || got[0].String() != "162.159.128.233" {
		t.Fatalf("discord.com on the alt port = %v, want the genuine §2 answer", got)
	}
}

// TestDNSISPReturnsSinkhole is the most dangerous shape in §2: the customer
// resolver answers, so nothing looks wrong, but the address is the BTK block
// page. A resolver that trusts it sends every connection to 195.175.254.2 and no
// desync strategy can help — the failure §5.4 spent a whole matrix run on.
func TestDNSISPReturnsSinkhole(t *testing.T) {
	s := newDNS(t, RoleISP)

	got, err := ask(t, s, "discord.com", dns.TypeA)
	if err != nil {
		t.Fatalf("isp query: %v", err)
	}
	if len(got) != 1 || got[0] != TTSinkhole {
		t.Fatalf("discord.com from the ISP resolver = %v, want %v", got, TTSinkhole)
	}
	// The same resolver answers everything else genuinely, which is exactly why
	// a naive liveness check does not detect it.
	genuine, err := ask(t, s, "google.com", dns.TypeA)
	if err != nil {
		t.Fatalf("isp query for an unblocked name: %v", err)
	}
	if len(genuine) != 1 || genuine[0].String() != "172.217.18.174" {
		t.Fatalf("google.com from the ISP resolver = %v, want the genuine answer", genuine)
	}
}

// TestDNSTCPIsAlwaysReset is MEASUREMENTS.md §2's hardest constraint: TCP/53 is
// RST-filtered at EVERY port tested, so a truncation fallback to TCP breaks for
// exactly the names that matter. resolve.ErrTCPForbidden exists so this counter
// stays at zero in every other test.
func TestDNSTCPIsAlwaysReset(t *testing.T) {
	s := newDNS(t, RoleAltPort)

	c, err := net.Dial("tcp", s.TCPAddr())
	if err != nil {
		// A refused connection is an acceptable shape too; either way no DNS
		// answer is ever obtainable over TCP.
		return
	}
	defer c.Close()
	_, _ = c.Write([]byte{0x00, 0x02, 0xff, 0xff})
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 16)); err == nil {
		t.Fatal("TCP/53 returned data; it must always fail")
	}
	if s.TCPAttempts() != 1 {
		t.Fatalf("TCPAttempts = %d, want 1", s.TCPAttempts())
	}
}

// TestDNSUnknownNameIsNoerrorEmpty keeps the fixture honest: a name the model
// knows nothing about must not look like a negative answer from the network.
func TestDNSUnknownNameIsNoerrorEmpty(t *testing.T) {
	s := newDNS(t, RolePublic53)
	got, err := ask(t, s, "unknown.example", dns.TypeA)
	if err != nil {
		t.Fatalf("unknown name: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("unknown name answered %v", got)
	}
}

// TestDNSQtypeIsHonoured pins that an A query never gets an AAAA back. The AAAA
// policy in resolve depends on the two being answered independently.
func TestDNSQtypeIsHonoured(t *testing.T) {
	m := DNSCensor()
	m.Answers["dual.example"] = []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("2001:db8::1"),
	}
	s, err := NewDNSServer(m, RoleAltPort)
	if err != nil {
		t.Fatalf("NewDNSServer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	v4, err := ask(t, s, "dual.example", dns.TypeA)
	if err != nil || len(v4) != 1 || !v4[0].Is4() {
		t.Fatalf("A query = %v, %v", v4, err)
	}
	v6, err := ask(t, s, "dual.example", dns.TypeAAAA)
	if err != nil || len(v6) != 1 || v6[0].Is4() {
		t.Fatalf("AAAA query = %v, %v", v6, err)
	}
}

// TestDNSMalformedQueryIsDropped keeps the server from answering garbage, which
// would let a fuzzed resolver test pass on nonsense.
func TestDNSMalformedQueryIsDropped(t *testing.T) {
	s := newDNS(t, RoleAltPort)
	if got := s.Answer([]byte{0x00}); got != nil {
		t.Fatalf("malformed query answered with % x", got)
	}
}

// TestDNSBlocklistIsLabelAnchored mirrors the TLS-side matcher: a suffix that is
// not a label boundary is a different name.
func TestDNSBlocklistIsLabelAnchored(t *testing.T) {
	m := DNSCensor()
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"discord.com.", true},
		{"gateway.discord.gg.", true},
		{"notdiscord.com.", false},
		{"discord.com.evil.tld.", false},
	} {
		if got := m.blocks(tc.name); got != tc.want {
			t.Errorf("blocks(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestDNSCloseIsIdempotent covers the cleanup path a test's t.Cleanup relies on.
func TestDNSCloseIsIdempotent(t *testing.T) {
	s, err := NewDNSServer(DNSCensor(), RoleISP)
	if err != nil {
		t.Fatalf("NewDNSServer: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if s.Role() != RoleISP {
		t.Errorf("Role = %v", s.Role())
	}
}
