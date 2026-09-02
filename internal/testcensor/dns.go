package testcensor

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// TTSinkhole is the address the Türk Telekom customer resolver returns for every
// blocked name: the BTK block page (MEASUREMENTS.md §2, `system resolver
// (192.168.0.1) discord.com -> 195.175.254.2`). It is a reliable positive
// censorship signal, which is why resolve treats it as a sentinel rather than as
// an answer.
var TTSinkhole = netip.MustParseAddr("195.175.254.2")

// DNSRole is where in the network a simulated resolver sits. The three roles
// exist because MEASUREMENTS.md §2 found three different behaviours from the
// same set of public resolvers depending only on how they were reached.
type DNSRole uint8

const (
	// RolePublic53 is a public resolver reached on UDP port 53. Queries for
	// blocked names are dropped: `dig @8.8.8.8 discord.com` timed out on
	// 8.8.8.8, 1.1.1.1, 9.9.9.9 and 77.88.8.8 alike, while google.com answered.
	RolePublic53 DNSRole = iota
	// RoleAltPort is the same resolver on a non-53 UDP port, which answers
	// truthfully: `dig -p 1253 @77.88.8.8 discord.com` returned the genuine
	// Cloudflare addresses. This is the working plaintext fallback.
	RoleAltPort
	// RoleISP is the customer-premises resolver, which answers blocked names
	// with the sinkhole and everything else genuinely — the most dangerous shape,
	// because it looks like success.
	RoleISP
)

var dnsRoleNames = [...]string{"public53", "altport", "isp"}

func (r DNSRole) String() string {
	if int(r) >= len(dnsRoleNames) {
		return "invalid"
	}
	return dnsRoleNames[r]
}

// DNSModel is the DNS-side hypothesis.
type DNSModel struct {
	Name string
	Doc  string
	// Blocked QNAMEs, matched label-anchored and case-insensitively.
	Blocked []string
	// Sinkhole is what RoleISP answers for a blocked name.
	Sinkhole netip.Addr
	// Answers is the genuine data, keyed by name without a trailing dot.
	Answers map[string][]netip.Addr
	// TTL on synthesised records.
	TTL uint32
}

// DNSCensor is the measured Türk Telekom DNS behaviour (MEASUREMENTS.md §2).
//
// The three facts that shape the resolver design are all encoded here:
// per-QNAME drop rather than a transparent port-53 redirect, so an alternate
// port is a working fallback; the ISP resolver's sinkhole answer, which is a
// positive censorship signal; and DNS over TCP being reset at EVERY port tested,
// so a truncation fallback to TCP breaks for exactly the names that matter.
// NewDNSServer refuses to answer over TCP and counts every attempt, so a test
// can assert the fallback is structurally impossible rather than merely unused.
func DNSCensor() DNSModel {
	return DNSModel{
		Name:     "tt2026-dns",
		Doc:      "Türk Telekom AS9121, 2026-09-02; MEASUREMENTS.md §2; confidence high",
		Blocked:  append([]string(nil), BlockedTT...),
		Sinkhole: TTSinkhole,
		TTL:      60,
		Answers: map[string][]netip.Addr{
			// §2: the genuine Cloudflare answers seen on port 1253 and 9953.
			"discord.com":        {netip.MustParseAddr("162.159.128.233"), netip.MustParseAddr("162.159.136.232")},
			"discord.gg":         {netip.MustParseAddr("162.159.128.233")},
			"cdn.discordapp.com": {netip.MustParseAddr("162.159.135.232")},
			// §1: the benign control, same address family, same edge.
			"cloudflare.com": {netip.MustParseAddr("162.159.128.233")},
			// §2: an unblocked name answers everywhere, including on :53.
			"google.com": {netip.MustParseAddr("172.217.18.174")},
		},
	}
}

func (m DNSModel) blocks(qname string) bool {
	h := strings.ToLower(strings.TrimSuffix(qname, "."))
	for _, b := range m.Blocked {
		b = strings.ToLower(strings.TrimSuffix(b, "."))
		if b != "" && (h == b || strings.HasSuffix(h, "."+b)) {
			return true
		}
	}
	return false
}

func (m DNSModel) answers(qname string) []netip.Addr {
	return m.Answers[strings.ToLower(strings.TrimSuffix(qname, "."))]
}

// ErrDNSNoTCP is returned by TCPAttempts' companion assertion helper. DNS over
// TCP is never a legitimate path in this tool.
var ErrDNSNoTCP = errors.New("testcensor: DNS over TCP was attempted")

// DNSServer is one simulated resolver: a UDP endpoint that behaves according to
// its role, and a TCP endpoint that resets every connection immediately.
type DNSServer struct {
	model DNSModel
	role  DNSRole

	pc net.PacketConn
	ln net.Listener
	wg sync.WaitGroup

	mu       sync.Mutex
	queries  []string
	tcpTries int
	closed   bool
}

// NewDNSServer starts a resolver on loopback with ephemeral UDP and TCP ports.
//
// The port numbers are ephemeral rather than 53 because binding 53 needs root
// and this must run in `go test`. The role, not the port number, carries the
// measured behaviour: what §2 established is that the same resolver censors when
// reached on its well-known port and does not when reached on another, and that
// distinction is what a test needs to express.
func NewDNSServer(m DNSModel, role DNSRole) (*DNSServer, error) {
	if m.TTL == 0 {
		m.TTL = 60
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("testcensor: dns udp listen: %w", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("testcensor: dns tcp listen: %w", err)
	}
	s := &DNSServer{model: m, role: role, pc: pc, ln: ln}
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	return s, nil
}

// UDPAddr is the resolver's UDP host:port.
func (s *DNSServer) UDPAddr() string { return s.pc.LocalAddr().String() }

// TCPAddr is the resolver's TCP host:port. Connecting to it is always a
// connection reset, at any port — measured on 8.8.8.8:53 and 77.88.8.8:1253
// alike (MEASUREMENTS.md §2).
func (s *DNSServer) TCPAddr() string { return s.ln.Addr().String() }

// Role reports which behaviour this server implements.
func (s *DNSServer) Role() DNSRole { return s.role }

// Queries returns the QNAMEs seen over UDP, in order.
func (s *DNSServer) Queries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.queries...)
}

// TCPAttempts is the number of TCP connections accepted. A resolver test asserts
// it stays zero: resolve.ErrTCPForbidden exists so this number is unreachable.
func (s *DNSServer) TCPAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tcpTries
}

// Close stops both listeners.
func (s *DNSServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	err := errors.Join(s.pc.Close(), s.ln.Close())
	s.wg.Wait()
	return err
}

func (s *DNSServer) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 1500)
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := s.Answer(buf[:n])
		if resp == nil {
			continue // dropped: the client must experience a timeout
		}
		if _, err := s.pc.WriteTo(resp, from); err != nil {
			return
		}
	}
}

// Answer applies the model to one wire-format query. A nil result means the
// query is dropped, which is the measured behaviour for a blocked QNAME on
// port 53 and is deliberately distinct from any rcode: a client that treats a
// timeout as NXDOMAIN would cache the censorship.
func (s *DNSServer) Answer(query []byte) []byte {
	var req dns.Msg
	if err := req.Unpack(query); err != nil || len(req.Question) == 0 {
		return nil
	}
	q := req.Question[0]
	s.mu.Lock()
	s.queries = append(s.queries, q.Name)
	s.mu.Unlock()

	blocked := s.model.blocks(q.Name)
	var addrs []netip.Addr
	switch {
	case blocked && s.role == RolePublic53:
		return nil
	case blocked && s.role == RoleISP:
		if s.model.Sinkhole.IsValid() {
			addrs = []netip.Addr{s.model.Sinkhole}
		}
	default:
		addrs = s.model.answers(q.Name)
	}

	var resp dns.Msg
	resp.SetReply(&req)
	resp.RecursionAvailable = true
	if len(addrs) == 0 {
		// A name the model knows nothing about: NOERROR with no answer, not
		// NXDOMAIN, so a test cannot mistake "unknown to the fixture" for a
		// negative answer from the network.
		out, err := resp.Pack()
		if err != nil {
			return nil
		}
		return out
	}
	for _, a := range addrs {
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: s.model.TTL}
		switch {
		case a.Is4() && q.Qtype == dns.TypeA:
			hdr.Rrtype = dns.TypeA
			resp.Answer = append(resp.Answer, &dns.A{Hdr: hdr, A: net.IP(a.AsSlice())})
		case !a.Is4() && q.Qtype == dns.TypeAAAA:
			hdr.Rrtype = dns.TypeAAAA
			resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IP(a.AsSlice())})
		}
	}
	out, err := resp.Pack()
	if err != nil {
		return nil
	}
	return out
}

func (s *DNSServer) serveTCP() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.tcpTries++
		s.mu.Unlock()
		// A genuine RST, not a clean close: `dig +tcp` reported "connection
		// reset" on every port tested, and a clean EOF would let a truncation
		// fallback appear to half-work.
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = c.Close()
	}
}
