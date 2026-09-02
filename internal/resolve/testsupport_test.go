package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The fakes in this file stand in for internal/testcensor.DNSCensor(), which
// M3 builds in parallel with this milestone. They implement the same measured
// behaviour: per-QNAME UDP drop on port 53, genuine answers on an alternate
// port, sinkhole answers from the ISP resolver, and a TCP/53 endpoint that is
// a test failure to reach at all.

// ttSinkhole is the address the ISP resolver hands back for every blocked name
// (MEASUREMENTS.md §2: `system resolver (192.168.0.1) discord.com ->
// 195.175.254.2`, the BTK block page).
var ttSinkhole = netip.MustParseAddr("195.175.254.2")

// blockedNames are the names measured blocked on Türk Telekom (§1).
var blockedNames = map[string]bool{
	"discord.com.":         true,
	"discord.gg.":          true,
	"cdn.discordapp.com.":  true,
	"gateway.discord.gg.":  true,
	"updates.discord.com.": true,
}

// genuineAnswer is the real Cloudflare answer §2 records for discord.com on the
// alternate port.
var genuineAnswer = []netip.Addr{
	netip.MustParseAddr("162.159.128.233"),
	netip.MustParseAddr("162.159.136.232"),
}

// buildAnswer packs a NOERROR response carrying addrs with the given TTL.
//
// It reports failures with Errorf rather than Fatalf because the fakes call it
// from resolver goroutines, where FailNow is not allowed.
func buildAnswer(t *testing.T, query []byte, ttl uint32, addrs ...netip.Addr) []byte {
	t.Helper()
	var req dns.Msg
	if err := req.Unpack(query); err != nil {
		t.Errorf("unpack query: %v", err)
		return nil
	}
	var resp dns.Msg
	resp.SetReply(&req)
	resp.RecursionAvailable = true
	q := req.Question[0]
	for _, a := range addrs {
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: ttl}
		if a.Is4() {
			hdr.Rrtype = dns.TypeA
			resp.Answer = append(resp.Answer, &dns.A{Hdr: hdr, A: net.IP(a.AsSlice())})
		} else {
			hdr.Rrtype = dns.TypeAAAA
			resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IP(a.AsSlice())})
		}
	}
	b, err := resp.Pack()
	if err != nil {
		t.Errorf("pack answer: %v", err)
		return nil
	}
	return b
}

// answerFor is the family-aware genuine answer used by the fake resolvers.
func answerFor(t *testing.T, query []byte, addrs ...netip.Addr) []byte {
	t.Helper()
	q, err := FirstQuestion(query)
	if err != nil {
		t.Errorf("FirstQuestion: %v", err)
		return nil
	}
	var keep []netip.Addr
	for _, a := range addrs {
		if (q.Type == dns.TypeA && a.Is4()) || (q.Type == dns.TypeAAAA && a.Is6()) {
			keep = append(keep, a)
		}
	}
	return buildAnswer(t, query, 300, keep...)
}

// udpEcho runs a UDP DNS endpoint driven by handler. A nil reply means the
// query is dropped, which is what MEASUREMENTS.md §2 measures port 53 doing for
// a blocked name.
func udpEcho(t *testing.T, handler func(query []byte) []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	var wg sync.WaitGroup
	// Close first, then wait: the reverse order deadlocks on the blocking read.
	t.Cleanup(func() { _ = pc.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := make([]byte, n)
			copy(q, buf[:n])
			if resp := handler(q); resp != nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

// tcpTrap listens on TCP and fails the test if anything ever connects.
//
// MEASUREMENTS.md §2 measures TCP DNS as connection-reset at every port tested,
// so a truncation fallback to TCP is not merely slow here, it is broken for
// exactly the names that matter. This trap is how "structurally impossible"
// stops being a claim in a comment.
func tcpTrap(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = l.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Errorf("something dialled the TCP DNS trap at %s; DNS over TCP must be structurally impossible (MEASUREMENTS.md §2)", l.Addr())
			_ = c.Close()
		}
	}()
	return l.Addr().String()
}

// censorPort53 answers benign names and silently drops blocked ones.
func censorPort53(t *testing.T) string {
	t.Helper()
	return udpEcho(t, func(q []byte) []byte {
		fq, err := FirstQuestion(q)
		if err != nil {
			return nil
		}
		if blockedNames[fq.Name] {
			return nil // per-QNAME drop, not an RST and not an NXDOMAIN
		}
		return answerFor(t, q, netip.MustParseAddr("142.250.187.174"), netip.MustParseAddr("2a00:1450:4001:80f::200e"))
	})
}

// censorAltPort answers everything, which is what §2 measured on :1253 and :9953.
func censorAltPort(t *testing.T) string {
	t.Helper()
	return udpEcho(t, func(q []byte) []byte {
		fq, err := FirstQuestion(q)
		if err != nil {
			return nil
		}
		if blockedNames[fq.Name] {
			return answerFor(t, q, genuineAnswer...)
		}
		return answerFor(t, q, netip.MustParseAddr("142.250.187.174"))
	})
}

// censorSystemResolver answers blocked names with the BTK sinkhole and
// everything else genuinely — the exact split §2 measured against 192.168.0.1.
func censorSystemResolver(t *testing.T) string {
	t.Helper()
	return udpEcho(t, func(q []byte) []byte {
		fq, err := FirstQuestion(q)
		if err != nil {
			return nil
		}
		if blockedNames[fq.Name] && fq.Type == dns.TypeA {
			return buildAnswer(t, q, 60, ttSinkhole)
		}
		return answerFor(t, q, netip.MustParseAddr("172.217.18.174"))
	})
}

// fakeResolver is a programmable chain rung.
type fakeResolver struct {
	label     string
	transport string
	delay     time.Duration
	err       error
	// reply builds the answer; nil means "return err".
	reply func(t *testing.T, query []byte) []byte

	mu    sync.Mutex
	calls int
	t     *testing.T
}

func (f *fakeResolver) Label() string     { return f.label }
func (f *fakeResolver) Transport() string { return f.transport }

func (f *fakeResolver) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeResolver) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.reply == nil {
		if f.err != nil {
			return nil, f.err
		}
		return nil, errors.New("fake resolver has no reply")
	}
	return f.reply(f.t, query), nil
}

// dropping is a rung that behaves like port 53 for a blocked name: silence
// until the per-try deadline expires.
func dropping(t *testing.T, label string) *fakeResolver {
	return &fakeResolver{label: label, transport: "udp", t: t, delay: time.Hour}
}

// answering is a rung that returns addrs.
func answering(t *testing.T, label, transport string, addrs ...netip.Addr) *fakeResolver {
	return &fakeResolver{
		label: label, transport: transport, t: t,
		reply: func(t *testing.T, q []byte) []byte { return answerFor(t, q, addrs...) },
	}
}

// sinkholing is a rung that answers with the BTK block page.
func sinkholing(t *testing.T, label string) *fakeResolver {
	return &fakeResolver{
		label: label, transport: "udp", t: t,
		reply: func(t *testing.T, q []byte) []byte { return buildAnswer(t, q, 60, ttSinkhole) },
	}
}

func mustQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	q, err := NewQuery(name, qtype)
	if err != nil {
		t.Fatalf("NewQuery(%s): %v", name, err)
	}
	return q
}

func addrStrings(addrs []netip.Addr) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ",")
}
