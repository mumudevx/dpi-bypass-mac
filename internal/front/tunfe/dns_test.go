package tunfe

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/mumudevx/dpb/internal/policy"
	"github.com/mumudevx/dpb/internal/resolve"
)

// resolverIP is where the machine thinks its DNS lives. In TUN mode that
// address is captured by a host route, so the query arrives here instead.
var resolverIP = netip.MustParseAddr("192.0.2.53")

// TestDNSOverUDPIsAnsweredInProcess: relaying UDP/53 would hand the ISP's
// resolver exactly the queries DoH exists to hide, so the whole DNS-poisoning
// defence would be lost the moment the user ran with sudo. The query must be
// answered from our own chain and no datagram may leave.
func TestDNSOverUDPIsAnsweredInProcess(t *testing.T) {
	reverse := policy.NewReverseMap(16)
	srv, _ := newTestResolver(t, reverse, map[string]netip.Addr{"discord.com.": originIP})
	udp := &countingUDPDialer{}
	l := newLab(t, labOpts{dns: srv, udp: udp, reverse: reverse})

	client, err := l.dialUDP(netip.AddrPortFrom(resolverIP, 53))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()

	if _, err := client.Write(dnsQuery(t, "discord.com.")); err != nil {
		t.Fatalf("write query: %v", err)
	}
	got := readDNSDatagram(t, client)
	if a := firstA(t, got); a != originIP {
		t.Fatalf("answer = %v, want %v from the in-process chain", a, originIP)
	}

	if n := udp.count(); n != 0 {
		t.Fatalf("%d datagram(s) were relayed upstream; DNS must never leave the process", n)
	}
	if s := l.server.Stats(); s.DNSFlows != 1 {
		t.Fatalf("DNSFlows = %d, want 1", s.DNSFlows)
	}
	// Every answer feeds the reverse map before the reply goes out, which is
	// what names the TCP flow that follows a millisecond later.
	if name, ok := reverse.Lookup(originIP); !ok || name != "discord.com" {
		t.Fatalf("reverse map has %q (%v) for %v, want discord.com", name, ok, originIP)
	}
}

// TestDNSOverTCPIsAnsweredInProcess: an application that gets TC=1 retries over
// TCP. MEASUREMENTS.md §2 measures upstream TCP/53 as connection-reset at every
// port on this line, so that retry only works because it never leaves the
// machine.
func TestDNSOverTCPIsAnsweredInProcess(t *testing.T) {
	reverse := policy.NewReverseMap(16)
	srv, _ := newTestResolver(t, reverse, map[string]netip.Addr{"discord.com.": originIP})
	l := newLab(t, labOpts{dns: srv, reverse: reverse})

	client, err := l.dial(netip.AddrPortFrom(resolverIP, 53))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	q := dnsQuery(t, "discord.com.")
	framed := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(framed, uint16(len(q)))
	copy(framed[2:], q)
	if _, err := client.Write(framed); err != nil {
		t.Fatalf("write query: %v", err)
	}

	hdr := readWithin(t, client, 2, 5*time.Second)
	if len(hdr) != 2 {
		t.Fatalf("read %d length bytes, want 2", len(hdr))
	}
	body := readWithin(t, client, int(binary.BigEndian.Uint16(hdr)), 5*time.Second)
	if a := firstA(t, body); a != originIP {
		t.Fatalf("answer = %v, want %v", a, originIP)
	}
	if n := len(l.up.targets()); n != 0 {
		t.Fatalf("%d upstream TCP dial(s); TCP/53 must be answered in process", n)
	}
	if s := l.server.Stats(); s.DNSFlows != 1 {
		t.Fatalf("DNSFlows = %d, want 1", s.DNSFlows)
	}
}

// TestDNSWithNoResolverIsDroppedNotRelayed: with nothing wired to answer, the
// query is dropped. That is a visible failure — the stub retries and times out
// — where relaying it would be an invisible one that reaches the poisoned
// resolver.
func TestDNSWithNoResolverIsDroppedNotRelayed(t *testing.T) {
	udp := &countingUDPDialer{}
	l := newLab(t, labOpts{udp: udp})

	client, err := l.dialUDP(netip.AddrPortFrom(resolverIP, 53))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(dnsQuery(t, "discord.com.")); err != nil {
		t.Fatalf("write query: %v", err)
	}

	if err := client.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, maxDatagram)
	if n, err := client.Read(buf); err == nil {
		t.Fatalf("got a %d-byte reply with no resolver wired", n)
	}
	if n := udp.count(); n != 0 {
		t.Fatalf("%d datagram(s) relayed; a DNS query must never be relayed", n)
	}
}

// TestOneConnListenerClosesWithItsConnection: the adapter that lets
// resolve.Server serve a single forwarded connection must end its accept loop
// when that connection ends, or every DNS-over-TCP session would leave a
// goroutine parked until the process exits.
func TestOneConnListenerClosesWithItsConnection(t *testing.T) {
	t.Parallel()
	a, b := netPipe(t)
	ln := newOneConnListener(a)

	c, err := ln.Accept()
	if err != nil {
		t.Fatalf("first Accept: %v", err)
	}
	if ln.Addr() == nil {
		t.Fatal("the listener reports no address")
	}
	_ = b.Close()
	_ = c.Close()

	done := make(chan error, 1)
	go func() {
		_, aerr := ln.Accept()
		done <- aerr
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept returned a second connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept stayed blocked after its one connection closed")
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// newTestResolver builds a real resolve.Chain over a scripted resolver, so the
// DNS tests exercise the shipped server, cache and reverse-map plumbing rather
// than a stand-in for them.
func newTestResolver(t *testing.T, reverse policy.ReverseMap, answers map[string]netip.Addr) (*resolve.Server, *scriptedResolver) {
	t.Helper()
	r := &scriptedResolver{answers: answers}
	chain := resolve.NewChain(resolve.Options{
		Resolvers: []resolve.Resolver{r},
		Detector:  resolve.NewDetector(nil, nil),
		Reverse:   reverse,
		Logf:      t.Logf,
	})
	return resolve.NewServer(chain, t.Logf), r
}

// scriptedResolver answers from a table and counts what it was asked.
type scriptedResolver struct {
	answers map[string]netip.Addr
	asked   atomic.Int64
}

func (r *scriptedResolver) Label() string     { return "scripted" }
func (r *scriptedResolver) Transport() string { return "doh" }

func (r *scriptedResolver) Exchange(_ context.Context, query []byte) ([]byte, error) {
	r.asked.Add(1)
	var m dns.Msg
	if err := m.Unpack(query); err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	resp.SetReply(&m)
	if len(m.Question) == 1 {
		q := m.Question[0]
		if a, ok := r.answers[q.Name]; ok && q.Qtype == dns.TypeA && a.Is4() {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   a.AsSlice(),
			})
		}
	}
	return resp.Pack()
}

// dnsQuery builds an A query for name.
func dnsQuery(t *testing.T, name string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return b
}

// readDNSDatagram reads one reply datagram.
func readDNSDatagram(t *testing.T, c net.Conn) []byte {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, maxDatagram)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return buf[:n]
}

// firstA returns the first A record of a reply.
func firstA(t *testing.T, msg []byte) netip.Addr {
	t.Helper()
	var m dns.Msg
	if err := m.Unpack(msg); err != nil {
		t.Fatalf("unpack reply: %v", err)
	}
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			addr, ok := netip.AddrFromSlice(a.A)
			if !ok {
				t.Fatalf("unparseable A record %v", a.A)
			}
			return addr.Unmap()
		}
	}
	t.Fatalf("reply carries no A record: %v", m)
	return netip.Addr{}
}

// netPipe is a connected pair with Close on both ends registered for cleanup.
func netPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}
