package proxyfe_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/front/proxyfe"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// SOCKS5 UDP ASSOCIATE, RFC 1928 §7 — the unprivileged datagram path.
//
// Everything below runs on real loopback sockets through the shipped
// flow.NetUDPDialer, because the properties under test (datagram boundaries,
// the reply header, one socket per destination) are properties of sockets.

// associate performs the greeting and a UDP ASSOCIATE, returning the control
// connection and the relay address the server bound.
func associate(t *testing.T, h *harness) (net.Conn, netip.AddrPort, byte) {
	t.Helper()
	c := h.dialProxy(t)
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	// ASSOCIATE with the conventional 0.0.0.0:0 "I do not know my source yet".
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(req); err != nil {
		t.Fatalf("associate: %v", err)
	}
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		t.Fatalf("read reply head: %v", err)
	}
	if head[0] != 0x05 {
		t.Fatalf("reply version = %d", head[0])
	}
	if head[1] != 0x00 {
		// A refusal carries a v4 address by convention; drain it.
		rest := make([]byte, 6)
		_, _ = io.ReadFull(c, rest)
		return c, netip.AddrPort{}, head[1]
	}
	var addr netip.Addr
	switch head[3] {
	case 0x01:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			t.Fatalf("read bound v4: %v", err)
		}
		addr = netip.AddrFrom4(b)
	case 0x04:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			t.Fatalf("read bound v6: %v", err)
		}
		addr = netip.AddrFrom16(b)
	default:
		t.Fatalf("bound address type %d", head[3])
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		t.Fatalf("read bound port: %v", err)
	}
	bound := netip.AddrPortFrom(addr.Unmap(), binary.BigEndian.Uint16(pb[:]))
	if bound.Port() == 0 {
		t.Fatal("the reply carried port 0: a client would have nowhere to send")
	}
	return c, bound, head[1]
}

// udpHeaderFor builds the RFC 1928 §7 request header for a destination.
func udpHeaderFor(t *testing.T, host string, port int) []byte {
	t.Helper()
	out := []byte{0, 0, 0}
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Is4() {
			out = append(out, 0x01)
			v4 := a.As4()
			out = append(out, v4[:]...)
		} else {
			out = append(out, 0x04)
			v6 := a.As16()
			out = append(out, v6[:]...)
		}
	} else {
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
	}
	return binary.BigEndian.AppendUint16(out, uint16(port))
}

// clientSocket is the client's own UDP socket, connected to the relay.
func clientSocket(t *testing.T, relay netip.AddrPort) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func readRelay(t *testing.T, c *net.UDPConn, within time.Duration) ([]byte, bool) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(within)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}

// echoUDP is an upstream that echoes each datagram whole.
type echoUDP struct {
	pc *net.UDPConn

	mu   sync.Mutex
	msgs [][]byte
}

func newEchoUDP(t *testing.T) *echoUDP {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	e := &echoUDP{pc: pc}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, rerr := pc.ReadFromUDP(buf)
			if n > 0 {
				e.mu.Lock()
				e.msgs = append(e.msgs, append([]byte(nil), buf[:n]...))
				e.mu.Unlock()
				_, _ = pc.WriteToUDP(buf[:n], from)
			}
			if rerr != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return e
}

func (e *echoUDP) addrPort() netip.AddrPort {
	ap := e.pc.LocalAddr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func (e *echoUDP) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.msgs)
}

// TestUDPAssociateRelaysWholeDatagrams: one datagram in, one datagram out, with
// the client's own header echoed on the reply. A relay that re-framed would
// hand a QUIC or DNS peer two glued datagrams, which it simply discards.
func TestUDPAssociateRelaysWholeDatagrams(t *testing.T) {
	t.Parallel()
	echo := newEchoUDP(t)
	h := serveTest(t, wiring{udpDial: &flow.NetUDPDialer{}})

	ctrl, relay, rep := associate(t, h)
	if rep != 0x00 {
		t.Fatalf("ASSOCIATE reply = %d, want success", rep)
	}
	defer ctrl.Close()
	c := clientSocket(t, relay)

	dst := echo.addrPort()
	hdr := udpHeaderFor(t, dst.Addr().String(), int(dst.Port()))
	for _, msg := range []string{"one", "twelve!!"} {
		if _, err := c.Write(append(append([]byte(nil), hdr...), msg...)); err != nil {
			t.Fatalf("write %q: %v", msg, err)
		}
	}
	for _, want := range []string{"one", "twelve!!"} {
		got, ok := readRelay(t, c, 5*time.Second)
		if !ok {
			t.Fatalf("no reply for %q", want)
		}
		if string(got[:len(hdr)]) != string(hdr) {
			t.Fatalf("reply header = % x, want the client's own % x", got[:len(hdr)], hdr)
		}
		if string(got[len(hdr):]) != want {
			t.Fatalf("reply payload = %q, want exactly one datagram %q", got[len(hdr):], want)
		}
	}
	if n := echo.count(); n != 2 {
		t.Fatalf("upstream saw %d datagrams, want 2 whole ones", n)
	}
	if s := h.srv.Stats(); s.UDPAssoc != 1 {
		t.Fatalf("UDPAssoc = %d, want 1", s.UDPAssoc)
	}
}

// TestUDPAssociateWithNoDialerIsRefused: a socket the client would wait on
// forever is worse than the RFC's own "command not supported".
func TestUDPAssociateWithNoDialerIsRefused(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{})
	ctrl, _, rep := associate(t, h)
	defer ctrl.Close()
	if rep != 0x07 {
		t.Fatalf("reply = %d, want 0x07 command-not-supported", rep)
	}
}

// TestUDPAssociateResolvesNamesThroughTheChain: a named destination is resolved
// through the tool's own chain and nowhere else. MEASUREMENTS.md §5.4 records
// Go's resolver returning the BTK sinkhole for exactly these names.
func TestUDPAssociateResolvesNamesThroughTheChain(t *testing.T) {
	t.Parallel()
	echo := newEchoUDP(t)
	var asked []string
	var mu sync.Mutex
	resolve := func(_ context.Context, host string) ([]netip.Addr, error) {
		mu.Lock()
		asked = append(asked, host)
		mu.Unlock()
		return []netip.Addr{echo.addrPort().Addr()}, nil
	}
	h := serveTest(t, wiring{udpDial: &flow.NetUDPDialer{}, resolve: resolve})

	ctrl, relay, _ := associate(t, h)
	defer ctrl.Close()
	c := clientSocket(t, relay)

	hdr := udpHeaderFor(t, "discord.com", int(echo.addrPort().Port()))
	if _, err := c.Write(append(append([]byte(nil), hdr...), "hello"...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, ok := readRelay(t, c, 5*time.Second)
	if !ok {
		t.Fatal("no reply for a named destination")
	}
	if string(got[:len(hdr)]) != string(hdr) {
		t.Fatalf("the reply header did not echo the name the client used: % x", got[:len(hdr)])
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 1 || asked[0] != "discord.com" {
		t.Fatalf("chain was asked %v, want exactly discord.com", asked)
	}
}

// TestUDPAssociateRefusesANamedDestinationWithNoChain: guessing is not an
// option, and neither is Go's resolver.
func TestUDPAssociateRefusesANamedDestinationWithNoChain(t *testing.T) {
	t.Parallel()
	echo := newEchoUDP(t)
	h := serveTest(t, wiring{udpDial: &flow.NetUDPDialer{}})
	ctrl, relay, _ := associate(t, h)
	defer ctrl.Close()
	c := clientSocket(t, relay)

	hdr := udpHeaderFor(t, "discord.com", int(echo.addrPort().Port()))
	if _, err := c.Write(append(append([]byte(nil), hdr...), "hello"...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, ok := readRelay(t, c, 500*time.Millisecond); ok {
		t.Fatal("a named destination was relayed with no resolver chain wired")
	}
	if echo.count() != 0 {
		t.Fatal("a datagram reached the upstream anyway")
	}
}

// quicInitial builds an RFC 9000 §17.2 v1 Initial with a constant payload.
func quicInitial(t *testing.T, n int) []byte {
	t.Helper()
	b := []byte{0xc0}
	b = binary.BigEndian.AppendUint32(b, tlsmsg.QUICVersion1)
	b = append(b, 8, 1, 2, 3, 4, 5, 6, 7, 8) // DCID
	b = append(b, 0)                         // zero-length SCID
	b = append(b, 0)                         // empty token
	b = binary.BigEndian.AppendUint16(b, uint16(n)|0x4000)
	for i := 0; i < n; i++ {
		b = append(b, 0xa7)
	}
	if _, ok := tlsmsg.ParseQUICInitial(b); !ok {
		t.Fatal("the fixture is not a QUIC Initial")
	}
	return b
}

// TestUDPAssociateRefusesAQUICInitialToAJudgedName: refusing pushes the client
// onto TCP, where every strategy in MEASUREMENTS.md §3 was measured. Relaying
// UDP/443 verbatim is strictly worse than proxy mode, which forces the fallback
// by accident.
func TestUDPAssociateRefusesAQUICInitialToAJudgedName(t *testing.T) {
	t.Parallel()
	echo := newEchoUDP(t)
	resolve := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{echo.addrPort().Addr()}, nil
	}
	h := serveTest(t, wiring{udpDial: &flow.NetUDPDialer{}, resolve: resolve, inspect: []int{443}})

	ctrl, relay, _ := associate(t, h)
	defer ctrl.Close()
	c := clientSocket(t, relay)

	// A NAME on port 443, which is what the policy judges: a loopback literal
	// is a bogon and would be ScopeDirect, so the test would prove nothing.
	hdr := udpHeaderFor(t, "discord.com", 443)
	if _, err := c.Write(append(append([]byte(nil), hdr...), quicInitial(t, 64)...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, ok := readRelay(t, c, 500*time.Millisecond); ok {
		t.Fatal("a refused QUIC Initial got a reply")
	}
	if echo.count() != 0 {
		t.Fatal("the Initial was relayed upstream")
	}
	waitUntil(t, 2*time.Second, func() bool { return h.srv.Stats().UDPDrops > 0 })
}

// TestUDPAssociateRelaysQUICToABypassedName: a host we have positive evidence
// about is never refused. Breaking a bank's QUIC would be a regression bought
// for nothing.
func TestUDPAssociateRelaysQUICToABypassedName(t *testing.T) {
	t.Parallel()
	echo := newEchoUDP(t)
	dst := echo.addrPort()
	resolve := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{dst.Addr()}, nil
	}
	h := serveTest(t, wiring{
		udpDial: &flow.NetUDPDialer{},
		resolve: resolve,
		inspect: []int{443},
		rules: []policy.Rule{
			{Pattern: "isbank.com.tr", Class: policy.ScopeBypass, From: policy.FromCompiledIn},
		},
	})
	ctrl, relay, _ := associate(t, h)
	defer ctrl.Close()
	c := clientSocket(t, relay)

	hdr := udpHeaderFor(t, "www.isbank.com.tr", int(dst.Port()))
	initial := quicInitial(t, 64)
	if _, err := c.Write(append(append([]byte(nil), hdr...), initial...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, ok := readRelay(t, c, 5*time.Second)
	if !ok {
		t.Fatal("a bypassed name's QUIC was refused")
	}
	if string(got[len(hdr):]) != string(initial) {
		t.Fatal("the relayed Initial was altered")
	}
}

// TestUDPAssociateDesyncsAQUICInitial: the third policy, and the reason
// quicfake is in the registry at all — a mechanism the prober can measure on a
// user's own line, over the unprivileged path.
func TestUDPAssociateDesyncsAQUICInitial(t *testing.T) {
	t.Parallel()
	echo := newEchoUDP(t)
	dst := echo.addrPort()
	resolve := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{dst.Addr()}, nil
	}
	st, err := strategy.Parse("quicfake:count=2,ttl=3")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The header must name port 443 for the QUIC policy to apply, and a test
	// cannot bind 443. The redirect maps that destination onto the echo
	// server's real port while everything else — the shipped dialer, a real
	// connected UDP socket, the real emitter — stays in the path.
	h := serveTest(t, wiring{
		udpDial:      &redirectUDPDialer{to: dst},
		resolve:      resolve,
		inspect:      []int{443},
		quic:         proxyfe.QUICDesync,
		quicStrategy: st,
	})
	ctrl, relay, _ := associate(t, h)
	defer ctrl.Close()
	c := clientSocket(t, relay)

	// A name on 443 so the policy judges the flow; the resolver above points it
	// at the echo server, which is where the datagrams actually land.
	hdr := udpHeaderFor(t, "discord.com", 443)
	initial := quicInitial(t, 200)
	if _, err := c.Write(append(append([]byte(nil), hdr...), initial...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitUntil(t, 5*time.Second, func() bool { return echo.count() >= 3 })

	echo.mu.Lock()
	defer echo.mu.Unlock()
	for i, d := range echo.msgs[:2] {
		q, ok := tlsmsg.ParseQUICInitial(d)
		if !ok {
			t.Fatalf("decoy %d is not a QUIC Initial", i)
		}
		real0, _ := tlsmsg.ParseQUICInitial(initial)
		if string(q.DCID(d)) != string(real0.DCID(initial)) {
			t.Errorf("decoy %d does not carry the real DCID", i)
		}
		if string(d) == string(initial) {
			t.Errorf("decoy %d is the real datagram", i)
		}
	}
	if string(echo.msgs[2]) != string(initial) {
		t.Fatal("the real Initial must arrive last and unmodified")
	}
}

// redirectUDPDialer dials the shipped dialer at a fixed address, so a test can
// use a privileged destination port in the SOCKS header without binding one.
type redirectUDPDialer struct{ to netip.AddrPort }

func (d *redirectUDPDialer) DialUDP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	return (&flow.NetUDPDialer{}).DialUDP(ctx, d.to)
}

// fakeDNS answers every query with a canned reply and records that it was
// asked.
type fakeDNS struct {
	mu    sync.Mutex
	asked int
	reply []byte
}

func (f *fakeDNS) Answer(context.Context, []byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked++
	return f.reply
}

func (f *fakeDNS) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.asked
}

// TestUDPAssociateAnswersDNSInProcess: relaying UDP/53 would hand the ISP's
// resolver exactly the queries DoH exists to hide — the same rule TUN mode
// applies, for the same reason.
func TestUDPAssociateAnswersDNSInProcess(t *testing.T) {
	t.Parallel()
	echo := newEchoUDP(t)
	dns := &fakeDNS{reply: []byte("canned-answer")}
	h := serveTest(t, wiring{udpDial: &flow.NetUDPDialer{}, dns: dns})
	ctrl, relay, _ := associate(t, h)
	defer ctrl.Close()
	c := clientSocket(t, relay)

	hdr := udpHeaderFor(t, echo.addrPort().Addr().String(), 53)
	if _, err := c.Write(append(append([]byte(nil), hdr...), "query"...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, ok := readRelay(t, c, 5*time.Second)
	if !ok {
		t.Fatal("no DNS reply")
	}
	if string(got[len(hdr):]) != "canned-answer" {
		t.Fatalf("reply = %q, want the in-process answer", got[len(hdr):])
	}
	if dns.calls() != 1 {
		t.Fatalf("the in-process resolver was asked %d times", dns.calls())
	}
	if echo.count() != 0 {
		t.Fatal("a DNS query left the machine")
	}
}

// TestUDPAssociateDropsMalformedDatagrams: nothing here may reach a socket. A
// fragmented datagram is dropped rather than reassembled, because reassembly
// means holding state for a peer that can simply never send the last fragment.
func TestUDPAssociateDropsMalformedDatagrams(t *testing.T) {
	t.Parallel()
	echo := newEchoUDP(t)
	h := serveTest(t, wiring{udpDial: &flow.NetUDPDialer{}})
	ctrl, relay, _ := associate(t, h)
	defer ctrl.Close()
	c := clientSocket(t, relay)

	dst := echo.addrPort()
	frag := udpHeaderFor(t, dst.Addr().String(), int(dst.Port()))
	frag[2] = 1 // FRAG
	badATYP := udpHeaderFor(t, dst.Addr().String(), int(dst.Port()))
	badATYP[3] = 0x09
	zeroPort := udpHeaderFor(t, dst.Addr().String(), 0)
	reserved := udpHeaderFor(t, dst.Addr().String(), int(dst.Port()))
	reserved[0] = 1

	for _, b := range [][]byte{
		append(frag, "payload"...),
		append(badATYP, "payload"...),
		append(zeroPort, "payload"...),
		append(reserved, "payload"...),
		{0, 0, 0, 1}, // shorter than a header
	} {
		if _, err := c.Write(b); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if _, ok := readRelay(t, c, 300*time.Millisecond); ok {
		t.Fatal("a malformed datagram produced a reply")
	}
	if echo.count() != 0 {
		t.Fatalf("%d malformed datagram(s) were relayed upstream", echo.count())
	}
}

// TestUDPAssociateCarriesSeveralClientPorts: one association, several client
// sockets. A stub resolver sends every query from a fresh port, so pinning the
// client's PORT — which is what a literal reading of RFC 1928's "recorded
// address" would do, given clients write 0.0.0.0:0 in the request — would break
// the single most likely user of this path. Each reply must go back to the port
// that asked.
func TestUDPAssociateCarriesSeveralClientPorts(t *testing.T) {
	t.Parallel()
	echo := newEchoUDP(t)
	h := serveTest(t, wiring{udpDial: &flow.NetUDPDialer{}})
	ctrl, relay, _ := associate(t, h)
	defer ctrl.Close()

	dst := echo.addrPort()
	hdr := udpHeaderFor(t, dst.Addr().String(), int(dst.Port()))
	first := clientSocket(t, relay)
	second := clientSocket(t, relay)

	for _, c := range []*net.UDPConn{first, second} {
		if _, err := c.Write(append(append([]byte(nil), hdr...), "hello"...)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	for i, c := range []*net.UDPConn{first, second} {
		got, ok := readRelay(t, c, 5*time.Second)
		if !ok {
			t.Fatalf("client socket %d got no reply", i)
		}
		if string(got[len(hdr):]) != "hello" {
			t.Fatalf("client socket %d got %q", i, got[len(hdr):])
		}
	}
}

// TestUDPAssociateIgnoresAnotherHost: the relay socket is bound to the address
// the client reached the proxy on, and datagrams from any other host are
// dropped — the association belongs to the process that opened the control
// connection.
func TestUDPAssociateIgnoresAnotherHost(t *testing.T) {
	t.Parallel()
	other, ok := secondLocalV4(t)
	if !ok {
		t.Skip("no second local IPv4 address on this machine to send from")
	}
	echo := newEchoUDP(t)
	h := serveTest(t, wiring{udpDial: &flow.NetUDPDialer{}})
	ctrl, relay, _ := associate(t, h)
	defer ctrl.Close()

	intruder, err := net.DialUDP("udp4", &net.UDPAddr{IP: other.AsSlice()}, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		t.Skipf("cannot send from %s: %v", other, err)
	}
	defer intruder.Close()

	dst := echo.addrPort()
	hdr := udpHeaderFor(t, dst.Addr().String(), int(dst.Port()))
	if _, err := intruder.Write(append(append([]byte(nil), hdr...), "theirs"...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, ok := readRelay(t, intruder, 500*time.Millisecond); ok {
		t.Fatal("a datagram from another host was relayed through somebody else's association")
	}
	if echo.count() != 0 {
		t.Fatal("a foreign datagram reached the upstream")
	}
}

// secondLocalV4 finds a routable IPv4 address of this machine, which is not the
// loopback address the proxy is bound to.
func secondLocalV4(t *testing.T) (netip.Addr, bool) {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return netip.Addr{}, false
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// TestUDPAssociateDiesWithItsControlConnection is RFC 1928 §7's only lifetime
// rule: "a UDP association terminates when the TCP connection that the UDP
// ASSOCIATE request arrived on terminates". Without it the relay socket and its
// upstream sockets outlive the client that asked for them.
func TestUDPAssociateDiesWithItsControlConnection(t *testing.T) {
	t.Parallel()
	echo := newEchoUDP(t)
	h := serveTest(t, wiring{udpDial: &flow.NetUDPDialer{}})
	ctrl, relay, _ := associate(t, h)
	c := clientSocket(t, relay)

	dst := echo.addrPort()
	hdr := udpHeaderFor(t, dst.Addr().String(), int(dst.Port()))
	if _, err := c.Write(append(append([]byte(nil), hdr...), "before"...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, ok := readRelay(t, c, 5*time.Second); !ok {
		t.Fatal("no reply while the association was live")
	}

	_ = ctrl.Close()
	waitUntil(t, 5*time.Second, func() bool {
		_, _ = c.Write(append(append([]byte(nil), hdr...), "after"...))
		_, ok := readRelay(t, c, 200*time.Millisecond)
		return !ok
	})
}

// TestUDPAssociateBoundsItsSessions: a client that sends to a thousand
// destinations must not cost a thousand sockets.
func TestUDPAssociateBoundsItsSessions(t *testing.T) {
	t.Parallel()
	first := newEchoUDP(t)
	second := newEchoUDP(t)
	h := serveTest(t, wiring{udpDial: &flow.NetUDPDialer{}, maxUDPSessions: 1})
	ctrl, relay, _ := associate(t, h)
	defer ctrl.Close()
	c := clientSocket(t, relay)

	one := udpHeaderFor(t, first.addrPort().Addr().String(), int(first.addrPort().Port()))
	if _, err := c.Write(append(append([]byte(nil), one...), "hello"...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, ok := readRelay(t, c, 5*time.Second); !ok {
		t.Fatal("the first destination was not relayed")
	}
	two := udpHeaderFor(t, second.addrPort().Addr().String(), int(second.addrPort().Port()))
	if _, err := c.Write(append(append([]byte(nil), two...), "hello"...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, ok := readRelay(t, c, 500*time.Millisecond); ok {
		t.Fatal("the session cap was exceeded")
	}
	if second.count() != 0 {
		t.Fatal("a datagram reached the second destination past the cap")
	}
}

func TestSOCKSUDPPolicyNames(t *testing.T) {
	t.Parallel()
	for p, want := range map[proxyfe.QUICPolicy]string{
		proxyfe.QUICRefuse: "refuse",
		proxyfe.QUICRelay:  "relay",
		proxyfe.QUICDesync: "desync",
	} {
		if got := p.String(); got != want {
			t.Errorf("QUICPolicy(%d) = %q, want %q", uint8(p), got, want)
		}
	}
	if got := proxyfe.QUICPolicy(9).String(); got != "quicpolicy(9)" {
		t.Errorf("QUICPolicy(9) = %q", got)
	}
}

// waitUntil polls until cond holds or the deadline passes.
func waitUntil(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %s", d)
}

// streamUDPDialer hands back a stream connection, which is what a datagram
// strategy must refuse: on a stream a decoy is not a decoy, it is corruption of
// the payload.
type streamUDPDialer struct {
	mu    sync.Mutex
	dials int
	wrote int
}

func (d *streamUDPDialer) DialUDP(context.Context, netip.AddrPort) (net.Conn, error) {
	d.mu.Lock()
	d.dials++
	d.mu.Unlock()
	a, b := net.Pipe()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := b.Read(buf)
			d.mu.Lock()
			d.wrote += n
			d.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return a, nil
}

func (d *streamUDPDialer) stats() (dials, wrote int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials, d.wrote
}

// TestUDPAssociateDesyncFailsClosed: an Initial we could not desync is NOT
// relayed plain for a name we judge — that is the one outcome the policy exists
// to prevent. The session is dropped too, so the next datagram starts a fresh
// one rather than reusing a socket whose hop limit we may have changed.
func TestUDPAssociateDesyncFailsClosed(t *testing.T) {
	t.Parallel()
	st, err := strategy.Parse("quicfake:count=1,ttl=2")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	dialer := &streamUDPDialer{}
	resolve := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
	}
	h := serveTest(t, wiring{
		udpDial:      dialer,
		resolve:      resolve,
		inspect:      []int{443},
		quic:         proxyfe.QUICDesync,
		quicStrategy: st,
	})
	ctrl, relay, _ := associate(t, h)
	defer ctrl.Close()
	c := clientSocket(t, relay)

	hdr := udpHeaderFor(t, "discord.com", 443)
	initial := quicInitial(t, 64)
	if _, err := c.Write(append(append([]byte(nil), hdr...), initial...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitUntil(t, 5*time.Second, func() bool { return h.srv.Stats().UDPDrops > 0 })
	if _, wrote := dialer.stats(); wrote != 0 {
		t.Fatalf("%d byte(s) were relayed after the desync failed", wrote)
	}

	// The failed session is gone: the next datagram opens a new one.
	if _, err := c.Write(append(append([]byte(nil), hdr...), initial...)); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitUntil(t, 5*time.Second, func() bool {
		dials, _ := dialer.stats()
		return dials >= 2
	})
}
