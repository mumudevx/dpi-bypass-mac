package tunfe

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/policy"
	"github.com/mumudevx/dpb/internal/tlsmsg"
)

// TestUDPRelayPreservesDatagramBoundaries: io.Copy is wrong on this path. A
// stream copy re-frames, so a short read truncates a datagram and a buffered
// write merges two of them — and a QUIC or DNS peer that receives two datagrams
// glued together simply discards them.
func TestUDPRelayPreservesDatagramBoundaries(t *testing.T) {
	echo := newUDPEcho(t)
	udp := &countingUDPDialer{peer: echo.dial}
	l := newLab(t, labOpts{udp: udp, quic: QUICRelay})

	client, err := l.dialUDP(netip.AddrPortFrom(originIP, 4711))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()

	// Two datagrams of different lengths, written back to back. A re-framing
	// relay would deliver them as one read of eight bytes.
	for _, msg := range []string{"one", "twelve!!"} {
		if _, err := client.Write([]byte(msg)); err != nil {
			t.Fatalf("write %q: %v", msg, err)
		}
	}
	for _, want := range []string{"one", "twelve!!"} {
		if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
		buf := make([]byte, 64)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf[:n]) != want {
			t.Fatalf("read %q, want exactly one datagram %q", buf[:n], want)
		}
	}
	if n := udp.count(); n != 1 {
		t.Fatalf("%d upstream sockets for one session, want 1", n)
	}
	if s := l.server.Stats(); s.UDPFlows != 1 {
		t.Fatalf("UDPFlows = %d, want 1", s.UDPFlows)
	}
}

// TestQUICInitialToAJudgedNameIsRefused: relaying UDP/443 verbatim is strictly
// worse than proxy mode, which forces the TCP fallback by accident. An ICMP
// port-unreachable makes that fallback deliberate and immediate, and no
// datagram leaves the machine.
func TestQUICInitialToAJudgedNameIsRefused(t *testing.T) {
	udp := &countingUDPDialer{}
	l := newLab(t, labOpts{udp: udp})

	client, err := l.dialUDP(netip.AddrPortFrom(originIP, 443))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(quicInitial(t, 64)); err != nil {
		t.Fatalf("write initial: %v", err)
	}

	waitFor(t, 5*time.Second, "the QUIC Initial to be refused", func() bool {
		return l.server.Stats().Refused > 0
	})
	if n := udp.count(); n != 0 {
		t.Fatalf("%d upstream socket(s) opened for a refused QUIC flow", n)
	}

	// The client's own netstack — an independent implementation of the receiver
	// — must match the ICMP error to this socket and report it. That is what a
	// browser sees when it marks the path QUIC-broken.
	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		if err := client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
		buf := make([]byte, 64)
		if _, err := client.Read(buf); err != nil && !isTimeoutErr(err) {
			last = err
			break
		}
	}
	if last == nil {
		t.Fatal("the client socket never saw the unreachable; a browser would wait out a QUIC timeout instead of falling back to TCP")
	}
	t.Logf("client observed %v", last)
}

// TestQUICRelayPolicyRelays: refusing is a policy, not a hardcoded behaviour.
// An operator whose measurements say QUIC is not blocked here gets it relayed.
func TestQUICRelayPolicyRelays(t *testing.T) {
	echo := newUDPEcho(t)
	udp := &countingUDPDialer{peer: echo.dial}
	l := newLab(t, labOpts{udp: udp, quic: QUICRelay})

	client, err := l.dialUDP(netip.AddrPortFrom(originIP, 443))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()
	initial := quicInitial(t, 64)
	if _, err := client.Write(initial); err != nil {
		t.Fatalf("write initial: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf[:n]) != string(initial) {
		t.Fatalf("the relayed datagram was altered: %d of %d bytes match", matching(buf[:n], initial), len(initial))
	}
	if s := l.server.Stats(); s.Refused != 0 {
		t.Fatalf("Refused = %d under QUICRelay", s.Refused)
	}
}

// TestQUICToABypassedNameIsRelayed: a host we have positive evidence about is
// never refused. Breaking a bank's QUIC would be a regression bought for
// nothing.
func TestQUICToABypassedNameIsRelayed(t *testing.T) {
	echo := newUDPEcho(t)
	reverse := policy.NewReverseMap(16)
	reverse.Learn("www.isbank.com.tr", []netip.Addr{bankIP}, time.Hour)
	udp := &countingUDPDialer{peer: echo.dial}
	l := newLab(t, labOpts{
		udp:     udp,
		reverse: reverse,
		rules: []policy.Rule{
			{Pattern: "isbank.com.tr", Class: policy.ScopeBypass, From: policy.FromCompiledIn},
		},
	})

	client, err := l.dialUDP(netip.AddrPortFrom(bankIP, 443))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(quicInitial(t, 32)); err != nil {
		t.Fatalf("write initial: %v", err)
	}
	waitFor(t, 5*time.Second, "the bypassed QUIC flow to be relayed", func() bool {
		return udp.count() == 1
	})
	if s := l.server.Stats(); s.Refused != 0 {
		t.Fatalf("a bypassed name's QUIC was refused (Refused = %d)", s.Refused)
	}
}

// TestNonInitialDatagramIsNotRefused: a datagram in the middle of an
// established session belongs to a connection the client already has, and
// refusing it would tear down something that works.
func TestNonInitialDatagramIsNotRefused(t *testing.T) {
	echo := newUDPEcho(t)
	udp := &countingUDPDialer{peer: echo.dial}
	l := newLab(t, labOpts{udp: udp})

	client, err := l.dialUDP(netip.AddrPortFrom(originIP, 443))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()
	// A short-header QUIC packet: the fixed bit is set but the long-header bit
	// is not, so it is not an Initial.
	if _, err := client.Write([]byte{0x40, 1, 2, 3, 4, 5, 6, 7}); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, 5*time.Second, "the non-Initial datagram to be relayed", func() bool {
		return udp.count() == 1
	})
	if s := l.server.Stats(); s.Refused != 0 {
		t.Fatalf("a non-Initial datagram was refused (Refused = %d)", s.Refused)
	}
}

// TestUDPWithNoDialerDropsRatherThanPanics: a UDP flow with nothing wired to
// carry it is dropped with a diagnosable log line.
func TestUDPWithNoDialerDropsRatherThanPanics(t *testing.T) {
	l := newLab(t, labOpts{quic: QUICRelay})
	client, err := l.dialUDP(netip.AddrPortFrom(originIP, 4711))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, 5*time.Second, "the flow to be counted", func() bool {
		return l.server.Stats().UDPFlows == 1
	})
}

// TestUDPFlowEndsWhenTheDatapathStops: a UDP session has no FIN, so before
// closeOnCancel the idle deadline was the ONLY bound on a relay — sixty seconds
// with the shipped DefaultUDPIdle. Cancelling the datapath did not touch a live
// flow at all: Serve returned, drain() waited out DrainGrace and logged "flow(s)
// still live", and the session went on holding a client endpoint on a netstack
// being torn down and an upstream socket on a route being withdrawn, for up to a
// minute after the user ran `dpb off`.
//
// The lab's UDPIdle is twenty seconds, so without the fix this test waits the
// full budget below with the flow still active and fails.
func TestUDPFlowEndsWhenTheDatapathStops(t *testing.T) {
	echo := newUDPEcho(t)
	udp := &countingUDPDialer{peer: echo.dial}
	l := newLab(t, labOpts{udp: udp, quic: QUICRelay, noStart: true})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- l.server.Serve(ctx) }()

	client, err := l.dialUDP(netip.AddrPortFrom(originIP, 4711))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Wait for the round trip rather than for the flow counter: that proves
	// both copy loops are running and parked on their idle deadlines, which is
	// the state cancellation has to be able to interrupt.
	if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 64)
	if _, err := client.Read(buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if a := l.server.Stats().Active; a != 1 {
		t.Fatalf("Active = %d before cancellation, want the relay to be live", a)
	}

	cancel()
	select {
	case <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return within 10s of cancellation")
	}
	waitFor(t, 5*time.Second, "the relayed UDP flow to end with the datapath", func() bool {
		return l.server.Stats().Active == 0
	})
}

// quicInitial builds a QUIC v1 long-header Initial packet with a payload of n
// bytes. tlsmsg.ParseQUICInitial is the parser under test on the other side, so
// this fixture is deliberately built to the RFC 9000 §17.2 layout rather than
// captured.
func quicInitial(t *testing.T, n int) []byte {
	t.Helper()
	var b []byte
	b = append(b, 0xc0) // long header, fixed bit, v1 type 0 = Initial
	b = binary.BigEndian.AppendUint32(b, tlsmsg.QUICVersion1)
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	b = append(b, byte(len(dcid)))
	b = append(b, dcid...)
	b = append(b, 0)    // zero-length SCID
	b = append(b, 0)    // zero-length token, as a 1-byte varint
	b = append(b, 0x40) // 2-byte varint length prefix
	b = append(b, byte(n))
	for i := 0; i < n; i++ {
		b = append(b, byte(i))
	}
	if _, ok := tlsmsg.ParseQUICInitial(b); !ok {
		t.Fatalf("the fixture is not a QUIC Initial: % x", b)
	}
	return b
}

// udpEcho is a loopback UDP server that echoes every datagram back, one for
// one.
type udpEcho struct {
	t  *testing.T
	pc *net.UDPConn
}

func newUDPEcho(t *testing.T) *udpEcho {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	e := &udpEcho{t: t, pc: pc}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, rerr := pc.ReadFromUDP(buf)
			if n > 0 {
				_, _ = pc.WriteToUDP(buf[:n], addr)
			}
			if rerr != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return e
}

// dial opens a connected socket to the echo server, which is what the Server's
// UDPDialer hands back.
func (e *udpEcho) dial() (net.Conn, error) {
	return net.DialUDP("udp", nil, e.pc.LocalAddr().(*net.UDPAddr))
}
