package tunfe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// QUICDesync, the third policy: emit the Initial through a UDP strategy instead
// of refusing it.
//
// It is not a default and these tests do not make it one. Refusing buys the TCP
// fallback, where every strategy in MEASUREMENTS.md §3 was measured; quicfake's
// efficacy against Turkish DPI is unmeasured (DOSSIER §3, P2). What the policy
// buys is that `dpb probe` can measure it on a user's own line.

// TestQUICDesyncEmitsTheStrategyAndThenRelays: the decoys and the real Initial
// go out on the SAME socket the session is then relayed on — a decoy from a
// different source port belongs to no flow at all.
func TestQUICDesyncEmitsTheStrategyAndThenRelays(t *testing.T) {
	sink := newDatagramSink(t)
	udp := &countingUDPDialer{peer: sink.dial}
	st, err := strategy.Parse("quicfake:count=2,ttl=3")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	l := newLab(t, labOpts{udp: udp, quic: QUICDesync, quicStrategy: st})

	client, err := l.dialUDP(netip.AddrPortFrom(originIP, 443))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()
	initial := quicInitialFilled(t, 200, 0xa7)
	if _, err := client.Write(initial); err != nil {
		t.Fatalf("write initial: %v", err)
	}

	got := sink.wait(t, 3)
	real0, ok := tlsmsg.ParseQUICInitial(initial)
	if !ok {
		t.Fatal("fixture is not a QUIC Initial")
	}
	for i, d := range got[:2] {
		q, ok := tlsmsg.ParseQUICInitial(d)
		if !ok {
			t.Fatalf("decoy %d is not a QUIC Initial", i)
		}
		if string(q.DCID(d)) != string(real0.DCID(initial)) {
			t.Errorf("decoy %d does not carry the real DCID, so a middlebox cannot associate it", i)
		}
		if string(d) == string(initial) {
			t.Errorf("decoy %d is the real datagram", i)
		}
	}
	if string(got[2]) != string(initial) {
		t.Fatal("the real Initial must arrive last and unmodified")
	}
	if s := l.server.Stats(); s.Refused != 0 {
		t.Fatalf("Refused = %d under QUICDesync", s.Refused)
	}

	// The socket is still the flow's: the session relays on it afterwards, at
	// the restored hop limit.
	if _, err := client.Write([]byte("second datagram")); err != nil {
		t.Fatalf("write second: %v", err)
	}
	more := sink.wait(t, 4)
	if string(more[3]) != "second datagram" {
		t.Fatalf("the relay after the desync delivered %q", more[3])
	}
}

// TestQUICDesyncFailsClosed is the property that matters most here. If the plan
// cannot be emitted, the client must get the ICMP unreachable and fall back to
// TCP — never an unprotected Initial for a name we judge.
//
// The failure is induced the way it can actually happen: a dialer that hands
// back something that is not a connected datagram socket, so segment boundaries
// would not be packet boundaries and flow.SendFirstDatagram refuses.
func TestQUICDesyncFailsClosed(t *testing.T) {
	streamed := &streamUDPDialer{}
	st, err := strategy.Parse("quicfake:count=1,ttl=2")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	l := newLab(t, labOpts{udp: streamed, quic: QUICDesync, quicStrategy: st})

	client, err := l.dialUDP(netip.AddrPortFrom(originIP, 443))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(quicInitial(t, 64)); err != nil {
		t.Fatalf("write initial: %v", err)
	}

	waitFor(t, 10*time.Second, "the failed desync to be refused", func() bool {
		return l.server.Stats().Refused > 0
	})
	if n := streamed.wrote(); n != 0 {
		t.Fatalf("%d byte(s) reached the upstream after the desync failed; the Initial must not be relayed plain", n)
	}
}

// TestQUICDesyncLeavesUnjudgedAndBypassedFlowsAlone: the policy only applies
// where the ladder applies. A bypassed host is one we have positive evidence
// about, and desyncing its QUIC would be a regression bought for nothing.
func TestQUICDesyncLeavesABypassedNameAlone(t *testing.T) {
	sink := newDatagramSink(t)
	reverse := policy.NewReverseMap(16)
	reverse.Learn("www.isbank.com.tr", []netip.Addr{bankIP}, time.Hour)
	st, err := strategy.Parse("quicfake:count=2,ttl=3")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	l := newLab(t, labOpts{
		udp:          &countingUDPDialer{peer: sink.dial},
		quic:         QUICDesync,
		quicStrategy: st,
		reverse:      reverse,
		rules: []policy.Rule{
			{Pattern: "isbank.com.tr", Class: policy.ScopeBypass, From: policy.FromCompiledIn},
		},
	})

	client, err := l.dialUDP(netip.AddrPortFrom(bankIP, 443))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer client.Close()
	initial := quicInitial(t, 64)
	if _, err := client.Write(initial); err != nil {
		t.Fatalf("write initial: %v", err)
	}
	got := sink.wait(t, 1)
	if string(got[0]) != string(initial) {
		t.Fatal("a bypassed name's Initial was altered")
	}
	// Nothing else may follow: one datagram in, one datagram out.
	if extra := sink.count(); extra != 1 {
		t.Fatalf("%d datagrams upstream for a bypassed flow, want 1", extra)
	}
}

// TestNewRefusesAnUnsatisfiableQUICStrategy is the capability validator at the
// datagram path: a profile naming a strategy the transport cannot satisfy must
// refuse to LOAD with the shortfall named, because there is no ladder here to
// fall back to and the alternative is a tunnel that kills QUIC while claiming
// to desync it.
func TestNewRefusesAnUnsatisfiableQUICStrategy(t *testing.T) {
	t.Parallel()
	a, _ := NewPipe(0)
	scope := policy.NewEngine(policy.EngineOptions{})
	runner := &flow.LadderRunner{Dial: &upstreamDialer{}}

	_, err := New(Options{Link: a, Scope: scope, Ladder: runner, QUIC: QUICDesync})
	if !errors.Is(err, ErrNoQUICStrategy) {
		t.Fatalf("New with quic=desync and no strategy = %v, want ErrNoQUICStrategy", err)
	}

	oob, perr := strategy.Parse("oob:pos=1")
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	_, err = New(Options{Link: a, Scope: scope, Ladder: runner, QUIC: QUICDesync, QUICStrategy: oob})
	if err == nil {
		t.Fatal("New accepted a strategy a connected UDP socket cannot emit")
	}
	if !strings.Contains(err.Error(), "oob") {
		t.Errorf("the shortfall must be named: %v", err)
	}

	quicfake, perr := strategy.Parse("quicfake:count=2,ttl=4")
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	srv, err := New(Options{Link: a, Scope: scope, Ladder: runner, QUIC: QUICDesync, QUICStrategy: quicfake})
	if err != nil {
		t.Fatalf("New with quicfake = %v; a connected UDP socket grants everything it needs", err)
	}
	srv.Close()
}

// quicInitialFilled is quicInitial with a constant payload byte.
//
// The pattern matters: quicfake's decoy filler is seed^i, and quicInitial's own
// payload is i, so a decoy with seed 0 is byte-identical to that fixture. That
// is a property of the two fixtures, not of the op, and asserting "the decoy is
// not the real datagram" needs a payload the filler cannot reproduce.
func quicInitialFilled(t *testing.T, n int, fill byte) []byte {
	t.Helper()
	b := quicInitial(t, n)
	for i := len(b) - n; i < len(b); i++ {
		b[i] = fill
	}
	if _, ok := tlsmsg.ParseQUICInitial(b); !ok {
		t.Fatalf("the filled fixture is no longer a QUIC Initial")
	}
	return b
}

// datagramSink is a loopback UDP server that keeps every datagram whole, so a
// test can assert boundaries and order rather than bytes.
type datagramSink struct {
	pc *net.UDPConn

	mu   sync.Mutex
	msgs [][]byte
}

func newDatagramSink(t *testing.T) *datagramSink {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	s := &datagramSink{pc: pc}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, rerr := pc.ReadFromUDP(buf)
			if n > 0 {
				s.mu.Lock()
				s.msgs = append(s.msgs, append([]byte(nil), buf[:n]...))
				s.mu.Unlock()
			}
			if rerr != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return s
}

func (s *datagramSink) dial() (net.Conn, error) {
	return net.DialUDP("udp4", nil, s.pc.LocalAddr().(*net.UDPAddr))
}

func (s *datagramSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.msgs)
}

// wait blocks until n datagrams have arrived and returns them in order.
//
// Ten seconds is a test-infrastructure bound, not a claim about latency: two
// gVisor stacks under -race on a loaded machine take far longer to move a
// datagram than the same code does on a real link. Nothing here asserts timing.
func (s *datagramSink) wait(t *testing.T, n int) [][]byte {
	t.Helper()
	waitFor(t, 10*time.Second, "datagrams to reach the upstream", func() bool { return s.count() >= n })
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.msgs))
	copy(out, s.msgs)
	return out
}

// streamUDPDialer hands back a stream connection, which is what a datagram
// strategy must refuse: on a stream a decoy is not a decoy, it is corruption of
// the payload.
type streamUDPDialer struct {
	mu sync.Mutex
	n  int
}

func (d *streamUDPDialer) DialUDP(_ context.Context, _ netip.AddrPort) (net.Conn, error) {
	a, b := net.Pipe()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := b.Read(buf)
			d.mu.Lock()
			d.n += n
			d.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return a, nil
}

func (d *streamUDPDialer) wrote() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.n
}
