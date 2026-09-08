//go:build darwin

package emit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/strategy"
)

// decoyPlan is the shape ops/quicfake now builds: N decoy datagrams at a low
// hop limit, then the real datagram at the socket default.
func decoyPlan() strategy.Plan {
	return strategy.Plan{
		Spec:    "quicfake:count=2,ttl=3",
		Payload: []byte("REAL-INITIAL"),
		Segments: []strategy.Segment{
			{Kind: strategy.SegFakeDatagram, Data: []byte("DECOY-1"), TTL: 3},
			{Kind: strategy.SegFakeDatagram, Data: []byte("DECOY-2"), TTL: 3},
			{Kind: strategy.SegStream, Data: []byte("REAL-INITIAL")},
		},
	}
}

// TestFakeDatagramSegmentsGoOutAsOrdinaryWrites is the emitter half of
// amendment A7: a decoy datagram is an ordinary write on a connected socket
// with the hop limit lowered, which is what byedpi's desync_udp does and what
// makes the mechanism reachable unprivileged on Darwin (DOSSIER §3, P2).
//
// Before the fix the decoys were SegFakeRaw, so emitSegment called InjectRaw,
// which UDPTransport refuses unconditionally: no datagram left the socket at
// all.
func TestFakeDatagramSegmentsGoOutAsOrdinaryWrites(t *testing.T) {
	ut, server := udpPair(t)
	p := decoyPlan()

	if missing := ut.Caps().Missing(p.Caps()); missing != 0 {
		t.Fatalf("UDP transport is missing %s for a decoy plan (has %s, needs %s)",
			missing, ut.Caps(), p.Caps())
	}
	if err := (&Sender{}).Send(context.Background(), ut, p); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	// Three datagrams, in order, each whole: the decoys are packets on the wire,
	// not bytes prepended to the payload.
	for _, want := range []string{"DECOY-1", "DECOY-2", "REAL-INITIAL"} {
		buf := make([]byte, 64)
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("read datagram %q: %v", want, err)
		}
		if got := string(buf[:n]); got != want {
			t.Fatalf("datagram = %q, want %q", got, want)
		}
	}

	// The socket relays the rest of the QUIC session, so leaving the hop limit
	// at 3 would black-hole every later datagram.
	def, err := defaultHopLimit(false)
	if err != nil {
		t.Fatalf("defaultHopLimit: %v", err)
	}
	if got, err := ut.ttl(); err != nil || got != def {
		t.Fatalf("hop limit after the plan = (%d, %v), want the default %d", got, err, def)
	}
}

// TestFakeDatagramIsRefusedOnAStreamTransport: a decoy written on a stream is
// not a decoy, it is corruption of the payload. The refusal must happen before
// any byte moves and must name the missing capability.
func TestFakeDatagramIsRefusedOnAStreamTransport(t *testing.T) {
	f := newFake() // every TCP capability, no CapDatagram
	err := (&Sender{}).Send(context.Background(), f, decoyPlan())
	if !errors.Is(err, ErrCapUnavailable) {
		t.Fatalf("err = %v, want ErrCapUnavailable", err)
	}
	if !strings.Contains(err.Error(), "datagram") {
		t.Errorf("the shortfall must be named: %v", err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("%d write(s) reached a transport that cannot carry the plan", len(f.writes))
	}
}

// TestUDPCapsMatchesTheTransportItDescribes: a front end refuses a UDP strategy
// at configuration time using UDPCaps, and a value that disagreed with the
// transport would either refuse a workable strategy or accept one that fails on
// an already-open socket.
func TestUDPCapsMatchesTheTransportItDescribes(t *testing.T) {
	ut, _ := udpPair(t)
	if got, want := UDPCaps(false), ut.Caps(); got != want {
		t.Fatalf("UDPCaps(false) = %s, transport grants %s", got, want)
	}
	if !UDPCaps(false).Has(strategy.CapDatagram) {
		t.Fatalf("UDPCaps = %s, want CapDatagram", UDPCaps(false))
	}
}

// TestFakeDatagramShortWriteIsAnError: a datagram socket either accepts the
// whole packet or none of it, so a partial write means the decoy on the wire is
// not the decoy the plan described.
func TestFakeDatagramShortWriteIsAnError(t *testing.T) {
	f := newFake()
	f.caps |= strategy.CapDatagram
	f.shortWrite = true
	err := (&Sender{}).Send(context.Background(), f, decoyPlan())
	if !errors.Is(err, ErrShortWrite) {
		t.Fatalf("err = %v, want ErrShortWrite", err)
	}
}

// TestFakeDatagramWriteErrorIsWrapped keeps the syscall error matchable at the
// call site, which is how the front end decides to fall back to refusing the
// flow rather than relaying it plain.
func TestFakeDatagramWriteErrorIsWrapped(t *testing.T) {
	f := newFake()
	f.caps |= strategy.CapDatagram
	f.failWriteAt = 1
	err := (&Sender{}).Send(context.Background(), f, decoyPlan())
	if !errors.Is(err, errFakeWrite) {
		t.Fatalf("err = %v, want the transport's own error", err)
	}
}
