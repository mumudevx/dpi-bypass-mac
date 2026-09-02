//go:build darwin

package emit

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

func udpPair(t *testing.T) (*UDPTransport, *net.UDPConn) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ut, err := NewUDPTransport(client)
	if err != nil {
		t.Fatalf("NewUDPTransport: %v", err)
	}
	return ut, server
}

// TestUDPTransportKeepsDatagramBoundaries is the property that makes this a
// separate transport: for quicfake, one segment is one QUIC Initial, and merging
// two segments would change what the peer receives rather than merely how.
func TestUDPTransportKeepsDatagramBoundaries(t *testing.T) {
	ut, server := udpPair(t)

	p := strategy.Plan{
		Spec:    "quicfake:count=1",
		Payload: []byte("FAKEREAL"),
		Segments: []strategy.Segment{
			{Kind: strategy.SegStream, Data: []byte("FAKE"), TTL: 2, Note: "decoy initial"},
			{Kind: strategy.SegStream, Data: []byte("REAL")},
		},
	}
	// The compatibility check that actually matters: strategy.Plan.Caps derives
	// CapSockTTL from any segment carrying a TTL, so a UDP transport that only
	// advertised CapUDPTTL would reject every quicfake plan.
	if missing := ut.Caps().Missing(p.Caps()); missing != 0 {
		t.Fatalf("UDP transport is missing %s for a quicfake plan (has %s, needs %s)",
			missing, ut.Caps(), p.Caps())
	}

	if err := (&Sender{}).Send(context.Background(), ut, p); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	for _, want := range []string{"FAKE", "REAL"} {
		buf := make([]byte, 64)
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("read datagram %q: %v", want, err)
		}
		if got := string(buf[:n]); got != want {
			t.Fatalf("datagram = %q, want %q: segments were merged", got, want)
		}
	}

	// The hop limit must be back at the kernel default; the socket goes on to
	// relay the rest of the QUIC session.
	def, err := defaultHopLimit(false)
	if err != nil {
		t.Fatalf("defaultHopLimit: %v", err)
	}
	if got, err := ut.ttl(); err != nil || got != def {
		t.Fatalf("hop limit after the plan = (%d, %v), want the default %d", got, err, def)
	}
}

func TestUDPTransportTTLRoundTrip(t *testing.T) {
	ut, _ := udpPair(t)
	if !ut.Caps().Has(strategy.CapUDPTTL) {
		t.Fatalf("caps = %s, want CapUDPTTL on darwin", ut.Caps())
	}
	if err := ut.SetTTL(2); err != nil {
		t.Fatalf("SetTTL: %v", err)
	}
	if got, err := ut.ttl(); err != nil || got != 2 {
		t.Fatalf("hop limit = (%d, %v), want 2", got, err)
	}
	for _, v := range []int{0, 256} {
		if err := ut.SetTTL(v); err == nil {
			t.Fatalf("SetTTL(%d) was accepted", v)
		}
	}
	if err := ut.ResetTTL(); err != nil {
		t.Fatalf("ResetTTL: %v", err)
	}
}

func TestUDPTransportWithholdsTCPOnlyCapabilities(t *testing.T) {
	ut, _ := udpPair(t)

	if _, err := ut.WriteOOB([]byte{'X'}); !errors.Is(err, ErrCapUnavailable) {
		t.Fatalf("WriteOOB err = %v, want ErrCapUnavailable: there is no urgent pointer on UDP", err)
	}
	if err := ut.InjectRaw([]byte{0x45}); !errors.Is(err, ErrCapUnavailable) {
		t.Fatalf("InjectRaw err = %v, want ErrCapUnavailable", err)
	}
	if s, ok := ut.SeqState(); ok || s != (SeqState{}) {
		t.Fatalf("SeqState = (%+v, %v), want the zero value and false", s, ok)
	}
	if ut.Caps().Has(strategy.CapOOB) || ut.Caps().Has(strategy.CapRawInject) {
		t.Fatalf("caps = %s, must not claim TCP-only capabilities", ut.Caps())
	}
	if !ut.Local().IsValid() || !ut.Remote().IsValid() {
		t.Fatalf("addresses = %s -> %s", ut.Local(), ut.Remote())
	}
	if ut.Conn() == nil {
		t.Fatal("Conn() is nil: the caller cannot relay datagrams afterwards")
	}
	if err := ut.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNewUDPTransportRequiresAConnectedSocket(t *testing.T) {
	if _, err := NewUDPTransport(nil); err == nil {
		t.Fatal("NewUDPTransport accepted nil")
	}
	// An unconnected socket has no remote address, so every Write would fail one
	// datagram at a time instead of once, here.
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer c.Close()
	if _, err := NewUDPTransport(c); err == nil {
		t.Fatal("NewUDPTransport accepted an unconnected socket")
	}
}
