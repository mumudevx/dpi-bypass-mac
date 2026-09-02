package flow

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// udpSink is a loopback UDP socket that collects whole datagrams, so a test can
// assert boundaries rather than bytes.
func udpSink(t *testing.T) (*net.UDPConn, netip.AddrPort) {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	ap := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	return pc, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func readDatagram(t *testing.T, pc *net.UDPConn) []byte {
	t.Helper()
	if err := pc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	return buf[:n]
}

// quicInitialFixture is an RFC 9000 §17.2 v1 Initial, built rather than
// captured so the parser under test is not also the fixture's author.
func quicInitialFixture(payload int) []byte {
	b := []byte{0xc0}
	b = binary.BigEndian.AppendUint32(b, tlsmsg.QUICVersion1)
	b = append(b, 8, 1, 2, 3, 4, 5, 6, 7, 8) // DCID
	b = append(b, 0)                         // zero-length SCID
	b = append(b, 0)                         // zero-length token
	b = binary.BigEndian.AppendUint16(b, uint16(payload)|0x4000)
	return append(b, make([]byte, payload)...)
}

// TestNetUDPDialerConnectsByAddressOnly: the datagram path never resolves. The
// dialer takes a netip.AddrPort and nothing else, so there is no shape in which
// a name could reach Go's resolver (MEASUREMENTS.md §5.4).
func TestNetUDPDialerConnectsByAddressOnly(t *testing.T) {
	sink, dst := udpSink(t)
	d := &NetUDPDialer{Logf: t.Logf}
	c, err := d.DialUDP(context.Background(), dst)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := string(readDatagram(t, sink)); got != "hello" {
		t.Fatalf("datagram = %q", got)
	}
	if _, ok := c.(*net.UDPConn); !ok {
		t.Fatalf("conn is %T, want *net.UDPConn: the desync path needs packet boundaries", c)
	}
}

func TestNetUDPDialerRefusesAnUnusableDestination(t *testing.T) {
	d := &NetUDPDialer{}
	for _, dst := range []netip.AddrPort{
		{}, // no address at all
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0),
	} {
		if _, err := d.DialUDP(context.Background(), dst); err == nil {
			t.Fatalf("DialUDP(%v) was accepted", dst)
		}
	}
}

// TestNetUDPDialerReportsAnUnbindableInterface: in TUN mode an unbound upstream
// socket is routed back into our own netstack and loops. Failing the dial is
// the only safe answer; a silent unbound socket is the loop.
func TestNetUDPDialerReportsAnUnbindableInterface(t *testing.T) {
	_, dst := udpSink(t)
	d := &NetUDPDialer{Interface: "utun-does-not-exist"}
	c, err := d.DialUDP(context.Background(), dst)
	if err == nil {
		c.Close()
		t.Fatal("a socket that could not be pinned to the uplink was returned anyway")
	}
	if !strings.Contains(err.Error(), "utun-does-not-exist") {
		t.Errorf("the error must name the interface: %v", err)
	}
}

// TestSendFirstDatagramPlainIsOneWrite: the shipped default applies no strategy
// at all, and one datagram in must be one datagram out.
func TestSendFirstDatagramPlainIsOneWrite(t *testing.T) {
	sink, dst := udpSink(t)
	c, err := (&NetUDPDialer{}).DialUDP(context.Background(), dst)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer c.Close()

	first := quicInitialFixture(64)
	if err := SendFirstDatagram(context.Background(), c, first, strategy.Strategy{}, nil, 443); err != nil {
		t.Fatalf("SendFirstDatagram: %v", err)
	}
	if got := readDatagram(t, sink); string(got) != string(first) {
		t.Fatalf("the plain datagram was altered: %d bytes vs %d", len(got), len(first))
	}
}

// TestSendFirstDatagramAppliesAUDPStrategy is the end of the A7 chain: a
// quicfake spec now reaches the wire as decoys plus the real datagram, on the
// socket the flow goes on using. Before the segment-kind fix this returned a
// capability error and nothing was sent.
func TestSendFirstDatagramAppliesAUDPStrategy(t *testing.T) {
	sink, dst := udpSink(t)
	c, err := (&NetUDPDialer{}).DialUDP(context.Background(), dst)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer c.Close()

	st, err := strategy.Parse("quicfake:count=2,ttl=3")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	first := quicInitialFixture(200)
	if err := SendFirstDatagram(context.Background(), c, first, st, nil, 443); err != nil {
		t.Fatalf("SendFirstDatagram: %v", err)
	}

	real0, ok := tlsmsg.ParseQUICInitial(first)
	if !ok {
		t.Fatal("fixture is not a QUIC Initial")
	}
	for i := 0; i < 2; i++ {
		d := readDatagram(t, sink)
		q, ok := tlsmsg.ParseQUICInitial(d)
		if !ok {
			t.Fatalf("decoy %d is not a QUIC Initial", i)
		}
		if string(q.DCID(d)) != string(real0.DCID(first)) {
			t.Errorf("decoy %d does not carry the real DCID", i)
		}
		if string(d) == string(first) {
			t.Errorf("decoy %d is the real datagram", i)
		}
	}
	if got := readDatagram(t, sink); string(got) != string(first) {
		t.Fatal("the real datagram must arrive last and unmodified")
	}
}

// TestSendFirstDatagramRefusesAStreamConnection: segment boundaries are packet
// boundaries only on a datagram socket. On anything else a decoy would be
// prepended to the payload, which is corruption, so this fails closed.
func TestSendFirstDatagramRefusesAStreamConnection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	st, err := strategy.Parse("quicfake:count=1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = SendFirstDatagram(context.Background(), a, quicInitialFixture(64), st, nil, 443)
	if !errors.Is(err, ErrNotDatagram) {
		t.Fatalf("err = %v, want ErrNotDatagram", err)
	}
}

// TestSendFirstDatagramNamesACapabilityShortfall: a strategy the socket cannot
// satisfy is refused with the missing capability named, never downgraded to a
// plain datagram the caller believes was desynced.
func TestSendFirstDatagramNamesACapabilityShortfall(t *testing.T) {
	_, dst := udpSink(t)
	c, err := (&NetUDPDialer{}).DialUDP(context.Background(), dst)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer c.Close()

	st, err := strategy.Parse("oob:pos=1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = SendFirstDatagram(context.Background(), c, quicInitialFixture(64), st, nil, 443)
	if !errors.Is(err, strategy.ErrCapUnavailable) {
		t.Fatalf("err = %v, want ErrCapUnavailable", err)
	}
	if !strings.Contains(err.Error(), "oob") {
		t.Errorf("the shortfall must be named: %v", err)
	}
}

func TestSendFirstDatagramRejectsEmptyInput(t *testing.T) {
	if err := SendFirstDatagram(context.Background(), nil, []byte("x"), strategy.Strategy{}, nil, 443); err == nil {
		t.Error("a nil connection was accepted")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := SendFirstDatagram(context.Background(), a, nil, strategy.Strategy{}, nil, 443); err == nil {
		t.Error("an empty datagram was accepted")
	}
}
