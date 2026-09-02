// These tests drive real Darwin sockets and the darwin-only socket-option
// helpers, so they are tagged rather than skipped: on any other GOOS the
// capabilities they assert are withheld by construction (stub_other.go).
//go:build darwin

package emit

import (
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// sysctlInt reads a sysctl through sysctl(8) — a different reader than the one
// under test, so a bug in our unix.Sysctl call cannot hide behind itself.
func sysctlInt(t *testing.T, name string) int {
	t.Helper()
	out, err := exec.Command("sysctl", "-n", name).Output()
	if err != nil {
		t.Skipf("sysctl(8) unavailable: %v", err)
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("sysctl -n %s printed %q: %v", name, out, err)
	}
	return v
}

// TestOOBByteIsStrippedFromThePeerStream is the whole point of the oob rung
// (MEASUREMENTS.md §3: `oob-at-1` and `oob-at-3` scored 3/3 on all three blocked
// targets, and §5.3 ships `oob:pos=1` as rung 5). The junk byte must reach the
// DPI in band and the origin's TCP out of band, so the peer's application sees
// the payload untouched.
func TestOOBByteIsStrippedFromThePeerStream(t *testing.T) {
	st, peer := loopbackPair(t, "tcp4", "127.0.0.1:0")
	if !st.Caps().Has(strategy.CapOOB) {
		t.Fatalf("caps = %s, want CapOOB on darwin", st.Caps())
	}

	if _, err := st.Write([]byte("ab")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if n, err := st.WriteOOB([]byte{'X'}); err != nil || n != 1 {
		t.Fatalf("WriteOOB = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := st.Write([]byte("cde")); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "abcde" {
		t.Fatalf("peer read %q, want %q: the urgent byte leaked into the in-band stream", buf, "abcde")
	}

	// Nothing else may follow: if the junk byte were inline there would be a
	// sixth byte waiting.
	if err := peer.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	extra := make([]byte, 1)
	n, err := peer.Read(extra)
	if err == nil {
		t.Fatalf("peer read a further %d byte(s) (%q); the stream must end at %q", n, extra[:n], "abcde")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("read after the payload = %v, want a timeout", err)
	}
}

func TestWriteOOBRefusesMoreThanOneByte(t *testing.T) {
	st, _ := loopbackPair(t, "tcp4", "127.0.0.1:0")
	// MSG_OOB marks only the LAST byte urgent, so a two-byte urgent write would
	// put the first byte in band and corrupt the payload the plan promised.
	if _, err := st.WriteOOB([]byte("XY")); err == nil {
		t.Fatal("WriteOOB accepted 2 bytes; only the last would be urgent")
	}
	if _, err := st.WriteOOB(nil); err == nil {
		t.Fatal("WriteOOB accepted an empty urgent write")
	}
}

// TestTTLIsSetOnTheSocketAndRestoredEvenWhenTheWriteFails reads the hop limit
// back through getsockopt rather than trusting setsockopt's return value, and
// asserts the socket is left at the kernel default from sysctl net.inet.ip.ttl
// (DOSSIER §3: read the real default TTL, never hardcode 64).
func TestTTLIsSetOnTheSocketAndRestoredEvenWhenTheWriteFails(t *testing.T) {
	st, _ := loopbackPair(t, "tcp4", "127.0.0.1:0")
	if !st.Caps().Has(strategy.CapSockTTL) {
		t.Fatalf("caps = %s, want CapSockTTL on darwin", st.Caps())
	}
	def, err := DefaultTTL()
	if err != nil {
		t.Fatalf("DefaultTTL: %v", err)
	}
	if got, err := st.ttl(); err != nil || got != def {
		t.Fatalf("fresh socket ttl = (%d, %v), want the kernel default %d", got, err, def)
	}

	var seen int
	fw := &failingWriteTransport{
		Transport: st,
		onWrite: func() {
			// Read the socket's real hop limit at the instant the segment is on
			// the wire; this is the disorder mechanism (GT11) actually happening.
			v, err := st.ttl()
			if err != nil {
				t.Errorf("read ttl during the write: %v", err)
			}
			seen = v
		},
	}

	p := streamPlan("disorder:pos=3", "ab")
	p.Segments[0].TTL = 1

	err = (&Sender{}).Send(context.Background(), fw, p)
	if !errors.Is(err, errSimulatedWrite) {
		t.Fatalf("Send err = %v, want the simulated write failure", err)
	}
	if seen != 1 {
		t.Fatalf("hop limit during the write = %d, want 1", seen)
	}
	got, err := st.ttl()
	if err != nil {
		t.Fatalf("read ttl after Send: %v", err)
	}
	if got != def {
		t.Fatalf("hop limit left at %d after a failed write, want the default %d: "+
			"the socket is about to become the relay", got, def)
	}
}

func TestTTLRoundTripsOnIPv6(t *testing.T) {
	st, _ := loopbackPair(t, "tcp6", "[::1]:0")
	if !st.Caps().Has(strategy.CapSockTTL) {
		t.Fatalf("caps = %s, want CapSockTTL", st.Caps())
	}
	if err := st.SetTTL(3); err != nil {
		t.Fatalf("SetTTL on an IPv6 socket: %v", err)
	}
	if got, err := st.ttl(); err != nil || got != 3 {
		t.Fatalf("IPv6 hop limit = (%d, %v), want 3", got, err)
	}
	if err := st.ResetTTL(); err != nil {
		t.Fatalf("ResetTTL: %v", err)
	}
	def, err := defaultHopLimit(true)
	if err != nil {
		t.Fatalf("defaultHopLimit(v6): %v", err)
	}
	if got, _ := st.ttl(); got != def {
		t.Fatalf("IPv6 hop limit after reset = %d, want %d", got, def)
	}
}

func TestSetTTLRejectsAnOutOfRangeHopLimit(t *testing.T) {
	st, _ := loopbackPair(t, "tcp4", "127.0.0.1:0")
	for _, v := range []int{0, -1, 256} {
		if err := st.SetTTL(v); err == nil {
			t.Fatalf("SetTTL(%d) was accepted", v)
		}
	}
}

// TestSeqStateIsNeverAvailable pins the reason the seqovl / fakedsplit family is
// registered-but-rejected: struct tcp_connection_info in the macOS 26 SDK's
// netinet/tcp.h has no snd_nxt field, so a kernel socket cannot report its own
// send sequence and CapRawSeq can never be granted. If this ever returns true,
// the whole unreachable-op family needs revisiting, not this test.
func TestSeqStateIsNeverAvailable(t *testing.T) {
	st, _ := loopbackPair(t, "tcp4", "127.0.0.1:0")
	if s, ok := st.SeqState(); ok || s != (SeqState{}) {
		t.Fatalf("SeqState = (%+v, %v), want the zero value and false", s, ok)
	}
	if st.Caps().Has(strategy.CapRawSeq) {
		t.Fatalf("caps = %s, must never include rawseq", st.Caps())
	}
}

func TestSockTransportCapsAndAddresses(t *testing.T) {
	st, peer := loopbackPair(t, "tcp4", "127.0.0.1:0")

	want := strategy.CapStreamWrite | strategy.CapNoDelay | strategy.CapSockTTL |
		strategy.CapUDPTTL | strategy.CapOOB
	if st.Caps() != want {
		t.Fatalf("caps = %s, want %s", st.Caps(), want)
	}
	if !st.Local().IsValid() || !st.Remote().IsValid() {
		t.Fatalf("addresses = %s -> %s, both must be valid", st.Local(), st.Remote())
	}
	if st.Remote().String() != peer.LocalAddr().String() {
		t.Fatalf("Remote() = %s, peer's local address is %s", st.Remote(), peer.LocalAddr())
	}
	if st.Conn() == nil {
		t.Fatal("Conn() is nil: the front-end cannot relay on the socket")
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestInjectRawIsUnavailableWithoutAnInjector(t *testing.T) {
	st, _ := loopbackPair(t, "tcp4", "127.0.0.1:0")
	err := st.InjectRaw([]byte{0x45})
	if !errors.Is(err, ErrCapUnavailable) {
		t.Fatalf("InjectRaw err = %v, want ErrCapUnavailable", err)
	}
	if st.Caps().Has(strategy.CapRawInject) {
		t.Fatalf("caps = %s, must not advertise rawinject without an injector", st.Caps())
	}
}

func TestInjectRawUsesTheInjectorWhenPresent(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	inj := &fakeInjector{}
	st, err := NewSockTransport(c.(*net.TCPConn), inj)
	if err != nil {
		t.Fatalf("NewSockTransport: %v", err)
	}
	if !st.Caps().Has(strategy.CapRawInject) {
		t.Fatalf("caps = %s, want rawinject", st.Caps())
	}
	if err := st.InjectRaw([]byte{0x45, 0x00}); err != nil {
		t.Fatalf("InjectRaw: %v", err)
	}
	if len(inj.pkts) != 1 {
		t.Fatalf("injector saw %d packets, want 1", len(inj.pkts))
	}

	inj.err = errors.New("route lookup failed")
	if err := st.InjectRaw([]byte{0x45}); err == nil || !strings.Contains(err.Error(), "route lookup failed") {
		t.Fatalf("InjectRaw err = %v, want the injector's error wrapped", err)
	}

	// Close must not close the injector: it is a process-wide resource shared by
	// every transport.
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if inj.closed {
		t.Fatal("Close closed a shared raw injector")
	}
}

func TestNewSockTransportRejectsNil(t *testing.T) {
	if _, err := NewSockTransport(nil, nil); err == nil {
		t.Fatal("NewSockTransport accepted a nil connection")
	}
}

func TestNewSockTransportRejectsAClosedConnection(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tc := c.(*net.TCPConn)
	if err := tc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := NewSockTransport(tc, nil); err == nil {
		t.Fatal("NewSockTransport accepted a closed connection")
	}
}

// TestDefaultTTLMatchesTheKernel verifies our sysctl read against the same value
// a user would see from sysctl(8) — an independent reader, in the spirit of the
// rest of the tree.
func TestDefaultTTLMatchesTheKernel(t *testing.T) {
	got, err := DefaultTTL()
	if err != nil {
		t.Fatalf("DefaultTTL: %v", err)
	}
	if got < 1 || got > 255 {
		t.Fatalf("DefaultTTL = %d, out of range", got)
	}
	want := sysctlInt(t, "net.inet.ip.ttl")
	if got != want {
		t.Fatalf("DefaultTTL = %d, sysctl net.inet.ip.ttl = %d", got, want)
	}
	// Verified 64 on the development machine, 2026-09-02 (DOSSIER §3). The value
	// is asserted against the kernel, not against 64, precisely because it is a
	// tunable.
	if v6, err := defaultHopLimit(true); err != nil || v6 < 1 || v6 > 255 {
		t.Fatalf("defaultHopLimit(v6) = (%d, %v)", v6, err)
	}
}

func TestReadTTLSysctlRejectsAnAbsentOrInsaneKey(t *testing.T) {
	if _, err := readTTLSysctl("net.inet.ip.dpb_no_such_key"); err == nil {
		t.Fatal("readTTLSysctl accepted a nonexistent key")
	}
	// A sysctl that is not a hop limit at all must not be mistaken for one.
	if v, err := readTTLSysctl("net.inet.tcp.sendspace"); err == nil {
		t.Fatalf("readTTLSysctl(net.inet.tcp.sendspace) = %d, want a range rejection", v)
	}
}

func TestHopLimitHelpersRejectANilRawConn(t *testing.T) {
	if err := setHopLimit(nil, false, 1); err == nil {
		t.Fatal("setHopLimit accepted a nil raw conn")
	}
	if _, err := getHopLimit(nil, false); err == nil {
		t.Fatal("getHopLimit accepted a nil raw conn")
	}
	if _, err := sendOOB(nil, []byte{'X'}); err == nil {
		t.Fatal("sendOOB accepted a nil raw conn")
	}
}

func TestToAddrPort(t *testing.T) {
	if got := toAddrPort(nil); got.IsValid() {
		t.Fatalf("toAddrPort(nil) = %s, want the zero value", got)
	}
	if got := toAddrPort(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 53}); got.Port() != 53 {
		t.Fatalf("toAddrPort(UDPAddr) = %s", got)
	}
	if got := toAddrPort(&net.UnixAddr{Name: "/tmp/x"}); got.IsValid() {
		t.Fatalf("toAddrPort(UnixAddr) = %s, want the zero value", got)
	}
}

var errSimulatedWrite = errors.New("simulated write failure")

// failingWriteTransport delegates every socket operation to a real SockTransport
// but refuses the write, so a test can assert the TTL restore path against a real
// file descriptor without needing a peer that resets at the right moment.
type failingWriteTransport struct {
	Transport
	onWrite func()
}

func (f *failingWriteTransport) Write([]byte) (int, error) {
	if f.onWrite != nil {
		f.onWrite()
	}
	return 0, errSimulatedWrite
}

type fakeInjector struct {
	pkts   [][]byte
	err    error
	closed bool
}

func (f *fakeInjector) Inject(pkt []byte) error {
	if f.err != nil {
		return f.err
	}
	f.pkts = append(f.pkts, append([]byte(nil), pkt...))
	return nil
}

func (f *fakeInjector) Close() error { f.closed = true; return nil }
