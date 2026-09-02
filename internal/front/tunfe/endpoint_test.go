package tunfe

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TestReadLoopErrorIsSurfacedNotSwallowed is the third shipped defect. The
// previous implementation's read loop was `if err != nil { return }` — no log,
// no retry, no signal to anyone. The capture routes still pointed at the device,
// so a transient read failure became a permanent, total IPv4 blackout with no
// symptom anywhere.
func TestReadLoopErrorIsSurfacedNotSwallowed(t *testing.T) {
	t.Parallel()
	_, b := NewPipe(0)
	ep := newEndpoint(b, DefaultMTU, t.Logf)
	st := stack.New(stack.Options{})
	t.Cleanup(st.Close)
	if err := st.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}

	boom := errors.New("device read failed")
	b.FailRead(boom)

	select {
	case err := <-ep.Errors():
		if !errors.Is(err, boom) {
			t.Fatalf("surfaced %v, want it to wrap %v", err, boom)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the read loop ended without reporting the device failure")
	}
	if got := ep.stats().ReadErrors; got != 1 {
		t.Fatalf("ReadErrors = %d, want 1", got)
	}
}

// TestServeReportsADeviceFailure: the supervisor learns about it too, because
// a datapath over a dead device must be torn down rather than left running with
// the capture routes pointing at it.
func TestServeReportsADeviceFailure(t *testing.T) {
	l := newLab(t, labOpts{noStart: true})
	done := make(chan error, 1)
	go func() { done <- l.server.Serve(context.Background()) }()

	boom := errors.New("device read failed")
	l.serverLink.FailRead(boom)

	select {
	case err := <-done:
		if !errors.Is(err, boom) {
			t.Fatalf("Serve returned %v, want it to wrap the device failure %v", err, boom)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve kept running over a device that reports read failures")
	}
}

// TestClosedDeviceIsNotAFailure: a device that went away during shutdown is an
// ordinary end, not something to report as broken.
func TestClosedDeviceIsNotAFailure(t *testing.T) {
	t.Parallel()
	_, b := NewPipe(0)
	ep := newEndpoint(b, DefaultMTU, t.Logf)
	st := stack.New(stack.Options{})
	t.Cleanup(st.Close)
	if err := st.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	_ = b.Close()

	select {
	case err := <-ep.Errors():
		t.Fatalf("a closed device was reported as a failure: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if got := ep.stats().ReadErrors; got != 0 {
		t.Fatalf("ReadErrors = %d after a clean close, want 0", got)
	}
}

// TestViewsAreReleased is the leak counter the plan asks for: every pooled View
// WritePackets takes from gVisor must be handed back. The previous
// implementation called ToView() with no Release, so the pool never got a
// packet back and the process grew for the life of the run.
//
// The counter is the endpoint's own accounting, incremented beside the ToView
// and decremented beside the Release, so the two statements cannot be separated
// without this test failing.
func TestViewsAreReleased(t *testing.T) {
	o := newOrigin(t)
	l := newLab(t, labOpts{firstMsg: shortFirstMsg()})
	l.up.serveOn(o.addr())

	client, err := l.dial(netip.AddrPortFrom(originIP, 25))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	up := o.accept()
	for i := 0; i < 20; i++ {
		if _, err := up.Write([]byte("0123456789")); err != nil {
			t.Fatalf("origin write: %v", err)
		}
	}
	if got := readWithin(t, client, 200, 5*time.Second); len(got) != 200 {
		t.Fatalf("client read %d of 200 bytes", len(got))
	}

	st := l.server.Stats()
	t.Logf("device carried %+v; link %+v", st, l.serverLink.Stats())
	if st.PacketsOut == 0 {
		t.Fatal("no packets were written to the device, so the leak counter proves nothing")
	}
	if st.ViewsOutstanding != 0 {
		t.Fatalf("%d pooled View(s) were never released", st.ViewsOutstanding)
	}
	if st.PacketsIn == 0 {
		t.Fatal("no packets were delivered inbound")
	}
}

// TestEndpointRefusesAShortOffset pins the Darwin address-family prefix
// contract from both directions. wireguard/tun writes the 4-byte prefix into
// buf[offset-4:offset], so an offset below 4 either corrupts the first four
// bytes of the packet or writes out of bounds.
func TestEndpointRefusesAShortOffset(t *testing.T) {
	t.Parallel()
	a, _ := NewPipe(0)
	bufs := [][]byte{make([]byte, 100)}
	sizes := make([]int, 1)

	for _, offset := range []int{0, 1, 3} {
		if _, err := a.Read(bufs, sizes, offset); !errors.Is(err, io.ErrShortBuffer) {
			t.Fatalf("Read at offset %d = %v, want io.ErrShortBuffer", offset, err)
		}
		if _, err := a.Write(bufs, offset); !errors.Is(err, io.ErrShortBuffer) {
			t.Fatalf("Write at offset %d = %v, want io.ErrShortBuffer", offset, err)
		}
	}
	if LinkOffset != 4 {
		t.Fatalf("LinkOffset = %d; the Darwin device contract is 4", LinkOffset)
	}
}

// TestEndpointDeliversByFamily: the version nibble picks the network protocol,
// and anything that is neither IPv4 nor IPv6 is dropped rather than delivered
// as garbage.
func TestEndpointDeliversByFamily(t *testing.T) {
	t.Parallel()
	_, b := NewPipe(0)
	ep := newEndpoint(b, DefaultMTU, t.Logf)
	d := &countingDispatcher{}
	ep.Attach(d)
	t.Cleanup(func() { _ = b.Close(); ep.Wait() })

	if !ep.IsAttached() {
		t.Fatal("IsAttached is false after Attach")
	}

	ep.deliver([]byte{0x45, 0, 0, 20})
	ep.deliver([]byte{0x60, 0, 0, 0})
	ep.deliver([]byte{0x35, 0, 0, 0}) // neither family
	ep.deliver(nil)

	got := d.protos()
	want := []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber}
	if len(got) != len(want) {
		t.Fatalf("delivered %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delivered %v, want %v", got, want)
		}
	}
	if n := ep.stats().PacketsIn; n != 2 {
		t.Fatalf("PacketsIn = %d, want 2", n)
	}
}

// TestEndpointLinkLayerDefaults pins the values gVisor reads off a link with no
// header of its own. Capabilities must stay empty: with no checksum-offload
// capability gVisor computes and validates every checksum itself, which is what
// a tunnel with no hardware behind it needs.
func TestEndpointLinkLayerDefaults(t *testing.T) {
	t.Parallel()
	_, b := NewPipe(0)
	ep := newEndpoint(b, 0, nil)

	if got := ep.MTU(); got != DefaultMTU {
		t.Fatalf("MTU = %d, want the default %d", got, DefaultMTU)
	}
	ep.SetMTU(1400)
	if got := ep.MTU(); got != 1400 {
		t.Fatalf("MTU after SetMTU = %d", got)
	}
	if got := ep.MaxHeaderLength(); got != 0 {
		t.Fatalf("MaxHeaderLength = %d, want 0: a utun carries bare IP packets", got)
	}
	if got := ep.Capabilities(); got != 0 {
		t.Fatalf("Capabilities = %d, want 0 so gVisor computes checksums itself", got)
	}
	if got := ep.LinkAddress(); got != "" {
		t.Fatalf("LinkAddress = %q, want empty", got)
	}
	ep.SetLinkAddress("00:00:00:00:00:01")
	if got := ep.LinkAddress(); got != "" {
		t.Fatalf("LinkAddress = %q after SetLinkAddress; a point-to-point link has none", got)
	}
	if got := ep.ARPHardwareType(); got != header.ARPHardwareNone {
		t.Fatalf("ARPHardwareType = %v, want none", got)
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{0x45})})
	defer pb.DecRef()
	ep.AddHeader(pb)
	if !ep.ParseHeader(pb) {
		t.Fatal("ParseHeader returned false; there is no link header to parse")
	}
	if ep.IsAttached() {
		t.Fatal("IsAttached is true before Attach")
	}

	closed := false
	ep.SetOnCloseAction(func() { closed = true })
	ep.Close()
	ep.Close() // idempotent
	if !closed {
		t.Fatal("the on-close action did not run")
	}
	ep.Wait()
}

// TestWriteRawRefusesAnEmptyPacket: writeRaw is the path an ICMP error takes,
// and an empty packet would be a 4-byte address-family prefix with nothing
// behind it.
func TestWriteRawRefusesAnEmptyPacket(t *testing.T) {
	t.Parallel()
	_, b := NewPipe(0)
	ep := newEndpoint(b, DefaultMTU, nil)
	if err := ep.writeRaw(nil); err == nil {
		t.Fatal("writeRaw accepted an empty packet")
	}
	if err := ep.writeRaw([]byte{0x45, 0, 0, 20}); err != nil {
		t.Fatalf("writeRaw: %v", err)
	}
	if n := ep.stats().PacketsOut; n != 1 {
		t.Fatalf("PacketsOut = %d, want 1", n)
	}
}

// countingDispatcher records what the endpoint delivered.
type countingDispatcher struct {
	mu   sync.Mutex
	nums []tcpip.NetworkProtocolNumber
}

func (d *countingDispatcher) DeliverNetworkPacket(p tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {
	d.mu.Lock()
	d.nums = append(d.nums, p)
	d.mu.Unlock()
}

func (d *countingDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func (d *countingDispatcher) protos() []tcpip.NetworkProtocolNumber {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]tcpip.NetworkProtocolNumber, len(d.nums))
	copy(out, d.nums)
	return out
}

// TestServerErrorsExposesTheDeviceFailure covers the accessor a supervisor uses
// when it watches the datapath some other way than by calling Serve — `dpb
// status` polling it, say. The failure must be the same one Serve would return.
func TestServerErrorsExposesTheDeviceFailure(t *testing.T) {
	l := newLab(t, labOpts{noStart: true})
	boom := errors.New("device read failed")
	l.serverLink.FailRead(boom)

	select {
	case err := <-l.server.Errors():
		if !errors.Is(err, boom) {
			t.Fatalf("Errors() delivered %v, want it to wrap %v", err, boom)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Errors() never delivered the device failure")
	}
}
