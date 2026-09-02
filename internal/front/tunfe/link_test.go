package tunfe

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"testing"
	"time"
)

// closedLinkErrors is every spelling of "the device went away" this package has
// to recognise as a clean shutdown rather than a failure.
func closedLinkErrors() []error {
	return []error{ErrLinkClosed, net.ErrClosed, io.EOF, fs.ErrClosed,
		fmt.Errorf("read: %w", net.ErrClosed)}
}

// TestPipeCarriesPacketsBothWays: what one end writes at offset, the other end
// reads at offset, with the packet intact and its length reported. That is the
// whole contract everything above the device is written against.
func TestPipeCarriesPacketsBothWays(t *testing.T) {
	t.Parallel()
	a, b := NewPipe(0)
	pkt := []byte{0x45, 0x00, 0x00, 0x14, 0xde, 0xad, 0xbe, 0xef}

	out := make([]byte, LinkOffset+len(pkt))
	copy(out[LinkOffset:], pkt)
	if n, err := a.Write([][]byte{out}, LinkOffset); n != 1 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}

	bufs := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	n, err := b.Read(bufs, sizes, LinkOffset)
	if err != nil || n != 1 {
		t.Fatalf("Read = %d, %v", n, err)
	}
	if sizes[0] != len(pkt) {
		t.Fatalf("read size = %d, want %d", sizes[0], len(pkt))
	}
	if got := bufs[0][LinkOffset : LinkOffset+sizes[0]]; !bytes.Equal(got, pkt) {
		t.Fatalf("read % x, want % x", got, pkt)
	}
	// The bytes before the offset are the device's own scratch and must not
	// have been touched by the write path.
	if got := bufs[0][:LinkOffset]; !bytes.Equal(got, make([]byte, LinkOffset)) {
		t.Fatalf("the address-family prefix was written into the read buffer: % x", got)
	}

	if s := a.Stats(); s.Writes != 1 {
		t.Fatalf("writer stats = %+v, want one write", s)
	}
	if s := b.Stats(); s.Reads != 1 {
		t.Fatalf("reader stats = %+v, want one read", s)
	}
}

// TestPipeReadRefusesAShortBuffer: a packet larger than the read buffer is an
// error, not a silent truncation. A truncated IP packet delivered to a netstack
// is worse than a dropped one.
func TestPipeReadRefusesAShortBuffer(t *testing.T) {
	t.Parallel()
	a, b := NewPipe(0)
	out := make([]byte, LinkOffset+64)
	if _, err := a.Write([][]byte{out}, LinkOffset); err != nil {
		t.Fatalf("Write: %v", err)
	}
	bufs := [][]byte{make([]byte, LinkOffset+8)}
	if _, err := b.Read(bufs, make([]int, 1), LinkOffset); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Read into a short buffer = %v, want io.ErrShortBuffer", err)
	}
}

// TestPipeReadRejectsAMissingSizeSlot: sizes must have room for every buffer,
// or a read would report a length nobody can see.
func TestPipeReadRejectsAMissingSizeSlot(t *testing.T) {
	t.Parallel()
	a, _ := NewPipe(0)
	if _, err := a.Read([][]byte{make([]byte, 64)}, nil, LinkOffset); err == nil {
		t.Fatal("Read accepted a buffer list with no size slots")
	}
	if _, err := a.Read(nil, nil, LinkOffset); err == nil {
		t.Fatal("Read accepted an empty buffer list")
	}
}

// TestPipeDropsRatherThanBlocks: a real link drops when its queue is full.
// Blocking would let a stalled reader deadlock the netstack feeding it, which
// on the server side is the device read loop itself.
func TestPipeDropsRatherThanBlocks(t *testing.T) {
	t.Parallel()
	a, _ := NewPipe(0)
	out := make([]byte, LinkOffset+4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < pipeDepth+10; i++ {
			if _, err := a.Write([][]byte{out}, LinkOffset); err != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Write blocked on a full queue")
	}
	if s := a.Stats(); s.Dropped == 0 {
		t.Fatalf("stats = %+v, want the overflow counted as dropped", s)
	}
}

// TestClosedPipeFailsEveryOperation: a device that has gone away reports it, on
// every call, rather than pretending to carry packets.
func TestClosedPipeFailsEveryOperation(t *testing.T) {
	t.Parallel()
	a, b := NewPipe(0)
	// Queue a packet first, so the close has to win over a readable queue.
	out := make([]byte, LinkOffset+4)
	if _, err := a.Write([][]byte{out}, LinkOffset); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := b.Read([][]byte{make([]byte, 64)}, make([]int, 1), LinkOffset); !errors.Is(err, ErrLinkClosed) {
		t.Fatalf("Read on a closed link = %v, want ErrLinkClosed", err)
	}
	if _, err := b.Write([][]byte{out}, LinkOffset); !errors.Is(err, ErrLinkClosed) {
		t.Fatalf("Write on a closed link = %v, want ErrLinkClosed", err)
	}
	if _, err := b.Name(); !errors.Is(err, ErrLinkClosed) {
		t.Fatalf("Name on a closed link = %v, want ErrLinkClosed", err)
	}
}

// TestPipeMetadata covers the values the bring-up sequence reads off a device.
func TestPipeMetadata(t *testing.T) {
	t.Parallel()
	a, _ := NewPipe(1400)
	if mtu, err := a.MTU(); err != nil || mtu != 1400 {
		t.Fatalf("MTU = %d, %v", mtu, err)
	}
	if n := a.BatchSize(); n < 1 {
		t.Fatalf("BatchSize = %d", n)
	}
	a.SetName("utun9")
	if name, err := a.Name(); err != nil || name != "utun9" {
		t.Fatalf("Name = %q, %v", name, err)
	}
	a.Emit(EventUp)
	select {
	case ev := <-a.Events():
		if ev != EventUp {
			t.Fatalf("event = %v, want up", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no event arrived")
	}
	// A full event channel drops rather than blocking the device's reader.
	for i := 0; i < 100; i++ {
		a.Emit(EventDown)
	}
}

// TestEventNames keeps the log line readable, including for a value the device
// never emits.
func TestEventNames(t *testing.T) {
	t.Parallel()
	cases := map[Event]string{
		EventUp:        "up",
		EventDown:      "down",
		EventMTUUpdate: "mtu-update",
		Event(0):       "event(0)",
		Event(99):      "event(99)",
	}
	for ev, want := range cases {
		if got := ev.String(); got != want {
			t.Fatalf("Event(%d).String() = %q, want %q", uint8(ev), got, want)
		}
	}
}

// TestQUICPolicyNames covers the same for the policy enum, which appears in
// status output.
func TestQUICPolicyNames(t *testing.T) {
	t.Parallel()
	if got := QUICRefuse.String(); got != "refuse" {
		t.Fatalf("QUICRefuse = %q", got)
	}
	if got := QUICRelay.String(); got != "relay" {
		t.Fatalf("QUICRelay = %q", got)
	}
	if got := QUICPolicy(9).String(); got != "quicpolicy(9)" {
		t.Fatalf("QUICPolicy(9) = %q", got)
	}
}

// TestIsClosedLinkErrRecognisesShutdown: a device that went away during
// shutdown must not be reported as a failure, however the closure was spelled.
func TestIsClosedLinkErrRecognisesShutdown(t *testing.T) {
	t.Parallel()
	for _, err := range closedLinkErrors() {
		if !isClosedLinkErr(err) {
			t.Fatalf("%v was not recognised as a closed device", err)
		}
	}
	if isClosedLinkErr(errors.New("input/output error")) {
		t.Fatal("a genuine device error was mistaken for a clean close")
	}
}
