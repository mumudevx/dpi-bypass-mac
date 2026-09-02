//go:build darwin

package tunfe

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// TestOpenDeviceRejectsANameTheKernelCannotUse is the one thing about the real
// device that can be checked without root.
//
// wireguard/tun parses the name before it opens anything — a utun unit number
// is the kernel's control-socket unit, so "eth0" cannot name one — and this
// asserts the wrapper reports that as an error naming the device rather than
// panicking or returning a nil Link with a nil error.
//
// Everything else in link_darwin.go needs a utun, which needs root. That is
// what deviceLink's wgDevice seam is for: the translation below is tested with
// a fake device, so what remains unexercised without root is one CreateTUN
// call.
func TestOpenDeviceRejectsANameTheKernelCannotUse(t *testing.T) {
	t.Parallel()
	l, err := OpenDevice("eth0", DefaultMTU, t.Logf)
	if err == nil {
		if l != nil {
			_ = l.Close()
		}
		t.Fatal("OpenDevice accepted a name that cannot be a utun unit")
	}
	if l != nil {
		t.Fatal("OpenDevice returned a Link alongside an error")
	}
	if !strings.Contains(err.Error(), "eth0") {
		t.Fatalf("error %q does not name the device that failed", err)
	}
}

// TestDeviceLinkTranslatesTheOffsetContract: the wrapper passes the offset
// through untouched to the device, which is what makes the 4-byte
// address-family prefix land where wireguard/tun expects it — and it refuses an
// offset below 4 rather than letting the library corrupt the packet.
func TestDeviceLinkTranslatesTheOffsetContract(t *testing.T) {
	t.Parallel()
	dev := &fakeWGDevice{name: "utun4", mtu: 1400, batch: 3, events: make(chan wgtun.Event, 4)}
	l := newDeviceLink(dev, t.Logf)

	pkt := []byte{0x45, 0, 0, 20, 9, 9}
	out := make([]byte, LinkOffset+len(pkt))
	copy(out[LinkOffset:], pkt)
	if _, err := l.Write([][]byte{out}, LinkOffset); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if dev.wroteOffset != LinkOffset {
		t.Fatalf("device saw offset %d, want %d", dev.wroteOffset, LinkOffset)
	}
	if !bytes.Equal(dev.written, out) {
		t.Fatalf("device received % x, want % x", dev.written, out)
	}

	dev.next = pkt
	bufs := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	n, err := l.Read(bufs, sizes, LinkOffset)
	if err != nil || n != 1 {
		t.Fatalf("Read = %d, %v", n, err)
	}
	if got := bufs[0][LinkOffset : LinkOffset+sizes[0]]; !bytes.Equal(got, pkt) {
		t.Fatalf("read % x, want % x", got, pkt)
	}

	for _, offset := range []int{0, 3} {
		if _, err := l.Read(bufs, sizes, offset); !errors.Is(err, io.ErrShortBuffer) {
			t.Fatalf("Read at offset %d = %v, want io.ErrShortBuffer", offset, err)
		}
		if _, err := l.Write([][]byte{out}, offset); !errors.Is(err, io.ErrShortBuffer) {
			t.Fatalf("Write at offset %d = %v, want io.ErrShortBuffer", offset, err)
		}
	}
}

// TestDeviceLinkReportsWhatTheKernelGaveUs: Name comes from the device, never
// from the name that was requested. Every route and ifconfig Op is told this
// name, so getting it from the request would configure an interface that does
// not exist when the kernel picked a different unit.
func TestDeviceLinkReportsWhatTheKernelGaveUs(t *testing.T) {
	t.Parallel()
	dev := &fakeWGDevice{name: "utun11", mtu: 1400, batch: 2, events: make(chan wgtun.Event, 4)}
	l := newDeviceLink(dev, nil)

	if name, err := l.Name(); err != nil || name != "utun11" {
		t.Fatalf("Name = %q, %v", name, err)
	}
	if mtu, err := l.MTU(); err != nil || mtu != 1400 {
		t.Fatalf("MTU = %d, %v", mtu, err)
	}
	if got := l.BatchSize(); got != 2 {
		t.Fatalf("BatchSize = %d, want the device's 2", got)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !dev.closed() {
		t.Fatal("Close did not reach the device")
	}
}

// TestDeviceLinkPumpsEvents: the device's channel MUST be drained. It is fed by
// a route-socket reader over a buffer of ten, and that reader wedges
// permanently once nobody is listening — after which no interface event is ever
// seen again. The pump also drops rather than blocking, so a supervisor that
// stops reading cannot wedge the device either.
func TestDeviceLinkPumpsEvents(t *testing.T) {
	t.Parallel()
	dev := &fakeWGDevice{name: "utun4", mtu: 1400, batch: 1, events: make(chan wgtun.Event, 32)}
	l := newDeviceLink(dev, nil)

	dev.events <- wgtun.EventUp
	dev.events <- wgtun.EventMTUUpdate
	dev.events <- wgtun.Event(0xff) // unknown: dropped, not translated to garbage
	dev.events <- wgtun.EventDown

	want := []Event{EventUp, EventMTUUpdate, EventDown}
	for _, w := range want {
		select {
		case got := <-l.Events():
			if got != w {
				t.Fatalf("event = %v, want %v", got, w)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("no %v event arrived", w)
		}
	}

	// Far more events than our own channel holds: the pump must keep consuming
	// the device's channel regardless.
	for i := 0; i < 100; i++ {
		dev.events <- wgtun.EventUp
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(dev.events) > 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if n := len(dev.events); n != 0 {
		t.Fatalf("%d event(s) left undrained on the device; its route-socket reader is wedged", n)
	}
	close(dev.events)
}

// fakeWGDevice is a wireguard/tun device that touches no kernel.
type fakeWGDevice struct {
	name        string
	mtu         int
	batch       int
	events      chan wgtun.Event
	next        []byte
	written     []byte
	wroteOffset int

	mu     sync.Mutex
	isDown bool
}

func (d *fakeWGDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(d.next) == 0 {
		return 0, io.EOF
	}
	copy(bufs[0][offset:], d.next)
	sizes[0] = len(d.next)
	d.next = nil
	return 1, nil
}

func (d *fakeWGDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.wroteOffset = offset
	d.written = append([]byte(nil), bufs[0]...)
	return len(bufs), nil
}

func (d *fakeWGDevice) MTU() (int, error)          { return d.mtu, nil }
func (d *fakeWGDevice) Name() (string, error)      { return d.name, nil }
func (d *fakeWGDevice) Events() <-chan wgtun.Event { return d.events }
func (d *fakeWGDevice) BatchSize() int             { return d.batch }

func (d *fakeWGDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.isDown = true
	return nil
}

func (d *fakeWGDevice) closed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.isDown
}
