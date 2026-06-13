//go:build darwin

package tun

import (
	"os"
	"sync"
	"testing"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// fakeTun is an in-memory tun.Device for testing the endpoint datapath.
type fakeTun struct {
	readCh  chan []byte
	mu      sync.Mutex
	written [][]byte
}

func newFakeTun() *fakeTun { return &fakeTun{readCh: make(chan []byte, 4)} }

func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt, ok := <-f.readCh
	if !ok {
		return 0, os.ErrClosed
	}
	copy(bufs[0][offset:], pkt)
	sizes[0] = len(pkt)
	return 1, nil
}

func (f *fakeTun) Write(bufs [][]byte, offset int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.written = append(f.written, append([]byte{}, bufs[0][offset:]...))
	return 1, nil
}

func (f *fakeTun) File() *os.File             { return nil }
func (f *fakeTun) MTU() (int, error)          { return 1500, nil }
func (f *fakeTun) Name() (string, error)      { return "utunTest", nil }
func (f *fakeTun) Events() <-chan wgtun.Event { return nil }
func (f *fakeTun) BatchSize() int             { return 1 }
func (f *fakeTun) Close() error               { close(f.readCh); return nil }

func (f *fakeTun) writes() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.written
}

type fakeDispatcher struct {
	got chan tcpip.NetworkProtocolNumber
}

func (d *fakeDispatcher) DeliverNetworkPacket(p tcpip.NetworkProtocolNumber, _ *stack.PacketBuffer) {
	d.got <- p
}
func (d *fakeDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func TestEndpointClassifiesIPv4(t *testing.T) {
	ft := newFakeTun()
	ep := newEndpoint(ft, 1500)
	disp := &fakeDispatcher{got: make(chan tcpip.NetworkProtocolNumber, 1)}
	ep.Attach(disp)
	defer ep.Close()

	// Minimal IPv4 header (version nibble 4).
	ft.readCh <- []byte{0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}

	select {
	case proto := <-disp.got:
		if proto != header.IPv4ProtocolNumber {
			t.Fatalf("proto = %v, want IPv4", proto)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("packet not dispatched")
	}
}

func TestEndpointWritePackets(t *testing.T) {
	ft := newFakeTun()
	ep := newEndpoint(ft, 1500)

	ipBytes := []byte{0x45, 0x00, 0x00, 0x10, 0xDE, 0xAD, 0xBE, 0xEF}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(ipBytes),
	})
	var list stack.PacketBufferList
	list.PushBack(pb)

	n, err := ep.WritePackets(list)
	if err != nil {
		t.Fatalf("WritePackets: %v", err)
	}
	if n != 1 {
		t.Fatalf("wrote %d packets, want 1", n)
	}
	w := ft.writes()
	if len(w) != 1 || string(w[0]) != string(ipBytes) {
		t.Fatalf("device received %v, want %v", w, ipBytes)
	}
	pb.DecRef()
}
