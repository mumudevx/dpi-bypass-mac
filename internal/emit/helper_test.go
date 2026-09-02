package emit

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// errFakeWrite is what fakeTransport returns when it is told to fail, so a test
// can assert the sender wrapped it rather than replaced it.
var errFakeWrite = errors.New("fake transport: write refused")

// errFakeOOB is the urgent-byte equivalent. It wraps a real syscall errno
// because the promise Sender.Send documents is that errors.Is(err,
// syscall.EPIPE) still holds at the call site, and oob:pos=1 is the last rung
// of the tr ladder — the one whose reported cause a user actually reads.
var errFakeOOB = fmt.Errorf("fake transport: urgent byte refused: %w", syscall.EPIPE)

// fakeTransport records everything the sender does, so a test can assert the
// exact call sequence without a socket.
type fakeTransport struct {
	mu sync.Mutex

	caps strategy.Cap

	writes   [][]byte
	oob      [][]byte
	injected [][]byte
	ttlSet   []int
	resets   int

	// failWriteAt is the 1-based stream write that fails; 0 means never.
	failWriteAt int
	shortWrite  bool
	// failOOBAt mirrors failWriteAt for the urgent-byte path, and shortOOB
	// mirrors shortWrite. Without them the SegOOBByte error branch in
	// emitSegment is unreachable from a test.
	failOOBAt int
	shortOOB  bool
	failReset bool
	// onWrite runs before each stream write, so a test can observe socket state
	// at the exact moment a segment is on the wire.
	onWrite func(n int)
}

func newFake() *fakeTransport {
	return &fakeTransport{caps: strategy.CapStreamWrite | strategy.CapNoDelay |
		strategy.CapSockTTL | strategy.CapOOB | strategy.CapUDPTTL}
}

func (f *fakeTransport) Caps() strategy.Cap { return f.caps }

func (f *fakeTransport) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, append([]byte(nil), b...))
	if f.onWrite != nil {
		f.onWrite(len(f.writes))
	}
	if f.failWriteAt != 0 && len(f.writes) == f.failWriteAt {
		return 0, errFakeWrite
	}
	if f.shortWrite && len(b) > 1 {
		return len(b) - 1, nil
	}
	return len(b), nil
}

func (f *fakeTransport) WriteOOB(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.oob = append(f.oob, append([]byte(nil), b...))
	if f.failOOBAt != 0 && len(f.oob) == f.failOOBAt {
		return 0, errFakeOOB
	}
	if f.shortOOB && len(b) > 1 {
		return len(b) - 1, nil
	}
	return len(b), nil
}

func (f *fakeTransport) SetTTL(ttl int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ttlSet = append(f.ttlSet, ttl)
	return nil
}

func (f *fakeTransport) ResetTTL() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resets++
	if f.failReset {
		return errors.New("fake transport: reset refused")
	}
	return nil
}

func (f *fakeTransport) InjectRaw(pkt []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.injected = append(f.injected, append([]byte(nil), pkt...))
	return nil
}

func (f *fakeTransport) SeqState() (SeqState, bool) { return SeqState{}, false }
func (f *fakeTransport) Local() netip.AddrPort      { return netip.MustParseAddrPort("127.0.0.1:1") }
func (f *fakeTransport) Remote() netip.AddrPort     { return netip.MustParseAddrPort("127.0.0.1:2") }
func (f *fakeTransport) Close() error               { return nil }

func (f *fakeTransport) stream() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []byte
	for _, w := range f.writes {
		out = append(out, w...)
	}
	return out
}

func (f *fakeTransport) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

// loopbackPair returns a connected TCP pair on the given loopback network, with
// the client wrapped in a real SockTransport.
func loopbackPair(t *testing.T, network, addr string) (*SockTransport, net.Conn) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("no %s loopback listener on this machine: %v", network, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
		c, err := ln.Accept()
		ch <- acc{c, err}
	}()

	client, err := net.Dial(network, ln.Addr().String())
	if err != nil {
		t.Fatalf("dial %s: %v", ln.Addr(), err)
	}
	t.Cleanup(func() { _ = client.Close() })

	a := <-ch
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	t.Cleanup(func() { _ = a.c.Close() })

	st, err := NewSockTransport(client.(*net.TCPConn), nil)
	if err != nil {
		t.Fatalf("NewSockTransport: %v", err)
	}
	return st, a.c
}

func streamPlan(spec string, chunks ...string) strategy.Plan {
	p := strategy.Plan{Spec: spec}
	for _, c := range chunks {
		p.Payload = append(p.Payload, c...)
		p.Segments = append(p.Segments, strategy.Segment{Kind: strategy.SegStream, Data: []byte(c)})
	}
	return p
}
