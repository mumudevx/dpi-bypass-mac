package flow_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/emit"
	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"

	"github.com/mumudevx/dpi-bypass-mac/internal/ops"
)

// TestMain installs the op set into the default registry. ops deliberately does
// not register from init (internal/strategy's own tests own that registry), so
// every binary that parses a user-supplied spec has to do this once — which is
// exactly what a LadderRunner with no explicit Registry depends on.
func TestMain(m *testing.M) {
	ops.Install()
	os.Exit(m.Run())
}

// testAddr is the destination every fake connection claims. It is a documentation
// address (RFC 5737 TEST-NET-1) so a test that accidentally reaches the network
// fails loudly instead of touching someone's server.
var testAddr = netip.MustParseAddrPort("192.0.2.10:443")

// step is one scripted upstream event.
type step struct {
	delay time.Duration
	data  []byte
	err   error
}

// scriptConn is a net.Conn AND an emit.Transport whose upstream behaviour is a
// list of steps. It exists so the escalation state machine can be driven
// deterministically — reset before response, reset after response, silence — with
// no sockets and no timing luck.
type scriptConn struct {
	mu        sync.Mutex
	steps     []step
	next      int
	writes    [][]byte
	oob       [][]byte
	ttls      []int
	ttlResets int
	writeErr  error
	closed    bool
	rdeadline time.Time
	caps      strategy.Cap
	remote    netip.AddrPort

	done chan struct{}
}

func newScriptConn(steps ...step) *scriptConn {
	return &scriptConn{
		steps:  steps,
		caps:   strategy.CapStreamWrite | strategy.CapNoDelay | strategy.CapSockTTL | strategy.CapOOB,
		remote: testAddr,
		done:   make(chan struct{}),
	}
}

// from is newScriptConn with the peer address the upstream connection claims,
// so a test can put a script behind the BTK sinkhole address.
func newScriptConnFrom(peer netip.AddrPort, steps ...step) *scriptConn {
	c := newScriptConn(steps...)
	c.remote = peer
	return c
}

func (c *scriptConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	dl := c.rdeadline
	var s step
	if c.next < len(c.steps) {
		s = c.steps[c.next]
		c.next++
	} else {
		s = step{delay: time.Hour} // silence, bounded only by the caller's deadline
	}
	c.mu.Unlock()

	var timeout <-chan time.Time
	if !dl.IsZero() {
		t := time.NewTimer(time.Until(dl))
		defer t.Stop()
		timeout = t.C
	}
	ready := time.NewTimer(s.delay)
	defer ready.Stop()

	select {
	case <-ready.C:
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	case <-c.done:
		return 0, net.ErrClosed
	}
	if len(s.data) > 0 {
		// data AND err together is the shape a middlebox that injects a forged
		// response and then a reset produces, and Read is allowed to return
		// both. A step with only data returns a nil error as before.
		return copy(b, s.data), s.err
	}
	if s.err != nil {
		return 0, s.err
	}
	return 0, io.EOF
}

func (c *scriptConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func (c *scriptConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.done)
	}
	return nil
}

func (c *scriptConn) LocalAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:1"))
}
func (c *scriptConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.remote) }

func (c *scriptConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }
func (c *scriptConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdeadline = t
	c.mu.Unlock()
	return nil
}
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }

func (c *scriptConn) Caps() strategy.Cap { return c.caps }
func (c *scriptConn) WriteOOB(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.oob = append(c.oob, append([]byte(nil), b...))
	return len(b), nil
}
func (c *scriptConn) SetTTL(ttl int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttls = append(c.ttls, ttl)
	return nil
}
func (c *scriptConn) ResetTTL() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttlResets++
	return nil
}
func (c *scriptConn) InjectRaw([]byte) error          { return emit.ErrCapUnavailable }
func (c *scriptConn) SeqState() (emit.SeqState, bool) { return emit.SeqState{}, false }
func (c *scriptConn) Local() netip.AddrPort           { return netip.MustParseAddrPort("127.0.0.1:1") }
func (c *scriptConn) Remote() netip.AddrPort          { return c.remote }

func (c *scriptConn) stream() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []byte
	for _, w := range c.writes {
		out = append(out, w...)
	}
	return out
}

func (c *scriptConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

var (
	_ net.Conn       = (*scriptConn)(nil)
	_ emit.Transport = (*scriptConn)(nil)
)

// scriptDialer hands out pre-built connections in order, so a test states the
// whole upstream script up front.
type scriptDialer struct {
	mu      sync.Mutex
	conns   []net.Conn
	errs    []error
	dials   int
	targets []flow.Target
}

func (d *scriptDialer) DialTCP(_ context.Context, t flow.Target) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	i := d.dials
	d.dials++
	d.targets = append(d.targets, t)
	if i < len(d.errs) && d.errs[i] != nil {
		return nil, d.errs[i]
	}
	if i >= len(d.conns) {
		return nil, errors.New("scriptDialer: no connection left for this attempt")
	}
	return d.conns[i], nil
}

func (d *scriptDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

// resetErr is shaped like the kernel's, which is what testcensor injects and
// what a real censored flow produces.
func resetErr() error {
	return &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
}

// censorTransport adapts a testcensor connection to emit.Transport so the ladder
// drives a simulated censor through exactly the code path it uses on a socket.
type censorTransport struct {
	testcensor.Conn
	remote netip.AddrPort
}

func (c *censorTransport) Caps() strategy.Cap {
	return strategy.CapStreamWrite | strategy.CapNoDelay | strategy.CapSockTTL | strategy.CapOOB
}
func (c *censorTransport) ResetTTL() error                 { return c.Conn.SetTTL(0) }
func (c *censorTransport) InjectRaw([]byte) error          { return emit.ErrCapUnavailable }
func (c *censorTransport) SeqState() (emit.SeqState, bool) { return emit.SeqState{}, false }
func (c *censorTransport) Local() netip.AddrPort           { return netip.MustParseAddrPort("127.0.0.1:1") }
func (c *censorTransport) Remote() netip.AddrPort          { return c.remote }

var (
	_ net.Conn       = (*censorTransport)(nil)
	_ emit.Transport = (*censorTransport)(nil)
)

// boxDialer dials every attempt through a testcensor Middlebox to one origin.
type boxDialer struct {
	box  *testcensor.Middlebox
	addr string

	mu    sync.Mutex
	dials int
}

func (d *boxDialer) DialTCP(ctx context.Context, _ flow.Target) (net.Conn, error) {
	d.mu.Lock()
	d.dials++
	d.mu.Unlock()
	c, err := d.box.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	cc, ok := c.(testcensor.Conn)
	if !ok {
		_ = c.Close()
		return nil, errors.New("boxDialer: middlebox returned a plain net.Conn")
	}
	return &censorTransport{Conn: cc, remote: testAddr}, nil
}

func (d *boxDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

// clientHello captures a genuine ClientHello for name from crypto/tls.
//
// A hand-built hello would be a second implementation of the thing under test.
// Capturing the real one means the record layout, the extension order and the
// post-quantum key share are whatever this Go version actually emits — which is
// the ~1512-1601 byte, two-segment message MEASUREMENTS.md §3.5 says the
// previous implementation silently truncated.
func clientHello(t *testing.T, name string) []byte {
	t.Helper()
	// Cached per name: capturing a post-quantum hello costs a real key
	// generation, and the -count=500 escalation soak would otherwise spend most
	// of its time in crypto/tls rather than in the state machine under test.
	if v, ok := helloCache.Load(name); ok {
		return append([]byte(nil), v.([]byte)...)
	}
	cli, srv := net.Pipe()
	t.Cleanup(func() { _ = cli.Close(); _ = srv.Close() })

	go func() {
		c := tls.Client(cli, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12})
		_ = c.Handshake()
		_ = c.Close()
	}()

	if err := srv.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := srv.Read(tmp)
		if err != nil {
			t.Fatalf("read ClientHello: %v", err)
		}
		buf = append(buf, tmp[:n]...)
		want, ok := tlsmsg.Need(buf, tlsmsg.ProtoTLS)
		if !ok {
			t.Fatalf("captured %d bytes that are not a TLS record", len(buf))
		}
		if want == 0 {
			helloCache.Store(name, append([]byte(nil), buf...))
			return buf
		}
	}
}

var helloCache sync.Map

// rawOrigin is a loopback listener that answers every connection with greeting
// once the client has said something. It stands in for a TLS origin where the
// test only needs "the upstream answered", which is all the commit guard reads.
func rawOrigin(t *testing.T, greeting []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				if _, err := c.Read(buf); err != nil {
					return
				}
				_, _ = c.Write(greeting)
				// Drain until the client goes away so a half-closed relay test
				// does not see a spurious reset.
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// memStore is a policy.Store that keeps verdicts in memory, so a test can assert
// exactly what the ladder learned without a filesystem.
type memStore struct {
	mu      sync.Mutex
	v       map[string]policy.Verdict
	demoted []string
	puts    int
}

func newMemStore() *memStore { return &memStore{v: map[string]policy.Verdict{}} }

func (s *memStore) Get(n policy.NetworkID, host string) (policy.Verdict, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.v[policy.Key(n, host)]
	return v, ok
}

func (s *memStore) Put(n policy.NetworkID, host string, v policy.Verdict) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.puts++
	s.v[policy.Key(n, host)] = v
	return nil
}

func (s *memStore) Demote(n policy.NetworkID, host string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.demoted = append(s.demoted, policy.Key(n, host))
	delete(s.v, policy.Key(n, host))
	return nil
}

func (s *memStore) ForEach(n policy.NetworkID, fn func(string, policy.Verdict) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.v {
		if !fn(k, v) {
			return
		}
	}
}

func (s *memStore) Flush() error { return nil }
func (s *memStore) Close() error { return nil }

func (s *memStore) get(t *testing.T, host string) policy.Verdict {
	t.Helper()
	v, ok := s.Get(policy.NetworkID{}, host)
	if !ok {
		t.Fatalf("no verdict cached for %q", host)
	}
	return v
}

var _ policy.Store = (*memStore)(nil)

// watchVerdict is the ScopeWatch verdict a front end hands the ladder for an
// unknown host on an inspect port: the shipped TR ladder, plain first.
func watchVerdict() policy.Verdict {
	specs, ok := strategy.LadderSpecs("tr")
	if !ok {
		panic("the tr ladder is missing from this build")
	}
	return policy.Verdict{Class: policy.ScopeWatch, Source: policy.SrcDefault, Ladder: specs}
}

func specsOf(atts []flow.Attempt) []string {
	out := make([]string, len(atts))
	for i, a := range atts {
		out[i] = a.Spec
	}
	return out
}

// plainConn is a net.Conn that is neither an emit.Transport nor a *net.TCPConn.
// The ladder must refuse it rather than guess its capabilities.
type plainConn struct{}

func (plainConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (plainConn) Write(b []byte) (int, error)      { return len(b), nil }
func (plainConn) Close() error                     { return nil }
func (plainConn) LocalAddr() net.Addr              { return nil }
func (plainConn) RemoteAddr() net.Addr             { return nil }
func (plainConn) SetDeadline(time.Time) error      { return nil }
func (plainConn) SetReadDeadline(time.Time) error  { return nil }
func (plainConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = plainConn{}
