package tunfe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/observ"
	"github.com/mumudevx/dpi-bypass-mac/internal/ops"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// TestMain installs the op set into the default registry. ops deliberately does
// not register from init, so every binary that parses a user-supplied spec has
// to do this once — which is what a LadderRunner with no explicit Registry
// depends on.
func TestMain(m *testing.M) {
	ops.Install()
	os.Exit(m.Run())
}

// Addresses used by the tests. They are documentation ranges (RFC 5737
// TEST-NET-1 and RFC 3849), so a test that accidentally reaches the network
// fails loudly instead of touching someone's server.
var (
	clientIP = netip.MustParseAddr("192.0.2.2")
	originIP = netip.MustParseAddr("192.0.2.10")
	bankIP   = netip.MustParseAddr("192.0.2.11")
	clientV6 = netip.MustParseAddr("2001:db8::2")
	originV6 = netip.MustParseAddr("2001:db8::10")
)

const clientNIC = tcpip.NICID(1)

// lab is the whole test topology: a client netstack, a pipe standing in for the
// utun, the Server under test, and a fake upstream dialer.
//
//	clientStack ──PipeLink──PipeLink── tunfe.Server ──upstream──> loopback
type lab struct {
	t      *testing.T
	client *stack.Stack
	server *Server

	clientLink *PipeLink
	serverLink *PipeLink

	up     *upstreamDialer
	events []observ.ConnEvent
	mu     sync.Mutex
	serve  chan error
}

// labOpts are the knobs a test needs; everything else is wired the same way for
// every test so that a difference in behaviour is a difference in the code
// under test.
type labOpts struct {
	rules []policy.Rule
	quic  QUICPolicy
	// quicStrategy is the UDP plan QUICDesync emits an Initial through.
	quicStrategy strategy.Strategy
	dns          *resolve.Server
	udp          UDPDialer
	reverse      policy.ReverseMap
	// wrapScope wraps the built scope, so a test can inject a defect into the
	// policy layer without mutating the Server's options while it is running.
	wrapScope func(policy.Scope) policy.Scope
	noStart   bool
	firstMsg  flow.FirstMsgOpts
}

// newLab builds the topology and starts the datapath.
//
// A test that calls this must NOT call t.Parallel(). gVisor's TCP protocol
// starts one processor goroutine per GOMAXPROCS per stack, and a lab holds two
// stacks; a dozen labs at once means several hundred of them parking and
// waking, which under -race spends so long in the race detector's scheduler
// bookkeeping that connect and read deadlines expire. Measured on this machine
// (12 cores): the suite passes in ~3 s without -race at full parallelism and in
// ~23 s under -race run serially, and fails on nearly every lab test under
// -race at full parallelism. Tests that build no netstack stay parallel.
func newLab(t *testing.T, o labOpts) *lab {
	t.Helper()

	a, b := NewPipe(DefaultMTU)
	up := &upstreamDialer{t: t}
	l := &lab{t: t, clientLink: a, serverLink: b, up: up, serve: make(chan error, 1)}

	matcher, err := policy.NewMatcher(o.rules)
	if err != nil {
		t.Fatalf("matcher: %v", err)
	}
	ipset, err := policy.NewIPSet(nil)
	if err != nil {
		t.Fatalf("ipset: %v", err)
	}
	bogons := false
	scope := policy.NewEngine(policy.EngineOptions{
		Rules: matcher,
		IPs:   ipset,
		// The documentation addresses these tests use are not bogons, but the
		// table also covers loopback, and an upstream on 127.0.0.1 must not be
		// vetoed before the datapath is reached.
		Bogons: &bogons,
		Store:  policy.NopStore(),
		Ladder: []string{"tlsfrag:pos=snimid"},
	})

	var scoped policy.Scope = scope
	if o.wrapScope != nil {
		scoped = o.wrapScope(scope)
	}

	runner := &flow.LadderRunner{
		Dial:        up,
		Store:       policy.NopStore(),
		RTT:         flow.NewRTTTracker(),
		TotalBudget: 4 * time.Second,
		Logf:        t.Logf,
	}

	reverse := o.reverse
	if reverse == nil {
		reverse = policy.NewReverseMap(16)
	}

	firstMsg := o.firstMsg
	if firstMsg == (flow.FirstMsgOpts{}) {
		firstMsg = labFirstMsg()
	}

	srv, err := New(Options{
		Link:         b,
		Scope:        scoped,
		Ladder:       runner,
		Dial:         up,
		UDPDial:      o.udp,
		Reverse:      reverse,
		DNS:          o.dns,
		QUIC:         o.quic,
		QUICStrategy: o.quicStrategy,
		FirstMsg:     firstMsg,
		RelayIdle:    3 * time.Second,
		// UDPIdle is a test-infrastructure bound, not a claim about how long a
		// UDP session should live; the shipped default is DefaultUDPIdle, 60 s.
		//
		// It used to be one second, which is BELOW this environment's scheduler
		// jitter and made TestUDPRelayPreservesDatagramBoundaries flaky
		// (~6-12% under -race -count=50). Measured on this machine with the
		// relay instrumented: the two copy goroutines are spawned back to back,
		// and the second one entered its loop 1.18 s after the first, while the
		// test's own goroutine took 1.18 s to observe a datagram already written
		// to it. In that window the downstream direction's one-second idle
		// deadline expired, closeBoth tore the session down, and the second
		// datagram — which the upstream direction had by then forwarded, and
		// which the echo server had already answered — arrived at a closed
		// socket. The lab's dial helper carries the same caveat and a ten-second
		// bound for the same reason.
		//
		// Nothing leaks by making this long: Server.closeOnCancel now ends a UDP
		// flow when the datapath's context is cancelled, so the lab's cleanup
		// reaps these sessions immediately rather than waiting out the idle.
		// A test that wants to observe idle reaping must set its own value.
		UDPIdle:     20 * time.Second,
		DialTimeout: 2 * time.Second,
		DrainGrace:  200 * time.Millisecond,
		OnConn:      l.record,
		Logf:        t.Logf,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	l.server = srv
	l.client = newClientStack(t, a, t.Logf)

	if !o.noStart {
		ctx, cancel := context.WithCancel(context.Background())
		go func() { l.serve <- srv.Serve(ctx) }()
		t.Cleanup(func() {
			cancel()
			select {
			case <-l.serve:
			case <-time.After(5 * time.Second):
				t.Error("Serve did not return within 5s of cancellation")
			}
		})
	}
	t.Cleanup(func() {
		srv.Close()
		_ = a.Close()
		_ = b.Close()
	})
	return l
}

func (l *lab) record(ev observ.ConnEvent) {
	l.mu.Lock()
	l.events = append(l.events, ev)
	l.mu.Unlock()
}

// conn returns the recorded events, waiting briefly for the flow to finish.
func (l *lab) conns() []observ.ConnEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]observ.ConnEvent, len(l.events))
	copy(out, l.events)
	return out
}

// dial opens a TCP connection from the client netstack to dst.
func (l *lab) dial(dst netip.AddrPort) (net.Conn, error) {
	l.t.Helper()
	// Ten seconds is a test-infrastructure bound, not a claim about latency: two
	// gVisor stacks under -race on a loaded machine take far longer to complete
	// a handshake than the same code does on a real link. Every assertion about
	// timing is made explicitly, never by relying on this bound.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
	if dst.Addr().Is6() {
		proto = ipv6.ProtocolNumber
	}
	return gonet.DialContextTCP(ctx, l.client, tcpip.FullAddress{
		NIC:  clientNIC,
		Addr: tcpipAddr(dst.Addr()),
		Port: dst.Port(),
	}, proto)
}

// dialUDP opens a UDP session from the client netstack to dst.
func (l *lab) dialUDP(dst netip.AddrPort) (*gonet.UDPConn, error) {
	l.t.Helper()
	raddr := tcpip.FullAddress{NIC: clientNIC, Addr: tcpipAddr(dst.Addr()), Port: dst.Port()}
	proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
	if dst.Addr().Is6() {
		proto = ipv6.ProtocolNumber
	}
	return gonet.DialUDP(l.client, nil, &raddr, proto)
}

// newClientStack is a second netstack on the far end of the pipe, standing in
// for the machine's own TCP/IP stack. It uses the SAME endpoint the server
// does, so the offset contract is exercised from both directions.
func newClientStack(t *testing.T, l Link, logf func(string, ...any)) *stack.Stack {
	t.Helper()
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := newEndpoint(l, DefaultMTU, logf)
	if err := st.CreateNIC(clientNIC, ep); err != nil {
		t.Fatalf("client CreateNIC: %v", err)
	}
	for _, a := range []netip.Addr{clientIP, clientV6} {
		proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
		if a.Is6() {
			proto = ipv6.ProtocolNumber
		}
		addr := tcpip.ProtocolAddress{
			Protocol:          proto,
			AddressWithPrefix: tcpipAddr(a).WithPrefix(),
		}
		if err := st.AddProtocolAddress(clientNIC, addr, stack.AddressProperties{}); err != nil {
			t.Fatalf("client AddProtocolAddress %s: %v", a, err)
		}
	}
	st.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: clientNIC},
		{Destination: header.IPv6EmptySubnet, NIC: clientNIC},
	})
	t.Cleanup(st.Close)
	return st
}

// upstreamDialer is the Server's flow.Dialer. Every dial is recorded and served
// by whatever the test installed: a real loopback listener, or a scripted
// failure.
type upstreamDialer struct {
	t *testing.T

	mu     sync.Mutex
	dials  []flow.Target
	target string // loopback address to connect to
	err    error
	fail   int // fail this many dials before succeeding
}

func (d *upstreamDialer) DialTCP(ctx context.Context, t flow.Target) (net.Conn, error) {
	d.mu.Lock()
	d.dials = append(d.dials, t)
	target, err, fail := d.target, d.err, d.fail
	if fail > 0 {
		d.fail--
	}
	d.mu.Unlock()

	switch {
	case err != nil:
		return nil, err
	case fail > 0:
		return nil, fmt.Errorf("%w: scripted dial failure", flow.ErrNoUpstream)
	case target == "":
		return nil, errors.New("upstreamDialer: no target installed")
	}
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", target)
}

func (d *upstreamDialer) serveOn(addr string) {
	d.mu.Lock()
	d.target = addr
	d.mu.Unlock()
}

func (d *upstreamDialer) targets() []flow.Target {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]flow.Target, len(d.dials))
	copy(out, d.dials)
	return out
}

// origin is a loopback TCP server the test drives directly.
type origin struct {
	t     *testing.T
	ln    net.Listener
	conns chan net.Conn
}

func newOrigin(t *testing.T) *origin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	o := &origin{t: t, ln: ln, conns: make(chan net.Conn, 8)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			o.conns <- c
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return o
}

func (o *origin) addr() string { return o.ln.Addr().String() }

// accept waits for the next upstream connection.
func (o *origin) accept() net.Conn {
	o.t.Helper()
	select {
	case c := <-o.conns:
		o.t.Cleanup(func() { _ = c.Close() })
		return c
	case <-time.After(10 * time.Second):
		o.t.Fatal("no upstream connection arrived within 10s")
		return nil
	}
}

// acceptWithin waits for an upstream connection, reporting whether one came.
func (o *origin) acceptWithin(d time.Duration) (net.Conn, bool) {
	select {
	case c := <-o.conns:
		return c, true
	case <-time.After(d):
		return nil, false
	}
}

// readAll reads until EOF or the deadline, returning what arrived.
func readWithin(t *testing.T, c net.Conn, n int, d time.Duration) []byte {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, n)
	got := 0
	for got < n {
		m, err := c.Read(buf[got:])
		got += m
		if err != nil {
			break
		}
	}
	return buf[:got]
}

// waitFor polls until cond is true or the deadline passes.
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", d, what)
}

// countingUDPDialer records every UDP dial and hands back a scripted peer.
type countingUDPDialer struct {
	mu    sync.Mutex
	dials []netip.AddrPort
	peer  func() (net.Conn, error)
	calls atomic.Int64
}

func (d *countingUDPDialer) DialUDP(_ context.Context, dst netip.AddrPort) (net.Conn, error) {
	d.calls.Add(1)
	d.mu.Lock()
	d.dials = append(d.dials, dst)
	peer := d.peer
	d.mu.Unlock()
	if peer == nil {
		return nil, errors.New("countingUDPDialer: no peer installed")
	}
	return peer()
}

func (d *countingUDPDialer) count() int64 { return d.calls.Load() }

// shortFirstMsg shrinks the first-byte window so a server-first test does not
// spend a quarter of a second per case proving the client is silent. The bound
// under test is the ORDERING — nothing is read before the scope decides — not
// the duration.

// labFirstMsg is the first-message bound a lab test gets when it names none.
//
// It is a TEST-INFRASTRUCTURE bound, not a claim about what a real client
// deserves: the shipped values are flow.DefaultFirstMsgOpts() and whether they
// are right is asserted in internal/flow, which is where that question belongs.
//
// CompleteWait is the one that matters. It is a PROGRESS deadline between
// reads, shipped at 250 ms, and it is armed between the segments of a first
// message that does not arrive in one piece. Under `-race -count=50` on this
// machine (12 cores, ~11.5 of them busy for the whole run) the 60 ms gap
// TestSplitClientHelloIsReassembledBeforePlanning writes between its two
// segments sometimes stretched past it. The assembly then ended on the first
// segment, tlsfrag refused a hello with no locatable SNI, plain became the last
// rung, and there was no second attempt for the test to accept — 3 rounds in 50:
//
//	--- FAIL: TestSplitClientHelloIsReassembledBeforePlanning (14.18s)
//	    ladder.go:885: flow: discord.com:443 was silent for the response window
//	                   on the last rung "plain"; handing the connection over
//	    tcp_test.go:151: no upstream connection arrived within 10s
//
// Reproducible on demand: set CompleteWait to 1 ms and that test fails with
// exactly those two lines.
//
// The fourth failure of that run was TestBypassedNameSurvivesTUNMode, whose
// hello goes out in ONE Write and is still more than 1500 bytes, so the deadline
// is armed between its segments too:
//
//	--- FAIL: TestBypassedNameSurvivesTUNMode (11.67s)
//	    tcp_test.go:245: timed out after 10s waiting for the bank flow to finish
//
// A first message cut before the SNI carries no name to re-scope the flow on,
// so the bank is judged rather than bypassed and the event carries no Host at
// all — reproduced deterministically by cutting that hello at 100 bytes with a
// 1 ms CompleteWait, which recorded exactly one event, `Host: ... Scope:watch`.
// Measured either side of this change, alone under -race: 1 failure in 200
// rounds with the shipped 250 ms bound, 0 in 300 with this one.
//
// This is not a timeout raised to make a test pass. The assertions are about
// what the datapath does with an ASSEMBLED first message, and nothing waits
// these bounds out — ReadFirstMessage returns the moment the declared message
// is complete, which on a healthy pipe is microseconds. What the wider bound
// removes is the scheduler's vote on whether the message was assembled.
//
// FirstByteWait is widened for the same reason, though no run failed on it: a
// lab client that is going to speak writes immediately, so waiting longer for a
// byte that is certainly coming weakens nothing. Server-first detection is
// asserted by tests that set their own bound.
func labFirstMsg() flow.FirstMsgOpts {
	o := flow.DefaultFirstMsgOpts()
	o.FirstByteWait = 10 * time.Second
	o.CompleteWait = 10 * time.Second
	o.MaxAssembly = 30 * time.Second
	return o
}

func shortFirstMsg() flow.FirstMsgOpts {
	o := flow.DefaultFirstMsgOpts()
	o.FirstByteWait = 80 * time.Millisecond
	o.CompleteWait = 80 * time.Millisecond
	o.MaxAssembly = 400 * time.Millisecond
	return o
}

// helloCache keeps one captured ClientHello per name: capturing a post-quantum
// hello costs a real key generation.
var helloCache sync.Map

// clientHello captures a genuine ClientHello for name from crypto/tls.
//
// A hand-built hello would be a second implementation of the thing under test.
// Capturing the real one means the record layout, the extension order and the
// post-quantum key share are whatever this Go version actually emits — which is
// the ~1512-1601 byte, two-segment message MEASUREMENTS.md §3.5 says the
// previous implementation silently truncated.
func clientHello(t *testing.T, name string) []byte {
	t.Helper()
	if v, ok := helloCache.Load(name); ok {
		return append([]byte(nil), v.([]byte)...)
	}
	c := &captureConn{}
	// The handshake cannot complete against a conn that never answers; the
	// ClientHello is written before that matters, which is exactly the byte
	// string wanted here.
	_ = tls.Client(c, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12}).Handshake()
	if len(c.written) == 0 {
		t.Fatalf("captured no ClientHello for %q", name)
	}
	helloCache.Store(name, append([]byte(nil), c.written...))
	return c.written
}

// captureConn records what a TLS client writes and refuses to read, so a
// handshake stops after its first flight with no goroutine and no socket.
type captureConn struct {
	net.Conn
	written []byte
}

func (c *captureConn) Write(b []byte) (int, error) {
	c.written = append(c.written, b...)
	return len(b), nil
}

func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

// matching counts the leading bytes two buffers share, for a failure message
// that says where they diverged.
func matching(a, b []byte) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}

// waitForEvent blocks until a recorded ConnEvent satisfies cond.
// It dumps what it DID see on the way out. "timed out waiting for the flow to
// finish" is two very different defects — no event at all (the flow is wedged)
// and an event that does not match (the flow finished and was judged wrongly) —
// and telling them apart from a -count=200 log is the difference between a
// diagnosis and a guess.
func waitForEvent(t *testing.T, l *lab, what string, cond func(observ.ConnEvent) bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, ev := range l.conns() {
			if cond(ev) {
				return
			}
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	evs := l.conns()
	if len(evs) == 0 {
		t.Fatalf("timed out after 10s waiting for %s; NO connection event was recorded at all, "+
			"so the flow never finished. Server stats: %+v", what, l.server.Stats())
	}
	t.Fatalf("timed out after 10s waiting for %s; %d event(s) were recorded and none matched: %+v",
		what, len(evs), evs)
}

// lastEvent returns the most recently recorded ConnEvent.
func lastEvent(t *testing.T, l *lab) observ.ConnEvent {
	t.Helper()
	evs := l.conns()
	if len(evs) == 0 {
		t.Fatal("no connection events were recorded")
	}
	return evs[len(evs)-1]
}

// resettingOrigin is a loopback listener that hands out connections one at a
// time and can reset one, which is what a censored line does to a flow whose
// SNI it matched (MEASUREMENTS.md §1: the TCP handshake completes and the RST
// arrives ~22 ms later).
type resettingOrigin struct {
	ln    net.Listener
	conns chan net.Conn
}

func newResettingOrigin(t *testing.T) *resettingOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	o := &resettingOrigin{ln: ln, conns: make(chan net.Conn, 8)}
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			o.conns <- c
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return o
}

func (o *resettingOrigin) addr() string { return o.ln.Addr().String() }

func (o *resettingOrigin) next(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-o.conns:
		t.Cleanup(func() { _ = c.Close() })
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("no upstream connection arrived within 10s")
		return nil
	}
}

// reset closes a connection with a zero linger, which puts a real RST on the
// wire rather than a FIN.
func (o *resettingOrigin) reset(t *testing.T, c net.Conn) {
	t.Helper()
	tc, ok := c.(*net.TCPConn)
	if !ok {
		t.Fatalf("%T is not a TCP connection", c)
	}
	if err := tc.SetLinger(0); err != nil {
		t.Fatalf("SetLinger: %v", err)
	}
	if err := tc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
