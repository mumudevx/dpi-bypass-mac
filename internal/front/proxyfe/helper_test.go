package proxyfe_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/emit"
	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/front/proxyfe"
	"github.com/mumudevx/dpi-bypass-mac/internal/ops"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
)

func init() { ops.Install() }

// mapDialer resolves a name to a loopback listener and then dials it with the
// SHIPPED dialer, so every test here runs on a real socket with a real
// emit.SockTransport and the capabilities the kernel actually granted. Only the
// name-to-address step is faked, which is the one step that needs a network.
type mapDialer struct {
	nd *flow.NetDialer

	mu    sync.Mutex
	to    map[string]netip.AddrPort
	dials []string
}

func newMapDialer() *mapDialer {
	return &mapDialer{nd: &flow.NetDialer{}, to: map[string]netip.AddrPort{}}
}

func (d *mapDialer) add(name string, addr net.Addr) {
	ap := netip.MustParseAddrPort(addr.String())
	d.mu.Lock()
	defer d.mu.Unlock()
	d.to[name] = ap
}

func (d *mapDialer) DialTCP(ctx context.Context, t flow.Target) (net.Conn, error) {
	d.mu.Lock()
	key := t.Name
	if key == "" {
		key = t.Addr.Addr().String()
	}
	ap, ok := d.to[key]
	d.dials = append(d.dials, fmt.Sprintf("%s:%d", key, t.Port))
	d.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("mapDialer: no listener for %q", key)
	}
	t.Addr = ap
	return d.nd.DialTCP(ctx, t)
}

func (d *mapDialer) calls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dials...)
}

// deadDialer fails every dial, which is how a 502 before the acknowledgement is
// provoked.
type deadDialer struct{ err error }

func (d deadDialer) DialTCP(context.Context, flow.Target) (net.Conn, error) {
	return nil, fmt.Errorf("%w: %v", flow.ErrNoUpstream, d.err)
}

// ── origins ──────────────────────────────────────────────────────────────────

// httpOrigin is a plaintext HTTP server that names itself in every response, so
// a test can tell WHICH backend answered a request. That is the whole point of
// the per-request dialing regression: the previous implementation delivered
// request two to request one's backend.
type httpOrigin struct {
	ln   net.Listener
	name string

	mu    sync.Mutex
	hosts []string
	conns int
	wg    sync.WaitGroup
}

func newHTTPOrigin(t *testing.T, name string) *httpOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	o := &httpOrigin{ln: ln, name: name}
	o.wg.Add(1)
	go o.accept()
	t.Cleanup(func() {
		_ = ln.Close()
		o.wg.Wait()
	})
	return o
}

func (o *httpOrigin) accept() {
	defer o.wg.Done()
	for {
		c, err := o.ln.Accept()
		if err != nil {
			return
		}
		o.mu.Lock()
		o.conns++
		o.mu.Unlock()
		o.wg.Add(1)
		go o.serve(c)
	}
}

func (o *httpOrigin) serve(c net.Conn) {
	defer o.wg.Done()
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body, _ := io.ReadAll(req.Body)
		req.Body.Close()
		o.mu.Lock()
		o.hosts = append(o.hosts, req.Host+req.URL.RequestURI()+"|"+string(body))
		o.mu.Unlock()
		payload := o.name + " answered " + req.URL.RequestURI()
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
			len(payload), payload)
	}
}

func (o *httpOrigin) addr() net.Addr { return o.ln.Addr() }

func (o *httpOrigin) seen() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.hosts...)
}

func (o *httpOrigin) connections() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.conns
}

// greetOrigin speaks first, the way SMTP, IMAP, POP3, FTP and MySQL do.
type greetOrigin struct {
	ln       net.Listener
	greeting string
	wg       sync.WaitGroup
}

func newGreetOrigin(t *testing.T, greeting string) *greetOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	o := &greetOrigin{ln: ln, greeting: greeting}
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			o.wg.Add(1)
			go func() {
				defer o.wg.Done()
				defer c.Close()
				_, _ = io.WriteString(c, greeting)
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		o.wg.Wait()
	})
	return o
}

// ── the censored line ────────────────────────────────────────────────────────

// lab puts a testcensor model in front of a real TLS origin on loopback, and
// turns the model's verdict into what a client socket actually observes: a
// genuine RST via SetLinger(0), or silence. The shipped classifier then sees
// ECONNRESET, which is what MEASUREMENTS.md §1 records on the live line.
type lab struct {
	origin *testcensor.Origin
	box    *testcensor.Middlebox
	ln     net.Listener
	wg     sync.WaitGroup
}

func newLab(t *testing.T, m testcensor.Model, names ...string) *lab {
	t.Helper()
	o, err := testcensor.NewOrigin(testcensor.OriginConfig{
		Names:    names,
		Response: []byte(labResponse),
	})
	if err != nil {
		t.Fatalf("origin: %v", err)
	}
	t.Cleanup(func() { _ = o.Close() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	l := &lab{
		origin: o,
		// Port 443 is asserted because the listener binds an ephemeral port and
		// a model scoped to 443 would otherwise inspect nothing.
		box: testcensor.New(m, testcensor.Options{Port: 443, Logf: t.Logf}),
		ln:  ln,
	}
	l.wg.Add(1)
	go l.accept()
	t.Cleanup(func() {
		_ = ln.Close()
		l.wg.Wait()
	})
	return l
}

const labResponse = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world"

func (l *lab) addr() net.Addr { return l.ln.Addr() }

func (l *lab) accept() {
	defer l.wg.Done()
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return
		}
		l.wg.Add(1)
		go l.relay(c)
	}
}

func (l *lab) relay(client net.Conn) {
	defer l.wg.Done()
	defer client.Close()

	up, err := l.box.DialContext(context.Background(), "tcp", l.origin.Addr())
	if err != nil {
		hardClose(client)
		return
	}
	defer up.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(client, up); err != nil {
			hardClose(client)
		}
		_ = client.Close()
	}()

	buf := make([]byte, 32<<10)
	for {
		n, rerr := client.Read(buf)
		if n > 0 {
			if _, werr := up.Write(buf[:n]); werr != nil {
				hardClose(client)
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	_ = up.Close()
	wg.Wait()
}

func hardClose(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}

// ── server wiring ────────────────────────────────────────────────────────────

type harness struct {
	srv   *proxyfe.Server
	dial  *mapDialer
	store policy.Store
	addr  string
}

type wiring struct {
	rules       []policy.Rule
	ladder      []string
	inspect     []int
	pac         *proxyfe.PAC
	dialer      flow.Dialer
	resolve     flow.ResolveFunc
	maxConns    int
	suspended   func() bool
	store       policy.Store
	includeOnly bool
	// the datagram path (SOCKS5 UDP ASSOCIATE)
	udpDial        flow.UDPDialer
	dns            proxyfe.DNSAnswerer
	quic           proxyfe.QUICPolicy
	quicStrategy   strategy.Strategy
	udpIdle        time.Duration
	maxUDPSessions int
}

// serveTest stands the whole front end up on a loopback listener and returns
// its address. Everything is the shipped code: policy.NewEngine, the real
// flow.LadderRunner, the real emitter.
func serveTest(t *testing.T, w wiring) *harness {
	t.Helper()
	if w.inspect == nil {
		w.inspect = []int{443, 80}
	}
	if w.ladder == nil {
		w.ladder = []string{"", "tlsfrag:pos=snimid", "chunk:size=12", "oob:pos=1"}
	}
	if w.store == nil {
		w.store = policy.NopStore()
	}
	dial := w.dialer
	md, _ := dial.(*mapDialer)
	if dial == nil {
		md = newMapDialer()
		dial = md
	}

	matcher, err := policy.NewMatcher(w.rules)
	if err != nil {
		t.Fatalf("matcher: %v", err)
	}
	ipset, err := policy.NewIPSet(nil)
	if err != nil {
		t.Fatalf("ipset: %v", err)
	}
	scope := policy.NewEngine(policy.EngineOptions{
		Rules:        matcher,
		IPs:          ipset,
		Store:        w.store,
		InspectPorts: w.inspect,
		Ladder:       w.ladder,
		Suspended:    w.suspended,
		IncludeOnly:  w.includeOnly,
	})

	runner := &flow.LadderRunner{
		Dial:   dial,
		Sender: &emit.Sender{Logf: t.Logf},
		Store:  w.store,
		RTT:    flow.NewRTTTracker(),
		Single: policy.NewSingleflight(),
		Logf:   t.Logf,
	}

	srv, err := proxyfe.New(proxyfe.Options{
		Scope:          scope,
		Ladder:         runner,
		Dial:           dial,
		Resolve:        w.resolve,
		PAC:            w.pac,
		MaxConns:       w.maxConns,
		UDPDial:        w.udpDial,
		DNS:            w.dns,
		QUIC:           w.quic,
		QUICStrategy:   w.quicStrategy,
		UDPIdle:        w.udpIdle,
		MaxUDPSessions: w.maxUDPSessions,
		ClientIdle:     5 * time.Second,
		RelayIdle:      5 * time.Second,
		DrainGrace:     2 * time.Second,
		Logf:           t.Logf,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ctx, ln); err != nil {
			t.Errorf("serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return after its context was cancelled")
		}
	})

	return &harness{srv: srv, dial: md, store: w.store, addr: ln.Addr().String()}
}

// dialProxy opens a client connection to the proxy.
func (h *harness) dialProxy(t *testing.T) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	return c
}

// connect performs a CONNECT and returns the connection and the status line.
func (h *harness) connect(t *testing.T, authority string) (net.Conn, string) {
	t.Helper()
	c := h.dialProxy(t)
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	// Drain the rest of the response head.
	for {
		l, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(l) == "" {
			break
		}
	}
	if br.Buffered() > 0 {
		t.Fatalf("proxy sent %d unexpected bytes after the CONNECT response", br.Buffered())
	}
	return c, strings.TrimSpace(line)
}

// failingResolve models a chain that has walked every rung and found nothing
// clean, which is resolve.ErrNoCleanTransport on a poisoned network.
func failingResolve(context.Context, string) ([]netip.Addr, error) {
	return nil, fmt.Errorf("no resolver answered")
}

func bypassRule(pattern string) policy.Rule {
	return policy.Rule{Pattern: pattern, Class: policy.ScopeBypass, From: "test"}
}

func watchRule(pattern string) policy.Rule {
	return policy.Rule{Pattern: pattern, Class: policy.ScopeWatch, From: "test"}
}

// tlsThrough completes a real TLS handshake over an established tunnel and
// fetches the origin's canned response.
func tlsThrough(t *testing.T, tunnel net.Conn, name string, cfg *tls.Config) (string, error) {
	t.Helper()
	c := tls.Client(tunnel, cfg)
	if err := c.HandshakeContext(context.Background()); err != nil {
		return "", err
	}
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+name+"\r\n\r\n"); err != nil {
		return "", err
	}
	buf := make([]byte, len(labResponse))
	if _, err := io.ReadFull(c, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}
