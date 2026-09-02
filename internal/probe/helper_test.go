package probe_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/emit"
	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/ops"
	"github.com/mumudevx/dpi-bypass-mac/internal/probe"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
)

// reg is the real op set. The prober compiles the specs the product compiles;
// a test registry with stub ops would measure a different program.
var reg = ops.NewRegistry()

func mustSpec(t *testing.T, spec string) strategy.Strategy {
	t.Helper()
	s, err := reg.Get(spec)
	if err != nil {
		t.Fatalf("parse %q: %v", spec, err)
	}
	return s
}

// lab is an origin behind a modelled middlebox, wired so a trial runs the real
// datapath: the real strategy compiler, the real emit.Sender, and a transport
// exposing the same capabilities a kernel socket does.
type lab struct {
	origin *testcensor.Origin
	box    *testcensor.Middlebox
	caps   strategy.Cap
}

func newLab(t *testing.T, m testcensor.Model, names ...string) *lab {
	t.Helper()
	if len(names) == 0 {
		names = []string{"discord.com", "cloudflare.com"}
	}
	o, err := testcensor.NewOrigin(testcensor.OriginConfig{Names: names})
	if err != nil {
		t.Fatalf("origin: %v", err)
	}
	t.Cleanup(func() { o.Close() })

	// Port 443 is asserted rather than inferred: the origin binds an ephemeral
	// loopback port, and a model scoped to 443 would otherwise inspect nothing
	// at all — silently, and in the direction that makes every test pass.
	box := testcensor.New(m, testcensor.Options{Port: 443, Logf: t.Logf})

	return &lab{
		origin: o,
		box:    box,
		caps:   strategy.CapStreamWrite | strategy.CapNoDelay | strategy.CapSockTTL | strategy.CapOOB,
	}
}

func (l *lab) options(t *testing.T) probe.TrialOptions {
	t.Helper()
	return probe.TrialOptions{
		Dial:      boxDialer{box: l.box, addr: l.origin.Addr()},
		Wrap:      func(c net.Conn) (emit.Transport, error) { return newBoxTransport(c, l.caps) },
		TLSConfig: func(host string) *tls.Config { return l.origin.ClientConfig(host) },
		Logf:      t.Logf,
	}
}

// boxDialer routes every dial through the middlebox, so the model applies to
// exactly the connections under test and to nothing else.
type boxDialer struct {
	box  *testcensor.Middlebox
	addr string
}

func (d boxDialer) DialTCP(ctx context.Context, _ flow.Target) (net.Conn, error) {
	return d.box.DialContext(ctx, "tcp", d.addr)
}

// errDialer fails every dial, which is the VerdictDialFail path.
type errDialer struct{ err error }

func (d errDialer) DialTCP(context.Context, flow.Target) (net.Conn, error) { return nil, d.err }

// plainDialer hands back a conn that is not a *net.TCPConn, which is what the
// default Wrap must refuse rather than silently skip the desync.
type plainDialer struct{}

func (plainDialer) DialTCP(context.Context, flow.Target) (net.Conn, error) {
	a, _ := net.Pipe()
	return a, nil
}

// boxTransport adapts a testcensor.Conn to emit.Transport. It is the only piece
// of the datapath a test substitutes: the plan, the Sender and the emission
// order are the shipped ones.
type boxTransport struct {
	c    testcensor.Conn
	caps strategy.Cap
}

func newBoxTransport(c net.Conn, caps strategy.Cap) (emit.Transport, error) {
	cc, ok := c.(testcensor.Conn)
	if !ok {
		return nil, errors.New("probe test: dialler did not return a testcensor.Conn")
	}
	return &boxTransport{c: cc, caps: caps}, nil
}

func (t *boxTransport) Caps() strategy.Cap             { return t.caps }
func (t *boxTransport) Write(b []byte) (int, error)    { return t.c.Write(b) }
func (t *boxTransport) WriteOOB(b []byte) (int, error) { return t.c.WriteOOB(b) }
func (t *boxTransport) SetTTL(ttl int) error           { return t.c.SetTTL(ttl) }
func (t *boxTransport) ResetTTL() error                { return t.c.SetTTL(0) }
func (t *boxTransport) InjectRaw([]byte) error         { return emit.ErrCapUnavailable }
func (t *boxTransport) SeqState() (emit.SeqState, bool) {
	return emit.SeqState{}, false
}
func (t *boxTransport) Local() netip.AddrPort  { return addrPort(t.c.LocalAddr()) }
func (t *boxTransport) Remote() netip.AddrPort { return addrPort(t.c.RemoteAddr()) }
func (t *boxTransport) Close() error           { return t.c.Close() }

func addrPort(a net.Addr) netip.AddrPort {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(ta.Port))
}
