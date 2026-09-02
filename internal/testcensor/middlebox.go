package testcensor

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Conn is the client-side connection a Middlebox hands out.
//
// Beyond net.Conn it exposes the two controls a desync transport reaches for on
// a kernel socket, so an emit.Transport can drive a simulated flow through
// exactly the same code path it uses on a real one. Both are no-ops as far as
// the origin is concerned; only the middlebox's view changes, which is the
// point of both mechanisms.
type Conn interface {
	net.Conn
	// WriteOOB sends bytes as urgent data. The middlebox sees them inline; the
	// receiving TCP does not deliver them.
	WriteOOB(b []byte) (int, error)
	// SetTTL sets the IP TTL applied to subsequent writes. A segment below the
	// model's MinTTL reaches the middlebox but not the origin.
	SetTTL(ttl int) error
}

// Flow is the middlebox's record of one connection, for assertions.
type Flow struct {
	Addr       string
	ServerName string
	Verdict    Verdict
	Segments   int
	Bytes      int
}

// Options configure a Middlebox.
type Options struct {
	// Upstream dials the origin. nil uses a plain net.Dialer, which is what a
	// test wants when the origin is a loopback listener.
	Upstream func(ctx context.Context, network, addr string) (net.Conn, error)
	// Seed makes LossRate reproducible. 0 seeds a fixed constant, never the
	// clock: a censor simulator that fails one run in ten is worse than none.
	Seed int64
	// Port overrides the destination port the model is told about. A simulated
	// origin binds an ephemeral loopback port, so a model scoped to 443 would
	// otherwise never inspect anything — silently, and in the direction that
	// makes every test pass.
	Port int
	Logf func(string, ...any)
}

// Middlebox interposes a Model on in-process connections.
//
// It is not a proxy the system routes through — it is a dialer. Every dial made
// through DialContext is subject to the model, and nothing else is, which keeps
// a test's blast radius exactly as wide as the code under test.
type Middlebox struct {
	model Model
	opts  Options

	mu    sync.Mutex
	flows []Flow
	rnd   *rand.Rand
}

// New builds a Middlebox enforcing m.
func New(m Model, o Options) *Middlebox {
	seed := uint64(o.Seed)
	if seed == 0 {
		seed = 0x5DEECE66D
	}
	return &Middlebox{
		model: m,
		opts:  o,
		rnd:   rand.New(rand.NewPCG(seed, seed^0x9E3779B97F4A7C15)),
	}
}

// Model returns the enforced model.
func (b *Middlebox) Model() Model { return b.model }

// Flows returns a copy of the recorded per-connection decisions.
func (b *Middlebox) Flows() []Flow {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Flow(nil), b.flows...)
}

func (b *Middlebox) record(f Flow) {
	b.mu.Lock()
	b.flows = append(b.flows, f)
	b.mu.Unlock()
	if b.opts.Logf != nil {
		b.opts.Logf("testcensor: %s %s -> %s", b.model.Name, f.Addr, f.Verdict)
	}
}

func (b *Middlebox) lossy() bool {
	if b.model.LossRate <= 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rnd.Float64() < b.model.LossRate
}

// DialContext dials addr through the model. The returned net.Conn also
// satisfies Conn.
func (b *Middlebox) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dial := b.opts.Upstream
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	up, err := dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	port := 0
	var dst netip.Addr
	if host, p, e := net.SplitHostPort(addr); e == nil {
		port, _ = strconv.Atoi(p)
		if a, e := netip.ParseAddr(host); e == nil {
			dst = a
		}
	}
	if b.opts.Port != 0 {
		port = b.opts.Port
	}

	c := &censorConn{
		Conn: up,
		box:  b,
		addr: addr,
		in:   b.model.Inspect(port),
		ttl:  0,
	}
	// An address-level block fires before the client writes anything at all,
	// which is what makes ShapeIPBlock distinguishable from an SNI block: even a
	// benign hostname to the same address fails (MEASUREMENTS.md §1 measures the
	// opposite for Türk Telekom, so TT2026 never sets it).
	if v := c.in.Dst(dst); v.Blocked() {
		c.apply(v)
	}
	if b.lossy() {
		c.apply(Verdict{Action: ActionDrop, Reason: "modelled packet loss"})
	}
	return c, nil
}

// resetError is what a client observes when the middlebox injects an RST. It is
// shaped like the kernel's so that a classifier keyed on syscall.ECONNRESET —
// which is what real traffic produces — is what the tests exercise.
func resetError(op, addr string) error {
	var a net.Addr
	// Built from the literal only. net.ResolveTCPAddr on a hostname would reach
	// the system resolver, which MEASUREMENTS.md §5.4 forbids anywhere in this
	// tree — a censor simulator that quietly queries the ISP's resolver is a
	// spectacular way to lose an afternoon.
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		a = net.TCPAddrFromAddrPort(ap)
	}
	return &net.OpError{Op: op, Net: "tcp", Addr: a, Err: syscall.ECONNRESET}
}

type censorConn struct {
	net.Conn
	box  *Middlebox
	addr string

	mu       sync.Mutex
	in       *Inspector
	ttl      int
	segments int
	bytes    int
	pending  []byte // bytes the middlebox injects toward the client (a TLS alert)
	state    Action
	fired    bool
	recorded bool
}

// apply enacts a verdict once. The caller must not hold c.mu.
func (c *censorConn) apply(v Verdict) {
	c.mu.Lock()
	if c.fired || !v.Blocked() {
		c.mu.Unlock()
		return
	}
	c.fired = true
	c.state = v.Action
	if v.Action == ActionAlert {
		desc := c.box.model.AlertDesc
		if desc == 0 {
			desc = AlertIllegalParameter
		}
		c.pending = append(c.pending, AlertRecord(desc)...)
	}
	flow := Flow{Addr: c.addr, ServerName: c.in.ServerName(), Verdict: v,
		Segments: c.segments, Bytes: c.bytes}
	c.recorded = true
	c.mu.Unlock()

	c.box.record(flow)

	switch v.Action {
	case ActionReset:
		// SetLinger(0) makes the close a genuine RST toward the origin, so the
		// server side of a simulated block sees what a real one produces.
		if tc, ok := c.Conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = c.Conn.Close()
	case ActionEOF:
		_ = c.Conn.Close()
	case ActionAlert:
		if tc, ok := c.Conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = c.Conn.Close()
	case ActionDrop:
		// Deliberately left open and silent: the client must experience a
		// timeout, which is a different failure class from a reset and one the
		// ladder is required to treat differently.
	}
}

func (c *censorConn) Write(b []byte) (int, error) { return c.write(b, false) }

// WriteOOB implements Conn.
func (c *censorConn) WriteOOB(b []byte) (int, error) { return c.write(b, true) }

// SetTTL implements Conn.
func (c *censorConn) SetTTL(ttl int) error {
	c.mu.Lock()
	c.ttl = ttl
	c.mu.Unlock()
	return nil
}

func (c *censorConn) write(b []byte, oob bool) (int, error) {
	c.mu.Lock()
	if st := c.state; st != ActionPass {
		c.mu.Unlock()
		switch st {
		case ActionDrop:
			return len(b), nil // swallowed, exactly like a blackhole
		case ActionEOF:
			return 0, io.ErrClosedPipe
		default:
			return 0, resetError("write", c.addr)
		}
	}
	c.segments++
	c.bytes += len(b)
	ttl := c.ttl
	var v Verdict
	deliver := true
	if oob {
		v, deliver = c.in.ClientOOB(b), false
	} else {
		v, deliver = c.in.Client(b, ttl)
	}
	c.mu.Unlock()

	if v.Blocked() {
		c.apply(v)
		// The segment that triggered the block never reaches the origin, but the
		// client's Write succeeded: the kernel accepted the bytes and the RST
		// arrives on the next read. Reporting a short write here would be a
		// fiction no real socket produces.
		return len(b), nil
	}
	if !deliver {
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func (c *censorConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		c.mu.Unlock()
		return n, nil
	}
	st := c.state
	c.mu.Unlock()

	switch st {
	case ActionReset, ActionAlert:
		return 0, resetError("read", c.addr)
	case ActionEOF:
		return 0, io.EOF
	case ActionDrop:
		// Block until the caller's own deadline fires. Reading the (still open,
		// still silent) upstream does exactly that without inventing a timer.
	}

	n, err := c.Conn.Read(b)
	if err != nil {
		c.mu.Lock()
		st := c.state
		c.mu.Unlock()
		switch st {
		case ActionReset, ActionAlert:
			return n, resetError("read", c.addr)
		case ActionEOF:
			return n, io.EOF
		}
	}
	return n, err
}

func (c *censorConn) Close() error {
	c.mu.Lock()
	if !c.recorded {
		c.recorded = true
		flow := Flow{Addr: c.addr, ServerName: c.in.ServerName(), Verdict: c.in.Verdict(),
			Segments: c.segments, Bytes: c.bytes}
		c.mu.Unlock()
		c.box.record(flow)
	} else {
		c.mu.Unlock()
	}
	return c.Conn.Close()
}

// SetDeadline forwards to the underlying conn. A dropped flow relies on it: the
// blackhole is only observable as a timeout if the caller sets one.
func (c *censorConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *censorConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *censorConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }

// IsReset reports whether err is the reset a Middlebox injects, or a genuine
// kernel ECONNRESET. Tests assert on this rather than on error strings.
func IsReset(err error) bool { return errors.Is(err, syscall.ECONNRESET) }
