package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/mumudevx/dpb/internal/emit"
	"github.com/mumudevx/dpb/internal/flow"
	"github.com/mumudevx/dpb/internal/resolve"
	"github.com/mumudevx/dpb/internal/strategy"
	"github.com/mumudevx/dpb/internal/tlsmsg"
)

// Verdict is the outcome of one attempt.
type Verdict uint8

const (
	VerdictUnknown Verdict = iota
	// VerdictPass means the TLS handshake completed AND the certificate
	// validates for the name. Not "TCP connected", not "bytes came back": that
	// is what rules out a half-open connection and a transparent block page.
	VerdictPass
	VerdictReset
	VerdictTimeout
	VerdictBlockPage
	// VerdictHandshakeFail is a TLS alert or a bad handshake message: a server
	// condition, discarded rather than attributed to a strategy.
	VerdictHandshakeFail
	VerdictDialFail
	// VerdictLocalError is our own downgrade or bug. Discarded, never scored,
	// because a strategy that was not emitted cannot be measured.
	VerdictLocalError
	// VerdictControlDown is set by the runner when a round's interleaved control
	// failed, so the whole round is discarded rather than scored.
	VerdictControlDown
)

var verdictNames = [...]string{
	"UNKNOWN", "PASS", "RESET", "TIMEOUT", "BLOCKPAGE",
	"HANDSHAKE-FAIL", "DIAL-FAIL", "LOCAL-ERROR", "CONTROL-DOWN",
}

func (v Verdict) String() string {
	if int(v) >= len(verdictNames) {
		return "INVALID"
	}
	return verdictNames[v]
}

// Scorable reports whether the verdict says anything about the strategy. A
// handshake failure, a local error and a downed control are all conditions of
// something other than the emitter, so scoring them would attribute someone
// else's failure to a candidate.
func (v Verdict) Scorable() bool {
	return v == VerdictPass || v == VerdictReset || v == VerdictTimeout || v == VerdictBlockPage
}

// Trial is one attempt: one strategy, one target, one round.
type Trial struct {
	Spec    string
	Target  Target
	Round   int
	Verdict Verdict
	Latency time.Duration
	Err     string
	At      time.Time

	// Peer is the address actually connected to. With a pinned target it is the
	// pin; with a resolved one it is what the chain returned, which is the fact
	// a reader needs to tell a strategy failure from a poisoned answer.
	Peer netip.AddrPort
	// Segments is how many writes the emitted plan actually used. A trial that
	// claims tlsfrag but emitted one segment carrying the whole hello measured
	// nothing, so the count is recorded rather than assumed.
	Segments int
	// SNIStart and SNIEnd are the body-relative extent of the SNI hostname in
	// the ClientHello this client actually produced, or 0 when there was none.
	//
	// They are recorded because the measured rule is stated in those
	// coordinates (MEASUREMENTS.md §3.2: "body=1497, sni at [112,122)"), and
	// the prober's first-record search has to be conducted in THIS client's
	// coordinates rather than in the ones one afternoon in Kayseri happened to
	// produce.
	SNIStart int
	SNIEnd   int
	// RecordEnd is the body-relative end of the first TLS record as the plan
	// actually emitted it — read back out of the emitted bytes, not predicted
	// from the spec. For an unreframed plan it is the whole first record.
	//
	// It is what makes "where did the cut land, relative to the hostname" a
	// measurement rather than a label, which is the distinction §3.5 records
	// the previous implementation getting wrong: its cut was never verified to
	// land before sniEnd at all.
	RecordEnd int
}

// DefaultTrialTimeout bounds one attempt end to end.
//
// MEASUREMENTS.md §6 measures a plain attempt reaching its RST in ~22 ms and a
// desync retry completing a handshake in ~23 ms, so anything short of a second
// is already two orders of magnitude of headroom on this line. The budget is
// set well above that so a genuinely silent drop is reported as TIMEOUT after a
// wait a mobile link could plausibly need, not misreported because we gave up.
const DefaultTrialTimeout = 8 * time.Second

// TrialOptions is everything one attempt needs. The zero value is not usable:
// Dial is required.
type TrialOptions struct {
	// Dial opens the upstream connection. Every attempt gets a fresh one.
	Dial flow.Dialer
	// Sender executes the plan. Nil means an ungoverned Sender, which is the
	// correct mode for a prober: a coalesced plan is not the plan that was
	// asked for, and scoring it would be a lie.
	Sender *emit.Sender
	// Caps overrides the transport's advertised capabilities. Zero means ask the
	// transport, which is what the product does.
	Caps strategy.Cap
	// Budget bounds the compiled plan. Zero means strategy.DefaultBudget.
	Budget strategy.Budget
	// Timeout bounds the whole attempt. Zero means DefaultTrialTimeout.
	Timeout time.Duration

	// Wrap turns a dialled connection into the transport a plan is emitted on.
	// Nil means emit.NewSockTransport — the same transport both front-ends use.
	// Tests substitute an in-process censor here; nothing else should.
	Wrap func(net.Conn) (emit.Transport, error)

	// TLSConfig builds the client config for a host. Nil means full verification
	// against the system roots, which is what makes VerdictPass mean "the
	// certificate validates for the name".
	TLSConfig func(host string) *tls.Config

	// Sinkholes are addresses that are a censorship answer rather than a host.
	// Nil means resolve.DefaultSinkholes. Reaching one is VerdictBlockPage no
	// matter how well the connection went (MEASUREMENTS.md §2).
	Sinkholes []netip.Addr

	Now  func() time.Time
	Logf func(string, ...any)
}

func (o TrialOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o TrialOptions) logf(format string, a ...any) {
	if o.Logf != nil {
		o.Logf(format, a...)
	}
}

func (o TrialOptions) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return DefaultTrialTimeout
}

func (o TrialOptions) sinkholes() []netip.Addr {
	if o.Sinkholes != nil {
		return o.Sinkholes
	}
	return resolve.DefaultSinkholes
}

func (o TrialOptions) tlsConfig(host string) *tls.Config {
	if o.TLSConfig != nil {
		if c := o.TLSConfig(host); c != nil {
			return c
		}
	}
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
}

func (o TrialOptions) wrap(c net.Conn) (emit.Transport, error) {
	if o.Wrap != nil {
		return o.Wrap(c)
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("probe: dialler returned %T, not a *net.TCPConn", c)
	}
	return emit.NewSockTransport(tc, nil)
}

// RunTrial performs one attempt and returns its verdict.
//
// It never returns an error: every failure IS a result, and the caller's job is
// to score it, not to handle it. The distinction that matters is the one baked
// into Verdict.Scorable — a reset is evidence about the strategy, a local
// downgrade is evidence about us.
func RunTrial(ctx context.Context, s strategy.Strategy, t Target, round int, o TrialOptions) Trial {
	tr := Trial{Spec: s.Spec, Target: t, Round: round, At: o.now()}

	if err := t.Validate(); err != nil {
		return tr.fail(VerdictLocalError, err, 0)
	}
	if o.Dial == nil {
		return tr.fail(VerdictLocalError, errors.New("probe: no dialler"), 0)
	}
	if a, ok := t.Pinned(); ok && isSinkhole(a, o.sinkholes()) {
		// Do not burn a connection proving what the address already says.
		return tr.fail(VerdictBlockPage,
			fmt.Errorf("probe: %s is pinned to the known sinkhole %s (MEASUREMENTS.md §2)", t.Host, a), 0)
	}

	ctx, cancel := context.WithTimeout(ctx, o.timeout())
	defer cancel()

	start := o.now()
	conn, err := o.Dial.DialTCP(ctx, t.Flow())
	if err != nil {
		return tr.fail(VerdictDialFail, err, o.now().Sub(start))
	}

	tp, err := o.wrap(conn)
	if err != nil {
		conn.Close()
		return tr.fail(VerdictLocalError, err, o.now().Sub(start))
	}
	defer tp.Close()

	tr.Peer = peerAddr(conn, tp)
	if tr.Peer.IsValid() && isSinkhole(tr.Peer.Addr(), o.sinkholes()) {
		return tr.fail(VerdictBlockPage,
			fmt.Errorf("probe: connected to the known sinkhole %s (MEASUREMENTS.md §2)", tr.Peer.Addr()),
			o.now().Sub(start))
	}

	if dl, ok := ctx.Deadline(); ok {
		// The TLS handshake reads and writes directly on the conn, so the
		// context alone would not unblock it.
		if err := conn.SetDeadline(dl); err != nil {
			// A conn that is already gone by the time the deadline is armed was
			// torn down by the peer between the dial returning and this call.
			// That is the network's doing and not ours, and calling it a local
			// error would be the worst possible misattribution here: an
			// address-level block resets at connect time, so the one shape a
			// prober must recognise and STOP on would read as "dpb is broken"
			// and be discarded from every denominator.
			if errors.Is(err, net.ErrClosed) || flow.IsReset(err) {
				return tr.fail(VerdictReset, fmt.Errorf("probe: connection gone before the handshake: %w", err),
					o.now().Sub(start))
			}
			return tr.fail(VerdictLocalError, fmt.Errorf("probe: set deadline: %w", err), o.now().Sub(start))
		}
	}

	dc := &desyncConn{
		Conn:     conn,
		tp:       tp,
		sender:   o.Sender,
		strat:    s,
		caps:     o.Caps,
		budget:   o.Budget,
		port:     t.DialPort(),
		ctx:      ctx,
		logf:     o.logf,
		emitFrom: o.now,
	}
	if dc.sender == nil {
		dc.sender = &emit.Sender{Logf: o.Logf}
	}
	if dc.caps == 0 {
		dc.caps = tp.Caps()
	}

	tlsConn := tls.Client(dc, o.tlsConfig(t.Host))
	hsErr := tlsConn.HandshakeContext(ctx)
	tr.Latency = o.now().Sub(start)
	tr.Segments = dc.segments
	tr.SNIStart, tr.SNIEnd, tr.RecordEnd = dc.sniStart, dc.sniEnd, dc.recordEnd

	// A build or emit failure is ours, not the network's, and outranks whatever
	// the handshake then reported: a strategy that never reached the wire has
	// not been measured.
	if dc.err != nil {
		return tr.fail(VerdictLocalError, dc.err, tr.Latency)
	}
	if hsErr != nil {
		return tr.fail(classifyHandshake(hsErr, ctx.Err()), hsErr, tr.Latency)
	}

	tr.Verdict = VerdictPass
	return tr
}

func (t Trial) fail(v Verdict, err error, d time.Duration) Trial {
	t.Verdict = v
	if err != nil {
		t.Err = err.Error()
	}
	if d > 0 {
		t.Latency = d
	}
	return t
}

// classifyHandshake maps a handshake error to a verdict.
//
// The order is deliberate. A certificate that does not validate for the name is
// the shape of a transparent block page, and it must be recognised before the
// generic transport classes, because such a handshake "succeeds" at the TCP and
// record layers. A remote TLS alert is the server refusing our handshake, which
// MEASUREMENTS.md §5 measures on yapikredi.com.tr under record splitting — that
// is a compatibility fact about the origin, never a bypass fact about the DPI.
func classifyHandshake(err error, ctxErr error) Verdict {
	if err == nil {
		return VerdictPass
	}
	if isCertError(err) {
		return VerdictBlockPage
	}
	// The peer answered on 443 with something that is not a TLS record. On this
	// line that is the block page's HTTP server, not a TLS endpoint.
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) {
		return VerdictBlockPage
	}
	if isRemoteAlert(err) {
		return VerdictHandshakeFail
	}
	if flow.IsTimeout(err) || errors.Is(ctxErr, context.DeadlineExceeded) {
		return VerdictTimeout
	}
	// flow.IsReset covers EOF as well as ECONNRESET: six of the ten fragile
	// hosts in MEASUREMENTS.md §5 failed with a bare "handshake: EOF". Anything
	// unrecognised lands here too, matching flow.Classify's documented default —
	// before any byte has been delivered, an unexplained end of connection is
	// the censorship-shaped case.
	return VerdictReset
}

func isCertError(err error) bool {
	var (
		unknown  x509.UnknownAuthorityError
		hostname x509.HostnameError
		invalid  x509.CertificateInvalidError
		verify   *tls.CertificateVerificationError
	)
	return errors.As(err, &unknown) || errors.As(err, &hostname) ||
		errors.As(err, &invalid) || errors.As(err, &verify)
}

// isRemoteAlert reports whether err is a fatal alert sent by the peer.
//
// crypto/tls renders these as a net.OpError with Op "remote error" wrapping an
// unexported alert type, so there is no exported error value to compare against
// and the prefix is the only handle the standard library offers.
func isRemoteAlert(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "remote error" {
		return true
	}
	return strings.Contains(err.Error(), "remote error: tls:")
}

func isSinkhole(a netip.Addr, set []netip.Addr) bool {
	a = a.Unmap()
	for _, s := range set {
		s = s.Unmap()
		if !s.IsValid() {
			continue
		}
		if s.Is4() {
			if a == s {
				return true
			}
			continue
		}
		// A censor answering from a /64 can move within it for free, so match
		// the containing prefix rather than the exact host (DOSSIER GT19).
		p := netip.PrefixFrom(s, 64)
		if p.IsValid() && a.Is6() && p.Masked().Contains(a) {
			return true
		}
	}
	return false
}

func peerAddr(c net.Conn, tp emit.Transport) netip.AddrPort {
	if ap := tp.Remote(); ap.IsValid() {
		return ap
	}
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		if a, ok := netip.AddrFromSlice(ta.IP); ok {
			return netip.AddrPortFrom(a.Unmap(), uint16(ta.Port))
		}
	}
	return netip.AddrPort{}
}

// desyncConn is the seam that makes a probe measure the product. The first
// write a client makes is the first application message, so it is the one the
// strategy compiles and the Sender emits; everything after it is an ordinary
// write on the same transport.
//
// crypto/tls hands the whole ClientHello record to Write in one call, which is
// exactly the contract tlsmsg.Parse and every reframing op are written against.
type desyncConn struct {
	net.Conn
	tp       emit.Transport
	sender   *emit.Sender
	strat    strategy.Strategy
	caps     strategy.Cap
	budget   strategy.Budget
	port     int
	ctx      context.Context
	logf     func(string, ...any)
	emitFrom func() time.Time

	first     bool
	segments  int
	sniStart  int
	sniEnd    int
	recordEnd int
	// err is a build or emit failure. It is recorded rather than returned
	// verbatim so RunTrial can tell "we never emitted this strategy" from "the
	// network killed the connection".
	err error
}

func (c *desyncConn) Write(b []byte) (int, error) {
	if c.first {
		return c.tp.Write(b)
	}
	c.first = true

	m := tlsmsg.Parse(b, c.port)
	if m.SNIEnd > 0 {
		c.sniStart, c.sniEnd = m.SNIStart, m.SNIEnd
	}
	bld := &strategy.Builder{
		Payload: append([]byte(nil), b...),
		Meta:    m,
		Caps:    c.caps,
		Budget:  c.budget,
		// A prober that silently downgrades measures a strategy nobody asked
		// for and reports it under the name of the one they did.
		Strict: true,
	}
	plan, err := c.strat.BuildWith(bld)
	if err != nil {
		c.err = fmt.Errorf("probe: compile %q: %w", label(c.strat.Spec), err)
		return 0, c.err
	}
	c.segments = plan.WriteCount()
	c.recordEnd = firstRecordEnd(plan.StreamBytes())
	if c.logf != nil {
		c.logf("probe: %s emits %d segment(s): %s", label(c.strat.Spec), plan.WriteCount(), plan.Summary())
	}

	if err := c.sender.Send(c.ctx, c.tp, plan); err != nil {
		// An emit failure can be either: a capability the transport does not
		// have (ours) or the censor tearing the connection down mid-plan
		// (theirs). Only the former is a local error.
		if errors.Is(err, emit.ErrCapUnavailable) || errors.Is(err, strategy.ErrCapUnavailable) {
			c.err = err
		}
		return 0, err
	}
	return len(b), nil
}

func label(spec string) string {
	if spec == "" {
		return "plain"
	}
	return spec
}

// firstRecordEnd reads the body-relative end of the first TLS record back out
// of the bytes a plan will actually put on the wire.
//
// Reading it from the emitted bytes rather than from the spec is deliberate: a
// spec is what was asked for and the bytes are what happened, and the whole
// reason strategy.ErrCutAfterSNI exists is that the previous implementation
// never checked that the two agreed.
func firstRecordEnd(b []byte) int {
	if len(b) < tlsHeaderLen || b[0] != tlsRecTypeHandshake {
		return 0
	}
	return int(binary.BigEndian.Uint16(b[3:5]))
}

const (
	tlsHeaderLen        = 5
	tlsRecTypeHandshake = 0x16
)
