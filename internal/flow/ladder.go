package flow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/emit"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

var (
	ErrLadderExhausted = errors.New("flow: every ladder rung failed")
	ErrNoUpstream      = errors.New("flow: upstream dial failed")
)

const (
	// DefaultMaxAttempts is the number of upstream connections one client
	// connection may cost. Five is the length of the shipped TR ladder
	// (MEASUREMENTS.md §5.3), so the default neither truncates it nor invites
	// an unbounded walk.
	DefaultMaxAttempts = 5
	// DefaultTotalBudget bounds the whole walk. §6 measures a plain attempt
	// resolving in ~22 ms and a desynced retry completing in ~23 ms, so five
	// seconds is two orders of magnitude of headroom and is really a guard
	// against a blackholed path, not a tuning knob.
	DefaultTotalBudget = 5 * time.Second
	// DefaultLadder is the named ladder used when a verdict carries none. The
	// shipped profiles select it explicitly; this is the fallback that keeps a
	// misconfigured build escalating rather than silently never escalating.
	DefaultLadder = "tr"
	// LearnedDesyncTTL is how long "this host needed a desync" is trusted.
	// MEASUREMENTS.md §4 records that Turkish DPI configurations rot on a
	// months-scale cadence and §5.2 asks for a TTL; a week re-tests often
	// enough to notice a host being unblocked (GT20's Roblox case) and rarely
	// enough that the cache is worth having.
	LearnedDesyncTTL = 7 * 24 * time.Hour
)

// Attempt is one upstream connection made for one client connection.
type Attempt struct {
	Spec    string
	Class   Failure
	Err     error
	Latency time.Duration
}

// Outcome is what the ladder produced.
type Outcome struct {
	// Conn is the live upstream connection on success, nil otherwise.
	Conn net.Conn
	// Spec is the winning strategy; "" means plain, which is the common case
	// and the one the whole design is arranged around.
	Spec string
	// Attempts lists every rung tried, in order, including the ones that
	// failed. `dpb why` prints it and the escalation-rate drift detector
	// counts it.
	Attempts []Attempt
	// Pre holds upstream bytes already read while judging the attempt. They
	// must be written to the client BEFORE the relay starts or the stream has
	// a hole in it.
	Pre []byte
}

// Escalations is the number of attempts past the first. Zero is the outcome the
// design optimises for: MEASUREMENTS.md §5.1 measured every bypassing emitter
// breaking Turkish banking, so not escalating is the safe result, not a
// missed opportunity.
func (o Outcome) Escalations() int {
	if len(o.Attempts) == 0 {
		return 0
	}
	return len(o.Attempts) - 1
}

// LadderRunner holds the buffered first message and walks the escalation ladder
// on fresh upstream connections.
type LadderRunner struct {
	Dial        Dialer
	Sender      *emit.Sender
	Registry    *strategy.Registry
	Store       policy.Store
	NetID       func() policy.NetworkID
	Single      *policy.Singleflight
	RTT         *RTTTracker
	Caps        strategy.Cap
	Budget      strategy.Budget
	MaxAttempts int
	TotalBudget time.Duration
	Now         func() time.Time
	OnOutcome   func(Target, policy.Verdict, Outcome)
	Logf        func(string, ...any)
}

// defaultSender is used when a runner carries none. It is ungoverned, which is
// the right default for a caller that did not think about the XNU small-write
// guard: the primary emitter is one write and never reaches a governor anyway.
var defaultSender emit.Sender

// Run holds the buffered first message and tries rungs on FRESH upstream
// connections. Retry is safe for exactly this window because the ClientHello is
// the first thing on the wire: if the handshake fails, no application bytes have
// been delivered in either direction, so re-dialling is invisible to the client.
// Validated on the wire, MEASUREMENTS.md §6: 18/18 immediate retries succeeded.
//
// first is the buffered first message and m its parse; extra is anything the
// client sent after it and before the dial, replayed on every attempt.
//
// Attempt one is plain for every verdict except a cached ScopeDesync — that is
// the correctness requirement of §5.2, not an optimisation, because 10 of the 41
// Turkish hosts probed in §5 break under the emitter that defeats the DPI and
// all ten are banks or .gov.tr.
func (l *LadderRunner) Run(ctx context.Context, t Target, v policy.Verdict,
	first []byte, m tlsmsg.Meta, extra []byte) (Outcome, error) {
	if l == nil || l.Dial == nil {
		return Outcome{}, errors.New("flow: ladder runner has no dialer")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	budget := l.TotalBudget
	if budget <= 0 {
		budget = DefaultTotalBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	rungs := l.rungs(v)

	// A walk with a single rung has nothing to learn and nothing to collapse.
	if l.Single == nil || len(rungs) < 2 || t.Name == "" {
		out, _, err := l.walk(ctx, t, v, rungs, first, m, extra)
		return out, err
	}

	// Singleflight collapses the six parallel connections a browser opens so
	// the ladder is walked once. The leader runs fn on this goroutine and keeps
	// its own connection; everyone else gets only the verdict and then makes a
	// single attempt with the winner.
	var (
		mine    *Outcome
		mineErr error
	)
	key := policy.Key(l.netID(), t.Name)
	learned, lerr := l.Single.Do(key, func() (policy.Verdict, error) {
		out, nv, err := l.walk(ctx, t, v, rungs, first, m, extra)
		mine, mineErr = &out, err
		return nv, err
	})
	if mine != nil {
		return *mine, mineErr
	}
	if lerr != nil {
		// The leader's walk failed. Its verdict says nothing useful about our
		// connection, so walk ourselves rather than inheriting a failure.
		out, _, err := l.walk(ctx, t, v, rungs, first, m, extra)
		return out, err
	}
	out, _, err := l.walk(ctx, t, learned, l.rungs(learned), first, m, extra)
	return out, err
}

// rungs is the ordered spec list for one verdict.
func (l *LadderRunner) rungs(v policy.Verdict) []string {
	if v.Class == policy.ScopeBypass {
		// A hard veto. Never buffered by the front end, and if it reaches here
		// anyway it is sent once, unmodified, and never escalated.
		return []string{""}
	}
	base := v.Ladder
	if len(base) == 0 {
		if specs, ok := strategy.LadderSpecs(DefaultLadder); ok {
			base = specs
		}
	}
	out := make([]string, 0, len(base)+1)
	seen := make(map[string]bool, len(base)+1)
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if v.Class == policy.ScopeDesync && v.Spec != "" {
		add(v.Spec)
	} else {
		// MEASUREMENTS.md §5.2 step 1: connect with no desync. Always. A
		// configured ladder that omits plain does not get to skip it, because
		// the cost of being wrong is a bank that stops working.
		add("")
	}
	for _, s := range base {
		add(s)
	}
	if len(out) == 0 {
		out = append(out, "")
	}
	return out
}

// walk tries each rung in order and returns the connection that survived.
func (l *LadderRunner) walk(ctx context.Context, t Target, v policy.Verdict, rungs []string,
	first []byte, m tlsmsg.Meta, extra []byte) (Outcome, policy.Verdict, error) {
	var out Outcome
	maxAtt := l.MaxAttempts
	if maxAtt <= 0 {
		maxAtt = DefaultMaxAttempts
	}

	var lastErr error
	for i, spec := range rungs {
		if len(out.Attempts) >= maxAtt {
			break
		}
		if cerr := ctx.Err(); cerr != nil {
			lastErr = cerr
			break
		}
		if i > 0 && !Replayable(first, m) {
			out.Attempts = append(out.Attempts, Attempt{Spec: spec, Class: FailNotReplayable, Err: ErrNotReplayable})
			lastErr = ErrNotReplayable
			break
		}

		st, perr := l.parse(spec)
		if perr != nil {
			// A ladder naming an unparseable spec is a configuration defect,
			// not a network condition. Failing loudly beats walking past it.
			out.Attempts = append(out.Attempts, Attempt{
				Spec: spec, Class: FailBudget,
				Err: fmt.Errorf("flow: rung %q: %w", specName(spec), perr),
			})
			lastErr = perr
			break
		}
		// Whether a rung can apply to THIS message is a pure question, so it is
		// answered before a socket is opened: a truncated hello must never
		// reach a reframer, which is the defect MEASUREMENTS.md §3.5 names.
		// When the caller has declared the transport's capabilities they are
		// checked here too; otherwise capabilities are checked after the dial,
		// against what the socket actually granted.
		if cerr := st.CheckAgainst(l.checkCaps(), m); cerr != nil {
			out.Attempts = append(out.Attempts, Attempt{Spec: spec, Class: FailBudget, Err: cerr})
			l.logf("flow: %s rung %q does not apply to this first message: %v", t, specName(spec), cerr)
			continue
		}

		start := l.now()
		conn, derr := l.Dial.DialTCP(ctx, t)
		if derr != nil {
			out.Attempts = append(out.Attempts, Attempt{
				Spec: spec, Class: FailDial, Err: derr, Latency: l.now().Sub(start),
			})
			lastErr = derr
			l.logf("flow: %s rung %q: dial failed: %v", t, specName(spec), derr)
			continue
		}

		last := i == len(rungs)-1 || len(out.Attempts)+1 >= maxAtt
		att, pre, res := l.attempt(ctx, conn, t, st, first, m, extra, last, start)
		out.Attempts = append(out.Attempts, att)
		switch res {
		case attemptOK:
			out.Conn, out.Spec, out.Pre = conn, spec, pre
			nv := l.recordWin(t, v, spec, out)
			l.report(t, nv, out)
			return out, nv, nil
		case attemptHandover:
			// Committed without evidence. The connection is usable and nothing
			// has been lost, but silence is not a result worth caching.
			out.Conn, out.Spec, out.Pre = conn, spec, pre
			l.report(t, v, out)
			return out, v, nil
		}
		_ = conn.Close()
		lastErr = att.Err
		if res == attemptStop {
			break
		}
	}

	nv := v
	// A cancelled walk is not evidence against a cached winner: nothing was
	// learned about the host, only about our own deadline.
	if ctx.Err() == nil {
		nv = l.recordLoss(t, v, out)
	}
	l.report(t, nv, out)
	if lastErr == nil {
		lastErr = errors.New("no rung was attempted")
	}
	if dialOnly(out.Attempts) {
		return out, nv, fmt.Errorf("%w: %s after %d attempt(s): %w", ErrNoUpstream, t, len(out.Attempts), lastErr)
	}
	return out, nv, fmt.Errorf("%w: %s after %d attempt(s): %w", ErrLadderExhausted, t, len(out.Attempts), lastErr)
}

// allCaps is every capability. It is what the pre-dial check uses when the
// caller has not declared the transport's capabilities, so that check answers
// only the message-shape half of Strategy.CheckAgainst and nothing is waved
// through: Strategy.Build re-checks capabilities after the dial against what the
// socket actually granted.
const allCaps = ^strategy.Cap(0)

func (l *LadderRunner) checkCaps() strategy.Cap {
	if l.Caps != 0 {
		return l.Caps
	}
	return allCaps
}

// dialOnly reports whether every attempt died before a byte was written. The
// distinction matters to the caller: no ladder rung can rescue a path that will
// not carry a TCP connection at all, so ErrNoUpstream must not be reported as an
// exhausted ladder.
func dialOnly(atts []Attempt) bool {
	if len(atts) == 0 {
		return false
	}
	for _, a := range atts {
		if a.Class != FailDial {
			return false
		}
	}
	return true
}

type attemptResult uint8

const (
	attemptOK       attemptResult = iota // committed with evidence: cache the win
	attemptHandover                      // committed without evidence: use it, learn nothing
	attemptRetry                         // censorship-shaped: advance one rung
	attemptSkip                          // this rung cannot apply to this message
	attemptStop                          // fatal: the walk ends here
)

// attempt emits one rung on conn and judges the result.
//
// last says no rung remains, so a retryable failure ends the walk here.
func (l *LadderRunner) attempt(ctx context.Context, conn net.Conn, t Target, st strategy.Strategy,
	first []byte, m tlsmsg.Meta, extra []byte, last bool, start time.Time) (Attempt, []byte, attemptResult) {
	spec := st.Spec
	att := Attempt{Spec: spec}
	fail := func(class Failure, res attemptResult, err error) (Attempt, []byte, attemptResult) {
		att.Class, att.Err, att.Latency = class, err, l.now().Sub(start)
		return att, nil, res
	}

	tr, err := transportFor(conn)
	if err != nil {
		return fail(FailDial, attemptStop, err)
	}
	caps := l.Caps
	if caps == 0 {
		caps = tr.Caps()
	}
	budget := l.Budget
	if budget.MaxSegments == 0 {
		budget = strategy.DefaultBudget()
	}
	plan, err := st.Build(first, m, caps, budget)
	if err != nil {
		// The transport does not grant what this rung needs, or the plan does
		// not fit the budget. The next rung may still work, so this is a skip
		// and not a failure.
		l.logf("flow: %s rung %q could not be planned: %v", t, specName(spec), err)
		return fail(FailBudget, attemptSkip, err)
	}

	snd := l.Sender
	if snd == nil {
		snd = &defaultSender
	}
	if err := snd.Send(ctx, tr, plan); err != nil {
		class := Classify(err, false)
		return fail(class, retryOn(class, last), err)
	}
	// Anything the client sent after the first message rides along on every
	// rung, or the replay would silently drop it.
	if len(extra) > 0 {
		if _, err := conn.Write(extra); err != nil {
			class := Classify(err, false)
			return fail(class, retryOn(class, last), err)
		}
	}

	pre, err := l.judge(ctx, conn, t)
	att.Latency = l.now().Sub(start)
	if len(pre) > 0 {
		// COMMIT. An upstream byte exists, so from here a retry would duplicate
		// bytes the client is about to see. Any later failure is the relay's to
		// report, never the ladder's to retry (MEASUREMENTS.md §5.2).
		l.RTT.Observe(t.Addr.Addr(), att.Latency)
		return att, pre, attemptOK
	}
	class := Classify(err, false)
	att.Class, att.Err = class, err

	if class == FailTimeoutBeforeResponse && last {
		// Silence with nothing left to escalate to. The origin may simply be
		// slow, and tearing the connection down would turn "slow" into
		// "broken" for no possible gain, so hand it over and learn nothing.
		l.logf("flow: %s was silent for the response window on the last rung %q; handing the connection over",
			t, specName(spec))
		return att, nil, attemptHandover
	}
	return att, nil, retryOn(class, last)
}

func retryOn(f Failure, last bool) attemptResult {
	if f.Retryable() && !last {
		return attemptRetry
	}
	return attemptStop
}

// judge waits for the first upstream byte, which is the only evidence that
// distinguishes a censored flow from a working one.
//
// The window is where the timeout policy lives, and it is deliberately narrower
// than "silence means censorship". MEASUREMENTS.md §5.2 escalates on RST/EOF and
// §1 measures this DPI resetting rather than dropping, so silence is the weak
// signal here. From a destination the tracker has measured answering, 3x its
// smoothed round trip of silence is evidence. From one we have never heard from,
// it is not: on a 600 ms-RTT mobile path a 300 ms window would call EVERY first
// connection censored and desync fragile hosts on no evidence at all, which is
// the one outcome §5.1 forbids. So an unmeasured destination gets the full
// MaxResponseWait before silence counts against it. Neither case delays a
// working connection: a byte that arrives early returns immediately.
func (l *LadderRunner) judge(ctx context.Context, conn net.Conn, t Target) ([]byte, error) {
	wait := MaxResponseWait
	if l.RTT.Known(t.Addr.Addr()) {
		wait = l.RTT.Wait(t.Addr.Addr())
	}
	deadline := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("flow: judge %s: set response deadline: %w", t, err)
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	buf := make([]byte, readChunk)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			return buf[:n:n], err
		}
		if err != nil {
			if isTimeout(err) {
				return nil, fmt.Errorf("flow: %s sent nothing in %s: %w", t, wait, err)
			}
			return nil, fmt.Errorf("flow: %s failed before its first response byte: %w", t, err)
		}
	}
}

// recordWin caches the outcome. Both outcomes are cached, and that symmetry is
// the point: MEASUREMENTS.md §5.2 step 4 asks for "plain works" to be as durable
// as a desync winner so a bank is desynced at most once, ever.
func (l *LadderRunner) recordWin(t Target, prev policy.Verdict, spec string, out Outcome) policy.Verdict {
	nv := prev
	now := l.now()
	nv.Learned = now
	nv.Losses = 0
	nv.Wins = 1
	if prev.Spec == spec && (prev.Source == policy.SrcLearnedPlain || prev.Source == policy.SrcLearnedDesync) {
		nv.Wins = prev.Wins + 1
	}
	if spec == "" {
		nv.Class = policy.ScopeDirect
		nv.Spec = ""
		nv.Source = policy.SrcLearnedPlain
		// Zero Expires on purpose. "Plain works" is self-revalidating at no
		// cost: a plain flow that starts failing simply escalates again.
		nv.Expires = time.Time{}
		nv.Reason = "plain succeeded; not desynced"
	} else {
		nv.Class = policy.ScopeDesync
		nv.Spec = spec
		nv.Source = policy.SrcLearnedDesync
		nv.Expires = now.Add(LearnedDesyncTTL)
		nv.Reason = fmt.Sprintf("plain failed before any response byte; %q succeeded on attempt %d",
			spec, len(out.Attempts))
	}
	l.put(t, prev, nv)
	return nv
}

// recordLoss counts a failed walk against a cached winner. policy.Store.Demote
// owns the threshold: three consecutive losses drop the host back to unknown so
// the next connection re-walks from plain.
func (l *LadderRunner) recordLoss(t Target, prev policy.Verdict, out Outcome) policy.Verdict {
	if l.Store == nil || t.Name == "" || len(out.Attempts) == 0 {
		return prev
	}
	switch prev.Source {
	case policy.SrcLearnedDesync, policy.SrcLearnedPlain, policy.SrcProbed:
	default:
		return prev
	}
	if err := l.Store.Demote(l.netID(), t.Name); err != nil {
		l.logf("flow: could not demote the cached verdict for %s: %v", t, err)
	}
	nv := prev
	nv.Losses = prev.Losses + 1
	nv.Reason = fmt.Sprintf("every rung failed (%d attempt(s))", len(out.Attempts))
	return nv
}

func (l *LadderRunner) put(t Target, prev, nv policy.Verdict) {
	if l.Store == nil || t.Name == "" {
		return
	}
	// A bypass is a decision about this host, not an observation of it. Never
	// let a successful connection overwrite one.
	switch prev.Source {
	case policy.SrcBuiltinBypass, policy.SrcUserBypass:
		return
	}
	if prev.Class == policy.ScopeBypass {
		return
	}
	if err := l.Store.Put(l.netID(), t.Name, nv); err != nil {
		l.logf("flow: could not cache the verdict for %s: %v", t, err)
	}
}

func (l *LadderRunner) report(t Target, v policy.Verdict, out Outcome) {
	if l.OnOutcome != nil {
		l.OnOutcome(t, v, out)
	}
}

func (l *LadderRunner) parse(spec string) (strategy.Strategy, error) {
	if l.Registry != nil {
		return l.Registry.Get(spec)
	}
	return strategy.Parse(spec)
}

func (l *LadderRunner) netID() policy.NetworkID {
	if l.NetID == nil {
		return policy.NetworkID{}
	}
	return l.NetID()
}

func (l *LadderRunner) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *LadderRunner) logf(format string, a ...any) {
	if l.Logf != nil {
		l.Logf(format, a...)
	}
}

// specName renders the empty spec the way every other layer prints it.
func specName(s string) string {
	if s == "" {
		return "plain"
	}
	return s
}

// transportFor gets the emit.Transport a plan is executed against.
//
// There is no fallback that "just writes the bytes". A transport whose
// capabilities were guessed rather than granted is how the previous
// implementation's flagship profile demanded root and then shipped the SNI
// unfragmented anyway; an explicit error names the wiring defect instead.
func transportFor(c net.Conn) (emit.Transport, error) {
	if t, ok := c.(emit.Transport); ok {
		return t, nil
	}
	if tc, ok := c.(*net.TCPConn); ok {
		return emit.NewSockTransport(tc, nil)
	}
	return nil, fmt.Errorf("flow: dialer returned %T, which is neither an emit.Transport nor a *net.TCPConn; "+
		"the emitter set cannot report which capabilities it actually has", c)
}
