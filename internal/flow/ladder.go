package flow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	// LearnedPlainTTL is how long "this host works plain" is trusted.
	//
	// It is NOT zero, and the difference is load-bearing. policy/scope.go
	// rewrites a SrcLearnedPlain verdict to ScopeDirect, which is relayed with
	// no buffering at all, so the ladder is never invoked for that host again:
	// a plain verdict cannot "simply escalate again" and cannot demote itself.
	// A host that works plain today and is added to the BTK list next month
	// would then never be bypassed on this network again. MEASUREMENTS.md §4
	// records months-scale rot in both directions, which is why the desync side
	// has a TTL, and §5.2 step 4 only asks that a bank be desynced at most once
	// per re-test window — one watched connection a week, not one per visit.
	LearnedPlainTTL = LearnedDesyncTTL
)

// DefaultSinkholes are the addresses this ISP returns instead of an answer, and
// therefore the addresses a "successful" connection proves nothing about.
//
// This is a copy of resolve.DefaultSinkholes, which flow cannot import:
// internal/resolve imports internal/flow, so the dependency only runs one way.
// TestFlowSinkholesMatchResolve pins the two tables together from the test
// binary — where the import IS legal — so the copy cannot drift.
// MEASUREMENTS.md §2 measures 195.175.254.2; §5.4 records the run of the
// compatibility matrix that scored every emitter 0/6 because every connection
// reached it instead of the origin.
var DefaultSinkholes = []netip.Addr{
	netip.MustParseAddr("195.175.254.2"),
	netip.MustParseAddr("2a01:358:4014:a00::3"),
}

// Attempt is one upstream connection made for one client connection.
type Attempt struct {
	Spec string
	// Class is why the attempt failed. FailNone together with Rejected set is
	// not a failure: the attempt produced a live connection and no evidence.
	Class   Failure
	Err     error
	Latency time.Duration
	// Addr is the address this attempt actually dialled, which for a
	// name-resolved flow is chosen by the dialer and is not Target.Addr.
	Addr netip.Addr
	// Emitted says an upstream connection was actually opened for this rung. A
	// rung refused before the dial (it cannot apply to this first message, or
	// the transport lacks a capability) is still recorded — `dpb why` must show
	// that it was considered — but it cost no connection, so it must not count
	// against MaxAttempts and must not read as an escalation.
	Emitted bool
	// Rejected says upstream bytes arrived that are evidence AGAINST this rung:
	// a TLS alert, bytes followed by a hard error, or an answer from a known
	// sinkhole. The connection is committed either way (the client is about to
	// see those bytes) but nothing may be cached from it.
	Rejected bool
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
//
// Only rungs that actually opened a connection count: a rung skipped before the
// dial escalated nothing, and M12's drift detector reads this number.
func (o Outcome) Escalations() int {
	n := emitted(o.Attempts)
	if n == 0 {
		return 0
	}
	return n - 1
}

// emitted counts the attempts that cost an upstream connection.
func emitted(atts []Attempt) int {
	n := 0
	for _, a := range atts {
		if a.Emitted {
			n++
		}
	}
	return n
}

// LadderRunner holds the buffered first message and walks the escalation ladder
// on fresh upstream connections.
type LadderRunner struct {
	Dial     Dialer
	Sender   *emit.Sender
	Registry *strategy.Registry
	Store    policy.Store
	NetID    func() policy.NetworkID
	// Sinkholes overrides DefaultSinkholes. A front end that has its own
	// resolver chain should pass resolve.DefaultSinkholes here so the two lists
	// are the same object rather than two copies.
	Sinkholes   []netip.Addr
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
	// The budget bounds ONE walk, and the clock starts when that walk starts.
	// Starting it here instead would charge a singleflight follower for the
	// leader's dial as well as its own: with the shipped 5 s budget and a 2.6 s
	// connect, five of six followers failed with "context deadline exceeded"
	// after a single attempt to a host the leader had just reached, which is
	// strictly worse than not collapsing them at all. The caller's own ctx is
	// still the outer bound.
	walkCtx := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(ctx, budget)
	}

	rungs := l.rungs(v)

	// A walk with a single rung has nothing to learn and nothing to collapse.
	if l.Single == nil || len(rungs) < 2 || t.storeKey() == "" {
		wctx, cancel := walkCtx()
		defer cancel()
		out, _, err := l.walk(wctx, t, v, rungs, first, m, extra)
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
	key := policy.Key(l.netID(), t.storeKey())
	learned, lerr := l.Single.Do(key, func() (policy.Verdict, error) {
		wctx, cancel := walkCtx()
		defer cancel()
		out, nv, err := l.walk(wctx, t, v, rungs, first, m, extra)
		mine, mineErr = &out, err
		return nv, err
	})
	if mine != nil {
		return *mine, mineErr
	}
	wctx, cancel := walkCtx()
	defer cancel()
	if lerr != nil {
		// The leader's walk failed. Its verdict says nothing useful about our
		// connection, so walk ourselves rather than inheriting a failure.
		out, _, err := l.walk(wctx, t, v, rungs, first, m, extra)
		return out, err
	}
	out, _, err := l.walk(wctx, t, learned, l.rungs(learned), first, m, extra)
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
	// dialled counts the rungs that actually cost an upstream connection. A
	// rung refused before the dial cost nothing, so it must not consume the
	// budget: with the global ladder and a truncated first message the walk
	// otherwise recorded five attempts having opened one connection, and
	// reported four escalations for a connection that escalated zero times.
	dialled := 0
	for i, spec := range rungs {
		if dialled >= maxAtt {
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
			dialled++
			out.Attempts = append(out.Attempts, Attempt{
				Spec: spec, Class: FailDial, Err: derr, Latency: l.now().Sub(start),
				Emitted: true,
			})
			lastErr = derr
			l.logf("flow: %s rung %q: dial failed: %v", t, specName(spec), derr)
			continue
		}
		dialled++

		// last decides whether a retryable failure ends the walk; final decides
		// whether SILENCE here has anything left to escalate to. They differ
		// when the rungs behind us exist but none of them can be emitted on
		// this first message, which is exactly the truncated-hello case: the
		// walk must not treat "plain, then four rungs that will all be refused"
		// as "there is more to try".
		last := i == len(rungs)-1 || dialled >= maxAtt
		final := last || !l.moreRungs(rungs, i, first, m)
		att, pre, res := l.attempt(ctx, conn, t, st, first, m, extra, last, final, start)
		att.Emitted = true
		out.Attempts = append(out.Attempts, att)
		switch res {
		case attemptOK:
			out.Conn, out.Spec, out.Pre = conn, spec, pre
			nv := l.recordWin(t, v, spec, out)
			l.report(t, nv, out)
			return out, nv, nil
		case attemptHandover:
			// Committed without evidence. The connection is usable and nothing
			// has been lost, but silence — or a response that is not the
			// origin's — is not a result worth caching.
			out.Conn, out.Spec, out.Pre = conn, spec, pre
			nv := v
			if att.Rejected {
				// The origin answered and what it said was a rejection of THIS
				// rung. A cached spec that starts producing alerts is dropped
				// on the first one rather than re-tried for a week: the walk
				// used to score those 7 alert bytes a win, refresh the TTL and
				// pin the bank to the emitter that breaks it (MEASUREMENTS.md
				// §5).
				nv = l.forget(t, v, spec, att.Err)
			}
			l.report(t, nv, out)
			return out, nv, nil
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
		return out, nv, fmt.Errorf("%w: %s after %d attempt(s): %w", ErrNoUpstream, t, dialled, lastErr)
	}
	return out, nv, fmt.Errorf("%w: %s after %d attempt(s): %w", ErrLadderExhausted, t, dialled, lastErr)
}

// moreRungs reports whether any rung after i could still be emitted on this
// first message.
//
// It is the difference between "there is another rung" and "there is another
// rung we can actually send". With a truncated hello every rung carrying
// ReqComplete is refused before the dial, so the tr ladder collapses to
// [plain, oob:pos=1] — and oob is the rung MEASUREMENTS.md §5.1 scores 0/20 on
// fragile hosts. A rung this build cannot parse counts as remaining: the walk
// does reach it, and reporting the configuration defect is the point.
func (l *LadderRunner) moreRungs(rungs []string, i int, first []byte, m tlsmsg.Meta) bool {
	if i+1 >= len(rungs) {
		return false
	}
	// Every rung past the first is a replay on a fresh connection, so a message
	// that may not be replayed ends the walk at i whatever the rungs say.
	if !Replayable(first, m) {
		return false
	}
	for _, spec := range rungs[i+1:] {
		st, err := l.parse(spec)
		if err != nil {
			return true
		}
		if st.CheckAgainst(l.checkCaps(), m) == nil {
			return true
		}
	}
	return false
}

// handoverRisk is the set of capabilities whose ops put something on the wire
// that the client's own protocol did not: an MSG_OOB junk byte, or a segment
// sent with a hop limit chosen to make it die in the middle of the path.
//
// A rung needing any of them may not be handed to the client on silence. The
// handover exists so a merely SLOW origin is not torn down, and for plain or a
// pure reframing that is a free win — the byte stream the origin sees is
// identical either way. For oob it is not: MEASUREMENTS.md §5.1 measures
// oob-at-1 at 0/20 on fragile hosts, so handing over an oob-poisoned socket at
// a bank is strictly worse than handing back no connection at all.
const handoverRisk = strategy.CapOOB | strategy.CapSockTTL | strategy.CapUDPTTL |
	strategy.CapRawInject | strategy.CapRawSeq

func safeToHandOver(st strategy.Strategy) bool {
	return st.IsPlain() || st.Caps()&handoverRisk == 0
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
	if emitted(atts) == 0 {
		return false
	}
	for _, a := range atts {
		if a.Emitted && a.Class != FailDial {
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
// last says no rung remains, so a retryable failure ends the walk here. final
// says no rung remains that could be EMITTED, which is what makes silence
// unescalatable; see moreRungs.
func (l *LadderRunner) attempt(ctx context.Context, conn net.Conn, t Target, st strategy.Strategy,
	first []byte, m tlsmsg.Meta, extra []byte, last, final bool, start time.Time) (Attempt, []byte, attemptResult) {
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
	// The address the dial actually used. Target.Addr is the PINNED address and
	// is empty for every name-resolved flow, so keying the RTT tracker on it
	// meant the tracker never learned anything and the adaptive response window
	// never engaged.
	peer := tr.Remote().Addr().Unmap()
	if !peer.IsValid() {
		peer = t.Addr.Addr().Unmap()
	}
	att.Addr = peer
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
		// A transport that cannot execute this rung says nothing about the next
		// one, so it is a skip — the same answer the Build path above gives to
		// the same condition. Without this a capability the transport lacks
		// ends the whole walk at whichever rung happens to need it.
		if errors.Is(err, emit.ErrCapUnavailable) {
			l.logf("flow: %s rung %q: transport cannot execute it: %v", t, specName(spec), err)
			return fail(FailBudget, attemptSkip, err)
		}
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

	pre, err := l.judge(ctx, conn, t, peer)
	att.Latency = l.now().Sub(start)
	if len(pre) > 0 {
		// COMMIT. An upstream byte exists, so from here a retry would duplicate
		// bytes the client is about to see. Any later failure is the relay's to
		// report, never the ladder's to retry (MEASUREMENTS.md §5.2).
		//
		// Committing is NOT the same question as "this rung worked", and
		// conflating them is what pinned a bank to the emitter that breaks it.
		// The commit guard is above; the evidence guard is here.
		if why := l.rejects(pre, err, m, peer); why != nil {
			att.Rejected, att.Err = true, why
			l.logf("flow: %s answered rung %q with %v; handing the connection over and caching nothing",
				t, specName(spec), why)
			return att, pre, attemptHandover
		}
		l.RTT.Observe(peer, att.Latency)
		return att, pre, attemptOK
	}
	class := Classify(err, false)
	att.Class, att.Err = class, err

	if class == FailTimeoutBeforeResponse && final && safeToHandOver(st) {
		// Silence with nothing left to escalate to. The origin may simply be
		// slow, and tearing the connection down would turn "slow" into
		// "broken" for no possible gain, so hand it over and learn nothing.
		// Only for a rung whose bytes are the client's own: see handoverRisk.
		l.logf("flow: %s was silent for the response window on the last rung %q; handing the connection over",
			t, specName(spec))
		return att, nil, attemptHandover
	}
	return att, nil, retryOn(class, last)
}

// rejects reports why upstream bytes are NOT evidence that this rung worked,
// or nil when they are. It never decides whether to retry — by the time it runs
// the connection is committed — only whether anything may be learned.
//
// Three shapes, each measured:
//
//   - A TLS alert. MEASUREMENTS.md §5 records www.yapikredi.com.tr answering a
//     ClientHello that spans two records with alert(21) fatal(2)
//     illegal_parameter(47): seven bytes that say "your desync broke my
//     handshake". Scoring them a win cached the breaking spec for a week and
//     refreshed the TTL on every connection, so demotion was unreachable.
//   - Bytes together with a hard error. A middlebox that injects a forged
//     response and then a reset produces exactly this, and judge returns both.
//   - An answer from a known sinkhole. §5.4: 195.175.254.2 completes the
//     handshake and returns a 1404-byte self-signed ServerHello, which taught
//     the store "plain works here, forever". internal/probe already scores a
//     connected sinkhole as VerdictBlockPage.
func (l *LadderRunner) rejects(pre []byte, err error, m tlsmsg.Meta, peer netip.Addr) error {
	if isSinkhole(peer, l.sinkholes()) {
		return fmt.Errorf("the known sinkhole %s, not the origin (MEASUREMENTS.md §5.4)", peer)
	}
	if m.Proto == tlsmsg.ProtoTLS && isTLSAlert(pre) {
		return fmt.Errorf("a TLS alert (%s), which is the terminator rejecting this rung (MEASUREMENTS.md §5)",
			alertText(pre))
	}
	if err != nil && !isTimeout(err) {
		return fmt.Errorf("%d byte(s) and then %w", len(pre), err)
	}
	return nil
}

// isTLSAlert reports whether b starts with a TLS alert record.
//
// ContentType 21 plus a legacy_record_version of 0x03 0x0N — every TLS version
// in use puts 0x0301 or 0x0303 there, and requiring it keeps an ordinary
// application byte stream that happens to start with 0x15 from being read as a
// rejection.
func isTLSAlert(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x15 && b[1] == 0x03 && b[2] <= 0x04
}

// alertText renders the alert level and description for the log and for
// `dpb why`. A record with no body yet still names the record.
func alertText(b []byte) string {
	if len(b) < 7 {
		return "truncated alert record"
	}
	return fmt.Sprintf("level %d, description %d", b[5], b[6])
}

func (l *LadderRunner) sinkholes() []netip.Addr {
	if l.Sinkholes != nil {
		return l.Sinkholes
	}
	return DefaultSinkholes
}

// isSinkhole is internal/probe's predicate, restated here because probe imports
// flow. An IPv4 sentinel matches exactly; an IPv6 one matches its containing
// /64, since a censor answering from a block can move within it for free
// (DOSSIER GT19).
func isSinkhole(a netip.Addr, set []netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() {
		return false
	}
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
		p := netip.PrefixFrom(s, 64)
		if p.IsValid() && a.Is6() && p.Masked().Contains(a) {
			return true
		}
	}
	return false
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
func (l *LadderRunner) judge(ctx context.Context, conn net.Conn, t Target, peer netip.Addr) ([]byte, error) {
	wait := MaxResponseWait
	if l.RTT.Known(peer) {
		wait = l.RTT.Wait(peer)
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
		// A TTL, not a zero Expires: see LearnedPlainTTL. A learned-plain
		// verdict is rewritten to ScopeDirect by the policy engine and the
		// ladder is then never invoked for this host again, so nothing can
		// revalidate it except its own expiry.
		nv.Expires = now.Add(LearnedPlainTTL)
		nv.Reason = "plain succeeded; not desynced"
	} else {
		nv.Class = policy.ScopeDesync
		nv.Spec = spec
		nv.Source = policy.SrcLearnedDesync
		nv.Expires = now.Add(LearnedDesyncTTL)
		nv.Reason = fmt.Sprintf("plain failed before any response byte; %q succeeded on attempt %d",
			spec, emitted(out.Attempts))
	}
	l.put(t, prev, nv)
	return nv
}

// recordLoss counts a failed walk against a cached winner. policy.Store.Demote
// owns the threshold: three consecutive losses drop the host back to unknown so
// the next connection re-walks from plain.
func (l *LadderRunner) recordLoss(t Target, prev policy.Verdict, out Outcome) policy.Verdict {
	if l.Store == nil || t.storeKey() == "" || emitted(out.Attempts) == 0 {
		return prev
	}
	switch prev.Source {
	case policy.SrcLearnedDesync, policy.SrcLearnedPlain, policy.SrcProbed:
	default:
		return prev
	}
	if err := l.Store.Demote(l.netID(), t.storeKey()); err != nil {
		l.logf("flow: could not demote the cached verdict for %s: %v", t, err)
	}
	nv := prev
	nv.Losses = prev.Losses + 1
	nv.Reason = fmt.Sprintf("every rung failed (%d attempt(s))", emitted(out.Attempts))
	return nv
}

// forget drops a cached verdict the origin has just rejected, rather than
// counting it towards Store.Demote's three-loss threshold.
//
// One alert is enough. The rung that produced it is the cached one, the
// evidence is the terminator's own, and re-sending it twice more only breaks
// the same handshake twice more. The record is rewritten rather than deleted
// because policy.Store has no delete; SrcDefault is a source policy.Engine
// ignores, so the next connection re-walks from plain.
func (l *LadderRunner) forget(t Target, prev policy.Verdict, spec string, why error) policy.Verdict {
	if l.Store == nil || t.storeKey() == "" {
		return prev
	}
	switch prev.Source {
	case policy.SrcLearnedDesync, policy.SrcLearnedPlain, policy.SrcProbed:
	default:
		return prev
	}
	if prev.Spec != spec {
		return prev
	}
	nv := prev
	nv.Class = policy.ScopeWatch
	nv.Spec = ""
	nv.Source = policy.SrcDefault
	nv.Expires = time.Time{}
	nv.Wins = 0
	nv.Losses = prev.Losses + 1
	nv.Learned = l.now()
	nv.Reason = fmt.Sprintf("the origin rejected %q: %v", specName(spec), why)
	l.put(t, prev, nv)
	return nv
}

// storeKey is the policy-store key for this target: the hostname when there is
// one, and otherwise the address literal.
//
// The address arm is not a convenience. policy.Engine.forAddr reads
// e.cached(addr.String()) for a TUN flow the ReverseMap could not name, and
// nothing wrote that key, so every unnamed flow re-walked the whole ladder on
// every connection — repeated escalation traffic at the middlebox, and for a
// fragile unnamed destination a repeated first-visit desync rather than the
// "desynced at most once" MEASUREMENTS.md §5.2 step 4 requires.
func (t Target) storeKey() string {
	if t.Name != "" {
		return t.Name
	}
	if a := t.Addr.Addr(); a.IsValid() {
		return a.Unmap().WithZone("").String()
	}
	return ""
}

func (l *LadderRunner) put(t Target, prev, nv policy.Verdict) {
	if l.Store == nil || t.storeKey() == "" {
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
	if err := l.Store.Put(l.netID(), t.storeKey(), nv); err != nil {
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
