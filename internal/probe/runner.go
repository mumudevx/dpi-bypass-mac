package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/emit"
	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// Progress is the running commentary a long sweep owes its user.
type Progress struct {
	Phase     string
	Done      int
	Total     int
	BestSoFar string
	Elapsed   time.Duration
	ETA       time.Duration
}

// Defaults for a sweep. Each is traced rather than chosen: reps is the rep
// count MEASUREMENTS.md used throughout, cooldown is anti-noise rather than
// anti-escalation (§6 measures the DPI as stateless between flows, so 15
// back-to-back attempts do not change the 16th), concurrency and budget are
// the plan's.
const (
	DefaultReps        = 3
	DefaultConcurrency = 4
	DefaultCooldown    = 400 * time.Millisecond
	DefaultBudget      = 8 * time.Minute
)

// eliminationTrials is the plan's elimination-only early exit: two scorable
// failures against the first blocked target with no pass eliminates a
// candidate. Success NEVER short-circuits — blockcheck's own summary warns
// that a greedy early exit on success makes the cross-target intersection
// untrustworthy, and the intersection is the whole point of scoring on two
// axes.
const eliminationTrials = 2

// unmeasurableAttempts is how many local errors it takes before a candidate is
// abandoned as unmeasurable. A build the emitter refuses is deterministic, so
// two is generous; the point of the second is to distinguish it from a
// transient.
const unmeasurableAttempts = 2

// roundRetries is how many times a round whose control was down is retried
// before it is discarded for good.
const roundRetries = 1

// Options configures a Runner. Dial is required; everything else has a
// documented default.
type Options struct {
	Targets     []Target
	Reps        int
	Concurrency int
	Cooldown    time.Duration
	Budget      time.Duration
	Registry    *strategy.Registry
	Chain       *resolve.Chain
	Dial        flow.Dialer
	Caps        strategy.Cap
	Now         func() time.Time
	// OnProgress is called as the sweep advances. Trials run concurrently, so
	// the Runner SERIALISES these calls behind its own lock rather than leaving
	// every caller to discover the hazard: the obvious implementation keeps a
	// "last printed at" variable and writes to one stream, and both are a data
	// race the moment two trials finish at once. The callback must not call
	// back into the Runner.
	OnProgress func(Progress)
	Logf       func(string, ...any)

	// Resolvers is the chain as a list, for the phase-1 transport matrix. The
	// Chain deliberately does not expose its rungs, and the matrix is a
	// per-(resolver, name) measurement rather than a per-chain one.
	Resolvers []resolve.Resolver
	// DNSControl is the name every transport is measured against. It MUST be a
	// name that is not blocked here, or every working resolver ranks dead
	// (MEASUREMENTS.md §2 uses google.com for exactly this). Empty means the
	// first control target, then google.com.
	DNSControl string
	// Depth selects the sweep: quick, full or paranoid. Empty means full.
	Depth string

	// Sender, Wrap, TLSConfig, Timeout and Sinkholes are handed to every trial.
	// Sender should be an ungoverned emit.Sender: a coalesced plan is not the
	// plan that was asked for, and scoring it would be a lie.
	Sender    *emit.Sender
	Wrap      func(net.Conn) (emit.Transport, error)
	TLSConfig func(host string) *tls.Config
	Timeout   time.Duration
	Sinkholes []netip.Addr

	// Seed makes the trial shuffle reproducible. 0 seeds a fixed constant and
	// never the clock: a prober whose result depends on the wall time is one
	// nobody can reproduce a complaint against.
	Seed int64
}

// Runner executes the phases of a tune against one network.
type Runner struct {
	o   Options
	rnd *rand.Rand

	mu sync.Mutex
	// progressMu serialises OnProgress and is never held together with mu, so
	// a slow callback cannot stall a trial that only wants to record a count.
	progressMu sync.Mutex

	blocked    []Target
	notBlocked []Target
	fragile    []Target
	controls   []Target

	dns    []resolve.Health
	matrix DNSMatrix
	shape  Shape

	rstLatency time.Duration
	warnings   []string

	discarded int
	attempted int

	started time.Time
	done    int
	total   int
	best    string
}

// NewRunner builds a Runner. It never fails: an unusable option produces a
// warning in the report rather than an error nobody sees.
func NewRunner(o Options) *Runner {
	if o.Registry == nil {
		o.Registry = strategy.Default()
	}
	seed := uint64(o.Seed)
	if seed == 0 {
		seed = 0x5DEECE66D
	}
	r := &Runner{o: o, rnd: rand.New(rand.NewPCG(seed, seed^0x9E3779B97F4A7C15))}
	for _, t := range o.Targets {
		switch t.Kind {
		case TargetControl:
			r.controls = append(r.controls, t)
		case TargetFragile:
			r.fragile = append(r.fragile, t)
		}
	}
	return r
}

func (r *Runner) now() time.Time {
	if r.o.Now != nil {
		return r.o.Now()
	}
	return time.Now()
}

func (r *Runner) logf(format string, a ...any) {
	if r.o.Logf != nil {
		r.o.Logf(format, a...)
	}
}

func (r *Runner) warn(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	r.mu.Lock()
	r.warnings = append(r.warnings, s)
	r.mu.Unlock()
	r.logf("probe: %s", s)
}

// Warnings is everything the run wants the reader to know but did not stop for.
func (r *Runner) Warnings() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.warnings...)
}

func (r *Runner) reps() int {
	if r.o.Reps > 0 {
		return r.o.Reps
	}
	return DepthReps(r.o.Depth)
}

func (r *Runner) concurrency() int {
	if r.o.Concurrency > 0 {
		return r.o.Concurrency
	}
	return DefaultConcurrency
}

func (r *Runner) cooldown() time.Duration {
	if r.o.Cooldown > 0 {
		return r.o.Cooldown
	}
	return DefaultCooldown
}

func (r *Runner) budget() time.Duration {
	if r.o.Budget > 0 {
		return r.o.Budget
	}
	return DefaultBudget
}

func (r *Runner) sinkholes() []netip.Addr {
	if r.o.Sinkholes != nil {
		return r.o.Sinkholes
	}
	return resolve.DefaultSinkholes
}

func (r *Runner) trialOptions() TrialOptions {
	return TrialOptions{
		Dial:      r.o.Dial,
		Sender:    r.o.Sender,
		Caps:      r.o.Caps,
		Timeout:   r.o.Timeout,
		Wrap:      r.o.Wrap,
		TLSConfig: r.o.TLSConfig,
		Sinkholes: r.o.Sinkholes,
		Now:       r.o.Now,
		Logf:      r.o.Logf,
	}
}

// pace applies the inter-attempt cooldown. i is the attempt index, so the first
// attempt of a burst does not wait.
func (r *Runner) pace(ctx context.Context, i int) error {
	if i == 0 {
		return nil
	}
	t := time.NewTimer(r.cooldown())
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// attempts runs one strategy against one target, reps times, serially.
func (r *Runner) attempts(ctx context.Context, s strategy.Strategy, t Target, reps int) []Trial {
	out := make([]Trial, 0, reps)
	opts := r.trialOptions()
	for i := 0; i < reps; i++ {
		if err := r.pace(ctx, i); err != nil {
			break
		}
		out = append(out, RunTrial(ctx, s, t, i+1, opts))
	}
	return out
}

// job is one trial the round scheduler has to run.
type job struct {
	spec    strategy.Strategy
	target  Target
	round   int
	control bool // a plain liveness probe, not part of any candidate's score
}

// Evaluate measures every candidate against every blocked, fragile and control
// target, with an interleaved liveness control in every round.
//
// The unit of scheduling is a ROUND: one candidate, one rep, all of its targets
// plus a plain probe of the control target, shuffled together and run with
// bounded concurrency. The liveness probe is plain and is separate from the
// candidate's own control trials, and that separation is the point:
//
//   - the PLAIN probe answers "was the ordinary internet up while we measured
//     this round"; if it was not, the round is discarded and retried, because
//     scoring it would attribute the network's failure to the candidate;
//   - the candidate's own trials against the control targets answer "does this
//     emitter break the ordinary internet", which is MEASUREMENTS.md §5.1's
//     control column and ranking key 1, and must NOT discard anything.
//
// Collapsing the two would make a destructive emitter erase its own evidence:
// every round it broke the control would be thrown away as noise.
func (r *Runner) Evaluate(ctx context.Context, cands []strategy.Strategy) ([]Trial, error) {
	if len(cands) == 0 {
		return nil, nil
	}
	plain, err := r.o.Registry.Get("")
	if err != nil {
		return nil, fmt.Errorf("probe: the plain strategy is not available: %w", err)
	}

	deadline := r.started.Add(r.budget())
	if r.started.IsZero() {
		r.started = r.now()
		deadline = r.started.Add(r.budget())
	}

	reps := r.reps()
	perRound := len(r.blocked) + len(r.fragile) + len(r.controls) + 1
	r.total = len(cands) * reps * perRound

	eliminated := make(map[string]bool, len(cands))
	localErrs := make(map[string]int, len(cands))
	firstTargetPass := make(map[string]int, len(cands))
	firstTargetTrials := make(map[string]int, len(cands))

	var out []Trial
	rounds := 0
	for rep := 1; rep <= reps; rep++ {
		for _, c := range cands {
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			if r.now().After(deadline) {
				r.warn("the %s budget expired after %d of %d planned trials; "+
					"the ranking below is over what was measured, not over the whole sweep",
					r.budget(), len(out), r.total)
				return out, nil
			}
			if eliminated[c.Spec] {
				continue
			}
			// The cooldown separates ROUNDS, not the dials inside one. §6
			// measures the DPI as stateless between flows — 15 back-to-back
			// blocked attempts did not change the outcome of the 16th — so
			// this is anti-noise, and pacing every dial instead would
			// serialise the sweep and turn the concurrency setting into a lie.
			if err := r.pace(ctx, rounds); err != nil {
				return out, err
			}
			rounds++

			ts, attempts, dropped, ok := r.round(ctx, c, plain, rep)
			r.attempted += attempts
			r.discarded += dropped
			out = append(out, ts...)
			if !ok {
				continue
			}

			// Elimination and unmeasurability, both computed only from this
			// candidate's own trials.
			for _, t := range ts {
				switch {
				case t.Spec != c.Spec:
				case t.Verdict == VerdictLocalError:
					localErrs[c.Spec]++
				case t.Target.Kind == TargetBlocked && len(r.blocked) > 0 &&
					t.Target.Host == r.blocked[0].Host && t.Verdict.Scorable():
					firstTargetTrials[c.Spec]++
					if t.Verdict == VerdictPass {
						firstTargetPass[c.Spec]++
					}
				}
			}
			switch {
			case firstTargetTrials[c.Spec] >= eliminationTrials && firstTargetPass[c.Spec] == 0:
				eliminated[c.Spec] = true
				r.logf("probe: eliminating %s: %d scorable attempts against %s, none passed",
					label(c.Spec), firstTargetTrials[c.Spec], r.blocked[0].Host)
			case localErrs[c.Spec] >= unmeasurableAttempts && firstTargetTrials[c.Spec] == 0:
				eliminated[c.Spec] = true
				r.warn("%s is UNMEASURABLE on this transport and was not scored: %s",
					label(c.Spec), localErrReason(ts))
			}
		}
	}
	return out, nil
}

// round runs one (candidate, rep) unit, retrying while the interleaved plain
// control is down.
//
// It returns EVERY attempt's trials, with the discarded ones rewritten to
// VerdictControlDown, plus how many attempts were made and how many were
// thrown away. Keeping the discarded trials is deliberate: they are excluded
// from every denominator by Scorable(), but a reader of `dpb tune --json` can
// see that a round was thrown away and why, and NoiseRate counts a retried
// round rather than quietly forgetting it.
func (r *Runner) round(ctx context.Context, c, plain strategy.Strategy, rep int) (ts []Trial, attempts, dropped int, ok bool) {
	for {
		attempts++
		got, live := r.runRound(ctx, c, plain, rep)
		if live {
			return append(ts, got...), attempts, dropped, true
		}
		dropped++
		markDiscarded(got)
		ts = append(ts, got...)
		if attempts > roundRetries || ctx.Err() != nil {
			r.logf("probe: discarding round %d of %s: the plain control did not pass", rep, label(c.Spec))
			return ts, attempts, dropped, false
		}
		r.logf("probe: retrying round %d of %s: the plain control did not pass", rep, label(c.Spec))
	}
}

// markDiscarded rewrites a round's trials so that no later reader can mistake a
// discarded round for a measured one.
func markDiscarded(ts []Trial) {
	for i := range ts {
		ts[i].Verdict = VerdictControlDown
		if ts[i].Err == "" {
			ts[i].Err = "round discarded: the interleaved plain control failed"
		}
	}
}

func (r *Runner) runRound(ctx context.Context, c, plain strategy.Strategy, rep int) ([]Trial, bool) {
	jobs := make([]job, 0, len(r.blocked)+len(r.fragile)+len(r.controls)+1)
	for _, t := range r.blocked {
		jobs = append(jobs, job{spec: c, target: t, round: rep})
	}
	for _, t := range r.fragile {
		jobs = append(jobs, job{spec: c, target: t, round: rep})
	}
	for _, t := range r.controls {
		jobs = append(jobs, job{spec: c, target: t, round: rep})
	}
	if len(r.controls) > 0 {
		jobs = append(jobs, job{spec: plain, target: r.controls[0], round: rep, control: true})
	}
	r.shuffle(jobs)

	res := r.runJobs(ctx, jobs)

	live := true
	out := make([]Trial, 0, len(res))
	for i, t := range res {
		if jobs[i].control {
			// The liveness probe is evidence about the round, not about a
			// candidate, so it never enters the trial set that Rank scores.
			if t.Verdict != VerdictPass {
				live = false
			}
			continue
		}
		out = append(out, t)
	}
	if len(r.controls) == 0 {
		// With no control target there is no liveness evidence at all. Say so
		// once rather than silently treating every round as clean.
		live = true
	}
	return out, live
}

func (r *Runner) shuffle(jobs []job) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rnd.Shuffle(len(jobs), func(i, j int) { jobs[i], jobs[j] = jobs[j], jobs[i] })
}

// runJobs runs a round's trials with bounded concurrency, preserving order.
func (r *Runner) runJobs(ctx context.Context, jobs []job) []Trial {
	out := make([]Trial, len(jobs))
	sem := make(chan struct{}, r.concurrency())
	var wg sync.WaitGroup
	opts := r.trialOptions()

	for i, j := range jobs {
		select {
		case <-ctx.Done():
			out[i] = Trial{Spec: j.spec.Spec, Target: j.target, Round: j.round,
				Verdict: VerdictLocalError, Err: ctx.Err().Error(), At: r.now()}
			continue
		case sem <- struct{}{}:
		}
		wg.Add(1)
		// flow.Safe rather than a bare `go`: Go runs only the panicking
		// goroutine's defers, so one malformed answer inside a trial would take
		// the whole tune down and leave the user with no report at all.
		flow.Safe("probe.trial", r.o.Logf, func() {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = RunTrial(ctx, j.spec, j.target, j.round, opts)
			r.tick()
		})
	}
	wg.Wait()
	return out
}

func (r *Runner) tick() {
	r.mu.Lock()
	r.done++
	done, total, best := r.done, r.total, r.best
	started := r.started
	r.mu.Unlock()

	if r.o.OnProgress == nil {
		return
	}
	elapsed := r.now().Sub(started)
	var eta time.Duration
	if done > 0 && total > done {
		eta = time.Duration(float64(elapsed) / float64(done) * float64(total-done))
	}
	r.progressMu.Lock()
	defer r.progressMu.Unlock()
	r.o.OnProgress(Progress{
		Phase:     "sweep",
		Done:      done,
		Total:     total,
		BestSoFar: best,
		Elapsed:   elapsed,
		ETA:       eta,
	})
}

func localErrReason(ts []Trial) string {
	for _, t := range ts {
		if t.Verdict == VerdictLocalError && t.Err != "" {
			return oneLine(t.Err)
		}
	}
	return "the emitter refused to build this strategy"
}

// oneLine flattens a multi-line error for a single table cell.
func oneLine(s string) string {
	out := make([]rune, 0, len(s))
	space := false
	for _, r := range s {
		if r == '\n' || r == '\t' || r == ' ' {
			space = true
			continue
		}
		if space && len(out) > 0 {
			out = append(out, ' ')
		}
		space = false
		out = append(out, r)
	}
	return string(out)
}

// sortTargets keeps report output stable regardless of probe order.
func sortTargets(ts []Target) {
	sort.SliceStable(ts, func(i, j int) bool { return ts[i].Host < ts[j].Host })
}
