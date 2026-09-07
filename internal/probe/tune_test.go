package probe_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/flow"
	"github.com/mumudevx/dpb/internal/probe"
	"github.com/mumudevx/dpb/internal/resolve"
	"github.com/mumudevx/dpb/internal/strategy"
	"github.com/mumudevx/dpb/internal/testcensor"
)

// TestTuneConvergesOnTLSFrag is M13's acceptance clause, run offline.
//
// Against the measured Türk Telekom mechanism in front of blocked hosts and a
// fragile Turkish bank terminator in front of the fragile ones, the sweep must
// converge on tlsfrag:pos=snimid, find the first-record limit at sniEnd-1, and
// rank chunk:size=12 above oob.
func TestTuneConvergesOnTLSFrag(t *testing.T) {
	lab := newTuneLab(t, testcensor.TT2026(labBlocked...), testcensor.Fragile())
	o := lab.options(t)
	o.Depth = probe.DepthFull

	r := probe.NewRunner(o)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rep, err := r.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	best, ok := rep.Winner()
	if !ok {
		t.Fatalf("no winner; ranking was %s", specList(rep.Ranked))
	}
	if best.Spec != "tlsfrag:pos=snimid" {
		t.Errorf("winner = %q, want tlsfrag:pos=snimid\nranking: %s", best.Spec, specList(rep.Ranked))
	}
	if got := rankOf(rep.Ranked, "tlsfrag:pos=snimid"); got != 1 {
		t.Errorf("tlsfrag:pos=snimid ranked %d, want 1\nranking: %s", got, specList(rep.Ranked))
	}

	// The first-record limit is the measured rule, in this client's
	// coordinates: MEASUREMENTS.md §3.2 puts the boundary exactly at sniEnd.
	if rep.Class.SNIEnd <= 0 {
		t.Fatalf("no SNI extent was recorded; the classifier measured nothing")
	}
	if want := rep.Class.SNIEnd - 1; rep.Class.FirstRecordLimit != want {
		t.Errorf("FirstRecordLimit = %d, want sniEnd-1 = %d", rep.Class.FirstRecordLimit, want)
	}
	if !rep.Class.RecordFrag {
		t.Error("the classifier did not identify record fragmentation as the axis")
	}
	if rep.Class.TCPSplit {
		t.Error("the classifier claimed TCP splitting works; MEASUREMENTS.md §3.1 measures 0/5 " +
			"and TT2026 reassembles TCP")
	}
	if rep.Class.Shape != probe.ShapeSNIReset {
		t.Errorf("shape = %s, want %s", rep.Class.Shape, probe.ShapeSNIReset)
	}

	// The two-axis result: the ordering among the non-bypassing rungs must come
	// from compatibility, not from a bypass-rate difference they do not have.
	chunk := rankOf(rep.Ranked, "chunk:size=12")
	oob := rankOf(rep.Ranked, "oob:pos=1")
	if chunk == 0 || oob == 0 {
		t.Fatalf("chunk:size=12 or oob:pos=1 missing from the ranking: %s", specList(rep.Ranked))
	}
	if chunk >= oob {
		t.Errorf("chunk:size=12 ranked %d and oob:pos=1 ranked %d; chunk must rank higher "+
			"(MEASUREMENTS.md §5.1: chunk-12 leaves 14/20 fragile hosts working, oob 0/20)",
			chunk, oob)
	}

	// chunk:size=4 is refused by the emitter at this segment budget, so it must
	// be reported as unmeasurable and must never contribute a fake 0/N.
	if s := scoreOf(t, rep.Ranked, "chunk:size=4"); !s.Unmeasurable || s.BypassTotal != 0 {
		t.Errorf("chunk:size=4 scored %d/%d with Unmeasurable=%v; the emitter refuses it at this "+
			"budget (MEASUREMENTS.md §3.4), so it is unmeasurable and not blocked",
			s.BypassPass, s.BypassTotal, s.Unmeasurable)
	}
	if chunk >= rankOf(rep.Ranked, "chunk:size=4") {
		t.Errorf("chunk:size=12 ranked %d, chunk:size=4 ranked %d; a measured candidate must "+
			"outrank an unmeasurable one", chunk, rankOf(rep.Ranked, "chunk:size=4"))
	}

	if rep.Confidence != probe.ConfidenceHigh {
		t.Errorf("confidence = %q, want %q (3 targets, 3 reps, clean controls, no noise)",
			rep.Confidence, probe.ConfidenceHigh)
	}
	if len(rep.Ladder) < 2 || rep.Ladder[0] != "" {
		t.Errorf("ladder = %q; rung 1 must be plain (MEASUREMENTS.md §5.2)", rep.Ladder)
	}
	if rep.Ladder[1] != "tlsfrag:pos=snimid" {
		t.Errorf("ladder rung 2 = %q, want tlsfrag:pos=snimid", rep.Ladder[1])
	}
}

// TestTuneWithNoCensorshipInventsNoWinner is the plan's "must NOT invent a
// winner" clause: an open network with 30% connection loss looks noisy, and a
// prober that mistakes loss for censorship would report a bypass for a block
// that does not exist.
func TestTuneWithNoCensorshipInventsNoWinner(t *testing.T) {
	lab := newTuneLab(t, testcensor.Open(0.30), testcensor.Open(0.30))
	o := lab.options(t)
	o.Depth = probe.DepthQuick
	// A dropped connection is silence, so a short per-attempt budget is what
	// keeps this test seconds rather than minutes. It changes nothing about
	// what is measured: on loopback a live attempt completes in microseconds.
	o.Timeout = 500 * time.Millisecond

	r := probe.NewRunner(o)
	rep, err := r.Run(context.Background())
	if !errors.Is(err, probe.ErrNothingBlocked) {
		t.Fatalf("Run error = %v, want ErrNothingBlocked", err)
	}
	if _, ok := rep.Winner(); ok {
		t.Errorf("a winner was reported on an uncensored network: %s", specList(rep.Ranked))
	}
	if len(rep.Blocked) != 0 {
		t.Errorf("blocked = %v, want none", rep.Blocked)
	}
	if rep.Confidence != probe.ConfidenceLow {
		t.Errorf("confidence = %q, want %q", rep.Confidence, probe.ConfidenceLow)
	}
	// And the profile must not be written at all.
	if err := rep.WriteConfig(t.TempDir() + "/tuned.toml"); err == nil {
		t.Error("WriteConfig succeeded with nothing measured as blocked")
	}
}

// TestTuneStopsOnIPBlock: when the benign SNI to the same address also fails,
// no desync can exist. Saying so and stopping is the single most valuable
// honest output the tool can produce.
func TestTuneStopsOnIPBlock(t *testing.T) {
	m := testcensor.IPBlock(loopbackPrefix)
	lab := newTuneLab(t, m, m)
	o := lab.options(t)
	o.Depth = probe.DepthQuick

	rep, err := probe.NewRunner(o).Run(context.Background())
	if !errors.Is(err, probe.ErrIPBlock) {
		t.Fatalf("Run error = %v, want ErrIPBlock", err)
	}
	if rep.Class.Shape != probe.ShapeIPBlock {
		t.Errorf("shape = %s, want %s", rep.Class.Shape, probe.ShapeIPBlock)
	}
	if _, ok := rep.Winner(); ok {
		t.Error("a winner was reported against an address-level block")
	}
	if len(rep.Ranked) != 0 {
		t.Errorf("the ladder was swept anyway: %s", specList(rep.Ranked))
	}
}

// TestTuneWritesProfile exercises the write-back against a temp directory. The
// real config path is never touched by a test: writing there would change the
// machine running it.
func TestTuneWritesProfile(t *testing.T) {
	lab := newTuneLab(t, testcensor.TT2026(labBlocked...), testcensor.Fragile())
	o := lab.options(t)
	o.Depth = probe.DepthQuick
	o.Reps = 2

	rep, err := probe.NewRunner(o).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	rep.NetworkKey = "test-network"
	rep.ToolVersion = "v0.0.0-test"

	path := t.TempDir() + "/tuned.toml"
	if err := rep.WriteConfig(path); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	tuned := rep.Tuned()
	if tuned.Strategy != "tlsfrag:pos=snimid" {
		t.Errorf("written strategy = %q, want tlsfrag:pos=snimid", tuned.Strategy)
	}
	if tuned.Classification.InspectBytes != 0 {
		t.Errorf("InspectBytes = %d; this build cannot measure it and must not claim a number",
			tuned.Classification.InspectBytes)
	}
	if !strings.Contains(tuned.Classification.InspectSource, "unmeasured") {
		t.Errorf("the inspection window carries no note saying it is unmeasured: %q",
			tuned.Classification.InspectSource)
	}
}

// TestPreflightStopsWhenEveryTransportIsPoisoned: no packet strategy fixes a
// poisoned resolver, so the honest answer is to stop.
func TestPreflightStopsWhenEveryTransportIsPoisoned(t *testing.T) {
	lab := newTuneLab(t, testcensor.TT2026(labBlocked...), testcensor.Fragile())
	o := lab.options(t)
	o.Resolvers = []resolve.Resolver{
		sinkholeResolver{label: "udp-isp"},
		sinkholeResolver{label: "udp-isp-2"},
	}

	rep, err := probe.NewRunner(o).Run(context.Background())
	if !errors.Is(err, resolve.ErrNoCleanTransport) {
		t.Fatalf("Run error = %v, want resolve.ErrNoCleanTransport", err)
	}
	if len(rep.DNS) != 2 {
		t.Fatalf("health rows = %d, want 2", len(rep.DNS))
	}
	if rep.Matrix.CleanCount() != 0 {
		t.Errorf("CleanCount = %d, want 0", rep.Matrix.CleanCount())
	}
	if _, ok := rep.Winner(); ok {
		t.Error("the sweep ran anyway and reported a winner")
	}
}

// TestPreflightKeepsAWorkingTransport: the alternate-port rung answers blocked
// names where :53 does not (MEASUREMENTS.md §2), so the matrix must keep it and
// rank it first.
func TestPreflightKeepsAWorkingTransport(t *testing.T) {
	lab := newTuneLab(t, testcensor.TT2026(labBlocked...), testcensor.Fragile())
	o := lab.options(t)
	o.Resolvers = []resolve.Resolver{
		droppingResolver{label: "udp-8.8.8.8-53"},
		sinkholeResolver{label: "udp-isp"},
		cleanResolver{label: "udp-yandex-1253", delay: time.Millisecond},
	}
	r := probe.NewRunner(o)
	health, err := r.Preflight(context.Background())
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if len(health) != 3 {
		t.Fatalf("health rows = %d, want 3", len(health))
	}
	m := r.Matrix()
	if m.CleanCount() != 1 {
		t.Errorf("CleanCount = %d, want 1", m.CleanCount())
	}
	if order := m.Order(); len(order) == 0 || order[0] != "udp-yandex-1253" {
		t.Errorf("chain order = %v, want the clean transport first", order)
	}
	// A transport that answers the control and sinkholes the blocked names is
	// live but useless, and must not be called clean.
	for _, row := range m.Rows {
		if row.Label == "udp-isp" && row.Clean {
			t.Error("a sinkholing transport was reported clean")
		}
	}
}

// flakyControlDialer fails dials to the control host once it is armed, so a
// round's interleaved liveness probe goes down while the strategy under test is
// perfectly healthy.
type flakyControlDialer struct {
	lab  *tuneLab
	left atomic.Int64
}

func (d *flakyControlDialer) arm(n int) { d.left.Store(int64(n)) }

func (d *flakyControlDialer) DialTCP(ctx context.Context, t flow.Target) (net.Conn, error) {
	if t.Name == labControl && d.left.Add(-1) >= 0 {
		return nil, errors.New("fixture: the ordinary internet was down for this round")
	}
	return d.lab.DialTCP(ctx, t)
}

// TestRoundsWithAFailedControlAreDiscardedNotScored is the statistical clause
// that matters most: when the network was down while a candidate was measured,
// the round is thrown away and retried, never counted as the candidate failing.
//
// The alternative — scoring it — attributes someone else's outage to a
// strategy, and on a flaky line that is enough to bury the only emitter that
// works.
//
// The phases are driven by hand rather than through Run so the outage lands
// during the sweep and not during the baseline, where it would mean something
// else entirely.
func TestRoundsWithAFailedControlAreDiscardedNotScored(t *testing.T) {
	lab := newTuneLab(t, testcensor.TT2026(labBlocked...), testcensor.Fragile())
	o := lab.options(t)
	o.Reps = 2

	d := &flakyControlDialer{lab: lab}
	o.Dial = d

	r := probe.NewRunner(o)
	ctx := context.Background()
	blocked, _, err := r.Baseline(ctx)
	if err != nil {
		t.Fatalf("Baseline: %v", err)
	}
	if len(blocked) != len(labBlocked) {
		t.Fatalf("blocked = %d targets, want %d", len(blocked), len(labBlocked))
	}

	// Exactly one round attempt's worth of dials to the FIRST control host:
	// the plain liveness probe, plus the candidate's own trial against it. One
	// attempt therefore fails and its retry succeeds, which is the case worth
	// testing — the round is discarded and replaced, not lost.
	const controlDialsPerRoundAttempt = 2
	d.arm(controlDialsPerRoundAttempt)

	cands := []strategy.Strategy{mustSpecIn(t, o, ""), mustSpecIn(t, o, "tlsfrag:pos=snimid")}
	trials, err := r.Evaluate(ctx, cands)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	var down int
	for _, tr := range trials {
		if tr.Verdict != probe.VerdictControlDown {
			continue
		}
		down++
		if tr.Verdict.Scorable() {
			t.Fatal("a discarded trial reports itself as scorable")
		}
	}
	if down == 0 {
		t.Fatal("no round was discarded, so this test measured nothing")
	}

	// The discarded round must be out of every denominator, and the retried
	// round must have taken its place: 2 reps x 3 blocked targets = 6.
	ranked := probe.Rank(trials, blocked, reg.Docs())
	for _, s := range ranked {
		if s.Unmeasurable {
			continue
		}
		if s.BypassTotal != o.Reps*len(labBlocked) {
			t.Errorf("%s scored over %d trials, want %d: a discarded round reached a denominator",
				s.Label(), s.BypassTotal, o.Reps*len(labBlocked))
		}
		if s.Spec == "tlsfrag:pos=snimid" && s.BypassPass != s.BypassTotal {
			t.Errorf("tlsfrag scored %d/%d: the outage was charged to the strategy",
				s.BypassPass, s.BypassTotal)
		}
	}
	if ranked[0].Spec != "tlsfrag:pos=snimid" {
		t.Errorf("rank 1 = %q, want tlsfrag:pos=snimid after the discarded round", ranked[0].Spec)
	}
}

func mustSpecIn(t *testing.T, o probe.Options, spec string) strategy.Strategy {
	t.Helper()
	s, err := o.Registry.Get(spec)
	if err != nil {
		t.Fatalf("parse %q: %v", spec, err)
	}
	return s
}
