package probe

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mumudevx/dpb/internal/resolve"
)

// Shape is what kind of blocking this line does.
type Shape uint8

const (
	ShapeUnknown Shape = iota
	// ShapeClean means nothing in the target set is blocked here.
	ShapeClean
	// ShapeDNSOnly means the names are poisoned but the paths are not: a pinned
	// dial with the real SNI reaches the origin.
	ShapeDNSOnly
	ShapeSNIReset
	ShapeSNIResetAndDNS
	// ShapeIPBlock: the path is unreachable even with a benign SNI. No desync
	// can help; say so and stop rather than burning a full ladder.
	ShapeIPBlock
)

var shapeNames = [...]string{
	"unknown", "clean", "dns-only", "sni-reset", "sni-reset+dns", "ip-block",
}

func (s Shape) String() string {
	if int(s) >= len(shapeNames) {
		return "invalid"
	}
	return shapeNames[s]
}

// Evidence is one observation, kept so a reader can audit a conclusion instead
// of trusting it. A prober that reports only its conclusions is indistinguishable
// from one that guessed them.
type Evidence struct {
	Claim    string
	Method   string
	Observed string
	At       time.Time
}

// Classification is what the mechanism probes concluded about this line.
type Classification struct {
	Shape Shape
	// FirstRecordLimit is the largest first-TLS-record end offset
	// (body-relative) at which the block stops firing, found by binary search
	// over record cut positions. On Türk Telekom this converges on sniEnd-1.
	//
	// It is bounded above by our own emitter: strategy.ErrCutAfterSNI refuses
	// any cut at or after sniEnd, so a middlebox with a larger window reads
	// identically to one whose window is exactly sniEnd. Evidence records that.
	FirstRecordLimit int
	// InspectBytes is the middlebox's apparent inspection window.
	//
	// It is 0 in this build and that means UNMEASURED, not "zero bytes". The
	// instrument the plan specifies for it — a ClientHello padding sweep — is
	// impossible for a byte relay: rewriting the hello desynchronises the
	// client's own TLS transcript, so tlspad is registered rejected and every
	// value would read as a failure on a censored and an open line alike
	// (PLAN amendment A2, internal/ops/pad.go).
	InspectBytes int
	RSTLatency   time.Duration
	DNS          []resolve.Health
	Evidence     []Evidence

	// SNIEnd is the body-relative end of the SNI hostname in the ClientHello
	// this line's targets actually produce. It is the coordinate system
	// FirstRecordLimit is stated in, so it is reported alongside it: a limit of
	// 121 means nothing without it.
	SNIEnd int

	// The three axes below record which mechanism was observed to work, and are
	// what narrows the SEARCH ORDER in Candidates. They never narrow the search
	// set: MEASUREMENTS.md §4 is one afternoon on one line, and a classifier
	// that deleted candidates would make the sweep unable to contradict it.
	//
	// Each is true only when EVERY scorable attempt on that axis passed, so
	// false covers three different things — measured and failed, measured and
	// mixed, and never measured at all. A reader who needs to tell them apart
	// must read Evidence, whose claim is selected by the tally rather than by
	// which code path ran (see axisClaim).
	RecordFrag bool // reframing the TLS record layer bypassed every attempt
	TCPSplit   bool // splitting the hostname across two TCP segments bypassed every attempt
	Chunking   bool // fixed-size TCP chunking bypassed every attempt
}

// classifyReps is how many attempts each mechanism probe makes.
//
// Two, not three: a mechanism probe only has to distinguish "this axis does
// something" from "this axis does nothing", and the axis it selects is then
// measured properly in phase 4 with the full rep count. §6 measures the DPI as
// stateless between flows, so two independent attempts are two samples.
const classifyReps = 2

// classifySpecs are the mechanism probes, each chosen because its outcome
// partitions the hypothesis space rather than because it is likely to win.
const (
	specRecordFrag = "tlsfrag:pos=snimid"
	specTCPSplit   = "split:pos=snimid"
	specChunk      = "chunk:size=12"
)

// axisClaim is the set of sentences one mechanism probe may print, one per
// outcome the probe can have.
//
// It exists because a claim MUST be selected by the measurement rather than by
// the code path that produced it. Before this type, axisEvidence took a single
// positive claim string and printed it whatever the trials said, so a run on
// the live Türk Telekom line emitted
//
//	the DPI does not reassemble TCP, so segment splitting also bypasses
//	  via split:pos=snimid: 0/2 PASS
//
// — the exact opposite of both the number beside it and of MEASUREMENTS.md
// §3.1, which measures every TCP split at 0/5 here precisely BECAUSE this DPI
// reassembles TCP. This whole tool exists because published claims about
// Turkish DPI were repeated without measurement; a prober that narrates a
// conclusion its own numbers contradict is worse than one that says nothing.
type axisClaim struct {
	// name is the mechanism in words, used to build the sentences for the two
	// outcomes that support no conclusion. It is a description of what was
	// EMITTED, never of what the middlebox does.
	name string
	// pass is printed only when every scorable attempt passed.
	pass string
	// fail is printed only when there were scorable attempts and NONE passed.
	// Only a clean zero licenses a negative mechanism conclusion.
	fail string
}

// claim picks the sentence the measurement supports, and only that one.
//
// The two middle cases are deliberately conclusion-free. A partial result is
// not evidence for either mechanism — a 1/2 on the splitting axis would make
// "the DPI reassembles TCP" and "it does not" equally unsupported — and an
// unmeasurable axis is not a result at all: the emitter refused to build the
// probe, so nothing was learned about this line in either direction.
func (a axisClaim) claim(pass, total int) string {
	switch {
	case total == 0:
		return "whether " + a.name + " bypasses was not measured here"
	case pass == total:
		return a.pass
	case pass == 0:
		return a.fail
	default:
		return a.name + " bypassed some attempts and not others here, which supports no conclusion"
	}
}

// axisClaims are the sentences each mechanism probe may print.
//
// Every positive sentence states what was emitted and what happened, and names
// a mechanism only where that mechanism is what the experiment isolates:
// splitting the hostname across two TCP segments distinguishes a middlebox
// that reassembles TCP from one that does not, which is exactly the experiment
// MEASUREMENTS.md §3.1 ran.
var axisClaims = map[string]axisClaim{
	specRecordFrag: {
		name: "reframing the TLS record layer",
		pass: "reframing the TLS record layer bypasses: the block does not fire when the SNI " +
			"hostname is not complete inside the first TLS record",
		fail: "reframing the TLS record layer does not bypass here",
	},
	specTCPSplit: {
		name: "splitting the hostname across two TCP segments",
		pass: "splitting the hostname across two TCP segments bypasses, so this line's " +
			"middlebox does not reassemble TCP",
		fail: "splitting the hostname across two TCP segments does not bypass, so this line's " +
			"middlebox reassembles TCP (MEASUREMENTS.md §3.1 measured the same result)",
	},
	specChunk: {
		name: "fixed-size TCP chunking",
		pass: "fixed-size TCP chunking bypasses",
		fail: "fixed-size TCP chunking does not bypass here",
	},
}

// Classify runs the mechanism probes and returns what they establish.
//
// It must run after Baseline: with no blocked target there is nothing to
// classify, and reporting a mechanism derived from a host that was never
// blocked would be the purest form of measuring nothing.
func (r *Runner) Classify(ctx context.Context) (Classification, error) {
	c := Classification{Shape: r.shape, DNS: r.dns}

	if len(r.blocked) == 0 {
		if c.Shape == ShapeUnknown {
			c.Shape = ShapeClean
		}
		c.Evidence = append(c.Evidence, r.note("nothing is blocked here",
			"baseline", "no target failed a plain dial to its pinned address"))
		return c, nil
	}
	if c.Shape == ShapeIPBlock {
		return c, ErrIPBlock
	}

	c.RSTLatency = r.rstLatency
	t := r.blocked[0]

	// Axis 1: record reframing. A pass here is the §3.2 mechanism.
	frag, fragTrials := r.axis(ctx, specRecordFrag, t)
	c.RecordFrag = frag
	c.Evidence = append(c.Evidence, axisEvidence(r.now(), specRecordFrag, t, fragTrials))

	// SNIEnd comes from the hello the trials actually emitted, never from a
	// constant: MEASUREMENTS.md §3.2's 122 is one client's hello on one day,
	// and the whole point of FirstRecordLimit is to be in this client's
	// coordinates.
	c.SNIEnd = sniEndOf(fragTrials)

	// Axis 2: plain TCP splitting. §3.1 measures this at 0/5 here and concludes
	// the DPI reassembles TCP; a pass would mean this line's middlebox does not,
	// which changes which candidates are worth trying first.
	split, splitTrials := r.axis(ctx, specTCPSplit, t)
	c.TCPSplit = split
	c.Evidence = append(c.Evidence, axisEvidence(r.now(), specTCPSplit, t, splitTrials))

	// Axis 3: chunking. The plan names chunk:size=1 as the instrument; the
	// shipped op refuses it, because with a 16-segment budget a 1-byte chunk
	// covers 15 bytes and cannot reach the SNI (§3.4's correction note). Asking
	// for it would produce an unmeasurable rung, which is not the same as a
	// blocked one, so the axis is probed at the size §3.4 measured twice.
	chunk, chunkTrials := r.axis(ctx, specChunk, t)
	c.Chunking = chunk
	c.Evidence = append(c.Evidence, axisEvidence(r.now(), specChunk, t, chunkTrials))

	// The first-record limit, by binary search, but only when reframing is the
	// axis: searching the cut position of a mechanism that does not work here
	// would return the largest buildable cut and call it a measurement.
	if c.RecordFrag && c.SNIEnd > 1 {
		limit, ev := r.firstRecordLimit(ctx, t, c.SNIEnd)
		c.FirstRecordLimit = limit
		c.Evidence = append(c.Evidence, ev...)
	} else if !c.RecordFrag {
		c.Evidence = append(c.Evidence, r.note(
			"the first-record limit was not searched",
			"binary search over tlsfrag cut positions",
			fmt.Sprintf("%s does not bypass %s, so there is no boundary to find", specRecordFrag, t.Host)))
	}

	// The inspection-window sweep, and why there is no number for it.
	c.Evidence = append(c.Evidence, r.note(
		"the inspection window is UNMEASURED, not zero",
		"ClientHello padding sweep",
		"tlspad is registered rejected: rewriting the hello in flight desynchronises the "+
			"client's own TLS transcript, so every padded value fails on an open line too "+
			"(PLAN amendment A2)"))

	return c, nil
}

// axis runs one mechanism probe and reports whether it bypassed.
//
// "Bypassed" is every scorable attempt passing, not a majority: these probes
// decide which family of candidates is tried first, and a family that works
// half the time is not the one to lead with. Unscorable attempts — a build the
// emitter refused, a local error — are neither passes nor failures, and an axis
// with no scorable attempt at all is false because it is unmeasured.
func (r *Runner) axis(ctx context.Context, spec string, t Target) (bool, []Trial) {
	s, err := r.o.Registry.Get(spec)
	if err != nil {
		r.logf("probe: classify: %s is not available in this build: %v", spec, err)
		return false, nil
	}
	var ts []Trial
	for i := 0; i < classifyReps; i++ {
		if err := r.pace(ctx, i); err != nil {
			break
		}
		ts = append(ts, RunTrial(ctx, s, t, i+1, r.trialOptions()))
	}
	pass, total := tally(ts)
	return total > 0 && pass == total, ts
}

// firstRecordLimit binary-searches the largest first-record end offset that
// still bypasses.
//
// The search space is [1, sniEnd-1] because that is what the emitter will
// build: strategy.ErrCutAfterSNI refuses a cut at or after sniEnd, and a rung
// the emitter refuses is UNMEASURABLE, not blocked. Scoring a refusal as a
// failure would make every search converge on the refusal boundary and call it
// the DPI's — the prober would be measuring its own validator and reporting it
// as a property of Türk Telekom.
//
// On a line where the §3.2 rule holds, every cut in the space passes and the
// answer is the top of the space, sniEnd-1. That is a real result and it is
// also the strongest statement this instrument can make: the boundary is at or
// beyond sniEnd-1.
func (r *Runner) firstRecordLimit(ctx context.Context, t Target, sniEnd int) (int, []Evidence) {
	ev := []Evidence{r.note(
		"the search space is bounded above by our own emitter",
		"strategy.ErrCutAfterSNI",
		fmt.Sprintf("cuts at or after sniEnd=%d are refused at build time, so the reported "+
			"limit is a lower bound on the DPI's (MEASUREMENTS.md §3.2)", sniEnd))}

	lo, hi := 1, sniEnd-1
	best := 0
	tried := 0
	for lo <= hi {
		if ctx.Err() != nil {
			break
		}
		mid := lo + (hi-lo)/2
		spec := fmt.Sprintf("tlsfrag:pos=%d", mid)
		ok, ts := r.axis(ctx, spec, t)
		tried++
		_, total := tally(ts)
		switch {
		case total == 0:
			// Unmeasurable at this cut: the emitter would not build it. Treat
			// it as out of the space rather than as a block.
			ev = append(ev, r.note("a cut position was unmeasurable",
				spec, unbuildableReason(ts)))
			hi = mid - 1
		case ok:
			best = mid
			lo = mid + 1
		default:
			hi = mid - 1
		}
	}
	// The claim follows the search, not the fact that a search ran: with no
	// passing cut there is no boundary to report, and "the first record may end
	// at 0 and still pass" would be a measurement of nothing stated as a result.
	claim := fmt.Sprintf("the first record may end at %d and still pass", best)
	observed := fmt.Sprintf("largest passing cut %d, sniEnd %d", best, sniEnd)
	if best == 0 {
		claim = "no cut position in the searchable space bypassed, so there is no first-record limit to report"
		observed = fmt.Sprintf("no passing cut in [1,%d], sniEnd %d", sniEnd-1, sniEnd)
	}
	ev = append(ev, r.note(claim,
		fmt.Sprintf("binary search over %d cut positions in [1,%d]", tried, sniEnd-1),
		observed))
	return best, ev
}

func unbuildableReason(ts []Trial) string {
	for _, t := range ts {
		if t.Err != "" {
			return t.Err
		}
	}
	return "no attempt produced a scorable result"
}

// sniEndOf reads the SNI extent the emitted hello actually had.
func sniEndOf(ts []Trial) int {
	for _, t := range ts {
		if t.SNIEnd > 0 {
			return t.SNIEnd
		}
	}
	return 0
}

// axisEvidence renders one mechanism probe as a claim its own numbers support.
//
// The claim is looked up by spec and then SELECTED by the tally, so there is no
// way to reach this function with a sentence that the measurement beside it
// does not license. A spec with no entry gets a bare description of the result
// rather than an invented mechanism.
func axisEvidence(now time.Time, spec string, t Target, ts []Trial) Evidence {
	pass, total := tally(ts)
	observed := fmt.Sprintf("%d/%d PASS against %s", pass, total, t)
	if total == 0 {
		observed = fmt.Sprintf("unmeasurable against %s: %s", t, unbuildableReason(ts))
	}
	a, ok := axisClaims[spec]
	if !ok {
		a = axisClaim{
			name: spec,
			pass: spec + " bypasses here",
			fail: spec + " does not bypass here",
		}
	}
	return Evidence{
		Claim:    a.claim(pass, total),
		Method:   spec,
		Observed: observed,
		At:       now,
	}
}

// tally counts passes over SCORABLE attempts. Everything else — a refused
// build, a TLS alert from the origin, a round whose control was down — is
// excluded from both numerator and denominator, which is the difference
// between "this strategy failed" and "we failed to measure this strategy".
func tally(ts []Trial) (pass, total int) {
	for _, t := range ts {
		if !t.Verdict.Scorable() {
			continue
		}
		total++
		if t.Verdict == VerdictPass {
			pass++
		}
	}
	return pass, total
}

// tallyReach counts "did this attempt reach the origin", which is a different
// question from "does this attempt say anything about a strategy".
//
// A dial failure is NOT scorable for a strategy — nothing was emitted, so the
// emitter cannot be blamed — but it is exactly the evidence the baseline needs:
// MEASUREMENTS.md §1's control experiment turns on whether the benign SNI got
// through to the same address, and an address-level block fails before a byte
// is written. Excluding it there would make an IP block read as "nothing is
// blocked here", which is the one conclusion that sends a user hunting for a
// strategy that cannot exist.
//
// A handshake failure stays excluded on both counts: that is the origin
// refusing us, not the path.
func tallyReach(ts []Trial) (pass, total int) {
	for _, t := range ts {
		switch t.Verdict {
		case VerdictPass:
			pass++
			total++
		case VerdictReset, VerdictTimeout, VerdictBlockPage, VerdictDialFail:
			total++
		}
	}
	return pass, total
}

func (r *Runner) note(claim, method, observed string) Evidence {
	return Evidence{Claim: claim, Method: method, Observed: observed, At: r.now()}
}

// ErrIPBlock is the honest stop condition: the path is unreachable even with a
// benign SNI, so no packet strategy exists that could help.
var ErrIPBlock = errors.New("probe: the destination is unreachable even with a benign SNI; no desync can help")

// ErrNothingBlocked is returned when every target reaches its origin plain.
// It is not a failure of the run — it is the run's result.
var ErrNothingBlocked = errors.New("probe: nothing in the target set is blocked on this network")
