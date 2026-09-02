package probe

import (
	"math"
	"sort"
	"time"
)

// Z95 is the two-sided 95% normal quantile.
//
// It is the z the plan names for ranking, and it is what makes evidence from
// three targets outrank evidence from one: 9/9 has a lower bound near 0.70
// while 3/3 has one near 0.44, so the interval itself pushes the ranking toward
// the cross-target intersection rather than a rule having to.
const Z95 = 1.959963984540054

// Wilson returns the Wilson score interval for passes out of trials at
// quantile z.
//
// The Wilson interval rather than the normal approximation because the
// interesting measurements here are at the edges — 0/6 and 6/6 are the two most
// common outcomes in MEASUREMENTS.md §3 — where the normal approximation gives
// a zero-width interval and would rank a single lucky trial level with thirty.
//
// n == 0 returns (0, 0): no evidence is not the same as evidence of failure,
// but a candidate with no evidence must never sort above one with some, and
// Rank enforces that separately rather than by pretending the interval is wide.
func Wilson(passes, trials int, z float64) (lo, hi float64) {
	if trials <= 0 || z <= 0 {
		return 0, 0
	}
	if passes < 0 {
		passes = 0
	}
	if passes > trials {
		passes = trials
	}
	n := float64(trials)
	p := float64(passes) / n
	z2 := z * z
	denom := 1 + z2/n
	centre := (p + z2/(2*n)) / denom
	margin := z * math.Sqrt(p*(1-p)/n+z2/(4*n*n)) / denom
	lo = centre - margin
	hi = centre + margin
	return clamp01(lo), clamp01(hi)
}

func clamp01(f float64) float64 {
	switch {
	case f < 0 || math.IsNaN(f):
		return 0
	case f > 1:
		return 1
	default:
		return f
	}
}

// NoiseRate is discarded rounds over attempted rounds.
//
// It is reported rather than hidden because it is the number that says whether
// to believe the rest of the report: a run where a third of the rounds were
// thrown away because the control was down measured the weather, not the DPI.
func NoiseRate(discarded, attempted int) float64 {
	if attempted <= 0 {
		return 0
	}
	return float64(discarded) / float64(attempted)
}

// Confidence labels, written into tuned.toml and printed by `dpb status`.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

const (
	// NoiseClean is the plan's "noise < 5%" bar for a high-confidence run.
	NoiseClean = 0.05
	// NoiseUnusable is where the run stops being a measurement of the network.
	// A fifth of rounds discarded is a sizing choice, stated as such: there is
	// no measurement behind it, only the judgement that a result carrying that
	// much noise must not be labelled anything but low.
	NoiseUnusable = 0.20
	// ConfidentTargets and ConfidentReps are the plan's "≥3 blocked targets ×
	// ≥3 reps all passing" bar.
	ConfidentTargets = 3
	ConfidentReps    = 3
)

// Confidence labels a completed run.
//
// high means every part of the plan's bar was met: at least three blocked
// targets, at least three reps, the winner passing all of them, its controls
// clean, and noise under 5%. Anything measured but short of that is medium.
// low is reserved for "we did not establish a winner at all" — no scorable
// bypass evidence, nothing that passed, or so much noise that the denominators
// mean nothing.
func Confidence(best Score, blockedTargets, reps int, noise float64) string {
	switch {
	case best.BypassTotal == 0, best.BypassPass == 0:
		return ConfidenceLow
	case noise >= NoiseUnusable:
		return ConfidenceLow
	}
	clean := best.ControlTotal == 0 || best.ControlPass == best.ControlTotal
	switch {
	case blockedTargets >= ConfidentTargets &&
		reps >= ConfidentReps &&
		best.AllTargets &&
		best.BypassPass == best.BypassTotal &&
		best.BypassTotal >= blockedTargets*ConfidentReps &&
		clean &&
		noise < NoiseClean:
		return ConfidenceHigh
	default:
		return ConfidenceMedium
	}
}

// cmpRate compares two pass rates exactly, as pass_a/total_a vs pass_b/total_b,
// without going through float64.
//
// Exactness matters here: ranking key 1 separates 8/8 from 6/8 (MEASUREMENTS.md
// §5.1's control column), and two rates that are equal as rationals must
// compare equal so the next key decides, rather than being separated by a
// rounding artefact that changes between runs.
//
// A rate with no trials is treated as 1: it is the absence of evidence of harm,
// not evidence of harm. Rank gates unmeasured candidates before this is reached.
func cmpRate(aPass, aTotal, bPass, bTotal int) int {
	if aTotal == 0 {
		aPass, aTotal = 1, 1
	}
	if bTotal == 0 {
		bPass, bTotal = 1, 1
	}
	l := aPass * bTotal
	r := bPass * aTotal
	switch {
	case l < r:
		return -1
	case l > r:
		return 1
	default:
		return 0
	}
}

// medianDuration is the middle latency, or the mean of the middle two. An
// even-sized sample takes the mean so that a two-sample median is not silently
// the slower of the pair.
func medianDuration(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}
