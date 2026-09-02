package probe_test

import (
	"math"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/probe"
)

// TestWilsonRewardsMoreEvidence is the plan's stated reason for choosing this
// interval: 9/9 across three targets (~0.70) must outrank 3/3 against one
// (~0.44), so the statistics themselves push toward the intersection.
func TestWilsonRewardsMoreEvidence(t *testing.T) {
	one, _ := probe.Wilson(3, 3, probe.Z95)
	three, _ := probe.Wilson(9, 9, probe.Z95)
	if !(three > one) {
		t.Fatalf("9/9 lower bound %.3f must exceed 3/3 lower bound %.3f", three, one)
	}
	if math.Abs(one-0.4385) > 0.005 {
		t.Errorf("3/3 lower bound = %.4f, want ~0.4385", one)
	}
	if math.Abs(three-0.7026) > 0.005 {
		t.Errorf("9/9 lower bound = %.4f, want ~0.7026", three)
	}
}

func TestWilsonEdges(t *testing.T) {
	for _, tc := range []struct {
		name           string
		pass, trials   int
		z              float64
		wantLo, wantHi float64
	}{
		{"no evidence", 0, 0, probe.Z95, 0, 0},
		{"no z", 3, 3, 0, 0, 0},
		{"total failure", 0, 6, probe.Z95, 0, 0.3903},
		{"negative passes clamp", -4, 3, probe.Z95, 0, 0.5614},
		{"passes above trials clamp", 9, 3, probe.Z95, 0.4385, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lo, hi := probe.Wilson(tc.pass, tc.trials, tc.z)
			if math.Abs(lo-tc.wantLo) > 0.005 || math.Abs(hi-tc.wantHi) > 0.005 {
				t.Errorf("Wilson(%d,%d,%g) = (%.4f,%.4f), want (%.4f,%.4f)",
					tc.pass, tc.trials, tc.z, lo, hi, tc.wantLo, tc.wantHi)
			}
			if lo < 0 || lo > 1 || hi < 0 || hi > 1 || lo > hi {
				t.Errorf("interval [%.4f,%.4f] is not a probability interval", lo, hi)
			}
		})
	}
}

func TestWilsonIsMonotonicInPasses(t *testing.T) {
	prev := -1.0
	for k := 0; k <= 10; k++ {
		lo, _ := probe.Wilson(k, 10, probe.Z95)
		if lo < prev {
			t.Fatalf("lower bound fell from %.4f to %.4f at %d/10", prev, lo, k)
		}
		prev = lo
	}
}

func TestNoiseRate(t *testing.T) {
	if got := probe.NoiseRate(0, 0); got != 0 {
		t.Errorf("NoiseRate(0,0) = %v, want 0", got)
	}
	if got := probe.NoiseRate(1, 20); math.Abs(got-0.05) > 1e-9 {
		t.Errorf("NoiseRate(1,20) = %v, want 0.05", got)
	}
}

// TestConfidenceNeedsTheWholeBar: the plan's "high" is ≥3 blocked targets ×
// ≥3 reps all passing, clean controls and noise under 5%. Each clause is
// load-bearing, so each one is dropped in turn.
func TestConfidenceNeedsTheWholeBar(t *testing.T) {
	full := probe.Score{
		BypassPass: 9, BypassTotal: 9, AllTargets: true,
		ControlPass: 8, ControlTotal: 8,
	}
	if got := probe.Confidence(full, 3, 3, 0.0); got != probe.ConfidenceHigh {
		t.Fatalf("the full bar scored %q, want high", got)
	}

	drop := []struct {
		name    string
		s       probe.Score
		targets int
		reps    int
		noise   float64
		want    string
	}{
		{"two targets", full, 2, 3, 0, probe.ConfidenceMedium},
		{"two reps", full, 3, 2, 0, probe.ConfidenceMedium},
		{"noisy", full, 3, 3, 0.06, probe.ConfidenceMedium},
		{"unusable noise", full, 3, 3, 0.25, probe.ConfidenceLow},
		{"a broken control", probe.Score{
			BypassPass: 9, BypassTotal: 9, AllTargets: true, ControlPass: 6, ControlTotal: 8,
		}, 3, 3, 0, probe.ConfidenceMedium},
		{"one target missed", probe.Score{
			BypassPass: 6, BypassTotal: 9, ControlPass: 8, ControlTotal: 8,
		}, 3, 3, 0, probe.ConfidenceMedium},
		{"nothing passed", probe.Score{BypassTotal: 9}, 3, 3, 0, probe.ConfidenceLow},
		{"nothing measured", probe.Score{}, 3, 3, 0, probe.ConfidenceLow},
	}
	for _, tc := range drop {
		t.Run(tc.name, func(t *testing.T) {
			if got := probe.Confidence(tc.s, tc.targets, tc.reps, tc.noise); got != tc.want {
				t.Errorf("Confidence = %q, want %q", got, tc.want)
			}
		})
	}
}
