package netwatch

import (
	"strings"
	"testing"
	"time"
)

var epoch = time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)

func inst(mono, wall time.Duration) Instant {
	return Instant{Mono: epoch.Add(mono), Wall: epoch.Add(wall)}
}

func TestSleepDetectorReportsWallMonotonicDivergence(t *testing.T) {
	cases := []struct {
		name string
		gap  time.Duration
		// samples after the baseline at (0, 0).
		samples []Instant
		want    []time.Duration
	}{
		{
			name:    "a machine that is merely running reports nothing",
			samples: []Instant{inst(5*time.Second, 5*time.Second), inst(10*time.Second, 10*time.Second)},
			want:    []time.Duration{0, 0},
		},
		{
			name: "a closed lid: the wall clock ran on while the monotonic clock did not",
			// One 5 s tick during which 20 minutes of wall time passed.
			samples: []Instant{inst(5*time.Second, 20*time.Minute+5*time.Second)},
			want:    []time.Duration{20 * time.Minute},
		},
		{
			name:    "a divergence under the threshold is scheduler jitter, not sleep",
			gap:     10 * time.Second,
			samples: []Instant{inst(5*time.Second, 14*time.Second)},
			want:    []time.Duration{0},
		},
		{
			name:    "exactly at the threshold counts",
			gap:     10 * time.Second,
			samples: []Instant{inst(5*time.Second, 15*time.Second)},
			want:    []time.Duration{10 * time.Second},
		},
		{
			// An NTP step backwards must not be reported as sleep, and must
			// not leave the detector permanently convinced: the next ordinary
			// tick reports zero because the baseline moved with the step.
			name: "a backwards wall-clock step is not sleep and does not stick",
			samples: []Instant{
				inst(5*time.Second, -time.Hour),
				inst(10*time.Second, -time.Hour+5*time.Second),
			},
			want: []time.Duration{0, 0},
		},
		{
			name: "a second sleep after a first is measured on its own",
			samples: []Instant{
				inst(5*time.Second, time.Hour),
				inst(10*time.Second, time.Hour+5*time.Second),
				inst(15*time.Second, 2*time.Hour),
			},
			want: []time.Duration{time.Hour - 5*time.Second, 0, time.Hour - 10*time.Second},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &SleepDetector{Gap: tc.gap}
			d.Reset(inst(0, 0))
			for i, s := range tc.samples {
				if got := d.Observe(s); got != tc.want[i] {
					t.Fatalf("sample %d: gap = %v, want %v", i, got, tc.want[i])
				}
			}
		})
	}
}

// TestSleepDetectorFirstObserveIsABaseline pins that a detector nobody Reset
// does not report the whole time since the zero Time as a sleep — which would
// fire a wake on the very first tick of every run.
func TestSleepDetectorFirstObserveIsABaseline(t *testing.T) {
	var d SleepDetector
	if got := d.Observe(inst(0, 0)); got != 0 {
		t.Fatalf("first Observe reported %v, want 0", got)
	}
	if got := d.Observe(inst(5*time.Second, time.Hour)); got == 0 {
		t.Fatal("the second Observe reported no sleep after an hour of wall-clock divergence")
	}
}

// TestSleepDetectorDefaultThreshold pins that a zero Gap uses the plan's 10 s
// rather than firing on every sample.
func TestSleepDetectorDefaultThreshold(t *testing.T) {
	var d SleepDetector
	d.Reset(inst(0, 0))
	if got := d.Observe(inst(time.Second, time.Second+DefaultSleepGap-time.Millisecond)); got != 0 {
		t.Fatalf("a gap just under the default reported %v, want 0", got)
	}
	d.Reset(inst(0, 0))
	if got := d.Observe(inst(time.Second, time.Second+DefaultSleepGap)); got != DefaultSleepGap {
		t.Fatalf("a gap at the default reported %v, want %v", got, DefaultSleepGap)
	}
}

// TestRealClockSeparatesTheTwoAxes is the one assertion that the production
// clock actually hands the detector two different readings. A Clock whose Wall
// still carried a monotonic reading would make every divergence zero and the
// detector would silently never fire.
func TestRealClockSeparatesTheTwoAxes(t *testing.T) {
	c := RealClock()
	a := c.Now()
	b := c.Now()
	// Time.Equal falls back to wall comparison when one side has no monotonic
	// reading, so it cannot answer this question; the formatted form names the
	// monotonic clock explicitly and is the only honest test.
	if !strings.Contains(a.Mono.String(), " m=") {
		t.Errorf("Instant.Mono carries no monotonic reading (%s), so Sub would measure wall time", a.Mono)
	}
	if strings.Contains(b.Wall.String(), " m=") {
		t.Errorf("Instant.Wall still carries a monotonic reading (%s), so sleep can never be detected", b.Wall)
	}
	if b.Mono.Before(a.Mono) {
		t.Error("the monotonic reading went backwards")
	}
}

func TestRealClockAfterFires(t *testing.T) {
	select {
	case <-RealClock().After(time.Millisecond):
	case <-time.After(2 * time.Second):
		t.Fatal("RealClock().After never fired")
	}
}
