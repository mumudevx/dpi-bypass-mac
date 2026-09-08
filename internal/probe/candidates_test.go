package probe_test

import (
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/probe"
	"github.com/mumudevx/dpb/internal/strategy"
)

func specsOf(ss []strategy.Strategy) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.Spec)
	}
	return out
}

func has(ss []strategy.Strategy, spec string) bool {
	for _, s := range ss {
		if s.Spec == spec {
			return true
		}
	}
	return false
}

// TestCandidatesSweepTheMeasuredPoints: the sweep must contain the discrete
// points MEASUREMENTS.md §3 and §3.4 actually measured, including the ones
// measured as failures — the prober's job is to measure THIS line, not to
// replay Kayseri.
func TestCandidatesSweepTheMeasuredPoints(t *testing.T) {
	got := probe.CandidatesWith(reg, probe.DepthFull, probe.Classification{}, 0)
	for _, want := range []string{
		"", // the reference every rate is read against
		"tlsfrag:pos=snimid", "tlsfrag:pos=sniend-1", "tlsfrag:pos=snistart-20",
		"tlsevery:period=16", "tlsevery:period=64", "tlsevery:period=256",
		"chunk:size=12", "chunk:size=40", "chunk:size=120",
		"split:pos=snimid", "disorder:pos=3", "oob:pos=1",
	} {
		if !has(got, want) {
			t.Errorf("the sweep is missing %q; it has %v", want, specsOf(got))
		}
	}
}

// TestCandidatesNeverInterpolateChunkSizes: §3.4 records a non-monotonic curve
// that no simple model explains, so a size that was never measured has no
// evidence behind it and must not appear wearing the same label as one that was.
func TestCandidatesNeverInterpolateChunkSizes(t *testing.T) {
	measured := map[string]bool{
		"1": true, "2": true, "3": true, "4": true, "5": true, "8": true,
		"12": true, "20": true, "35": true, "40": true, "60": true, "120": true,
	}
	for _, s := range probe.CandidatesWith(reg, probe.DepthFull, probe.Classification{}, 0) {
		for _, tok := range strings.Split(s.Spec, "|") {
			size, ok := strings.CutPrefix(tok, "chunk:size=")
			if !ok {
				continue
			}
			if !measured[size] {
				t.Errorf("the sweep contains chunk:size=%s, which MEASUREMENTS.md §3.4 never "+
					"measured; §3.4's curve is non-monotonic, so an interpolated size is a "+
					"number with no evidence behind it", size)
			}
		}
	}
}

// TestCandidatesNarrowOrderNotMembership: a classification reorders the sweep
// so the live axis is tried first, but must not delete anything — a classifier
// that removed candidates would make the sweep incapable of contradicting it.
func TestCandidatesNarrowOrderNotMembership(t *testing.T) {
	base := probe.CandidatesWith(reg, probe.DepthFull, probe.Classification{}, 0)
	rec := probe.CandidatesWith(reg, probe.DepthFull, probe.Classification{RecordFrag: true}, 0)
	split := probe.CandidatesWith(reg, probe.DepthFull, probe.Classification{TCPSplit: true}, 0)

	if len(base) != len(rec) || len(base) != len(split) {
		t.Fatalf("membership changed: base %d, record %d, split %d", len(base), len(rec), len(split))
	}
	for _, s := range base {
		if !has(rec, s.Spec) || !has(split, s.Spec) {
			t.Errorf("%q was dropped by a classification", s.Spec)
		}
	}
	if rec[0].Spec != "" {
		t.Errorf("rung 1 = %q, want plain first in every ordering", rec[0].Spec)
	}
	if !strings.HasPrefix(rec[1].Spec, "tls") {
		t.Errorf("with the record axis live, the sweep starts %q; want a reframer first", rec[1].Spec)
	}
	if !strings.HasPrefix(split[1].Spec, "split") && !strings.HasPrefix(split[1].Spec, "disorder") {
		t.Errorf("with the TCP axis live, the sweep starts %q; want a splitter first", split[1].Spec)
	}
}

// TestCandidatesDropWhatTheTransportCannotCarry: a strategy the transport
// cannot emit is unmeasurable, not blocked, so it must not enter the sweep and
// then score 0.
func TestCandidatesDropWhatTheTransportCannotCarry(t *testing.T) {
	caps := strategy.CapStreamWrite | strategy.CapNoDelay // no CapOOB, no CapSockTTL
	got := probe.CandidatesWith(reg, probe.DepthFull, probe.Classification{}, caps)
	for _, s := range got {
		if strings.HasPrefix(s.Spec, "oob") || strings.HasPrefix(s.Spec, "disorder") {
			t.Errorf("%q entered the sweep without the capability to emit it", s.Spec)
		}
	}
	if !has(got, "tlsfrag:pos=snimid") {
		t.Error("the primary emitter was dropped by a capability filter it satisfies")
	}
}

func TestCandidatesDepths(t *testing.T) {
	quick := probe.CandidatesWith(reg, probe.DepthQuick, probe.Classification{}, 0)
	full := probe.CandidatesWith(reg, probe.DepthFull, probe.Classification{}, 0)
	paranoid := probe.CandidatesWith(reg, probe.DepthParanoid, probe.Classification{}, 0)
	unknown := probe.CandidatesWith(reg, "wat", probe.Classification{}, 0)

	if len(quick) >= len(full) {
		t.Errorf("quick swept %d specs and full swept %d", len(quick), len(full))
	}
	if len(paranoid) != len(full) {
		t.Errorf("paranoid swept %d specs and full swept %d; paranoid changes reps, not the "+
			"sweep set, because there is no measured point beyond full", len(paranoid), len(full))
	}
	if len(unknown) != len(full) {
		t.Errorf("an unknown depth swept %d specs, want the full sweep (%d)", len(unknown), len(full))
	}
	if probe.DepthReps(probe.DepthQuick) != 2 ||
		probe.DepthReps(probe.DepthFull) != 3 ||
		probe.DepthReps(probe.DepthParanoid) != 5 ||
		probe.DepthReps("") != 3 {
		t.Error("DepthReps does not match the documented rep counts")
	}
}

// TestCandidatesUseTheGivenRegistry: an empty registry has no ops, so a sweep
// against it must be empty rather than silently reporting "nothing works here".
func TestCandidatesUseTheGivenRegistry(t *testing.T) {
	empty := strategy.NewRegistry()
	got := probe.CandidatesWith(empty, probe.DepthFull, probe.Classification{}, 0)
	if len(got) != 1 || got[0].Spec != "" {
		t.Errorf("an empty registry swept %v, want only the plain strategy", specsOf(got))
	}
	// The package-level entry point resolves against the default registry, so
	// it must at least agree with itself.
	if a, b := probe.Candidates(probe.DepthQuick, probe.Classification{}, 0),
		probe.Candidates(probe.DepthQuick, probe.Classification{}, 0); len(a) != len(b) {
		t.Errorf("Candidates is not deterministic: %d then %d", len(a), len(b))
	}
}
