package flow

import (
	"net/netip"
	"testing"
	"time"
)

// TestMeasuredKeepsASubTickResponse is the unit half of the Windows defect
// `measured` exists for: a first response that arrived inside one system timer
// tick must still register as a response.
//
// It is an internal test rather than a flow_test one because `measured` is the
// seam and not the behaviour — the behaviour is
// TestLadderObservesTheDialledAddress, which is what failed on Windows, and
// which cannot distinguish "the tracker keyed on the wrong address" from "the
// sample was discarded". This one can.
func TestMeasuredKeepsASubTickResponse(t *testing.T) {
	t.Parallel()
	if got := measured(0); got <= 0 {
		t.Fatalf("measured(0) = %v; a response the clock was too coarse to time "+
			"must not be discarded as a non-sample", got)
	}
	// A backwards clock is a different statement and stays rejected, so
	// RTTTracker.Observe's guard keeps the case it was written for.
	if got := measured(-time.Second); got != -time.Second {
		t.Fatalf("measured(-1s) = %v, want it passed through for Observe to reject", got)
	}
	// A real measurement is never rewritten.
	if got := measured(22 * time.Millisecond); got != 22*time.Millisecond {
		t.Fatalf("measured(22ms) = %v", got)
	}
}

// TestRTTLearnsASubTickResponse closes the loop: the value `measured` produces
// has to be one the tracker actually keeps, because Observe is what decides.
func TestRTTLearnsASubTickResponse(t *testing.T) {
	t.Parallel()
	tr := NewRTTTracker()
	a := netip.MustParseAddr("192.0.2.11")
	tr.Observe(a, measured(0))
	if !tr.Known(a) {
		t.Fatal("a response timed as zero left the destination unknown; " +
			"the adaptive response window never engages for it")
	}
	// And the window it produces is the floor, not something shorter: a
	// destination that answered fast still gets MinResponseWait.
	if got := tr.Wait(a); got != MinResponseWait {
		t.Fatalf("Wait = %v, want MinResponseWait (%v)", got, MinResponseWait)
	}
}
