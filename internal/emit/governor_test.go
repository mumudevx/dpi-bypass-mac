package emit

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/strategy"
)

func TestGovernorGrantsFromTheBurstThenRefillsAtRate(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	g := newGovernor(100, 10, clock)

	if got := g.Reserve(4); got != 4 {
		t.Fatalf("Reserve(4) from a full burst = %d, want 4", got)
	}
	if got := g.Reserve(16); got != 6 {
		t.Fatalf("Reserve(16) with 6 tokens left = %d, want 6", got)
	}
	// Bucket is empty: the floor of one write keeps the plan emittable, and the
	// token is still spent so the bucket goes into debt.
	if got := g.Reserve(8); got != 1 {
		t.Fatalf("Reserve(8) on an empty bucket = %d, want the floor of 1", got)
	}
	if g.tokens >= 0 {
		t.Fatalf("tokens = %v, want negative: a floor grant must still be charged", g.tokens)
	}

	// +2 tokens at 100/s against a debt of 1 leaves 1: the debt is honoured
	// within the window, which is what keeps a flood of connections from each
	// buying a full burst.
	now = now.Add(20 * time.Millisecond)
	if got := g.Reserve(32); got != 1 {
		t.Fatalf("Reserve(32) after a 20ms refill against debt = %d, want 1", got)
	}

	now = now.Add(time.Second) // refills past the burst ceiling
	if got := g.Reserve(32); got != 10 {
		t.Fatalf("Reserve(32) after a long refill = %d, want the burst of 10", got)
	}

	st := g.Stats()
	if st.Granted != 4+6+1+1+10 {
		t.Fatalf("Granted = %d, want %d", st.Granted, 4+6+1+1+10)
	}
	if st.Coalesced != (16-6)+(8-1)+(32-1)+(32-10) {
		t.Fatalf("Coalesced = %d, want %d", st.Coalesced, (16-6)+(8-1)+(32-1)+(32-10))
	}
}

func TestGovernorCapsTheBucketAtBurst(t *testing.T) {
	now := time.Now()
	g := newGovernor(100, 10, func() time.Time { return now })
	now = now.Add(time.Hour)
	if got := g.Reserve(50); got != 10 {
		t.Fatalf("Reserve after an hour idle = %d, want the burst of 10", got)
	}
}

func TestGovernorZeroRateIsUngoverned(t *testing.T) {
	// `--small-write-rate 0` is the escape hatch for a user who would rather risk
	// the Apple defect than lose a ladder rung.
	g := NewGovernor(0, 0)
	if got := g.Reserve(1000); got != 1000 {
		t.Fatalf("Reserve(1000) ungoverned = %d, want 1000", got)
	}
	if got := g.Reserve(0); got != 0 {
		t.Fatalf("Reserve(0) = %d, want 0", got)
	}
	if st := g.Stats(); st.Granted != 1000 {
		t.Fatalf("Granted = %d, want 1000", st.Granted)
	}
}

func TestGovernorBurstDefaultsToRate(t *testing.T) {
	g := newGovernor(32, 0, time.Now)
	if g.burst != 32 {
		t.Fatalf("burst = %v, want it to default to the rate", g.burst)
	}
}

// TestGovernorCoalescesTwoHundredConcurrentSmallWritePlans is the guard for
// DOSSIER GT13: the XNU `assertion failed: ifp->if_sndbyte_unsent >= 0` panic is
// a pre-existing Apple defect provoked by a high VOLUME of small writes, and
// SpoofDPI #386 reproduced it from Turkey with chunk-size=1. The panic itself is
// destructive to test, so the test is of the guard: 200 concurrent one-byte-chunk
// plans must stay under the process-wide cap, must all complete, and must each
// deliver their payload intact.
func TestGovernorCoalescesTwoHundredConcurrentSmallWritePlans(t *testing.T) {
	const (
		conns = 200
		segs  = 16 // strategy.DefaultBudget().MaxSegments
	)
	gov := NewGovernor(DefaultSmallWriteRate, DefaultSmallWriteBurst)
	s := &Sender{Gov: gov}

	payload := bytes.Repeat([]byte{'x'}, segs)
	plan := strategy.Plan{Spec: "chunk:size=1", Payload: payload}
	for i := range segs {
		plan.Segments = append(plan.Segments,
			strategy.Segment{Kind: strategy.SegStream, Data: payload[i : i+1]})
	}

	fakes := make([]*fakeTransport, conns)
	errs := make([]error, conns)
	var wg sync.WaitGroup
	start := time.Now()
	for i := range conns {
		fakes[i] = newFake()
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.Send(context.Background(), fakes[i], plan)
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	total := 0
	for i, f := range fakes {
		if errs[i] != nil {
			t.Fatalf("plan %d failed: %v — the governor must coalesce, never block or error", i, errs[i])
		}
		if !bytes.Equal(f.stream(), payload) {
			t.Fatalf("plan %d delivered %q, want %q: coalescing must not touch the stream", i, f.stream(), payload)
		}
		total += f.writeCount()
	}

	// Every plan is guaranteed one write; beyond that the bucket allows the burst
	// plus whatever refilled while the test ran.
	maxWrites := conns + DefaultSmallWriteBurst + int(elapsed.Seconds()*DefaultSmallWriteRate) + 1
	if total > maxWrites {
		t.Fatalf("%d small writes in %s, cap is %d", total, elapsed, maxWrites)
	}
	if total >= conns*segs {
		t.Fatalf("%d writes: nothing was coalesced", total)
	}
	if total < conns {
		t.Fatalf("%d writes for %d plans: a plan was starved of its floor write", total, conns)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("200 plans took %s: the governor blocked instead of coalescing", elapsed)
	}

	st := gov.Stats()
	if st.Granted+st.Coalesced != conns*segs {
		t.Fatalf("governor accounted %d+%d writes, want %d", st.Granted, st.Coalesced, conns*segs)
	}
	if st.Coalesced == 0 {
		t.Fatal("Coalesced = 0: the cap never engaged")
	}
	if uint64(total) != st.Granted {
		t.Fatalf("transports saw %d writes but the governor granted %d", total, st.Granted)
	}
}
