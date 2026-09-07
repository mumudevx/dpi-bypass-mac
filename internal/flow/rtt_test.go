package flow_test

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/flow"
)

func TestRTTWaitBounds(t *testing.T) {
	t.Parallel()
	a := netip.MustParseAddr("192.0.2.1")
	tr := flow.NewRTTTracker()

	if got := tr.Wait(a); got != flow.MinResponseWait {
		t.Fatalf("unknown destination waits %s, want the %s floor", got, flow.MinResponseWait)
	}
	if tr.Known(a) {
		t.Fatal("an unobserved destination must not be Known")
	}

	// The measured line: ~22 ms to a verdict (MEASUREMENTS.md §6). Three times
	// that is still under the floor, so the floor governs and gives ~13x
	// headroom over the measured RST latency.
	tr.Observe(a, 22*time.Millisecond)
	if !tr.Known(a) {
		t.Fatal("an observed destination must be Known")
	}
	if got := tr.Wait(a); got != flow.MinResponseWait {
		t.Fatalf("Wait after a 22ms sample = %s, want the %s floor", got, flow.MinResponseWait)
	}

	slow := netip.MustParseAddr("192.0.2.2")
	tr.Observe(slow, 5*time.Second)
	if got := tr.Wait(slow); got != flow.MaxResponseWait {
		t.Fatalf("Wait for a 5s destination = %s, want the %s ceiling", got, flow.MaxResponseWait)
	}

	mid := netip.MustParseAddr("192.0.2.3")
	tr.Observe(mid, 200*time.Millisecond)
	if got, want := tr.Wait(mid), 600*time.Millisecond; got != want {
		t.Fatalf("Wait for a 200ms destination = %s, want %s (3x the smoothed RTT)", got, want)
	}
}

func TestRTTSmooths(t *testing.T) {
	t.Parallel()
	a := netip.MustParseAddr("192.0.2.4")
	tr := flow.NewRTTTracker()
	tr.Observe(a, 200*time.Millisecond)
	// One outlier must not move the window to the outlier.
	tr.Observe(a, 2*time.Second)
	got := tr.Wait(a)
	if got >= 2*time.Second || got <= 600*time.Millisecond {
		t.Fatalf("Wait after 200ms then 2s = %s; a single outlier must move the EWMA, not define it", got)
	}
}

func TestRTTIgnoresNonsense(t *testing.T) {
	t.Parallel()
	tr := flow.NewRTTTracker()
	a := netip.MustParseAddr("192.0.2.5")
	tr.Observe(a, -time.Second) // a clock that went backwards
	tr.Observe(netip.Addr{}, time.Second)
	if tr.Len() != 0 {
		t.Fatalf("tracker holds %d entries, want 0", tr.Len())
	}
	if tr.Known(a) {
		t.Fatal("a negative sample must not register the destination")
	}
}

func TestRTTNilReceiverIsUsable(t *testing.T) {
	t.Parallel()
	var tr *flow.RTTTracker
	a := netip.MustParseAddr("192.0.2.6")
	tr.Observe(a, time.Second) // must not panic
	if got := tr.Wait(a); got != flow.MinResponseWait {
		t.Fatalf("nil tracker Wait = %s, want the floor", got)
	}
	if tr.Known(a) || tr.Len() != 0 {
		t.Fatal("a nil tracker knows nothing")
	}
}

func TestRTTIsConcurrencySafe(t *testing.T) {
	t.Parallel()
	tr := flow.NewRTTTracker()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
			for j := 0; j < 200; j++ {
				tr.Observe(a, time.Duration(j)*time.Millisecond)
				_ = tr.Wait(a)
				_ = tr.Known(a)
			}
		}(i)
	}
	wg.Wait()
	if tr.Len() == 0 {
		t.Fatal("nothing was recorded")
	}
}

// TestRTTIsBounded: a long-lived process must not grow the map without limit.
func TestRTTIsBounded(t *testing.T) {
	t.Parallel()
	tr := flow.NewRTTTracker()
	for i := 0; i < 5000; i++ {
		a := netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 1})
		tr.Observe(a, 10*time.Millisecond)
	}
	if tr.Len() > 4096 {
		t.Fatalf("tracker holds %d entries, want it capped", tr.Len())
	}
}

// TestRTTUnmapsV4In6 so the same destination reached over a mapped address is
// the same destination.
func TestRTTUnmapsV4In6(t *testing.T) {
	t.Parallel()
	tr := flow.NewRTTTracker()
	v4 := netip.MustParseAddr("192.0.2.7")
	mapped := netip.AddrFrom16(v4.As16())
	tr.Observe(mapped, 300*time.Millisecond)
	if !tr.Known(v4) {
		t.Fatal("a v4-in-v6 sample must register under the v4 address")
	}
}
