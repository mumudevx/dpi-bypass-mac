package flow

import (
	"net/netip"
	"sync"
	"time"
)

// The first-response window. The ladder waits this long for the upstream's first
// byte before deciding the attempt was censored.
//
// MEASUREMENTS.md §6 measured the RST arriving ~22 ms after a plain ClientHello
// on the line this tool was built against, and a successful desynced handshake
// completing in ~23 ms. MinResponseWait is therefore ~13x the measured verdict
// latency: long enough that an ordinary origin is never mistaken for a censor,
// short enough to be invisible on the one first visit that pays it.
//
// MaxResponseWait caps the window on a slow path, because the window is also the
// worst-case added latency for a host that is simply unreachable.
const (
	MinResponseWait = 300 * time.Millisecond
	MaxResponseWait = 2 * time.Second
	// RTTFactor multiplies the smoothed round trip. Three is a headroom choice,
	// not a measurement: two would fire on ordinary jitter and more would push
	// the common case past MaxResponseWait anyway.
	RTTFactor = 3
)

// rttAlpha is the EWMA weight given to the newest sample. A sizing choice: 0.25
// converges within a handful of connections while a single slow response cannot
// move the window far.
const rttAlpha = 0.25

// rttCap bounds how many destinations are remembered. A browsing session touches
// a few hundred; the cap exists only so a long-lived process cannot grow a map
// without limit.
const rttCap = 4096

// RTTTracker keeps a per-destination smoothed round trip so the first-response
// window adapts to a satellite link or a distant origin instead of being a
// constant tuned on one Turkish DSL line.
//
// It is safe for concurrent use: every connection observes into it.
type RTTTracker struct {
	mu   sync.Mutex
	ewma map[netip.Addr]time.Duration
}

func NewRTTTracker() *RTTTracker {
	return &RTTTracker{ewma: make(map[netip.Addr]time.Duration)}
}

// Observe records how long a destination took to produce its first byte.
// Non-positive samples are ignored: a clock that went backwards must not be
// allowed to shorten the window for every later connection.
func (t *RTTTracker) Observe(a netip.Addr, d time.Duration) {
	if t == nil || d <= 0 || !a.IsValid() {
		return
	}
	a = a.Unmap()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ewma == nil {
		t.ewma = make(map[netip.Addr]time.Duration)
	}
	prev, ok := t.ewma[a]
	if !ok {
		if len(t.ewma) >= rttCap {
			t.evictLocked()
		}
		t.ewma[a] = d
		return
	}
	t.ewma[a] = time.Duration(rttAlpha*float64(d) + (1-rttAlpha)*float64(prev))
}

// evictLocked drops one arbitrary entry. Map iteration order is what makes this
// arbitrary, which is all the policy a soft cache needs: the cost of evicting
// the wrong destination is one connection judged with the default window.
func (t *RTTTracker) evictLocked() {
	for k := range t.ewma {
		delete(t.ewma, k)
		return
	}
}

// Wait is how long to wait for a's first response byte before treating silence
// as censorship: max(MinResponseWait, min(RTTFactor x ewma, MaxResponseWait)).
// An unknown destination gets MinResponseWait.
func (t *RTTTracker) Wait(a netip.Addr) time.Duration {
	d := MinResponseWait
	if t != nil && a.IsValid() {
		t.mu.Lock()
		prev, ok := t.ewma[a.Unmap()]
		t.mu.Unlock()
		if ok {
			d = prev * RTTFactor
		}
	}
	if d > MaxResponseWait {
		d = MaxResponseWait
	}
	if d < MinResponseWait {
		d = MinResponseWait
	}
	return d
}

// Known reports whether this destination has ever answered, which is what makes
// silence from it evidence rather than a guess. The ladder needs the difference:
// see the timeout policy on LadderRunner.attempt.
func (t *RTTTracker) Known(a netip.Addr) bool {
	if t == nil || !a.IsValid() {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.ewma[a.Unmap()]
	return ok
}

// Len reports how many destinations are remembered. It backs `dpb status` and
// makes the eviction bound observable in a test.
func (t *RTTTracker) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.ewma)
}
