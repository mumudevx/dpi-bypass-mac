package emit

import (
	"sync"
	"time"
)

// DefaultSmallWriteRate and DefaultSmallWriteBurst are the shipped governor
// settings. They are UNMEASURED and labelled as such everywhere they appear:
// DOSSIER GT13 establishes that high-volume small writes trip the XNU
// if_sndbyte_unsent assertion but quantifies no threshold, and no public report
// does either.
//
// The structural justification for shipping a guard anyway: the primary emitter
// (tlsfrag) emits exactly ONE write, so it never reaches the governor at all.
// Only ladder rungs 3-5 (chunk, oob) produce multi-write plans, and they are
// reached only after tlsfrag has already failed. So the cap costs nothing on the
// path that matters and bounds the path that can panic a kernel.
const (
	DefaultSmallWriteRate  = 512
	DefaultSmallWriteBurst = 64
)

type tokenGovernor struct {
	rate  float64 // writes per second; <= 0 means unlimited
	burst float64
	now   func() time.Time

	mu     sync.Mutex
	tokens float64
	last   time.Time
	stats  GovernorStats
}

// NewGovernor returns a process-wide token bucket over plan writes.
//
// perSecond <= 0 disables governing entirely (every write is granted), which is
// what `--small-write-rate 0` must mean: an escape hatch for a user who would
// rather risk the Apple defect than lose a rung. burst <= 0 defaults to
// perSecond, so a one-second stall is always absorbable.
func NewGovernor(perSecond, burst int) Governor {
	return newGovernor(perSecond, burst, time.Now)
}

func newGovernor(perSecond, burst int, now func() time.Time) *tokenGovernor {
	if now == nil {
		now = time.Now
	}
	if burst <= 0 {
		burst = perSecond
	}
	g := &tokenGovernor{
		rate:  float64(perSecond),
		burst: float64(burst),
		now:   now,
		last:  now(),
	}
	g.tokens = g.burst
	return g
}

func (g *tokenGovernor) Reserve(n int) int {
	if n <= 0 {
		return 0
	}
	if g.rate <= 0 {
		g.mu.Lock()
		g.stats.Granted += uint64(n)
		g.mu.Unlock()
		return n
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	if elapsed := now.Sub(g.last); elapsed > 0 {
		g.tokens += elapsed.Seconds() * g.rate
		if g.tokens > g.burst {
			g.tokens = g.burst
		}
		g.last = now
	}

	granted := n
	if avail := int(g.tokens); avail < n {
		granted = avail
	}
	// A plan with bytes to send must always be able to send them; the floor of
	// one write is what makes this a coalescer rather than a blocker. The token
	// is still spent, so the bucket goes into debt and a flood of simultaneous
	// connections cannot each buy a fresh burst — the debt is repaid out of the
	// next refill, up to the burst ceiling.
	if granted < 1 {
		granted = 1
	}
	g.tokens -= float64(granted)

	g.stats.Granted += uint64(granted)
	g.stats.Coalesced += uint64(n - granted)
	return granted
}

func (g *tokenGovernor) Stats() GovernorStats {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.stats
}
