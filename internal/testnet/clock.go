package testnet

import (
	"sort"
	"sync"
	"time"
)

// Clock is a deterministic clock for deadline, TTL and backoff tests.
//
// Real time in a test is a race dressed up as a delay. The ladder's escalation
// window, the resolver's negative-cache TTL and the verdict store's expiry are
// all decided by comparisons against a clock; driven by time.Now they can only
// be tested by sleeping, which makes the suite slow and flaky in the same stroke.
// Advance moves the clock and fires every waiter synchronously, so a test states
// exactly when things happen.
type Clock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []*waiter
	seq     uint64
}

type waiter struct {
	at      time.Time
	seq     uint64
	ch      chan time.Time
	fn      func()
	stopped bool
	clock   *Clock
}

// NewClock returns a clock reading start. A zero start is replaced with a fixed,
// arbitrary, obviously-not-now instant so a test that prints a timestamp gets a
// stable one.
func NewClock(start time.Time) *Clock {
	if start.IsZero() {
		start = time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	}
	return &Clock{now: start}
}

// Now returns the current simulated time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Set moves the clock to t. Waiters due at or before t fire, in due order.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t
	due := c.dueLocked(t)
	c.mu.Unlock()
	fire(due, t)
}

// Advance moves the clock forward by d.
func (c *Clock) Advance(d time.Duration) { c.Set(c.Now().Add(d)) }

// dueLocked removes and returns the waiters due at or before t, in due order.
func (c *Clock) dueLocked(t time.Time) []*waiter {
	var due []*waiter
	keep := c.waiters[:0]
	for _, w := range c.waiters {
		if !w.stopped && !w.at.After(t) {
			due = append(due, w)
			continue
		}
		keep = append(keep, w)
	}
	c.waiters = keep
	sort.SliceStable(due, func(i, j int) bool {
		if due[i].at.Equal(due[j].at) {
			return due[i].seq < due[j].seq
		}
		return due[i].at.Before(due[j].at)
	})
	return due
}

// fire delivers to due waiters. Callbacks run on the goroutine that called
// Advance, after the clock's lock is released, so a callback may schedule more
// work without deadlocking.
func fire(due []*waiter, t time.Time) {
	for _, w := range due {
		if w.ch != nil {
			select {
			case w.ch <- t:
			default: // buffered, cap 1: a second fire on an undrained timer is dropped
			}
		}
		if w.fn != nil {
			w.fn()
		}
	}
}

func (c *Clock) add(d time.Duration, ch chan time.Time, fn func()) *waiter {
	c.mu.Lock()
	c.seq++
	w := &waiter{at: c.now.Add(d), seq: c.seq, ch: ch, fn: fn, clock: c}
	// A non-positive duration is already due; fire it without waiting for the
	// next Advance, exactly as time.After does.
	if d <= 0 {
		now := c.now
		c.mu.Unlock()
		fire([]*waiter{w}, now)
		return w
	}
	c.waiters = append(c.waiters, w)
	c.mu.Unlock()
	return w
}

// After returns a channel that receives once the clock has advanced by d.
func (c *Clock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.add(d, ch, nil)
	return ch
}

// AfterFunc schedules fn to run once the clock has advanced by d.
func (c *Clock) AfterFunc(d time.Duration, fn func()) *Timer {
	return &Timer{w: c.add(d, nil, fn)}
}

// NewTimer returns a timer whose channel fires after d.
func (c *Clock) NewTimer(d time.Duration) *Timer {
	ch := make(chan time.Time, 1)
	return &Timer{C: ch, w: c.add(d, ch, nil)}
}

// Sleep blocks until the clock has advanced by d. It must not be called from the
// goroutine that advances the clock.
func (c *Clock) Sleep(d time.Duration) { <-c.After(d) }

// Waiters is the number of timers still pending. A test asserts it returns to
// zero to prove the code under test is not leaking timers.
func (c *Clock) Waiters() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, w := range c.waiters {
		if !w.stopped {
			n++
		}
	}
	return n
}

// Timer is a pending Clock event.
type Timer struct {
	C <-chan time.Time
	w *waiter
}

// Stop cancels the timer, reporting whether it was still pending.
func (t *Timer) Stop() bool {
	c := t.w.clock
	c.mu.Lock()
	defer c.mu.Unlock()
	if t.w.stopped {
		return false
	}
	for i, w := range c.waiters {
		if w == t.w {
			c.waiters = append(c.waiters[:i], c.waiters[i+1:]...)
			t.w.stopped = true
			return true
		}
	}
	return false
}
