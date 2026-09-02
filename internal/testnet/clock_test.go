package testnet

import (
	"testing"
	"time"
)

func TestClockAdvance(t *testing.T) {
	c := NewClock(time.Time{})
	start := c.Now()
	if start.IsZero() {
		t.Fatal("NewClock(zero) must pick a stable non-zero instant")
	}
	c.Advance(90 * time.Second)
	if got := c.Now().Sub(start); got != 90*time.Second {
		t.Fatalf("advanced by %v", got)
	}
}

// TestClockAfterFiresOnlyWhenDue is the property that makes deadline tests
// deterministic instead of merely fast.
func TestClockAfterFiresOnlyWhenDue(t *testing.T) {
	c := NewClock(time.Time{})
	ch := c.After(250 * time.Millisecond)

	c.Advance(249 * time.Millisecond)
	select {
	case at := <-ch:
		t.Fatalf("fired early at %v", at)
	default:
	}
	if c.Waiters() != 1 {
		t.Fatalf("Waiters = %d, want 1", c.Waiters())
	}

	c.Advance(time.Millisecond)
	select {
	case at := <-ch:
		if !at.Equal(c.Now()) {
			t.Errorf("delivered %v, clock reads %v", at, c.Now())
		}
	default:
		t.Fatal("did not fire at its deadline")
	}
	if c.Waiters() != 0 {
		t.Fatalf("Waiters = %d after firing, want 0", c.Waiters())
	}
}

// TestClockFiresInDueOrder matters for the ladder, where a first-byte wait and a
// total budget can both be pending and the order decides the outcome.
func TestClockFiresInDueOrder(t *testing.T) {
	c := NewClock(time.Time{})
	var order []string
	c.AfterFunc(30*time.Millisecond, func() { order = append(order, "late") })
	c.AfterFunc(10*time.Millisecond, func() { order = append(order, "early") })
	c.AfterFunc(10*time.Millisecond, func() { order = append(order, "early-2") })

	c.Advance(time.Second)
	want := []string{"early", "early-2", "late"}
	if len(order) != len(want) {
		t.Fatalf("order = %v", order)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

// TestClockAfterFuncMayReschedule pins that a callback can schedule more work,
// which a retry loop driven by the clock needs.
func TestClockAfterFuncMayReschedule(t *testing.T) {
	c := NewClock(time.Time{})
	hits := 0
	var again func()
	again = func() {
		hits++
		if hits < 3 {
			c.AfterFunc(10*time.Millisecond, again)
		}
	}
	c.AfterFunc(10*time.Millisecond, again)

	for range 3 {
		c.Advance(10 * time.Millisecond)
	}
	if hits != 3 {
		t.Fatalf("hits = %d, want 3", hits)
	}
}

func TestClockNonPositiveDurationFiresImmediately(t *testing.T) {
	c := NewClock(time.Time{})
	select {
	case <-c.After(0):
	default:
		t.Fatal("After(0) did not fire")
	}
	select {
	case <-c.After(-time.Second):
	default:
		t.Fatal("After(-1s) did not fire")
	}
	if c.Waiters() != 0 {
		t.Fatalf("Waiters = %d", c.Waiters())
	}
}

func TestClockTimerStop(t *testing.T) {
	c := NewClock(time.Time{})
	tm := c.NewTimer(time.Second)
	if !tm.Stop() {
		t.Fatal("Stop reported the timer was not pending")
	}
	if tm.Stop() {
		t.Fatal("Stop reported a second cancellation")
	}
	c.Advance(time.Hour)
	select {
	case at := <-tm.C:
		t.Fatalf("a stopped timer fired at %v", at)
	default:
	}
	if c.Waiters() != 0 {
		t.Fatalf("Waiters = %d after Stop", c.Waiters())
	}
}

func TestClockSleepAndSet(t *testing.T) {
	c := NewClock(time.Date(2026, time.September, 2, 0, 0, 0, 0, time.UTC))
	done := make(chan struct{})
	go func() {
		c.Sleep(time.Minute)
		close(done)
	}()

	// Wait for the sleeper to register before advancing, so the test is not
	// racing the goroutine it is driving.
	for c.Waiters() == 0 {
		time.Sleep(time.Millisecond)
	}
	c.Set(c.Now().Add(time.Minute))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Sleep did not return after the clock passed its deadline")
	}
}
