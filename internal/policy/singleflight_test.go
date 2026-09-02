package policy

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The plan's acceptance criterion: six concurrent Do calls on one key collapse
// into one invocation. That is the six connections a browser opens to a host,
// and without this each one walks the ladder and each one gets its own chance
// to escalate a host that plain would have served.
func TestSingleflightCollapsesConcurrentCalls(t *testing.T) {
	s := NewSingleflight()
	var calls atomic.Int32
	release := make(chan struct{})
	entered := make(chan struct{}, 6)

	var wg sync.WaitGroup
	results := make([]Verdict, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := s.Do("wifi-abc|discord.com", func() (Verdict, error) {
				calls.Add(1)
				entered <- struct{}{}
				<-release
				return Verdict{Class: ScopeDesync, Spec: "tlsfrag:pos=snimid"}, nil
			})
			if err != nil {
				t.Errorf("Do: %v", err)
			}
			results[i] = v
		}(i)
	}

	// Wait for the leader to be inside fn AND for the other five to have
	// attached to its call. Releasing earlier would let a straggler start its
	// own walk after the leader finished, which is exactly the behaviour this
	// test exists to forbid.
	<-entered
	waitForWaiters(t, s, "wifi-abc|discord.com", 5)
	close(release)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("the ladder ran %d times, want 1", got)
	}
	for i, v := range results {
		if v.Spec != "tlsfrag:pos=snimid" {
			t.Errorf("caller %d got %+v, want the shared result", i, v)
		}
	}
	if s.InFlight() != 0 {
		t.Errorf("InFlight = %d after completion, want 0", s.InFlight())
	}
}

func TestSingleflightDistinctKeysRunSeparately(t *testing.T) {
	s := NewSingleflight()
	var calls atomic.Int32
	for _, key := range []string{"a|discord.com", "b|discord.com", "a|isbank.com.tr"} {
		if _, err := s.Do(key, func() (Verdict, error) {
			calls.Add(1)
			return Verdict{}, nil
		}); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("calls = %d, want 3 — distinct keys must not collapse", got)
	}
}

func TestSingleflightPropagatesErrors(t *testing.T) {
	s := NewSingleflight()
	want := errors.New("ladder exhausted")
	if _, err := s.Do("k", func() (Verdict, error) { return Verdict{}, want }); !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
	// A failed call must not be cached: the next connection walks again.
	var calls int
	if _, err := s.Do("k", func() (Verdict, error) { calls++; return Verdict{}, nil }); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if calls != 1 {
		t.Error("a failed call was cached")
	}
	if _, err := s.Do("k", nil); err == nil {
		t.Error("Do accepted a nil function")
	}
}

// A panic in one ladder walk must kill that connection and nothing else. Go
// runs only the panicking goroutine's defers, so without the recover here
// every other connection to the same host would block forever.
func TestSingleflightPanicDoesNotWedgeWaiters(t *testing.T) {
	s := NewSingleflight()
	started := make(chan struct{})
	release := make(chan struct{})

	go func() {
		defer func() { _ = recover() }()
		_, _ = s.Do("k", func() (Verdict, error) {
			close(started)
			<-release
			panic("boom")
		})
	}()
	<-started

	waiter := make(chan error, 1)
	go func() {
		_, err := s.Do("k", func() (Verdict, error) { return Verdict{}, nil })
		waiter <- err
	}()
	waitForWaiters(t, s, "k", 1)
	close(release)

	select {
	case err := <-waiter:
		if err == nil {
			t.Error("the waiter got a success from a panicking call")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the waiter was wedged by a panic in the leader")
	}

	// The key must be released, so the next caller runs cleanly.
	if _, err := s.Do("k", func() (Verdict, error) { return Verdict{Spec: "ok"}, nil }); err != nil {
		t.Errorf("the key stayed poisoned: %v", err)
	}
}

func TestSingleflightZeroValueIsUsable(t *testing.T) {
	var s Singleflight
	if _, err := s.Do("k", func() (Verdict, error) { return Verdict{Spec: "x"}, nil }); err != nil {
		t.Fatalf("Do on a zero Singleflight: %v", err)
	}
}

func TestKeyIsPerNetworkAndNormalised(t *testing.T) {
	a, b := netA(), netB()
	if Key(a, "Discord.com.") != Key(a, "discord.com") {
		t.Error("Key did not normalise the host")
	}
	if Key(a, "discord.com") == Key(b, "discord.com") {
		t.Error("Key collapsed two networks — a verdict would leak across lines")
	}
}

// waitForWaiters blocks until n callers have attached to the in-flight call
// for key. It reads the group's own bookkeeping under its lock, which is the
// only way to observe the attachment rather than guess at it with a sleep.
func waitForWaiters(t *testing.T, s *Singleflight, key string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		c, ok := s.calls[key]
		dups := 0
		if ok {
			dups = c.dups
		}
		s.mu.Unlock()
		if ok && dups >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d callers attached to the in-flight call for %q", dups, n, key)
		}
		time.Sleep(time.Millisecond)
	}
}
