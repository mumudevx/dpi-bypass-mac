package policy

import (
	"fmt"
	"sync"
)

// Singleflight collapses the parallel connections a browser opens to one host
// so the ladder is walked once per (network, host) rather than six times.
//
// It matters for more than efficiency. Every ladder rung that is not "plain"
// is, by MEASUREMENTS.md §5.1, a change that can break a fragile origin; six
// concurrent walks means six independent chances to escalate on a host where
// one walk would have settled on plain, and six times the retry traffic
// arriving at a middlebox at once.
type Singleflight struct {
	mu    sync.Mutex
	calls map[string]*sfCall
}

type sfCall struct {
	done chan struct{}
	v    Verdict
	err  error
	// dups counts the callers that waited on this call rather than running fn.
	dups int
}

// NewSingleflight returns an empty group.
func NewSingleflight() *Singleflight {
	return &Singleflight{calls: make(map[string]*sfCall)}
}

// Do runs fn for key, or waits for the in-flight call with the same key and
// returns its result.
//
// The key is expected to be (NetworkID, host): a verdict learned on one
// network says nothing about another, so collapsing across networks would be
// wrong rather than merely wasteful. Use Key to build it.
func (s *Singleflight) Do(key string, fn func() (Verdict, error)) (Verdict, error) {
	if fn == nil {
		return Verdict{}, fmt.Errorf("policy: singleflight: nil function for %q", key)
	}
	s.mu.Lock()
	if s.calls == nil {
		s.calls = make(map[string]*sfCall)
	}
	if c, ok := s.calls[key]; ok {
		c.dups++
		s.mu.Unlock()
		<-c.done
		return c.v, c.err
	}
	c := &sfCall{done: make(chan struct{})}
	s.calls[key] = c
	s.mu.Unlock()

	// A panic in fn must not wedge the waiters. Go runs only the panicking
	// goroutine's defers, so without this every other connection to the same
	// host would block on c.done for the life of the process — a single
	// crashing ladder walk would take a whole site down instead of one tab.
	defer func() {
		if r := recover(); r != nil {
			c.err = fmt.Errorf("policy: singleflight: panic in ladder for %q: %v", key, r)
			s.finish(key, c)
			panic(r)
		}
	}()

	c.v, c.err = fn()
	s.finish(key, c)
	return c.v, c.err
}

func (s *Singleflight) finish(key string, c *sfCall) {
	s.mu.Lock()
	if s.calls[key] == c {
		delete(s.calls, key)
	}
	s.mu.Unlock()
	close(c.done)
}

// InFlight reports how many keys are currently being walked. It backs
// `dpb status` and makes the collapsing behaviour observable in tests.
func (s *Singleflight) InFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// Key builds the canonical singleflight key for a (network, host) pair.
func Key(net NetworkID, host string) string {
	return net.Key() + "|" + Normalize(host)
}
