package observ

import (
	"sync"
	"sync/atomic"
	"time"
)

// Event is anything the bus carries. The three concrete kinds below use only
// primitive field types on purpose: observ sits at the bottom of the import
// graph and must never import policy, flow or netstate, all of which want to
// publish to it.
type Event interface {
	Kind() string
	At() time.Time
}

// Event kinds, also used as the `kind` value in the NDJSON event log.
const (
	KindConn  = "conn"
	KindState = "state"
	KindDrift = "drift"
)

// ConnEvent is the outcome of one client connection through either front end.
type ConnEvent struct {
	Time time.Time
	// ID is unique within this process run, so a `dpb why` explanation can be
	// tied to the exact connection that produced it.
	ID uint64

	Host string // the name we dialled for, "" for an unnamed IP-literal flow
	Addr string // ip:port actually dialled
	Port int

	Scope    string // policy scope class, as a string to avoid the import
	Verdict  string // the verdict in force before the attempt
	Strategy string // the spec that ultimately carried the connection
	Source   string // where that verdict came from (cache, config, ladder)

	Rung     int // ladder index that succeeded, 0 for plain
	Attempts int
	Outcome  string // "ok", "reset", "timeout", "refused", "local-error", ...
	Failure  string // classified failure when Outcome != "ok"
	Err      string // the raw error text, already redacted where required

	BytesUp   int64
	BytesDown int64
	Duration  time.Duration
	// Escalated records whether this connection needed anything beyond plain.
	// It is the input to the drift detector.
	Escalated bool
}

func (e ConnEvent) Kind() string  { return KindConn }
func (e ConnEvent) At() time.Time { return e.Time }

// StateEvent is one step of a system-state mutation's lifecycle: begin, apply,
// verify, commit, revert. It is the live mirror of the on-disk journal.
type StateEvent struct {
	Time time.Time

	Op     string // op name, e.g. "proxy.pac", "route.capture"
	Target string // what it was applied to, e.g. "Wi-Fi", "0.0.0.0/1"
	Phase  string // "begin", "applied", "verified", "committed", "reverted", "failed"

	// Adopted marks state that already existed and that we did not create, so
	// Revert is a no-op. Deleting a VPN's route on Ctrl-C is the failure this
	// flag exists to prevent.
	Adopted bool
	// Verified records whether an independent subsystem confirmed the state,
	// not merely whether the command exited 0.
	Verified bool
	Err      string
}

func (e StateEvent) Kind() string  { return KindState }
func (e StateEvent) At() time.Time { return e.Time }

// DriftEvent fires when the escalation rate says the ISP's DPI likely changed.
type DriftEvent struct {
	Time time.Time

	Window    time.Duration
	Hosts     int     // in-scope hosts observed in the window
	Escalated int     // how many of them escalated past the persisted default
	Rate      float64 // Escalated/Hosts
	Suspected string  // human summary
	Remedy    string  // what the user should do, e.g. "run `dpb tune` (~3 min)"
}

func (e DriftEvent) Kind() string  { return KindDrift }
func (e DriftEvent) At() time.Time { return e.Time }

// DefaultSubBuffer is the per-subscriber queue depth. It is small on purpose:
// a subscriber that falls this far behind is not going to catch up, and the
// right answer is to drop and say so, not to grow without bound.
const DefaultSubBuffer = 256

// Sub is a bus subscription. Read C until it is closed.
type Sub struct {
	// C delivers events. Unsubscribe closes it.
	C <-chan Event

	name    string
	ch      chan Event
	dropped atomic.Uint64
}

// Name is the subscriber label, used in diagnostics about drops.
func (s *Sub) Name() string { return s.name }

// Dropped is how many events this subscriber missed because it was too slow.
func (s *Sub) Dropped() uint64 { return s.dropped.Load() }

// Bus is an in-process fan-out of events to subscribers.
//
// Publish NEVER blocks. A per-connection goroutine publishing an outcome must
// not be able to stall because `dpb status --watch` stopped reading, so a full
// subscriber queue drops the event and increments a counter that `dpb status`
// surfaces. Losing a diagnostic is acceptable; stalling a connection is not.
type Bus struct {
	mu     sync.RWMutex
	subs   map[*Sub]struct{}
	closed bool

	published atomic.Uint64
	dropped   atomic.Uint64
}

// NewBus returns an empty bus.
func NewBus() *Bus { return &Bus{subs: make(map[*Sub]struct{})} }

// Subscribe registers a subscriber. buffer <= 0 uses DefaultSubBuffer.
// Subscribing to a closed bus returns a subscription whose channel is already
// closed, so a late subscriber sees EOF rather than blocking forever.
func (b *Bus) Subscribe(name string, buffer int) *Sub {
	if buffer <= 0 {
		buffer = DefaultSubBuffer
	}
	ch := make(chan Event, buffer)
	s := &Sub{C: ch, name: name, ch: ch}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		close(ch)
		return s
	}
	b.subs[s] = struct{}{}
	return s
}

// Unsubscribe removes s and closes its channel. It is idempotent.
func (b *Bus) Unsubscribe(s *Sub) {
	if s == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subs[s]; !ok {
		return
	}
	delete(b.subs, s)
	close(s.ch)
}

// Publish delivers ev to every subscriber that has room, and drops it for
// those that do not.
func (b *Bus) Publish(ev Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return
	}
	b.published.Add(1)
	for s := range b.subs {
		select {
		case s.ch <- ev:
		default:
			s.dropped.Add(1)
			b.dropped.Add(1)
		}
	}
}

// Published is the number of Publish calls accepted.
func (b *Bus) Published() uint64 { return b.published.Load() }

// Dropped is the total number of per-subscriber deliveries dropped. A non-zero
// value means some diagnostic view is incomplete, never that traffic was lost.
func (b *Bus) Dropped() uint64 { return b.dropped.Load() }

// Subscribers is the current subscription count.
func (b *Bus) Subscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

// Close closes every subscription. Publish after Close is a no-op, because
// teardown races with in-flight connection goroutines by construction.
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for s := range b.subs {
		delete(b.subs, s)
		close(s.ch)
	}
}
