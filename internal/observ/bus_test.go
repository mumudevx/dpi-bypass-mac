package observ

import (
	"sync"
	"testing"
	"time"
)

func TestBusFansOutToEverySubscriber(t *testing.T) {
	b := NewBus()
	defer b.Close()

	a := b.Subscribe("status", 4)
	c := b.Subscribe("eventlog", 4)
	if b.Subscribers() != 2 {
		t.Fatalf("Subscribers = %d, want 2", b.Subscribers())
	}

	ev := ConnEvent{Time: time.Unix(1, 0), Host: "discord.com", Outcome: "ok", Rung: 1}
	b.Publish(ev)

	for _, s := range []*Sub{a, c} {
		select {
		case got := <-s.C:
			ce, ok := got.(ConnEvent)
			if !ok {
				t.Fatalf("%s got %T, want ConnEvent", s.Name(), got)
			}
			if ce.Host != "discord.com" || ce.Kind() != KindConn {
				t.Errorf("%s got %+v", s.Name(), ce)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s never received the event", s.Name())
		}
	}
	if b.Published() != 1 || b.Dropped() != 0 {
		t.Errorf("Published=%d Dropped=%d, want 1/0", b.Published(), b.Dropped())
	}
}

// Publish must never block. A connection goroutine publishing its outcome
// cannot be allowed to stall because `dpb status --watch` stopped reading.
func TestPublishDropsRatherThanBlocking(t *testing.T) {
	b := NewBus()
	defer b.Close()

	slow := b.Subscribe("slow", 1)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			b.Publish(StateEvent{Time: time.Unix(int64(i), 0), Op: "route.capture", Phase: "applied"})
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a full subscriber queue")
	}

	if slow.Dropped() == 0 {
		t.Error("a full subscriber must record drops, not silently lose count")
	}
	if b.Dropped() != slow.Dropped() {
		t.Errorf("bus drops %d != subscriber drops %d", b.Dropped(), slow.Dropped())
	}
	if b.Published() != 100 {
		t.Errorf("Published = %d, want 100", b.Published())
	}
}

func TestUnsubscribeClosesChannelAndIsIdempotent(t *testing.T) {
	b := NewBus()
	defer b.Close()

	s := b.Subscribe("one", 2)
	b.Unsubscribe(s)
	b.Unsubscribe(s)
	b.Unsubscribe(nil)

	if _, open := <-s.C; open {
		t.Error("Unsubscribe must close the channel")
	}
	if b.Subscribers() != 0 {
		t.Errorf("Subscribers = %d after Unsubscribe", b.Subscribers())
	}
	// Publishing to a bus with no subscribers must not panic on the closed chan.
	b.Publish(DriftEvent{Time: time.Unix(2, 0), Rate: 0.7})
}

func TestCloseClosesEverySubscriptionAndSilencesPublish(t *testing.T) {
	b := NewBus()
	s := b.Subscribe("watch", 2)

	b.Close()
	b.Close() // idempotent

	if _, open := <-s.C; open {
		t.Error("Close must close every subscription")
	}
	b.Publish(ConnEvent{})
	if b.Published() != 0 {
		t.Errorf("Publish after Close must be a no-op, Published=%d", b.Published())
	}

	// A subscriber that arrives after Close must see EOF, not block forever.
	late := b.Subscribe("late", 1)
	select {
	case _, open := <-late.C:
		if open {
			t.Error("late subscriber channel should be closed")
		}
	case <-time.After(time.Second):
		t.Fatal("late subscriber blocked on a closed bus")
	}
}

func TestSubscribeDefaultBuffer(t *testing.T) {
	b := NewBus()
	defer b.Close()
	s := b.Subscribe("default", 0)
	if got := cap(s.ch); got != DefaultSubBuffer {
		t.Errorf("buffer = %d, want %d", got, DefaultSubBuffer)
	}
}

func TestEventKindsAndTimes(t *testing.T) {
	now := time.Unix(1756800000, 0)
	cases := []struct {
		ev   Event
		kind string
	}{
		{ConnEvent{Time: now}, KindConn},
		{StateEvent{Time: now}, KindState},
		{DriftEvent{Time: now}, KindDrift},
	}
	for _, tc := range cases {
		if tc.ev.Kind() != tc.kind {
			t.Errorf("Kind() = %q, want %q", tc.ev.Kind(), tc.kind)
		}
		if !tc.ev.At().Equal(now) {
			t.Errorf("At() = %v, want %v", tc.ev.At(), now)
		}
	}
}

func TestBusConcurrentPublishAndSubscribe(t *testing.T) {
	b := NewBus()
	defer b.Close()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := b.Subscribe("s", 8)
			for j := 0; j < 20; j++ {
				b.Publish(ConnEvent{Time: time.Unix(int64(j), 0), ID: uint64(i)})
			}
			b.Unsubscribe(s)
		}(i)
	}
	wg.Wait()

	if b.Published() != 160 {
		t.Errorf("Published = %d, want 160", b.Published())
	}
}
