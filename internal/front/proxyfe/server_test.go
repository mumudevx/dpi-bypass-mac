package proxyfe_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/emit"
	"github.com/mumudevx/dpb/internal/flow"
	"github.com/mumudevx/dpb/internal/front/proxyfe"
	"github.com/mumudevx/dpb/internal/observ"
	"github.com/mumudevx/dpb/internal/policy"
	"github.com/mumudevx/dpb/internal/testcensor"
)

func TestNewRefusesIncompleteWiring(t *testing.T) {
	t.Parallel()
	scope := policy.NewEngine(policy.EngineOptions{})
	if _, err := proxyfe.New(proxyfe.Options{Scope: scope}); !errors.Is(err, proxyfe.ErrNoLadder) {
		t.Fatalf("err = %v, want ErrNoLadder", err)
	}
	if _, err := proxyfe.New(proxyfe.Options{Ladder: &flow.LadderRunner{}}); !errors.Is(err, proxyfe.ErrNoScope) {
		t.Fatalf("err = %v, want ErrNoScope", err)
	}
	// No dialer anywhere: refusing at construction is the only way this never
	// becomes a connection that silently relays everything unjudged.
	if _, err := proxyfe.New(proxyfe.Options{Scope: scope, Ladder: &flow.LadderRunner{}}); err == nil {
		t.Fatal("a server with no dialer was constructed")
	}
}

func TestNewTakesTheDialerFromTheLadderWhenNotGiven(t *testing.T) {
	t.Parallel()
	d := newMapDialer()
	srv, err := proxyfe.New(proxyfe.Options{
		Scope:  policy.NewEngine(policy.EngineOptions{}),
		Ladder: &flow.LadderRunner{Dial: d, Sender: &emit.Sender{}},
	})
	if err != nil || srv == nil {
		t.Fatalf("New: %v", err)
	}
}

// Cancelling Serve's context closes the listener — a blocking Accept has no
// other way to be interrupted — and Serve returns nil, because a cancelled
// context is a normal shutdown rather than an error.
func TestServeReturnsWhenItsContextIsCancelled(t *testing.T) {
	t.Parallel()
	srv, err := proxyfe.New(proxyfe.Options{
		Scope:  policy.NewEngine(policy.EngineOptions{}),
		Ladder: &flow.LadderRunner{Dial: newMapDialer(), Sender: &emit.Sender{}},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve = %v, want nil on cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancellation")
	}
	if _, err := net.Dial("tcp", ln.Addr().String()); err == nil {
		t.Fatal("the listener is still accepting after Serve returned")
	}
}

// A wedged relay must not hold up the revert of the system proxy settings: the
// process is about to exit and take the socket with it, whereas an unreverted
// proxy setting outlives us.
func TestServeGivesUpOnAWedgedRelayAfterTheDrainGrace(t *testing.T) {
	t.Parallel()
	o := newGreetOrigin(t, "220 ready\r\n")
	d := newMapDialer()
	d.add("mail.example.com", o.ln.Addr())

	srv, err := proxyfe.New(proxyfe.Options{
		Scope:      policy.NewEngine(policy.EngineOptions{InspectPorts: []int{443}}),
		Ladder:     &flow.LadderRunner{Dial: d, Sender: &emit.Sender{}, RTT: flow.NewRTTTracker()},
		Dial:       d,
		RelayIdle:  time.Hour,
		DrainGrace: 200 * time.Millisecond,
		Logf:       t.Logf,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "CONNECT mail.example.com:25 HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 12)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read status: %v", err)
	}

	start := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve waited past the drain grace for a live relay")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("shutdown took %v, want roughly the drain grace", d)
	}
}

func TestMaxConnsRefusesRatherThanQueues(t *testing.T) {
	t.Parallel()
	o := newGreetOrigin(t, "220 ready\r\n")
	d := newMapDialer()
	d.add("mail.example.com", o.ln.Addr())
	h := serveTest(t, wiring{dialer: d, maxConns: 1, inspect: []int{443}})

	first := h.dialProxy(t)
	if _, err := io.WriteString(first, "CONNECT mail.example.com:25 HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 12)
	if _, err := io.ReadFull(first, buf); err != nil {
		t.Fatalf("read status: %v", err)
	}

	second, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer second.Close()
	if err := second.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	// Refused means closed, not queued: a queued connection makes the browser
	// wait on something nothing is going to serve.
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("the refused connection was served")
	}
	if st := h.srv.Stats(); st.Rejected != 1 {
		t.Fatalf("stats = %+v, want one rejection", st)
	}
}

// `dpb off` and the captive-portal suspend both work by making the scope answer
// ScopeDirect for everything. Nothing may be judged, nothing escalated, and the
// listener keeps working so the system settings stay valid.
func TestSuspendedScopeRelaysEverythingDirect(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.TT2026(), "discord.com")
	d := newMapDialer()
	d.add("discord.com", l.addr())

	var off atomic.Bool
	off.Store(true)
	h := serveTest(t, wiring{dialer: d, suspended: off.Load, store: openStore(t)})

	tunnel, status := h.connect(t, "discord.com:443")
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("status = %q", status)
	}
	// The censor resets it, because nothing is being bypassed. That is the
	// point: suspended means out of the way.
	if _, err := tlsThrough(t, tunnel, "discord.com", l.origin.ClientConfig("discord.com")); err == nil {
		t.Fatal("a suspended proxy bypassed the censor")
	}
	if got := len(d.calls()); got != 1 {
		t.Fatalf("%d dials while suspended, want exactly 1: the ladder was walked", got)
	}
}

// The event stream is what `dpb why`, `dpb status` and the drift detector read.
// A flow that produced no event is a flow nobody can debug.
func TestEveryFlowPublishesAConnEvent(t *testing.T) {
	t.Parallel()
	a := newHTTPOrigin(t, "alpha")
	d := newMapDialer()
	d.add("a.test", a.addr())

	events := make(chan observ.ConnEvent, 8)
	srv, err := proxyfe.New(proxyfe.Options{
		Scope: policy.NewEngine(policy.EngineOptions{InspectPorts: []int{80}, Ladder: []string{""}}),
		Ladder: &flow.LadderRunner{
			Dial: d, Sender: &emit.Sender{}, RTT: flow.NewRTTTracker(), Store: policy.NopStore(),
		},
		Dial:   d,
		OnConn: func(e observ.ConnEvent) { events <- e },
		Logf:   t.Logf,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "GET http://a.test/x HTTP/1.1\r\nHost: a.test\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(c, make([]byte, 15)); err != nil {
		t.Fatalf("read: %v", err)
	}

	select {
	case ev := <-events:
		if ev.Host != "a.test" || ev.Port != 80 {
			t.Fatalf("event = %+v", ev)
		}
		if ev.Outcome != "ok" {
			t.Fatalf("outcome = %q", ev.Outcome)
		}
		if ev.BytesUp == 0 || ev.BytesDown == 0 {
			t.Fatalf("event carries no byte counts: %+v", ev)
		}
		if ev.ID == 0 {
			t.Fatal("event has no id")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no ConnEvent was published")
	}
}

// A client that connects and says nothing is ordinary — browsers pre-open
// connections they never use — and must not produce noise or a stuck goroutine.
func TestSilentClientIsDroppedQuietly(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{dialer: newMapDialer()})
	c := h.dialProxy(t)
	_ = c.Close()
	if st := h.srv.Stats(); st.Failed != 0 {
		t.Fatalf("a silent client was counted as a failure: %+v", st)
	}
}
