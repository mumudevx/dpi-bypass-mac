package flow_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/flow"
)

// The lost wakeup between Pipe's cancellation and pipeDir's idle re-arm.
//
// pipeDir arms src.SetReadDeadline(now+Idle) at the top of every loop
// iteration. Pipe's ctx watcher poisons both deadlines with a past time. If the
// poisoning lands between "read returned" and "deadline re-armed", the re-arm
// overwrites it and the direction parks for the whole idle bound with the
// cancellation already delivered — Pipe waits on it, the caller's drain waits
// on Pipe, and the connection outlives the run.
//
// Observed rather than theorised: proxyfe's
// TestServeGivesUpOnAWedgedRelayAfterTheDrainGrace uses Idle = 1 h, and under
// `-race -count=200` the package timed out at 10 minutes with pipeDir in IO
// wait, Pipe in chan receive and Server.drain waiting on the WaitGroup.
//
// swallowFirstPoison reproduces that ordering deterministically: it drops the
// FIRST past deadline it is given, which is exactly what the losing interleave
// does. With the fix (Pipe re-poisons on a ticker until the directions report)
// the second poisoning lands and Pipe returns; without it, Pipe never returns
// and this test fails on its own deadline rather than hanging the package.
type swallowFirstPoison struct {
	net.Conn
	once sync.Once
}

func (c *swallowFirstPoison) SetReadDeadline(t time.Time) error {
	if !t.IsZero() && t.Before(time.Now()) {
		swallowed := false
		c.once.Do(func() { swallowed = true })
		if swallowed {
			return nil
		}
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *swallowFirstPoison) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}

func TestPipeCancelSurvivesALostDeadlinePoisoning(t *testing.T) {
	t.Parallel()
	clientA, clientB := tcpPair(t)
	upA, upB := tcpPair(t)
	// Both peers stay silent and open, so nothing but the cancellation can end
	// the relay — which is the shape of a shutdown while a connection idles.
	_ = clientB
	_ = upB

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		// BOTH sides swallow their first poisoning: a single direction losing
		// the race is rescued by the other one failing and forcing a second
		// unblock, so the hang needs the interleave to be lost on both — which
		// is what a loaded machine cancelling a wholly idle relay produces.
		done <- flow.Pipe(ctx, &swallowFirstPoison{Conn: clientA}, &swallowFirstPoison{Conn: upA}, flow.PipeOpts{
			Idle:      time.Hour,
			HalfClose: true,
			Logf:      t.Logf,
		})
	}()

	// Let both directions reach their blocking read before cancelling, so the
	// poisoning has something to be lost against.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pipe did not return within 5s of cancellation: a poisoning that " +
			"lost the race with pipeDir's idle re-arm is never retried, so the " +
			"relay parks for the whole idle bound after shutdown")
	}
}

// TestPipeForcedUnblockSurvivesALostDeadlinePoisoning is the same race on the
// other path. When one direction ends and half-close was not asked for, Pipe
// unblocks the survivor rather than waiting out its idle bound — and that
// poisoning can be lost to pipeDir's re-arm exactly as the cancellation one
// can, which parks a relay whose peer has already gone away.
func TestPipeForcedUnblockSurvivesALostDeadlinePoisoning(t *testing.T) {
	t.Parallel()
	clientA, clientB := tcpPair(t)
	upA, _ := tcpPair(t)

	done := make(chan error, 1)
	go func() {
		done <- flow.Pipe(context.Background(), clientA, &swallowFirstPoison{Conn: upA}, flow.PipeOpts{
			Idle: time.Hour,
			// No half-close: the first direction to end tears the relay down,
			// which is what makes Pipe force the survivor.
			HalfClose: false,
			Logf:      t.Logf,
		})
	}()

	time.Sleep(50 * time.Millisecond)
	// The client goes away: its direction ends, and the upstream direction is
	// then blocked on a read nothing will ever satisfy.
	_ = clientB.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pipe did not return within 5s of one direction ending: the forced " +
			"unblock lost the race with pipeDir's idle re-arm and was never retried")
	}
}
