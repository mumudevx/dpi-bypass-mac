package flow

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ErrIdle is returned when neither direction moved a byte for PipeOpts.Idle.
var ErrIdle = errors.New("flow: relay idle timeout")

// ErrRelayPanic is what Pipe returns when one of its directions panicked. The
// panic itself is recovered and reported by flow.Safe; this is how the surviving
// direction learns the connection is finished.
var ErrRelayPanic = errors.New("flow: relay goroutine panicked; the connection was closed")

// relayBuf is the per-direction copy buffer.
const relayBuf = 32 << 10

// cancelRepoison is how often a cancelled relay re-poisons its deadlines. It
// bounds the lost-wakeup window described in Pipe: short enough that a
// cancelled relay is gone well inside the 10 s teardown budget, long enough
// that it is one syscall per direction per tick and nothing more.
const cancelRepoison = 50 * time.Millisecond

// PipeOpts configures the relay.
type PipeOpts struct {
	// Idle closes the relay if neither byte moves for this long. Zero disables
	// it, which is correct only where something else owns the lifetime.
	Idle time.Duration
	// HalfClose propagates EOF as a TCP half-close instead of tearing the whole
	// connection down. A client that shuts down its write side and then waits
	// for the rest of a response — the shape `curl -T` and every SMTP DATA
	// produce — hangs without it.
	HalfClose bool
	// OnFirstByte fires as the first upstream byte is about to reach the client.
	// That instant is the commit: after it, a retry would duplicate delivered
	// bytes, so no failure past this point may be escalated.
	OnFirstByte func()
	// Logf receives the panic report if a relay goroutine dies. May be nil.
	Logf func(string, ...any)
}

// Pipe relays between a client connection and an upstream connection until both
// directions end.
//
// a is the CLIENT side and b is the UPSTREAM side. The asymmetry is real:
// OnFirstByte fires only for b to a, because the commit guard is a statement
// about bytes the client has seen.
func Pipe(ctx context.Context, a, b net.Conn, o PipeOpts) error {
	if a == nil || b == nil {
		return errors.New("flow: pipe: nil connection")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	done := make(chan error, 2)
	stop := make(chan struct{})

	if ctx.Done() != nil {
		Safe("flow.pipe.cancel", o.Logf, func() {
			select {
			case <-ctx.Done():
			case <-stop:
				return
			}
			// Unblock both reads without closing conns the caller owns — and
			// keep unblocking until the directions have reported.
			//
			// Once is not enough, and the difference is a hang. pipeDir arms
			// its idle deadline at the TOP of every loop iteration, so a
			// poisoning that lands between "read returned" and "deadline
			// re-armed" is overwritten with now+Idle, and the direction parks
			// for the whole idle bound with the cancellation already delivered.
			// Reproduced by running proxyfe's own
			// TestServeGivesUpOnAWedgedRelayAfterTheDrainGrace (Idle = 1 h)
			// under -race -count=200: the package times out at 10 minutes with
			// pipeDir in IO wait and Pipe waiting on it. Re-poisoning on a
			// ticker closes the window for good; it costs one setsockopt per
			// tick per cancelled relay, and only after cancellation.
			repoison(stop, a, b)
		})
	}

	// Client to upstream.
	Safe("flow.pipe.up", o.Logf, func() {
		// The result is reported from a defer so that a panic — which
		// flow.Safe recovers one frame above — still releases the aggregator.
		// Without it a panicking relay goroutine would wedge Pipe forever and
		// leak both connections, which is exactly the failure mode Safe exists
		// to prevent.
		err := ErrRelayPanic
		defer func() { done <- err }()
		err = pipeDir(b, a, o, nil)
	})
	// Upstream to client.
	Safe("flow.pipe.down", o.Logf, func() {
		err := ErrRelayPanic
		defer func() { done <- err }()
		err = pipeDir(a, b, o, o.OnFirstByte)
	})

	first := <-done
	forced := false
	// A half-close is for a clean EOF only. A direction that ended in an error
	// tears the whole relay down.
	var second error
	if !o.HalfClose || first != nil {
		// One direction is finished and half-close was not asked for, so the
		// other has nothing left to serve. Unblock it rather than waiting out
		// its idle deadline — and keep unblocking, for the same reason the
		// cancellation path does: a single poisoning that lands while pipeDir
		// is between reads is overwritten by its own idle re-arm, and the
		// surviving direction then parks for the whole idle bound.
		forced = true
		forceStop := make(chan struct{})
		Safe("flow.pipe.force", o.Logf, func() { repoison(forceStop, a, b) })
		second = <-done
		close(forceStop)
	} else {
		second = <-done
	}
	close(stop)

	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("flow: relay cancelled: %w", cerr)
	}
	if forced && (isTimeout(second) || errors.Is(second, ErrIdle) || errors.Is(second, net.ErrClosed)) {
		// We stopped that direction ourselves; reporting our own teardown as
		// the connection's failure would attribute a clean close to the peer.
		second = nil
	}
	if first != nil {
		return first
	}
	return second
}

// pipeDir copies src to dst, resetting the idle deadline before every read.
// onFirst fires before the first byte is written, never after.
func pipeDir(dst, src net.Conn, o PipeOpts, onFirst func()) error {
	buf := make([]byte, relayBuf)
	fired := false
	for {
		if o.Idle > 0 {
			if err := src.SetReadDeadline(time.Now().Add(o.Idle)); err != nil {
				return fmt.Errorf("flow: relay: set idle deadline: %w", err)
			}
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if !fired {
				fired = true
				if onFirst != nil {
					onFirst()
				}
			}
			if o.Idle > 0 {
				// The idle policy reads "neither byte moves for this long", and
				// a peer that has stopped reading moves no byte. Bounding only
				// the read half left a direction parked in Write against a zero
				// receive window with no bound at all.
				if err := dst.SetWriteDeadline(time.Now().Add(o.Idle)); err != nil {
					return fmt.Errorf("flow: relay: set write idle deadline: %w", err)
				}
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				if o.Idle > 0 && isTimeout(werr) {
					return fmt.Errorf("%w after %s: the peer stopped reading %d byte(s) in", ErrIdle, o.Idle, n)
				}
				return fmt.Errorf("flow: relay: write %d byte(s): %w", n, werr)
			}
		}
		if rerr == nil {
			continue
		}
		if errors.Is(rerr, io.EOF) {
			if o.HalfClose {
				closeWrite(dst)
			}
			return nil
		}
		if o.Idle > 0 && isTimeout(rerr) {
			return fmt.Errorf("%w after %s", ErrIdle, o.Idle)
		}
		if errors.Is(rerr, net.ErrClosed) {
			// Our own teardown, not the peer's failure.
			return nil
		}
		return fmt.Errorf("flow: relay: read: %w", rerr)
	}
}

// repoison unblocks conns now and keeps doing it until stop is closed.
//
// The repetition is the point. pipeDir arms its idle deadline at the TOP of
// every loop iteration, so a single poisoning that lands between "read
// returned" and "deadline re-armed" is overwritten with now+Idle and the
// direction parks for the whole idle bound — with the teardown already under
// way. Reproduced with proxyfe's own
// TestServeGivesUpOnAWedgedRelayAfterTheDrainGrace (Idle = 1 h) under
// `-race -count=200`: the package timed out at 10 minutes with pipeDir in IO
// wait, Pipe waiting on it and the server's drain waiting on Pipe. With the
// retry the same 200 iterations finish in under six seconds.
func repoison(stop <-chan struct{}, conns ...net.Conn) {
	t := time.NewTicker(cancelRepoison)
	defer t.Stop()
	for {
		unblock(conns...)
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

// unblock forces every pending read AND write to return immediately. A past
// deadline is used rather than Close because the connections belong to the
// caller, which may still want to read what is buffered or report on them; the
// caller must clear the deadlines before reusing them.
//
// The write half is not optional. A direction parked in dst.Write against a
// zero receive window — the ordinary state when a peer stops reading, produced
// by a closed lid, a suspended tab or a dropped hotspot — is released by
// nothing else, so a read-only unblock left both Pipe's teardown and its
// ctx.Done() escape hatch waiting forever on a wedged goroutine, leaking two
// connections and two 32 KiB buffers per stalled relay until fd exhaustion.
func unblock(conns ...net.Conn) {
	past := time.Now().Add(-time.Second)
	for _, c := range conns {
		_ = c.SetDeadline(past)
	}
}

// closeWrite propagates EOF as a half-close where the connection supports it.
// A conn that does not (a net.Pipe, a gVisor endpoint without CloseWrite) is
// left alone: closing it outright would drop the direction still in flight,
// which is the exact bug half-close exists to avoid.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
