package flow_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
)

// deafPeerPair returns a loopback TCP pair whose far end never reads, plus a
// filler large enough that the relay's Write is guaranteed to park in the
// kernel: 8 MiB is two orders of magnitude past any loopback socket buffer, so
// the direction cannot drain it and blocks in dst.Write.
//
// net.Pipe cannot express this: it is synchronous and unbuffered, so a Write
// there blocks on the first byte and SetDeadline releases it either way. The
// wedge in MF11 is a kernel socket with a zero receive window — the ordinary
// state when a peer stops reading — so these tests use real sockets.
func deafPeerPair(t *testing.T) (ours net.Conn, filler []byte) {
	t.Helper()
	ours, _ = deafPeerHalf(t)
	return ours, make([]byte, 8<<20)
}

// deafPeerHalf returns the near end of a loopback pair plus the far end, which
// the caller must not read from.
func deafPeerHalf(t *testing.T) (near, far net.Conn) {
	t.Helper()
	far, near = tcpPair(t)
	// Shrinking the deaf end's receive buffer makes the wedge arrive in
	// milliseconds instead of megabytes.
	if tc, ok := far.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4 << 10)
	}
	return near, far
}

// TestPipeReleasesADirectionBlockedInWriteOnCancel is MF11.
//
// Before the fix unblock() set only a read deadline, so a direction parked in
// dst.Write against a peer that stopped reading was released by nothing:
// ctx.Done() fired, unblock ran, and Pipe still never returned. A closed lid, a
// suspended tab or a dropped hotspot is enough to produce that state, and the
// end of it is fd exhaustion.
func TestPipeReleasesADirectionBlockedInWriteOnCancel(t *testing.T) {
	t.Parallel()
	clientSide, filler := deafPeerPair(t)
	upstream, origin := tcpPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	// PipeOpts{} is the default configuration: no idle bound at all, so
	// cancellation is the ONLY escape hatch. That is the configuration MF11
	// says had no test.
	go func() { done <- flow.Pipe(ctx, clientSide, upstream, flow.PipeOpts{}) }()

	// Push far more than the client side can absorb; the relay wedges in Write.
	go func() { _, _ = origin.Write(filler) }()

	// Give the relay time to fill the socket and park in Write.
	time.Sleep(300 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Pipe never returned after cancellation: a direction is wedged in Write")
	}
}

// TestPipeTeardownReleasesADirectionBlockedInWrite is the other half of MF11:
// one direction finishes, Pipe forces the other down, and the forced direction
// is parked in Write. `second := <-done` blocked forever before the fix.
//
// The wedge is put on the UPSTREAM side here so the surviving direction can end
// on its own: closing a connection Pipe holds would release the blocked Write
// through net.ErrClosed and prove nothing.
func TestPipeTeardownReleasesADirectionBlockedInWrite(t *testing.T) {
	t.Parallel()
	client, ours := tcpPair(t)
	upstream, deafOrigin := deafPeerHalf(t)
	filler := make([]byte, 8<<20)

	done := make(chan error, 1)
	go func() { done <- flow.Pipe(context.Background(), ours, upstream, flow.PipeOpts{}) }()

	// The client floods; the origin never reads, so client-to-upstream wedges
	// in Write.
	go func() { _, _ = client.Write(filler) }()
	time.Sleep(300 * time.Millisecond)

	// The origin half-closes: upstream-to-client sees a clean EOF and ends.
	// HalfClose is off, so Pipe tears the whole relay down and must release the
	// direction still parked in Write.
	if err := deafOrigin.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("origin CloseWrite: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Pipe never returned after teardown: the forced direction is wedged in Write")
	}
}

// TestPipeIdleBoundsAStalledWrite: the idle policy is documented as "neither
// byte moves for this long", and a peer that stopped reading moves no byte. It
// was enforced on reads only, so an idle-bounded relay could still wedge.
func TestPipeIdleBoundsAStalledWrite(t *testing.T) {
	t.Parallel()
	clientSide, deaf := deafPeerHalf(t)
	upstream, origin := tcpPair(t)
	stop := make(chan struct{})
	defer close(stop)

	// Both directions idling at once would let the READ bound satisfy this
	// test, which is how it previously passed with the write bound deleted.
	// Keeping the client->upstream direction busy leaves the stalled write as
	// the only thing that can time out, so the assertion has one possible cause.
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				if _, err := deaf.Write([]byte("k")); err != nil {
					return
				}
			}
		}
	}()
	go func() { _, _ = io.Copy(io.Discard, origin) }()

	done := make(chan error, 1)
	go func() {
		done <- flow.Pipe(context.Background(), clientSide, upstream,
			flow.PipeOpts{Idle: 150 * time.Millisecond})
	}()
	// deaf never reads, so this fills its receive window and parks the
	// upstream->client direction inside Write.
	go func() { _, _ = origin.Write(make([]byte, 8<<20)) }()

	select {
	case err := <-done:
		if !errors.Is(err, flow.ErrIdle) {
			t.Fatalf("err = %v, want ErrIdle for a peer that stopped reading", err)
		}
		// Only the write path reports how far it got, so this is what
		// distinguishes the bound under test from the read bound.
		if !strings.Contains(err.Error(), "stopped reading") {
			t.Fatalf("err = %v, want the stalled-write bound; a read timeout means "+
				"the write half is unbounded again", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Pipe never returned: the idle bound does not cover a stalled write")
	}
}

// TestPipeDefaultOptsRelayBothDirections covers PipeOpts{} carrying bytes. MF11
// records that two separate one-character mutations which stop the relay
// carrying anything passed the whole suite, because the default configuration
// had no test at all.
func TestPipeDefaultOptsRelayBothDirections(t *testing.T) {
	t.Parallel()
	client, ours := tcpPair(t)
	upstream, origin := tcpPair(t)

	done := make(chan error, 1)
	go func() { done <- flow.Pipe(context.Background(), ours, upstream, flow.PipeOpts{}) }()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_ = origin.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(origin, buf); err != nil {
		t.Fatalf("origin read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("origin got %q, want ping", buf)
	}

	if _, err := origin.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("client got %q, want pong", buf)
	}

	// A clean EOF with HalfClose off ends the whole relay, and that is not an
	// error: nothing failed.
	_ = origin.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Pipe after a clean EOF = %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Pipe did not return after a clean EOF with HalfClose off")
	}
}
