package flow_test

import (
	"net"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
)

// dribble writes src to c in pieces of the given size, pausing between them,
// and reports how long the whole hand-over took.
func dribble(c net.Conn, src []byte, piece int, gap time.Duration) {
	for off := 0; off < len(src); off += piece {
		end := off + piece
		if end > len(src) {
			end = len(src)
		}
		if _, err := c.Write(src[off:end]); err != nil {
			return
		}
		time.Sleep(gap)
	}
}

// TestReadFirstMessageCompletesForASlowButSteadyClient is SF2.
//
// CompleteWait is documented as "how long we keep reading, AFTER the first
// byte, for the rest of the declared message" and ReadFirstMessage's own
// contract says it loops until the declared message is complete. Setting the
// deadline once, on the first byte, made it a total assembly budget instead: a
// genuine hello handed over in 200-byte pieces 120 ms apart — never a gap
// anywhere near CompleteWait, every read making progress — was cut off at
// 250 ms and returned truncated.
//
// A truncated first message is not a cosmetic loss: every reframing op refuses
// an incomplete message, so the payload goes out plain and the connection is
// silently unbypassed.
func TestReadFirstMessageCompletesForASlowButSteadyClient(t *testing.T) {
	t.Parallel()
	h := clientHello(t, "discord.com")
	if len(h) < 900 {
		t.Fatalf("the captured hello is %d bytes; this test needs a multi-piece one", len(h))
	}
	client, ours := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = ours.Close() })

	// 200 bytes every 120 ms: well inside the 250 ms CompleteWait on every
	// single read, but many times it in total.
	go dribble(client, h, 200, 120*time.Millisecond)

	o := flow.DefaultFirstMsgOpts()
	start := time.Now()
	payload, kind, m, err := flow.ReadFirstMessage(ours, 443, o)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ReadFirstMessage: %v", err)
	}
	if kind != flow.MsgTLS {
		t.Fatalf("kind = %s, want tls", kind)
	}
	if !m.Complete || m.Truncated {
		t.Fatalf("Complete=%v Truncated=%v after %s with %d of %d bytes: a client that "+
			"makes steady progress must not be cut off", m.Complete, m.Truncated, elapsed, len(payload), len(h))
	}
	if len(payload) != len(h) {
		t.Fatalf("payload = %d bytes, want the whole %d-byte hello", len(payload), len(h))
	}
	if elapsed <= o.CompleteWait {
		t.Fatalf("the hand-over took %s, which is inside CompleteWait (%s); this test "+
			"is not exercising the progress deadline", elapsed, o.CompleteWait)
	}
}

// TestReadFirstMessageMaxAssemblyBoundsADribblingClient is the other half of
// SF2: a per-progress deadline must still be bounded overall, or a peer that
// hands over one byte just inside CompleteWait forever holds the connection.
func TestReadFirstMessageMaxAssemblyBoundsADribblingClient(t *testing.T) {
	t.Parallel()
	h := clientHello(t, "discord.com")
	client, ours := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = ours.Close() })

	// 20 bytes every 30 ms: always progress, never finishing inside the budget.
	go dribble(client, h, 20, 30*time.Millisecond)

	o := flow.DefaultFirstMsgOpts()
	o.CompleteWait = 100 * time.Millisecond
	o.MaxAssembly = 400 * time.Millisecond
	start := time.Now()
	payload, kind, m, err := flow.ReadFirstMessage(ours, 443, o)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ReadFirstMessage: %v", err)
	}
	if kind != flow.MsgTLS {
		t.Fatalf("kind = %s, want tls", kind)
	}
	if m.Complete || !m.Truncated {
		t.Fatalf("Complete=%v Truncated=%v after %s: MaxAssembly must cap the total wait",
			m.Complete, m.Truncated, elapsed)
	}
	if len(payload) == 0 || len(payload) >= len(h) {
		t.Fatalf("payload = %d bytes of %d, want a bounded prefix", len(payload), len(h))
	}
	// Progress renewed the deadline well past one CompleteWait window...
	if elapsed < o.CompleteWait+50*time.Millisecond {
		t.Fatalf("returned after %s, which is one CompleteWait (%s): the deadline was "+
			"not renewed by the reads that made progress", elapsed, o.CompleteWait)
	}
	// ...and MaxAssembly, not MaxAssembly + CompleteWait, is where it stopped.
	if elapsed > o.MaxAssembly+300*time.Millisecond {
		t.Fatalf("returned after %s, want ~%s", elapsed, o.MaxAssembly)
	}
}

// TestDefaultFirstMsgOptsMaxAssembly pins the shipped overall bound.
func TestDefaultFirstMsgOptsMaxAssembly(t *testing.T) {
	t.Parallel()
	d := flow.DefaultFirstMsgOpts()
	if d.MaxAssembly < d.CompleteWait {
		t.Fatalf("MaxAssembly = %s, must be at least CompleteWait (%s)", d.MaxAssembly, d.CompleteWait)
	}
	var zero flow.FirstMsgOpts
	// A zero MaxAssembly must be filled in, not treated as "no bound".
	h := clientHello(t, "discord.com")
	client, ours := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = ours.Close() })
	go func() { _, _ = client.Write(h) }()
	if _, _, m, err := flow.ReadFirstMessage(ours, 443, zero); err != nil || !m.Complete {
		t.Fatalf("zero opts: err=%v Complete=%v, want the defaults applied", err, m.Complete)
	}
}
