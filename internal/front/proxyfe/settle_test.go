package proxyfe_test

import (
	"crypto/tls"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
)

// resetBehindSegment is the measured Türk Telekom shape that the ladder alone
// cannot see: the first connection is reset before the origin answers, and the
// second is answered with one segment and then reset.
//
// It is the difference between "the origin spoke" and "the handshake worked",
// and only the relay is standing in the right place to tell them apart.
type resetBehindSegment struct {
	ln net.Listener
	n  atomic.Int32
}

func newResetBehindSegment(t *testing.T) *resetBehindSegment {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	o := &resetBehindSegment{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go o.accept()
	return o
}

func (o *resetBehindSegment) addr() net.Addr { return o.ln.Addr() }

func (o *resetBehindSegment) accept() {
	for {
		c, err := o.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn, nth int32) {
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 4096)
			_, _ = c.Read(buf)
			if nth > 1 {
				// The rung past plain gets an answer, which is what makes the
				// walk commit and cache it.
				_, _ = c.Write(make([]byte, 64))
				// Let loopback deliver the segment before the reset discards
				// it. On the wire the middlebox's segment is already in flight
				// when its RST goes out; here the two would race.
				time.Sleep(200 * time.Millisecond)
			}
			hardClose(c)
		}(c, o.n.Add(1))
	}
}

// TestCONNECTDropsARungTheRelayProvedBroken is the end-to-end statement of the
// bug that pinned Discord's updater to an "Update Failed" loop on a TT line.
//
// The walk escalates past plain, the rung is answered, and the walk caches it as
// a winner — then the handshake dies with the client never having written a
// byte. Cached, that verdict is replayed for a week and the host never recovers,
// so the relay's report has to reach the store.
func TestCONNECTDropsARungTheRelayProvedBroken(t *testing.T) {
	t.Parallel()
	const name = "updates.discord.com"
	o := newResetBehindSegment(t)
	d := newMapDialer()
	d.add(name, o.addr())
	store := openStore(t)

	h := serveTest(t, wiring{dialer: d, store: store})

	tunnel, status := h.connect(t, name+":443")
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("CONNECT status = %q", status)
	}
	if _, err := tlsThrough(t, tunnel, name, &tls.Config{
		ServerName:         name,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}); err == nil {
		t.Fatal("the handshake succeeded against an origin that never speaks TLS")
	}
	_ = tunnel.Close()

	// The relay reports after the client is gone, so give it a moment to land.
	deadline := time.Now().Add(5 * time.Second)
	var v policy.Verdict
	for time.Now().Before(deadline) {
		got, ok := store.Get(policy.NetworkID{}, name)
		if ok && got.Spec == "" {
			v = got
			break
		}
		v = got
		time.Sleep(20 * time.Millisecond)
	}

	if v.Spec != "" {
		t.Errorf("cached Spec = %q; a rung whose relay carried no client byte must not stay the winner", v.Spec)
	}
	for _, s := range v.Ladder {
		if s != "" && s == v.Spec {
			t.Errorf("ladder still offers the disproved rung: %q", v.Ladder)
		}
	}
	if len(v.Ladder) > 0 && v.Ladder[len(v.Ladder)-1] != "oob:pos=1" {
		t.Logf("ladder after settling: %q", v.Ladder)
	}
}
