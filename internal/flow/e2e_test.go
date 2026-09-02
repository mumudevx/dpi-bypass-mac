package flow_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
)

// serve is the whole front-end datapath in one function: read the first message,
// walk the ladder, replay whatever the ladder already read, then relay. Every
// front end in this tree is this sequence, so testing it here is testing the
// contract M11 and M12 are built against.
func serve(t *testing.T, l *flow.LadderRunner, client net.Conn, tgt flow.Target, v policy.Verdict) (flow.Outcome, error) {
	t.Helper()
	first, kind, m, err := flow.ReadFirstMessage(client, tgt.Port, flow.DefaultFirstMsgOpts())
	if err != nil {
		return flow.Outcome{}, err
	}
	if kind == flow.MsgServerFirst {
		t.Fatalf("a TLS client was classified as server-first")
	}
	out, err := l.Run(context.Background(), tgt, v, first, m, nil)
	if err != nil {
		return out, err
	}
	go func() {
		if len(out.Pre) > 0 {
			if _, werr := client.Write(out.Pre); werr != nil {
				return
			}
		}
		_ = flow.Pipe(context.Background(), client, out.Conn, flow.PipeOpts{
			Idle: 10 * time.Second, HalfClose: true,
		})
	}()
	return out, nil
}

// TestEndToEndTT2026StreamIsContinuous is the acceptance claim in full: a real
// crypto/tls client, a real TLS origin, the measured middlebox in between, and a
// ladder that resets once and retries. The client must observe ONE continuous
// stream — a completed handshake and an exact response body — with no duplicate
// and no missing bytes across the retry.
func TestEndToEndTT2026StreamIsContinuous(t *testing.T) {
	t.Parallel()
	body := "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world"
	origin, err := testcensor.NewOrigin(testcensor.OriginConfig{
		Names:    []string{"discord.com"},
		Response: []byte(body),
	})
	if err != nil {
		t.Fatalf("origin: %v", err)
	}
	t.Cleanup(func() { _ = origin.Close() })

	box := testcensor.New(testcensor.TT2026(), testcensor.Options{Port: 443})
	store := newMemStore()
	l := &flow.LadderRunner{
		Dial:  &boxDialer{box: box, addr: origin.Addr()},
		Store: store,
		RTT:   flow.NewRTTTracker(),
	}

	client, ours := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = ours.Close() })

	type result struct {
		got string
		err error
	}
	res := make(chan result, 1)
	go func() {
		c := tls.Client(client, origin.ClientConfig("discord.com"))
		defer c.Close()
		if err := c.Handshake(); err != nil {
			res <- result{err: err}
			return
		}
		if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: discord.com\r\n\r\n")); err != nil {
			res <- result{err: err}
			return
		}
		buf := make([]byte, len(body))
		if _, err := io.ReadFull(c, buf); err != nil {
			res <- result{err: err}
			return
		}
		res <- result{got: string(buf)}
	}()

	out, err := serve(t, l, ours, flow.Target{Name: "discord.com", Addr: testAddr, Port: 443}, watchVerdict())
	if err != nil {
		t.Fatalf("datapath: %v", err)
	}

	select {
	case r := <-res:
		if r.err != nil {
			t.Fatalf("client: %v (winning spec %q, attempts %v)", r.err, out.Spec, specsOf(out.Attempts))
		}
		if r.got != body {
			t.Fatalf("client read %q, want %q: the stream lost or duplicated bytes across the retry", r.got, body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the client never completed; the retry was not transparent")
	}

	if out.Escalations() != 1 {
		t.Fatalf("escalations = %d, want exactly 1 (plain then tlsfrag)", out.Escalations())
	}
	if out.Spec != "tlsfrag:pos=snimid" {
		t.Fatalf("winning spec = %q", out.Spec)
	}
	if v := store.get(t, "discord.com"); v.Source != policy.SrcLearnedDesync {
		t.Fatalf("cached source = %s, want SrcLearnedDesync", v.Source)
	}
	// Two TCP connections reached the origin and only the second carried a
	// hello, which is the measured shape: MEASUREMENTS.md §1 records the TCP
	// handshake completing on a blocked flow and only the SNI deciding its
	// fate. That the SECOND one completed a real TLS handshake is the proof
	// that a conforming server reconstructs an identical ClientHello from two
	// records — the property §3.2 depends on.
	if origin.Conns() != 2 {
		t.Fatalf("origin accepted %d connections, want 2", origin.Conns())
	}
}

// TestEndToEndFragileOriginIsUntouched: the same datapath against a terminator
// that rejects a spanning ClientHello. It must succeed plain, on the first
// attempt, and never be reframed — MEASUREMENTS.md §5, where 10 of 41 Turkish
// hosts broke exactly this way.
func TestEndToEndFragileOriginIsUntouched(t *testing.T) {
	t.Parallel()
	body := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	origin, err := testcensor.NewOrigin(testcensor.OriginConfig{
		Names:    []string{"www.yapikredi.com.tr"},
		Response: []byte(body),
	})
	if err != nil {
		t.Fatalf("origin: %v", err)
	}
	t.Cleanup(func() { _ = origin.Close() })

	box := testcensor.New(testcensor.Fragile(), testcensor.Options{Port: 443})
	store := newMemStore()
	l := &flow.LadderRunner{
		Dial:  &boxDialer{box: box, addr: origin.Addr()},
		Store: store,
		RTT:   flow.NewRTTTracker(),
	}

	client, ours := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = ours.Close() })

	res := make(chan error, 1)
	go func() {
		c := tls.Client(client, origin.ClientConfig("www.yapikredi.com.tr"))
		defer c.Close()
		if err := c.Handshake(); err != nil {
			res <- err
			return
		}
		if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: www.yapikredi.com.tr\r\n\r\n")); err != nil {
			res <- err
			return
		}
		buf := make([]byte, len(body))
		_, err := io.ReadFull(c, buf)
		res <- err
	}()

	out, err := serve(t, l, ours, flow.Target{Name: "www.yapikredi.com.tr", Addr: testAddr, Port: 443}, watchVerdict())
	if err != nil {
		t.Fatalf("datapath: %v", err)
	}
	select {
	case err := <-res:
		if err != nil {
			t.Fatalf("client: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the client never completed against an origin that works plain")
	}

	if out.Escalations() != 0 {
		t.Fatalf("a fragile origin was desynced %d time(s)", out.Escalations())
	}
	if v := store.get(t, "www.yapikredi.com.tr"); v.Expires.IsZero() || v.Source != policy.SrcLearnedPlain {
		t.Fatalf("cached verdict = %s expires %v, want SrcLearnedPlain with a TTL: a plain verdict is "+
			"relayed as ScopeDirect and so can only be re-tested by expiring", v.Source, v.Expires)
	}
}
