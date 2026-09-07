package testcensor

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/tlsmsg"
)

func newOrigin(t *testing.T, names ...string) *Origin {
	t.Helper()
	o, err := NewOrigin(OriginConfig{Names: names})
	if err != nil {
		t.Fatalf("NewOrigin: %v", err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

// dialThrough opens a censored connection to the origin.
func dialThrough(t *testing.T, b *Middlebox, o *Origin) Conn {
	t.Helper()
	c, err := b.DialContext(context.Background(), "tcp", o.Addr())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	cc, ok := c.(Conn)
	if !ok {
		t.Fatalf("middlebox conn does not implement testcensor.Conn")
	}
	if err := cc.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	return cc
}

// handshake drives a real TLS handshake over c, optionally reframing the
// ClientHello with the given body-relative cuts.
// A captured ClientHello cannot be replayed: crypto/tls cannot finish a
// handshake whose key share it did not generate. So the emitter is modelled
// where the real one sits — on the write path of a live handshake — which is
// also the only place that proves reframing survives a conforming terminator.
func handshake(t *testing.T, c net.Conn, o *Origin, name string, cuts ...int) error {
	t.Helper()
	tc := tls.Client(&reframeConn{Conn: c, cuts: cuts}, o.ClientConfig(name))
	return tc.Handshake()
}

// reframeConn splits the first write at the given body-relative record cuts,
// standing in for the tlsfrag emitter that M4 builds.
type reframeConn struct {
	net.Conn
	cuts []int
	done bool
	orig []byte // the first flight as crypto/tls handed it over, pre-reframing
}

func (r *reframeConn) Write(b []byte) (int, error) {
	if r.done || len(r.cuts) == 0 {
		return r.Conn.Write(b)
	}
	r.done = true
	r.orig = append(r.orig, b...)
	out, err := tlsmsg.SplitRecord(b, r.cuts)
	if err != nil {
		return 0, err
	}
	if _, err := r.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

// TestMiddleboxResetsBlockedHandshake is the end-to-end shape of §1: a real TLS
// handshake to a blocked name dies with a connection reset, and the origin never
// completes one.
func TestMiddleboxResetsBlockedHandshake(t *testing.T) {
	o := newOrigin(t, "discord.com")
	b := New(TT2026(), Options{Port: 443})
	c := dialThrough(t, b, o)

	err := handshake(t, c, o, "discord.com")
	if err == nil {
		t.Fatal("handshake succeeded through a blocking middlebox")
	}
	if !IsReset(err) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("handshake error = %v, want a reset-shaped failure", err)
	}
	flows := b.Flows()
	if len(flows) == 0 || !flows[0].Verdict.Blocked() {
		t.Fatalf("flows = %+v, want one blocked flow", flows)
	}
	if flows[0].ServerName != "discord.com" {
		t.Errorf("flow server name = %q", flows[0].ServerName)
	}
}

// TestMiddleboxPassesRecordSplitHandshake is the claim MEASUREMENTS.md §3.2
// makes, driven all the way to a completed TLS handshake against a real
// terminator: the cut hides the hostname from the DPI and the server still
// reconstructs the identical ClientHello.
func TestMiddleboxPassesRecordSplitHandshake(t *testing.T) {
	o := newOrigin(t, "discord.com")
	b := New(TT2026(), Options{Port: 443})
	c := dialThrough(t, b, o)

	hello := clientHello(t, "discord.com")
	sniStart, sniEnd := sniExtent(t, hello)
	if err := handshake(t, c, o, "discord.com", (sniStart+sniEnd)/2); err != nil {
		t.Fatalf("record-split handshake failed: %v", err)
	}
	if flows := b.Flows(); len(flows) > 0 && flows[0].Verdict.Blocked() {
		t.Fatalf("flow was blocked: %v", flows[0].Verdict)
	}
	if errs := o.Errs(); len(errs) > 0 {
		t.Fatalf("origin reported %v", errs)
	}
}

// TestMiddleboxPlainHandshakeIsUntouched is the control: with no censorship the
// same code path completes, so a failure elsewhere in the suite is the model
// talking and not the plumbing.
func TestMiddleboxPlainHandshakeIsUntouched(t *testing.T) {
	o := newOrigin(t, "cloudflare.com")
	b := New(TT2026(), Options{Port: 443})
	c := dialThrough(t, b, o)
	if err := handshake(t, c, o, "cloudflare.com"); err != nil {
		t.Fatalf("benign handshake failed: %v", err)
	}
}

// TestMiddleboxIntegrity is the categorical anti-corruption check: whatever the
// emitter did to the framing, the origin must reassemble exactly the bytes the
// client wrote, and the handshake it reconstructs must be the original one.
func TestMiddleboxIntegrity(t *testing.T) {
	o := newOrigin(t, "discord.com")
	b := New(TT2026(), Options{Port: 443})
	c := dialThrough(t, b, o)

	sniStart, sniEnd := sniExtent(t, clientHello(t, "discord.com"))
	cut := (sniStart + sniEnd) / 2

	rec := &captureConn{Conn: c}
	w := &reframeConn{Conn: rec, cuts: []int{cut}}
	tc := tls.Client(w, o.ClientConfig("discord.com"))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	_ = tc.Close()

	// Give the origin a moment to drain; Close on the client side is what ends
	// its read loop.
	deadline := time.Now().Add(5 * time.Second)
	var got []byte
	for time.Now().Before(deadline) {
		got = o.Received(0)
		if len(got) >= len(rec.wrote) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := CheckIntegrity(rec.wrote, got[:min(len(got), len(rec.wrote))]); err != nil {
		t.Fatalf("stream integrity: %v", err)
	}
	// The two records the origin received must reconstruct, byte for byte, the
	// single record crypto/tls actually produced on this connection.
	firstRecords := got[:recordSpan(t, got, 2)]
	if err := CheckHandshakeIntegrity(w.orig, firstRecords); err != nil {
		t.Fatalf("handshake integrity: %v", err)
	}
}

// recordSpan returns the byte length of the first n records in b.
func recordSpan(t *testing.T, b []byte, n int) int {
	t.Helper()
	off := 0
	for range n {
		h, ok := tlsmsg.ParseHeader(b[off:])
		if !ok || len(b) < off+5+h.Length {
			t.Fatalf("record %d missing from %d bytes", n, len(b))
		}
		off += 5 + h.Length
	}
	return off
}

type captureConn struct {
	net.Conn
	wrote []byte
}

func (c *captureConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.wrote = append(c.wrote, b[:n]...)
	return n, err
}

// TestMiddleboxDropIsATimeoutNotAReset pins the distinction the ladder depends
// on: a blackhole and a reset are different failure classes, and a runner that
// conflates them cannot implement §5.2's escalate-on-reset rule.
func TestMiddleboxDropIsATimeoutNotAReset(t *testing.T) {
	o := newOrigin(t, "discord.com")
	m := TT2026()
	m.Action = ActionDrop
	b := New(m, Options{Port: 443})
	c := dialThrough(t, b, o)
	if err := c.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	err := handshake(t, c, o, "discord.com")
	if err == nil {
		t.Fatal("handshake succeeded through a dropping middlebox")
	}
	if IsReset(err) {
		t.Fatalf("drop produced a reset: %v", err)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("drop error = %v, want a deadline", err)
	}
}

// TestMiddleboxLossRate covers the uncensored-but-lossy network a prober must
// not mistake for censorship. The seed is fixed so the simulator never fails one
// run in ten.
func TestMiddleboxLossRate(t *testing.T) {
	o := newOrigin(t, "example.com")
	run := func() int {
		b := New(Open(0.5), Options{Seed: 7})
		for range 40 {
			c, err := b.DialContext(context.Background(), "tcp", o.Addr())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			_ = c.Close()
		}
		lost := 0
		for _, f := range b.Flows() {
			if f.Verdict.Blocked() {
				lost++
			}
		}
		return lost
	}
	lost := run()
	if lost == 0 || lost == 40 {
		t.Fatalf("lost %d of 40 connections at LossRate 0.5; want a mix", lost)
	}
	// Reproducibility is the point: the same seed must lose the same count.
	if again := run(); again != lost {
		t.Fatalf("seeded loss is not reproducible: %d then %d", lost, again)
	}
}

// TestMiddleboxDialFailurePropagates keeps the simulator honest about errors it
// did not cause.
func TestMiddleboxDialFailurePropagates(t *testing.T) {
	want := errors.New("upstream down")
	b := New(TT2026(), Options{
		Upstream: func(context.Context, string, string) (net.Conn, error) { return nil, want },
	})
	if _, err := b.DialContext(context.Background(), "tcp", "127.0.0.1:1"); !errors.Is(err, want) {
		t.Fatalf("dial error = %v, want %v", err, want)
	}
}

// TestMiddleboxRecordsFlowOnClose makes an unblocked flow observable too, so a
// test can assert the middlebox saw the connection at all.
func TestMiddleboxRecordsFlowOnClose(t *testing.T) {
	o := newOrigin(t, "cloudflare.com")
	b := New(TT2026(), Options{Port: 443, Logf: func(string, ...any) {}})
	c := dialThrough(t, b, o)
	if err := handshake(t, c, o, "cloudflare.com"); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	flows := b.Flows()
	if len(flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(flows))
	}
	if flows[0].Verdict.Blocked() || flows[0].ServerName != "cloudflare.com" {
		t.Fatalf("flow = %+v", flows[0])
	}
	if flows[0].Segments == 0 || flows[0].Bytes == 0 {
		t.Errorf("flow counters not recorded: %+v", flows[0])
	}
}

// TestMiddleboxWriteAfterBlockFails pins that a client which keeps writing after
// the reset sees the reset, rather than silently succeeding.
func TestMiddleboxWriteAfterBlockFails(t *testing.T) {
	o := newOrigin(t, "discord.com")
	b := New(TT2026(), Options{Port: 443})
	c := dialThrough(t, b, o)

	hello := clientHello(t, "discord.com")
	if _, err := c.Write(hello); err != nil {
		t.Fatalf("the blocking write itself must succeed: %v", err)
	}
	if _, err := c.Write([]byte("more")); !IsReset(err) {
		t.Fatalf("write after reset = %v, want ECONNRESET", err)
	}
	if _, err := c.Read(make([]byte, 1)); !IsReset(err) {
		t.Fatalf("read after reset = %v, want ECONNRESET", err)
	}
}

// TestMiddleboxSetTTLDropsFakes wires the fake-segment mechanism through a real
// connection: the middlebox sees the junk, the origin does not.
func TestMiddleboxSetTTLDropsFakes(t *testing.T) {
	o := newOrigin(t, "cloudflare.com")
	m := TT2026()
	m.MinTTL = 6
	b := New(m, Options{Port: 443})
	c := dialThrough(t, b, o)

	if err := c.SetTTL(1); err != nil {
		t.Fatalf("SetTTL: %v", err)
	}
	if _, err := c.Write([]byte("FAKE")); err != nil {
		t.Fatalf("write fake: %v", err)
	}
	if err := c.SetTTL(64); err != nil {
		t.Fatalf("SetTTL: %v", err)
	}
	if _, err := c.Write([]byte("REAL")); err != nil {
		t.Fatalf("write real: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := o.Received(0); len(got) >= 4 {
			if string(got) != "REAL" {
				t.Fatalf("origin received %q, want only REAL", got)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("origin never received the real segment")
}

// TestMiddleboxWriteOOBEvades drives the §3 oob rows through a real connection:
// the middlebox counts the urgent byte, the origin never receives it, and the
// hostname the DPI thinks it read is shifted by one.
func TestMiddleboxWriteOOBEvades(t *testing.T) {
	o := newOrigin(t, "discord.com")
	b := New(TT2026(), Options{Port: 443})
	if b.Model().Name != "tt2026" {
		t.Fatalf("Model() = %q", b.Model().Name)
	}
	c := dialThrough(t, b, o)
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	hello := clientHello(t, "discord.com")
	if _, err := c.Write(hello[:1]); err != nil {
		t.Fatalf("write head: %v", err)
	}
	if _, err := c.WriteOOB([]byte{0xff}); err != nil {
		t.Fatalf("WriteOOB: %v", err)
	}
	if _, err := c.Write(hello[1:]); err != nil {
		t.Fatalf("write tail: %v", err)
	}
	for _, f := range b.Flows() {
		if f.Verdict.Blocked() {
			t.Fatalf("oob flow was blocked: %v", f.Verdict)
		}
	}
	// The origin must have received the clean hello: the urgent byte is the
	// middlebox's problem, never the server's.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := o.Received(0); len(got) >= len(hello) {
			if err := CheckIntegrity(hello, got[:len(hello)]); err != nil {
				t.Fatalf("origin stream: %v", err)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("origin never received the full hello")
}

// TestInspectorDecided pins the "still watching" state: a prefix that could
// still become a blocked hello must not be judged.
func TestInspectorDecided(t *testing.T) {
	hello := clientHello(t, "discord.com")
	in := TT2026().Inspect(443)
	if _, _ = in.Client(hello[:10], 0); in.Decided() {
		t.Fatalf("decided on a 10-byte prefix: %v", in.Verdict())
	}
	if _, _ = in.Client(hello[10:], 0); !in.Decided() {
		t.Fatal("not decided after the whole hello arrived")
	}
}
