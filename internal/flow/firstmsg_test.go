package flow_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/flow"
	"github.com/mumudevx/dpb/internal/tlsmsg"
)

// TestReadFirstMessageServerFirstProtocols is the deadlock regression.
//
// SMTP, IMAP, POP3, FTP and MySQL all speak first. The previous implementation
// issued an unconditional, un-deadlined client.Read on every connection and hung
// on all five. The greeting must reach the client inside FirstByteWait with ZERO
// bytes buffered.
func TestReadFirstMessageServerFirstProtocols(t *testing.T) {
	t.Parallel()
	greetings := []struct {
		proto    string
		port     int
		greeting string
	}{
		{"smtp", 25, "220 mail.example.com ESMTP Postfix\r\n"},
		{"imap", 143, "* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n"},
		{"pop3", 110, "+OK POP3 server ready <1896.697170952@example>\r\n"},
		{"ftp", 21, "220 (vsFTPd 3.0.5)\r\n"},
		{"mysql", 3306, "\x4a\x00\x00\x00\x0a8.0.36\x00"},
	}
	for _, g := range greetings {
		t.Run(g.proto, func(t *testing.T) {
			t.Parallel()
			client, ours := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = ours.Close() })

			opts := flow.DefaultFirstMsgOpts()
			start := time.Now()
			payload, kind, m, err := flow.ReadFirstMessage(ours, g.port, opts)
			elapsed := time.Since(start)

			if err != nil {
				t.Fatalf("ReadFirstMessage: %v", err)
			}
			if kind != flow.MsgServerFirst {
				t.Fatalf("kind = %s, want server-first", kind)
			}
			if len(payload) != 0 {
				t.Fatalf("buffered %d bytes from a peer that never spoke", len(payload))
			}
			if m.Complete {
				t.Error("Meta.Complete is set for a message that does not exist")
			}
			if elapsed > 4*opts.FirstByteWait {
				t.Fatalf("waited %s for a silent client; FirstByteWait is %s", elapsed, opts.FirstByteWait)
			}

			// And the greeting then flows, which is the behaviour the detection
			// exists to enable.
			upstream, origin := net.Pipe()
			t.Cleanup(func() { _ = upstream.Close(); _ = origin.Close() })
			go func() {
				_, _ = origin.Write([]byte(g.greeting))
			}()
			go func() { _ = flow.Pipe(context.Background(), ours, upstream, flow.PipeOpts{Idle: 5 * time.Second}) }()

			if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, len(g.greeting))
			if _, err := io.ReadFull(client, buf); err != nil {
				t.Fatalf("read greeting: %v", err)
			}
			if string(buf) != g.greeting {
				t.Fatalf("greeting = %q, want %q", buf, g.greeting)
			}
		})
	}
}

// TestReadFirstMessageAssemblesASplitHello is the completeness loop.
//
// MEASUREMENTS.md §3.5: a post-quantum ClientHello is ~1512-1601 bytes and
// arrives in two segments on a 1500-byte MTU. A single un-looped Read returns
// the first one, and planning a record split against that prefix degrades it
// into the 1-byte TCP split §3.1 measures at 0/5.
func TestReadFirstMessageAssemblesASplitHello(t *testing.T) {
	t.Parallel()
	h := clientHello(t, "discord.com")
	if len(h) < 600 {
		t.Fatalf("captured hello is only %d bytes; the split test needs a real one", len(h))
	}
	cut := len(h) / 2

	client, ours := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = ours.Close() })
	go func() {
		_, _ = client.Write(h[:cut])
		_, _ = client.Write(h[cut:])
	}()

	payload, kind, m, err := flow.ReadFirstMessage(ours, 443, flow.DefaultFirstMsgOpts())
	if err != nil {
		t.Fatalf("ReadFirstMessage: %v", err)
	}
	if kind != flow.MsgTLS {
		t.Fatalf("kind = %s, want tls", kind)
	}
	if !bytes.Equal(payload, h) {
		t.Fatalf("assembled %d bytes, want the whole %d-byte hello", len(payload), len(h))
	}
	if !m.Complete || m.Truncated {
		t.Fatalf("Complete=%v Truncated=%v, want a complete untruncated parse", m.Complete, m.Truncated)
	}
	if !m.HasSNI() || m.ServerName != "discord.com" {
		t.Fatalf("SNI = %q (%d..%d), want discord.com", m.ServerName, m.SNIStart, m.SNIEnd)
	}
	if end, ok := m.MaxFirstRecordEnd(); !ok || end != m.SNIEnd-1 {
		t.Fatalf("MaxFirstRecordEnd = %d,%v; the measured rule is sniEnd-1 = %d", end, ok, m.SNIEnd-1)
	}
}

// TestReadFirstMessageTruncatesOnTheSizeCap: a message larger than the cap is
// handed on marked truncated, never buffered without limit.
func TestReadFirstMessageTruncatesOnTheSizeCap(t *testing.T) {
	t.Parallel()
	h := clientHello(t, "discord.com")
	client, ours := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = ours.Close() })
	go func() { _, _ = client.Write(h) }()

	o := flow.DefaultFirstMsgOpts()
	o.Max = 64
	payload, kind, m, err := flow.ReadFirstMessage(ours, 443, o)
	if err != nil {
		t.Fatalf("ReadFirstMessage: %v", err)
	}
	if len(payload) > o.Max {
		t.Fatalf("buffered %d bytes, cap is %d", len(payload), o.Max)
	}
	if kind != flow.MsgTLS {
		t.Fatalf("kind = %s, want tls", kind)
	}
	if m.Complete || !m.Truncated {
		t.Fatalf("Complete=%v Truncated=%v, want a truncated parse so every reframer refuses it",
			m.Complete, m.Truncated)
	}
}

// TestReadFirstMessageTruncatesOnTheCompletionDeadline: a client that starts a
// record and stops does not hold the connection open forever.
func TestReadFirstMessageTruncatesOnTheCompletionDeadline(t *testing.T) {
	t.Parallel()
	h := clientHello(t, "discord.com")
	client, ours := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = ours.Close() })
	go func() { _, _ = client.Write(h[:100]) }()

	o := flow.DefaultFirstMsgOpts()
	o.CompleteWait = 80 * time.Millisecond
	payload, kind, m, err := flow.ReadFirstMessage(ours, 443, o)
	if err != nil {
		t.Fatalf("ReadFirstMessage: %v", err)
	}
	if len(payload) != 100 || kind != flow.MsgTLS {
		t.Fatalf("payload %d bytes kind %s, want the 100-byte prefix as tls", len(payload), kind)
	}
	if m.Complete || !m.Truncated {
		t.Fatalf("Complete=%v Truncated=%v, want truncated", m.Complete, m.Truncated)
	}
}

// TestReadFirstMessageHTTP: the plaintext path, where offsets are absolute.
func TestReadFirstMessageHTTP(t *testing.T) {
	t.Parallel()
	req := "GET /a HTTP/1.1\r\nHost: discord.com\r\nUser-Agent: x\r\n\r\n"
	client, ours := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = ours.Close() })
	go func() {
		_, _ = client.Write([]byte(req[:20]))
		_, _ = client.Write([]byte(req[20:]))
	}()

	payload, kind, m, err := flow.ReadFirstMessage(ours, 80, flow.DefaultFirstMsgOpts())
	if err != nil {
		t.Fatalf("ReadFirstMessage: %v", err)
	}
	if kind != flow.MsgHTTP {
		t.Fatalf("kind = %s, want http", kind)
	}
	if string(payload) != req {
		t.Fatalf("payload = %q, want the whole request head", payload)
	}
	if !m.Complete || !m.HasHost() {
		t.Fatalf("Complete=%v HasHost=%v", m.Complete, m.HasHost())
	}
	if got := string(payload[m.HostStart:m.HostEnd]); got != "discord.com" {
		t.Fatalf("Host extent = %q, want discord.com", got)
	}
}

// TestReadFirstMessageOpaqueStopsWaiting: an unrecognisable shape is handed on
// immediately rather than stalling the connection until a deadline.
func TestReadFirstMessageOpaqueStopsWaiting(t *testing.T) {
	t.Parallel()
	client, ours := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = ours.Close() })
	go func() { _, _ = client.Write([]byte{0xff, 0xfe, 0x01}) }()

	start := time.Now()
	payload, kind, _, err := flow.ReadFirstMessage(ours, 443, flow.DefaultFirstMsgOpts())
	if err != nil {
		t.Fatalf("ReadFirstMessage: %v", err)
	}
	if kind != flow.MsgOpaque || len(payload) != 3 {
		t.Fatalf("kind = %s with %d bytes, want opaque with 3", kind, len(payload))
	}
	if d := time.Since(start); d > flow.DefaultFirstMsgOpts().CompleteWait {
		t.Errorf("waited %s on an unrecognisable shape", d)
	}
}

// TestReadFirstMessageClientVanishes: a real error is surfaced, not swallowed.
func TestReadFirstMessageClientVanishes(t *testing.T) {
	t.Parallel()
	client, ours := net.Pipe()
	t.Cleanup(func() { _ = ours.Close() })
	_ = client.Close()

	if _, kind, _, err := flow.ReadFirstMessage(ours, 443, flow.DefaultFirstMsgOpts()); err == nil {
		t.Fatalf("want an error when the client closed before saying anything; kind = %s", kind)
	}
}

// TestReadFirstMessagePartialThenError returns the bytes AND the error, so a
// caller can log what it had without ever treating a broken read as a message.
func TestReadFirstMessagePartialThenError(t *testing.T) {
	t.Parallel()
	h := clientHello(t, "discord.com")
	client, ours := net.Pipe()
	t.Cleanup(func() { _ = ours.Close() })
	go func() {
		_, _ = client.Write(h[:50])
		_ = client.Close()
	}()

	payload, _, _, err := flow.ReadFirstMessage(ours, 443, flow.DefaultFirstMsgOpts())
	if err == nil {
		t.Fatal("want the read error surfaced")
	}
	if len(payload) != 50 {
		t.Fatalf("payload = %d bytes, want the 50 read before the error", len(payload))
	}
}

// TestReadFirstMessageWithoutDeadlines still assembles a complete message: the
// bound is a property of the connection, not of the loop.
func TestReadFirstMessageWithoutDeadlines(t *testing.T) {
	t.Parallel()
	h := clientHello(t, "discord.com")
	payload, kind, m, err := flow.ReadFirstMessage(bytes.NewReader(h), 443, flow.DefaultFirstMsgOpts())
	if err != nil {
		t.Fatalf("ReadFirstMessage: %v", err)
	}
	if kind != flow.MsgTLS || !m.Complete || !bytes.Equal(payload, h) {
		t.Fatalf("kind=%s complete=%v len=%d, want a complete tls hello of %d bytes",
			kind, m.Complete, len(payload), len(h))
	}
}

// TestReadFirstMessageNilReader.
func TestReadFirstMessageNilReader(t *testing.T) {
	t.Parallel()
	if _, _, _, err := flow.ReadFirstMessage(nil, 443, flow.FirstMsgOpts{}); err == nil {
		t.Fatal("want an error from a nil reader")
	}
}

// TestReadFirstMessageDeadlineOnAClosedConn surfaces the deadline failure rather
// than reading with no bound at all.
func TestReadFirstMessageDeadlineOnAClosedConn(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	_ = a.Close()
	_ = b.Close()
	if _, _, _, err := flow.ReadFirstMessage(b, 443, flow.DefaultFirstMsgOpts()); err == nil {
		t.Fatal("want an error when the deadline cannot be set")
	} else if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
		t.Logf("error was %v, which is acceptable as long as it is surfaced", err)
	}
}

// TestMsgKindString keeps the log vocabulary stable.
func TestMsgKindString(t *testing.T) {
	t.Parallel()
	for k, want := range map[flow.MsgKind]string{
		flow.MsgTLS: "tls", flow.MsgHTTP: "http", flow.MsgOpaque: "opaque",
		flow.MsgServerFirst: "server-first", flow.MsgKind(9): "invalid",
	} {
		if got := k.String(); got != want {
			t.Errorf("MsgKind(%d) = %q, want %q", k, got, want)
		}
	}
}

// TestDefaultFirstMsgOpts pins the shipped bounds, which other packages size
// themselves against (httpmsg.MaxHead is the same 64 KiB).
func TestDefaultFirstMsgOpts(t *testing.T) {
	t.Parallel()
	o := flow.DefaultFirstMsgOpts()
	if o.FirstByteWait != 250*time.Millisecond || o.CompleteWait != 250*time.Millisecond {
		t.Errorf("waits = %s/%s, want 250ms/250ms", o.FirstByteWait, o.CompleteWait)
	}
	if o.Max != 64<<10 {
		t.Errorf("Max = %d, want 64 KiB", o.Max)
	}
}

// TestReadFirstMessageQUICOverTCPIsOpaque: a QUIC Initial has no business on a
// TCP stream, and mangling one would be worse than relaying it.
func TestReadFirstMessageQUICOverTCPIsOpaque(t *testing.T) {
	t.Parallel()
	client, ours := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = ours.Close() })
	go func() { _, _ = client.Write([]byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08}) }()

	_, kind, m, err := flow.ReadFirstMessage(ours, 443, flow.DefaultFirstMsgOpts())
	if err != nil {
		t.Fatalf("ReadFirstMessage: %v", err)
	}
	if kind != flow.MsgOpaque {
		t.Fatalf("kind = %s, want opaque", kind)
	}
	if m.Proto == tlsmsg.ProtoTLS {
		t.Fatal("a QUIC long header must not be parsed as a TLS record")
	}
}
