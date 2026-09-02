package testcensor

import (
	"bufio"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// TestOriginCompletesRealHandshake pins that the origin is a genuine TLS
// terminator verified against its own certificate, with no InsecureSkipVerify
// anywhere. A test that disables verification is not testing a handshake, and
// every reframing claim in this package rests on a conforming server actually
// accepting the bytes.
func TestOriginCompletesRealHandshake(t *testing.T) {
	o := newOrigin(t, "discord.com")

	raw, err := net.Dial("tcp", o.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))

	c := tls.Client(raw, o.ClientConfig("discord.com"))
	if err := c.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	st := c.ConnectionState()
	if st.ServerName != "discord.com" {
		t.Errorf("server saw SNI %q", st.ServerName)
	}
	if st.Version < tls.VersionTLS12 {
		t.Errorf("negotiated %#x, want TLS 1.2 or better", st.Version)
	}

	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: discord.com\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("response = %q", line)
	}
	if o.Conns() != 1 {
		t.Errorf("Conns = %d, want 1", o.Conns())
	}
	if got := o.Received(0); len(got) == 0 || got[0] != 0x16 {
		t.Fatalf("Received(0) does not start with a TLS record: % x", got[:min(len(got), 8)])
	}
	if o.Received(7) != nil {
		t.Errorf("Received on an unknown index must be nil")
	}
}

// TestOriginRejectsAnUntrustedName keeps the certificate honest: the pool is not
// a blanket "accept anything", so a name mismatch is still a failure.
func TestOriginRejectsAnUntrustedName(t *testing.T) {
	o := newOrigin(t, "discord.com")
	raw, err := net.Dial("tcp", o.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))

	c := tls.Client(raw, o.ClientConfig("example.invalid"))
	if err := c.Handshake(); err == nil {
		t.Fatal("handshake succeeded for a name the certificate does not cover")
	}
}

// TestOriginCustomResponse covers the knob a prober needs: a block page served
// over a perfectly good TLS connection is a distinct censorship shape from a
// reset, and the trial code has to be able to see one.
func TestOriginCustomResponse(t *testing.T) {
	body := "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	o, err := NewOrigin(OriginConfig{
		Names:      []string{"blocked.example"},
		Response:   []byte(body),
		NextProtos: []string{"http/1.1"},
		Logf:       func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("NewOrigin: %v", err)
	}
	defer o.Close()

	raw, err := net.Dial("tcp", o.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))

	cfg := o.ClientConfig("blocked.example")
	cfg.NextProtos = []string{"http/1.1"}
	c := tls.Client(raw, cfg)
	if err := c.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if got := c.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Errorf("ALPN = %q, want http/1.1", got)
	}
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(line, "HTTP/1.1 403") {
		t.Fatalf("response = %q", line)
	}
}

// TestOriginRecordsHandshakeFailures makes the origin's own view assertable: a
// test that expects a terminator to reject something must be able to prove the
// terminator saw it.
func TestOriginRecordsHandshakeFailures(t *testing.T) {
	o := newOrigin(t, "discord.com")
	c, err := net.Dial("tcp", o.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(o.Errs()) > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("origin recorded no error for a plaintext request")
}

// TestOriginCloseIsIdempotent covers the cleanup path.
func TestOriginCloseIsIdempotent(t *testing.T) {
	o, err := NewOrigin(OriginConfig{})
	if err != nil {
		t.Fatalf("NewOrigin: %v", err)
	}
	if err := o.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := o.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}
