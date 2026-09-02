package proxyfe_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
)

// socksConnect performs the SOCKS5 greeting and a CONNECT request for name.
func socksConnect(t *testing.T, h *harness, atyp byte, name string, port int) (net.Conn, byte) {
	t.Helper()
	c := h.dialProxy(t)
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		t.Fatalf("read greeting reply: %v", err)
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		t.Fatalf("greeting reply = % x, want 05 00", greet)
	}

	req := []byte{0x05, 0x01, 0x00, atyp}
	switch atyp {
	case 0x03:
		req = append(req, byte(len(name)))
		req = append(req, name...)
	case 0x01:
		ip := net.ParseIP(name).To4()
		req = append(req, ip...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		t.Fatalf("request: %v", err)
	}

	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[0] != 0x05 {
		t.Fatalf("reply version = %d", reply[0])
	}
	return c, reply[1]
}

// SOCKS5 must preserve the NAME. That is what makes it defeat DNS censorship
// for free, exactly as CONNECT does: the application never resolves, so the
// poisoned answer is never asked for.
func TestSOCKS5PreservesTheHostname(t *testing.T) {
	t.Parallel()
	l := newLab(t, testcensor.TT2026(), "discord.com")
	d := newMapDialer()
	d.add("discord.com", l.addr())
	store := openStore(t)
	h := serveTest(t, wiring{dialer: d, store: store})

	tunnel, rep := socksConnect(t, h, 0x03, "discord.com", 443)
	if rep != 0x00 {
		t.Fatalf("SOCKS5 reply = %d, want success", rep)
	}
	body, err := tlsThrough(t, tunnel, "discord.com", l.origin.ClientConfig("discord.com"))
	if err != nil {
		t.Fatalf("TLS through the SOCKS tunnel: %v", err)
	}
	if body != labResponse {
		t.Fatalf("body = %q", body)
	}
	// The name reached the ladder, not an address: the verdict is keyed on it.
	v := verdictOf(t, store, "discord.com")
	if v.Source != policy.SrcLearnedDesync {
		t.Fatalf("cached source = %s", v.Source)
	}
	if st := h.srv.Stats(); st.SOCKS != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestSOCKS5AddressLiteralIsScopedByAddress(t *testing.T) {
	t.Parallel()
	o := newGreetOrigin(t, "220 ready\r\n")
	d := newMapDialer()
	d.add("127.0.0.1", o.ln.Addr())
	h := serveTest(t, wiring{dialer: d})

	tunnel, rep := socksConnect(t, h, 0x01, "127.0.0.1", 25)
	if rep != 0x00 {
		t.Fatalf("reply = %d", rep)
	}
	buf := make([]byte, len("220 ready\r\n"))
	if _, err := io.ReadFull(tunnel, buf); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
}

// BIND and UDP ASSOCIATE get the RFC's "command not supported" rather than a
// hang. UDP ASSOCIATE is the unprivileged QUIC path and lands in M17.
func TestSOCKS5UnsupportedCommandsAreRefusedNotHung(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{dialer: newMapDialer()})
	for _, cmd := range []byte{0x02, 0x03} {
		c := h.dialProxy(t)
		if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatalf("greeting: %v", err)
		}
		var greet [2]byte
		if _, err := io.ReadFull(c, greet[:]); err != nil {
			t.Fatalf("greeting reply: %v", err)
		}
		req := append([]byte{0x05, cmd, 0x00, 0x03, byte(len("a.test"))}, "a.test"...)
		req = binary.BigEndian.AppendUint16(req, 443)
		if _, err := c.Write(req); err != nil {
			t.Fatalf("request: %v", err)
		}
		var reply [10]byte
		if _, err := io.ReadFull(c, reply[:]); err != nil {
			t.Fatalf("cmd %d: read reply: %v", cmd, err)
		}
		if reply[1] != 0x07 {
			t.Errorf("cmd %d: reply = %d, want 0x07 command-not-supported", cmd, reply[1])
		}
	}
}

// A client offering only authenticated methods is told so, rather than being
// left waiting for a request we will never read.
func TestSOCKS5RefusesWhenNoMethodIsAcceptable(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{dialer: newMapDialer()})
	c := h.dialProxy(t)
	if _, err := c.Write([]byte{0x05, 0x01, 0x02}); err != nil { // username/password only
		t.Fatalf("greeting: %v", err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if greet[1] != 0xFF {
		t.Fatalf("method = %d, want 0xFF", greet[1])
	}
}

func TestSOCKS5DialFailureIsReportedInTheReply(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{
		dialer: deadDialer{err: fmt.Errorf("nothing there")},
		rules:  []policy.Rule{bypassRule("gone.test")},
	})
	_, rep := socksConnect(t, h, 0x03, "gone.test", 443)
	if rep == 0x00 {
		t.Fatal("a failed dial replied success")
	}
}

func TestSOCKS5RejectsAnUnknownAddressType(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{dialer: newMapDialer()})
	c := h.dialProxy(t)
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if _, err := c.Write([]byte{0x05, 0x01, 0x00, 0x09, 0, 0, 0, 0, 0, 443 >> 8, 443 & 0xff}); err != nil {
		t.Fatalf("request: %v", err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] == 0x00 {
		t.Fatal("an unknown address type replied success")
	}
}
