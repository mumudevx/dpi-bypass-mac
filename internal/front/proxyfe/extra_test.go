package proxyfe_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/front/proxyfe"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
)

// upgradeOrigin accepts a protocol upgrade and then echoes, which is the shape
// of a WebSocket handshake followed by frames.
type upgradeOrigin struct {
	ln net.Listener
	wg sync.WaitGroup
}

func newUpgradeOrigin(t *testing.T) *upgradeOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	o := &upgradeOrigin{ln: ln}
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			o.wg.Add(1)
			go func() {
				defer o.wg.Done()
				defer c.Close()
				br := bufio.NewReader(c)
				// The origin upgrades ONLY when it is actually asked to. A
				// fixture that answers 101 unconditionally would pass even if
				// the proxy stripped the Upgrade headers, which is exactly the
				// defect this test exists to catch.
				asked, connUpgrade := false, false
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					low := strings.ToLower(strings.TrimSpace(line))
					if strings.HasPrefix(low, "upgrade:") && strings.Contains(low, "websocket") {
						asked = true
					}
					if strings.HasPrefix(low, "connection:") && strings.Contains(low, "upgrade") {
						connUpgrade = true
					}
					if strings.TrimSpace(line) == "" {
						break
					}
				}
				if !asked || !connUpgrade {
					const body = "the upgrade headers never arrived"
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\n"+
					"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				_, _ = io.Copy(c, br)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		o.wg.Wait()
	})
	return o
}

// A 101 hands the rest of the connection over to the relay in both directions.
// Reframing it as an ordinary response would truncate every frame after the
// handshake.
func TestProtocolUpgradeBecomesARelay(t *testing.T) {
	t.Parallel()
	o := newUpgradeOrigin(t)
	d := newMapDialer()
	d.add("ws.test", o.ln.Addr())
	h := serveTest(t, wiring{dialer: d, store: openStore(t)})

	c := h.dialProxy(t)
	if _, err := io.WriteString(c, "GET http://ws.test/socket HTTP/1.1\r\n"+
		"Host: ws.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := readStatusLine(br)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(resp, "101") {
		t.Fatalf("status = %q, want 101", resp)
	}
	if _, err := io.WriteString(c, "framed"); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	buf := make([]byte, len("framed"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "framed" {
		t.Fatalf("echo = %q", buf)
	}
}

func readStatusLine(br *bufio.Reader) (string, error) {
	status, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	upgrade := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return status, err
		}
		if strings.HasPrefix(strings.ToLower(line), "upgrade:") {
			upgrade = true
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	if !upgrade {
		return status, fmt.Errorf("the Upgrade header was stripped from a 101, which makes it meaningless")
	}
	return status, nil
}

// refusedDialer reports the errors a SOCKS5 reply code has to distinguish.
type refusedDialer struct{ err error }

func (d refusedDialer) DialTCP(context.Context, flow.Target) (net.Conn, error) { return nil, d.err }

func TestSOCKS5ReplyCodesDistinguishRefusedFromUnreachable(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		err  error
		want byte
	}{
		"refused":     {syscall.ECONNREFUSED, 0x05},
		"unreachable": {syscall.EHOSTUNREACH, 0x04},
		"no resolver": {flow.ErrNoResolver, 0x04},
		"other":       {io.ErrUnexpectedEOF, 0x01},
	} {
		h := serveTest(t, wiring{
			dialer: refusedDialer{err: tc.err},
			rules:  []policy.Rule{bypassRule("gone.test")},
		})
		if _, rep := socksConnect(t, h, 0x03, "gone.test", 443); rep != tc.want {
			t.Errorf("%s: reply = %d, want %d", name, rep, tc.want)
		}
	}
}

func TestSOCKS5RejectsAnEmptyGreetingAndAnEmptyName(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{dialer: newMapDialer()})

	// NMETHODS = 0: there is nothing to select, so say so rather than block.
	c := h.dialProxy(t)
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		t.Fatalf("write: %v", err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		t.Fatalf("read: %v", err)
	}
	if greet[1] != 0xFF {
		t.Fatalf("method = %d, want 0xFF", greet[1])
	}

	// A zero-length domain name, and a zero port: both are refusals.
	for _, req := range [][]byte{
		{0x05, 0x01, 0x00, 0x03, 0x00, 0x01, 0xBB},
		append(append([]byte{0x05, 0x01, 0x00, 0x03, byte(len("a.test"))}, "a.test"...), 0x00, 0x00),
	} {
		c := h.dialProxy(t)
		if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatalf("greeting: %v", err)
		}
		if _, err := io.ReadFull(c, greet[:]); err != nil {
			t.Fatalf("greeting reply: %v", err)
		}
		if _, err := c.Write(req); err != nil {
			t.Fatalf("request: %v", err)
		}
		var reply [10]byte
		if _, err := io.ReadFull(c, reply[:]); err != nil {
			t.Fatalf("read reply: %v", err)
		}
		if reply[1] == 0x00 {
			t.Errorf("% x replied success", req)
		}
	}
}

func TestSOCKS5IPv6LiteralIsAccepted(t *testing.T) {
	t.Parallel()
	// Port 25 is not an inspect port, so the flow is relayed directly and the
	// dial happens before the reply — which is what makes the reply code
	// meaningful here.
	h := serveTest(t, wiring{dialer: refusedDialer{err: syscall.ECONNREFUSED}, inspect: []int{443}})
	c := h.dialProxy(t)
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x04}
	req = append(req, net.ParseIP("2001:db8::1").To16()...)
	req = binary.BigEndian.AppendUint16(req, 25)
	if _, err := c.Write(req); err != nil {
		t.Fatalf("request: %v", err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != 0x05 {
		t.Fatalf("reply = %d, want connection-refused", reply[1])
	}
}

func TestCONNECTToAnIPv6LiteralIsParsed(t *testing.T) {
	t.Parallel()
	h := serveTest(t, wiring{dialer: refusedDialer{err: syscall.ECONNREFUSED}})
	c := h.dialProxy(t)
	if _, err := io.WriteString(c, "CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// It must not be a 400: the authority is well formed. A bogon-free v6
	// literal is dialled and the dial is what fails here.
	if strings.Contains(line, "400") {
		t.Fatalf("an IPv6 authority was rejected as malformed: %q", line)
	}
}

// A bare address in the bypass list becomes a /32 in the PAC, and a v6 literal
// is declared unenforceable rather than dropped.
func TestPACHandlesBareAddresses(t *testing.T) {
	t.Parallel()
	p := &proxyfe.PAC{Host: "127.0.0.1", Port: 8080, Bypass: []string{"198.51.100.7", "2001:db8::1", ""}}
	s := string(p.Active())
	if !strings.Contains(s, `isInNet(host, "198.51.100.7", "255.255.255.255")`) {
		t.Errorf("a bare IPv4 literal did not become a /32:\n%s", s)
	}
	if !strings.Contains(s, "NOT ENFORCED HERE: 2001:db8::1") {
		t.Errorf("a bare IPv6 literal was dropped silently:\n%s", s)
	}
}

// The PAC's name comparison must be anchored on a label boundary: the previous
// implementation compared with a bare suffix test, so a bypass for bank.com
// also fired on evilbank.com and a censored host could opt itself out by
// choosing its name.
func TestPACComparesOnLabelBoundaries(t *testing.T) {
	t.Parallel()
	p := &proxyfe.PAC{Host: "127.0.0.1", Port: 8080, Bypass: []string{"bank.com"}}
	s := string(p.Active())
	if !strings.Contains(s, `host.charAt(n) === "."`) {
		t.Fatalf("the PAC does not check for a label boundary:\n%s", s)
	}
	if bytes.Contains([]byte(s), []byte("indexOf(base)")) {
		t.Fatal("the PAC matches by substring")
	}
}
