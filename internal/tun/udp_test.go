//go:build darwin

package tun

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// udpEcho starts a local UDP server that echoes each datagram back with an
// "echo:" prefix, so the test can tell relayed bytes from fabricated ones.
func udpEcho(t *testing.T) (net.IP, int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()

	host, portStr, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("split echo addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse echo port: %v", err)
	}
	return net.ParseIP(host), port
}

// realDial counts dials and then performs a genuine one.
func realDial(count *atomic.Int32, network *atomic.Value) DialFunc {
	return func(ctx context.Context, net_, addr string) (net.Conn, error) {
		count.Add(1)
		if network != nil {
			network.Store(net_)
		}
		var d net.Dialer
		return d.DialContext(ctx, net_, addr)
	}
}

func TestUDPRelayForwardsDatagramsBothWays(t *testing.T) {
	dstIP, dstPort := udpEcho(t)

	var dialed atomic.Int32
	var network atomic.Value
	srv := &Server{opt: Options{Dial: realDial(&dialed, &network), UDPIdle: 2 * time.Second}}

	clientSide, tunSide := net.Pipe()
	defer clientSide.Close()
	go srv.serveUDP(tunSide, dstIP, dstPort)

	if _, err := clientSide.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = clientSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, err := clientSide.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "echo:ping" {
		t.Fatalf("relayed reply = %q, want %q", got, "echo:ping")
	}
	if dialed.Load() != 1 {
		t.Fatalf("upstream dialled %d times, want 1", dialed.Load())
	}
	if got, _ := network.Load().(string); got != "udp" {
		t.Fatalf("dialled network %q, want \"udp\"", got)
	}
}

func TestUDPPort53IsAnsweredByTheEncryptedChain(t *testing.T) {
	var dialed atomic.Int32
	gotQuery := make(chan []byte, 1)
	srv := &Server{opt: Options{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dialed.Add(1)
			return nil, errors.New("must not dial")
		},
		DNSExchange: func(_ context.Context, q []byte) ([]byte, error) {
			gotQuery <- append([]byte(nil), q...)
			return []byte("dns-reply"), nil
		},
		UDPIdle: time.Second,
	}}

	clientSide, tunSide := net.Pipe()
	defer clientSide.Close()
	go srv.serveUDP(tunSide, net.ParseIP("192.168.1.1"), 53)

	if _, err := clientSide.Write([]byte("dns-query")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = clientSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, err := clientSide.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "dns-reply" {
		t.Fatalf("reply = %q, want %q", got, "dns-reply")
	}
	select {
	case q := <-gotQuery:
		if string(q) != "dns-query" {
			t.Fatalf("exchanger saw %q, want %q", q, "dns-query")
		}
	default:
		t.Fatal("exchanger never saw the query")
	}
	if dialed.Load() != 0 {
		t.Fatal("port 53 was relayed in the clear instead of going over the resolver chain")
	}
}

func TestUDPPort53RelaysWhenNoExchangerIsConfigured(t *testing.T) {
	dstIP, dstPort := udpEcho(t)

	var dialed atomic.Int32
	srv := &Server{opt: Options{Dial: realDial(&dialed, nil), UDPIdle: 2 * time.Second}}

	clientSide, tunSide := net.Pipe()
	defer clientSide.Close()
	// Same datapath, but the echo server stands in for the upstream on port 53.
	go srv.serveUDP(tunSide, dstIP, dstPort)

	if _, err := clientSide.Write([]byte("q")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = clientSide.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	if _, err := clientSide.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if dialed.Load() != 1 {
		t.Fatalf("upstream dialled %d times, want 1", dialed.Load())
	}
}

func TestUDPRelayReapsIdleSessions(t *testing.T) {
	dstIP, dstPort := udpEcho(t)

	var dialed atomic.Int32
	srv := &Server{opt: Options{Dial: realDial(&dialed, nil), UDPIdle: 50 * time.Millisecond}}

	clientSide, tunSide := net.Pipe()
	defer clientSide.Close()
	done := make(chan struct{})
	go func() {
		srv.serveUDP(tunSide, dstIP, dstPort)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("idle UDP session was never reaped — every silent flow would leak a goroutine")
	}

	_ = clientSide.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := clientSide.Read(make([]byte, 1)); err == nil {
		t.Fatal("client side left open after the session was reaped")
	}
}

func TestUDPRelayReportsDialFailureWithoutHanging(t *testing.T) {
	srv := &Server{opt: Options{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no route")
		},
		UDPIdle: time.Second,
	}}

	clientSide, tunSide := net.Pipe()
	defer clientSide.Close()
	done := make(chan struct{})
	go func() {
		srv.serveUDP(tunSide, net.ParseIP("203.0.113.1"), 443)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serveUDP hung after the upstream dial failed")
	}
}
