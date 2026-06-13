package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type staticResolver struct{ ip net.IP }

func (s staticResolver) Resolve(_ context.Context, _ string) ([]net.IP, error) {
	return []net.IP{s.ip}, nil
}

func TestConnectTunnelAppliesDesync(t *testing.T) {
	// Fake upstream that records everything it receives.
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	upPort := up.Addr().(*net.TCPAddr).Port
	recvCh := make(chan []byte, 1)
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		recvCh <- b
	}()

	var gotPort int
	var gotFirst []byte
	srv := New(Options{
		Resolver:    staticResolver{ip: net.ParseIP("127.0.0.1")},
		DesyncPorts: map[int]bool{upPort: true},
		Apply: func(_ context.Context, upstream *net.TCPConn, first []byte, dstPort int) error {
			gotPort = dstPort
			gotFirst = append([]byte{}, first...)
			// Emit in two segments to exercise the relay path.
			if _, err := upstream.Write(first[:1]); err != nil {
				return err
			}
			_, err := upstream.Write(first[1:])
			return err
		},
	})

	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyPort := pl.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, pl)

	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT test.local:%d HTTP/1.1\r\nHost: test.local:%d\r\n\r\n", upPort, upPort)

	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("status = %q err=%v", status, err)
	}
	for { // consume headers up to blank line
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "\n" || line == "" {
			break
		}
	}

	payload := []byte("\x16\x03\x01\x00\x10fake-clienthello")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	c.(*net.TCPConn).CloseWrite()

	select {
	case recv := <-recvCh:
		if string(recv) != string(payload) {
			t.Fatalf("upstream got %q, want %q", recv, payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for upstream data")
	}

	if gotPort != upPort {
		t.Fatalf("desync port = %d, want %d", gotPort, upPort)
	}
	if string(gotFirst) != string(payload) {
		t.Fatalf("desync first = %q, want %q", gotFirst, payload)
	}
}

func TestSkipHostBypassesDesync(t *testing.T) {
	up, _ := net.Listen("tcp", "127.0.0.1:0")
	defer up.Close()
	upPort := up.Addr().(*net.TCPAddr).Port
	recvCh := make(chan []byte, 1)
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		recvCh <- b
	}()

	applyCalled := false
	srv := New(Options{
		Resolver:    staticResolver{ip: net.ParseIP("127.0.0.1")},
		DesyncPorts: map[int]bool{upPort: true},
		SkipHost:    func(h string) bool { return h == "skip.local" },
		Apply: func(_ context.Context, upstream *net.TCPConn, first []byte, _ int) error {
			applyCalled = true
			_, err := upstream.Write(first)
			return err
		},
	})
	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	proxyPort := pl.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, pl)

	c, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	defer c.Close()
	fmt.Fprintf(c, "CONNECT skip.local:%d HTTP/1.1\r\n\r\n", upPort)
	br := bufio.NewReader(c)
	_, _ = br.ReadString('\n')
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "" {
			break
		}
	}
	c.Write([]byte("hello"))
	c.(*net.TCPConn).CloseWrite()

	select {
	case recv := <-recvCh:
		if string(recv) != "hello" {
			t.Fatalf("got %q", recv)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
	if applyCalled {
		t.Fatal("desync should have been skipped for skip.local")
	}
}
