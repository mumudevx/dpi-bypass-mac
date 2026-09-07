package flow_test

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/flow"
)

// tcpPair returns a connected loopback TCP pair, which is what half-close needs:
// net.Pipe has no CloseWrite.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	var d net.Dialer
	client, err = d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = r.c.Close() })
	return client, r.c
}

// TestPipeRelaysBothDirections.
func TestPipeRelaysBothDirections(t *testing.T) {
	t.Parallel()
	client, ours := net.Pipe()
	upstream, origin := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = ours.Close()
		_ = upstream.Close()
		_ = origin.Close()
	})

	done := make(chan error, 1)
	go func() { done <- flow.Pipe(context.Background(), ours, upstream, flow.PipeOpts{Idle: 2 * time.Second}) }()

	go func() {
		_, _ = client.Write([]byte("ping"))
	}()
	buf := make([]byte, 4)
	if err := origin.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(origin, buf); err != nil {
		t.Fatalf("origin read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("origin got %q", buf)
	}

	go func() { _, _ = origin.Write([]byte("pong")) }()
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("client got %q", buf)
	}

	_ = client.Close()
	_ = origin.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Pipe did not return after both ends closed")
	}
}

// TestPipeOnFirstByteFiresOnceBeforeTheClientSeesAnything is the commit hook.
// It must fire before the byte is written, or the front end would commit after
// the client already had the data.
func TestPipeOnFirstByteFiresOnceBeforeTheClientSeesAnything(t *testing.T) {
	t.Parallel()
	client, ours := net.Pipe()
	upstream, origin := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = ours.Close()
		_ = upstream.Close()
		_ = origin.Close()
	})

	var fired atomic.Int64
	var seen atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- flow.Pipe(context.Background(), ours, upstream, flow.PipeOpts{
			Idle: 2 * time.Second,
			OnFirstByte: func() {
				if seen.Load() {
					t.Error("OnFirstByte fired after the client already had bytes")
				}
				fired.Add(1)
			},
		})
	}()

	go func() {
		_, _ = origin.Write([]byte("aaa"))
		_, _ = origin.Write([]byte("bbb"))
	}()
	buf := make([]byte, 3)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	seen.Store(true)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("client read 2: %v", err)
	}
	if got := fired.Load(); got != 1 {
		t.Fatalf("OnFirstByte fired %d times, want exactly 1", got)
	}
	_ = origin.Close()
	_ = client.Close()
	<-done
}

// TestPipeHalfClose: a client that shuts down its write side must still receive
// the rest of the response. Tearing the whole connection down there is the bug
// half-close exists to avoid.
func TestPipeHalfClose(t *testing.T) {
	t.Parallel()
	client, ours := tcpPair(t)
	upstream, origin := tcpPair(t)

	done := make(chan error, 1)
	go func() {
		done <- flow.Pipe(context.Background(), ours, upstream, flow.PipeOpts{
			Idle: 3 * time.Second, HalfClose: true,
		})
	}()

	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}

	_ = origin.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 7)
	if _, err := io.ReadFull(origin, buf); err != nil {
		t.Fatalf("origin read: %v", err)
	}
	// The origin must see EOF, which is the half-close propagating.
	if _, err := origin.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("origin read after client half-close = %v, want EOF", err)
	}
	// And the response still flows the other way.
	if _, err := origin.Write([]byte("late response")); err != nil {
		t.Fatalf("origin write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, 13)
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("client read after half-close: %v", err)
	}
	if string(got) != "late response" {
		t.Fatalf("client got %q", got)
	}
	_ = origin.Close()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("Pipe did not return")
	}
}

// TestPipeIdleTimeout bounds a connection nothing is using.
func TestPipeIdleTimeout(t *testing.T) {
	t.Parallel()
	client, ours := net.Pipe()
	upstream, origin := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = ours.Close()
		_ = upstream.Close()
		_ = origin.Close()
	})
	err := flow.Pipe(context.Background(), ours, upstream, flow.PipeOpts{Idle: 60 * time.Millisecond})
	if !errors.Is(err, flow.ErrIdle) {
		t.Fatalf("err = %v, want ErrIdle", err)
	}
}

// TestPipeContextCancellation.
func TestPipeContextCancellation(t *testing.T) {
	t.Parallel()
	client, ours := net.Pipe()
	upstream, origin := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = ours.Close()
		_ = upstream.Close()
		_ = origin.Close()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- flow.Pipe(ctx, ours, upstream, flow.PipeOpts{}) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Pipe did not observe the cancellation")
	}
}

// TestPipeNilConn.
func TestPipeNilConn(t *testing.T) {
	t.Parallel()
	if err := flow.Pipe(context.Background(), nil, nil, flow.PipeOpts{}); err == nil {
		t.Fatal("want an error for a nil connection")
	}
}

// TestPipeSurvivesAPanicInAConnection: a panic in a relay goroutine kills the
// connection, not the process. Go runs only the panicking goroutine's defers, so
// flow.Safe is the only thing that makes the restoration promise true.
func TestPipeSurvivesAPanicInAConnection(t *testing.T) {
	t.Parallel()
	client, ours := net.Pipe()
	upstream, origin := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = ours.Close()
		_ = upstream.Close()
		_ = origin.Close()
	})

	before := flow.PanicCount()
	done := make(chan error, 1)
	go func() {
		done <- flow.Pipe(context.Background(), ours, upstream, flow.PipeOpts{
			Idle:        2 * time.Second,
			OnFirstByte: func() { panic("boom") },
			Logf:        func(string, ...any) {},
		})
	}()
	go func() { _, _ = origin.Write([]byte("x")) }()

	select {
	case <-time.After(3 * time.Second):
		t.Fatal("Pipe never returned after a panic in a relay goroutine")
	case <-done:
	}
	if flow.PanicCount() <= before {
		t.Fatal("the panic was not recorded by flow.Safe")
	}
}
