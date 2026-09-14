//go:build !windows

// This file contains tests that depend on Unix signals (SIGINT, SIGTERM, SIGHUP, SIGQUIT)
// which have different semantics or do not exist on Windows. Signal-driven testing
// cannot be implemented on Windows in the same way.

package main

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestSecondSignalForceExits is the second half. After the first SIGINT,
// signal.NotifyContext's goroutine returns without calling signal.Stop, so
// default handling stays disabled and nothing drains the channel: a second
// SIGINT and a SIGQUIT sent during the 10 s budget were both swallowed and the
// process ran the full budget. The user's next move is Force Quit — SIGKILL —
// which is the one exit that strands system state.
//
// This drives the real os/signal machinery with real signals sent to this test
// process, because the swallowing is a property of that machinery, not of our
// bookkeeping.
func TestSecondSignalForceExits(t *testing.T) {
	var errOut lockedWriter
	exited := make(chan int, 2)

	ctx, stop := installSignals(&errOut, func(code int) { exited <- code })
	t.Cleanup(stop)

	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("send first SIGINT: %v", err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the first SIGINT did not cancel the run context")
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("send second SIGINT: %v", err)
	}
	select {
	case code := <-exited:
		if code != exitError {
			t.Errorf("force exit code = %d, want %d", code, exitError)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the second SIGINT was swallowed: a user hammering Ctrl-C has no way out short of SIGKILL")
	}

	msg := errOut.String()
	if !strings.Contains(msg, journalPath()) {
		t.Errorf("the force-exit message must name the journal so the user can repair it; got %q", msg)
	}
	if !strings.Contains(msg, "doctor --repair") {
		t.Errorf("the force-exit message must name the repair command; got %q", msg)
	}
	if !strings.Contains(msg, "again") {
		t.Errorf("the first message must tell the user a second Ctrl-C is available; got %q", msg)
	}
}
