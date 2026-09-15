//go:build windows

package netstate

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// comspec is the command interpreter this machine actually has. %COMSPEC% is
// what Windows itself uses to find it; "cmd" through PATH is the fallback for
// a stripped environment, and System32 is always on PATH.
func comspec() string {
	if c := os.Getenv("COMSPEC"); c != "" {
		return c
	}
	return "cmd"
}

// TestExecRunnerOnWindows is runner_unix_test.go's TestExecRunner for the
// interpreter this platform has. The properties are the same six —
// output capture, a recorded duration, an exit code, stderr folded into
// Combined, a missing binary reported as an Err rather than a code, and one
// logf line per call — because they are properties of execRunner and not of
// the shell; only the argv differs, and the argv is the half Windows cannot
// share (see runner_unix_test.go).
//
// Before this file the whole of TestExecRunner failed on Windows at the first
// CreateProcess, so execRunner — which every netstate mutation on both
// platforms runs through — had never been executed by a test on Windows at
// all.
func TestExecRunnerOnWindows(t *testing.T) {
	var logged []string
	r := NewExecRunner(func(f string, a ...any) { logged = append(logged, f) })
	ctx := context.Background()
	cmd := comspec()

	// TrimRight(out, "\n") leaves the CR of a Windows CRLF, which is a fact
	// about the platform's line ending and not about this test: assert the
	// payload rather than the terminator.
	res := r.Run(ctx, cmd, "/c", "echo", "hello")
	if res.Failed() {
		t.Fatalf("echo failed: %s", res.Reason())
	}
	if got := strings.TrimSpace(res.Combined); got != "hello" {
		t.Fatalf("Combined = %q, want %q", res.Combined, "hello")
	}
	if res.Duration <= 0 {
		t.Fatal("Duration was not recorded")
	}

	// An exit code has to survive as a code, not as an Err: every liar table
	// in this package keys on Code.
	res = r.Run(ctx, cmd, "/c", "exit", "3")
	if !res.Failed() || res.Code != 3 {
		t.Fatalf("want exit 3 failure, got code=%d failed=%v err=%v", res.Code, res.Failed(), res.Err)
	}

	// Combined means combined: a tool that reports its failure on stderr and
	// exits 0 — the liar shape this package exists for — is unreadable
	// otherwise.
	res = r.Run(ctx, cmd, "/c", "echo", "oops", "1>&2")
	if !strings.Contains(res.Combined, "oops") {
		t.Fatalf("stderr was not captured: %q", res.Combined)
	}

	res = r.Run(ctx, `Z:\nonexistent\dpb-not-a-binary.exe`)
	if !res.Failed() || res.Err == nil {
		t.Fatalf("a missing binary must be a failure with an Err, got %+v", res)
	}

	if len(logged) != 4 {
		t.Fatalf("logf called %d times, want 4", len(logged))
	}

	// A nil logf must not panic.
	NewExecRunner(nil).Run(ctx, cmd, "/c", "echo", "quiet")
}

// TestExecRunnerContextCancelOnWindows is runner_unix_test.go's
// TestExecRunnerContextCancel with a sleeper this platform has.
//
// ping is spawned DIRECTLY rather than through cmd.exe on purpose: killing
// cmd.exe leaves its grandchild holding the write end of the output pipe, so
// CombinedOutput would block until the grandchild exited and the test would
// measure the sleeper's full duration instead of the kill.
func TestExecRunnerContextCancelOnWindows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	res := NewExecRunner(nil).Run(ctx, "ping", "-n", "20", "127.0.0.1")
	if !res.Failed() {
		t.Fatal("a killed command must be a failure")
	}
	if res.Err == nil {
		t.Fatalf("a killed command must carry the context error, got %+v", res)
	}
	if res.Duration > 5*time.Second {
		t.Fatalf("the command outlived its context by %s", res.Duration)
	}
}
