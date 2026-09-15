//go:build !windows

// The two execRunner tests that name absolute POSIX paths in their argv.
//
// What they assert that Windows cannot express: the argv itself. `/bin/echo`,
// `/bin/sh -c` and `/bin/sleep` are not "the echo command" — they are three
// files at fixed absolute paths, which is the whole reason they are safe to
// spawn from a test without a PATH. Windows has no such file, no `-c` shell
// convention, and no fixed-path sleep; a Windows run of either test fails at
// CreateProcess before any property of execRunner is reached (measured
// 2026-09-14: `exec: "/bin/echo": executable file not found in %PATH%`).
//
// The properties themselves are portable, and runner_windows_test.go asserts
// the same ones — output capture, an exit code, stderr folded into Combined, a
// missing binary as an Err, one logf line per call, a nil logf that does not
// panic, and a context kill — through cmd.exe. Neither file is a substitute for
// the other: this one pins the argv a macOS dpb actually issues.
//
// Both function bodies are unchanged from runner_test.go, where they lived
// until the Windows suite started running.

package netstate

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestExecRunner(t *testing.T) {
	var logged []string
	r := NewExecRunner(func(f string, a ...any) { logged = append(logged, f) })
	ctx := context.Background()

	res := r.Run(ctx, "/bin/echo", "hello")
	if res.Failed() {
		t.Fatalf("echo failed: %s", res.Reason())
	}
	if res.Combined != "hello" {
		t.Fatalf("Combined = %q, want %q", res.Combined, "hello")
	}
	if res.Duration <= 0 {
		t.Fatal("Duration was not recorded")
	}

	res = r.Run(ctx, "/bin/sh", "-c", "echo oops >&2; exit 3")
	if !res.Failed() || res.Code != 3 {
		t.Fatalf("want exit 3 failure, got code=%d failed=%v", res.Code, res.Failed())
	}
	if !strings.Contains(res.Combined, "oops") {
		t.Fatalf("stderr was not captured: %q", res.Combined)
	}

	res = r.Run(ctx, "/nonexistent/dpb-not-a-binary")
	if !res.Failed() || res.Err == nil {
		t.Fatalf("a missing binary must be a failure with an Err, got %+v", res)
	}

	if len(logged) != 3 {
		t.Fatalf("logf called %d times, want 3", len(logged))
	}

	// A nil logf must not panic.
	NewExecRunner(nil).Run(ctx, "/bin/echo", "quiet")
}

func TestExecRunnerContextCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	res := NewExecRunner(nil).Run(ctx, "/bin/sleep", "5")
	if !res.Failed() {
		t.Fatal("a killed command must be a failure")
	}
	if res.Err == nil {
		t.Fatalf("a killed command must carry the context error, got %+v", res)
	}
	if res.Duration > 3*time.Second {
		t.Fatalf("the command outlived its context by %s", res.Duration)
	}
}
