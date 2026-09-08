package netstate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return strings.TrimRight(string(b), "\n")
}

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

func TestNoRunnerFailsLoudly(t *testing.T) {
	res := Env{}.runner().Run(context.Background(), "route", "add")
	if !res.Failed() || res.Err == nil {
		t.Fatalf("a zero Env must fail explicitly, got %+v", res)
	}
	if !strings.Contains(res.Reason(), "Runner is nil") {
		t.Fatalf("Reason() = %q, want it to name the nil Runner", res.Reason())
	}
}
