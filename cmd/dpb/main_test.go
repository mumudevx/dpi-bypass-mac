package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/buildinfo"
)

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version"}, &out, &errOut); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %q)", code, exitOK, errOut.String())
	}
	if strings.TrimSpace(out.String()) != buildinfo.Short() {
		t.Errorf("stdout = %q, want %q", out.String(), buildinfo.Short())
	}
}

func TestRunUsageExitCodes(t *testing.T) {
	cases := []struct {
		args []string
		want int
	}{
		{nil, exitUsage},
		{[]string{"frobnicate"}, exitUsage},
		{[]string{"help"}, exitOK},
		{[]string{"--help"}, exitOK},
		{[]string{"--version"}, exitOK},
	}
	for _, tc := range cases {
		var out, errOut bytes.Buffer
		if got := run(tc.args, &out, &errOut); got != tc.want {
			t.Errorf("run(%v) = %d, want %d", tc.args, got, tc.want)
		}
	}
}

func TestUnknownCommandNamesIt(t *testing.T) {
	var out, errOut bytes.Buffer
	run([]string{"frobnicate"}, &out, &errOut)
	if !strings.Contains(errOut.String(), `"frobnicate"`) {
		t.Errorf("stderr = %q, want it to name the unknown command", errOut.String())
	}
}

// The panic barrier exists so system state is reverted BEFORE the stack dump.
// A user whose proxy settings point at a dead process does not care about the
// trace.
func TestPanicBarrierRunsTeardownThenRepanics(t *testing.T) {
	var order []string
	td := teardown{}
	td.push(func(context.Context) error { order = append(order, "first"); return nil })
	td.push(func(context.Context) error { order = append(order, "second"); return errors.New("revert failed") })

	var errOut bytes.Buffer
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("the panic must be re-raised after teardown")
			}
		}()
		defer func() {
			if r := recover(); r != nil {
				td.run(&errOut)
				panic(r)
			}
		}()
		panic("boom")
	}()

	// Reverse order: the last subsystem to come up is the first to go down.
	if len(order) != 2 || order[0] != "second" || order[1] != "first" {
		t.Errorf("teardown order = %v, want [second first]", order)
	}
	if !strings.Contains(errOut.String(), "revert failed") {
		t.Errorf("a failing teardown step must be reported: %q", errOut.String())
	}
}

func TestTeardownIsIdempotent(t *testing.T) {
	var calls int
	td := teardown{}
	td.push(func(context.Context) error { calls++; return nil })

	var errOut bytes.Buffer
	td.run(&errOut)
	td.run(&errOut)
	if calls != 1 {
		t.Errorf("teardown ran %d times, want 1", calls)
	}
}

// Teardown must get a live context even though the run context is already
// cancelled by the signal that started the shutdown.
func TestTeardownContextIsNotCancelled(t *testing.T) {
	td := teardown{}
	var gotErr error
	td.push(func(ctx context.Context) error { gotErr = ctx.Err(); return nil })
	td.run(&bytes.Buffer{})
	if gotErr != nil {
		t.Errorf("teardown context was already done: %v", gotErr)
	}
}
