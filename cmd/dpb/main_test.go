package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/buildinfo"
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

// lockedWriter serialises the stderr the signal watcher and the test goroutine
// both write to, so -race has nothing to complain about.
type lockedWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *lockedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// TestTeardownRunsOnANormalExit is the first half of the defect: td.run
// appeared exactly once in production code, inside `if r := recover()`. A
// signal cancels the context, dispatch returns an int, recover() is nil, and
// every revert a command registered through cliapp.Env.Push was dropped —
// leaving the system proxy pointed at a port that is about to close.
func TestTeardownRunsOnANormalExit(t *testing.T) {
	orig := dispatch
	t.Cleanup(func() { dispatch = orig })

	var reverted []string
	dispatch = func(_ context.Context, td *teardown, _ []string, _, _ io.Writer) int {
		td.push(func(context.Context) error { reverted = append(reverted, "first"); return nil })
		td.push(func(context.Context) error { reverted = append(reverted, "second"); return nil })
		return exitOK
	}

	var out bytes.Buffer
	var errOut lockedWriter
	if code := run([]string{"anything"}, &out, &errOut); code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	// Reverse order: the last subsystem to come up is the first to go down.
	if len(reverted) != 2 || reverted[0] != "second" || reverted[1] != "first" {
		t.Fatalf("teardown on a normal exit = %v, want [second first]", reverted)
	}
}

// TestTeardownRunsWhenTheContextWasCancelled pins the shape a signal actually
// produces: the run context is already done, and the reverts must still run on
// a live one with the full budget.
func TestTeardownRunsWhenTheContextWasCancelled(t *testing.T) {
	orig := dispatch
	t.Cleanup(func() { dispatch = orig })

	var ran bool
	var stepErr error
	dispatch = func(ctx context.Context, td *teardown, _ []string, _, _ io.Writer) int {
		td.push(func(tctx context.Context) error {
			ran = true
			stepErr = tctx.Err()
			return nil
		})
		// Stand in for the signal: the command observes a cancelled context and
		// returns, exactly as a `dpb run` interrupted with Ctrl-C would.
		c, cancel := context.WithCancel(ctx)
		cancel()
		<-c.Done()
		return exitError
	}

	var out bytes.Buffer
	var errOut lockedWriter
	if code := run(nil, &out, &errOut); code != exitError {
		t.Fatalf("exit code = %d, want %d", code, exitError)
	}
	if !ran {
		t.Fatal("the teardown stack was dropped on a cancelled-context exit")
	}
	if stepErr != nil {
		t.Fatalf("teardown ran on a dead context: %v", stepErr)
	}
}

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

// TestInstallSignalsStopIsIdempotent: run() defers stop() and the force-exit
// path can race it. Closing `done` twice would panic in a process that is
// already on its way out.
func TestInstallSignalsStopIsIdempotent(t *testing.T) {
	var errOut lockedWriter
	ctx, stop := installSignals(&errOut, func(int) {})
	stop()
	stop()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("stop must cancel the context it handed out")
	}
}

// journalPath is printed to a user who has just given up on a revert, so it
// must be an actual path, not an empty string.
func TestJournalPathIsNamed(t *testing.T) {
	if p := journalPath(); p == "" || !strings.Contains(p, "journal") {
		t.Fatalf("journalPath() = %q", p)
	}
}
