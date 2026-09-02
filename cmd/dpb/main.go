// Command dpb is the dpi-bypass-mac CLI.
//
// This file owns three things and nothing else: the process exit codes, the
// signal context, and the teardown stack that reverts system state on the way
// out — whether the way out is a normal return, a signal, or a panic.
// Everything a subcommand does lives in internal/cliapp.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/cliapp"
	"github.com/mumudevx/dpi-bypass-mac/internal/paths"
)

// Exit codes, as published in the CLI surface. They are part of the tool's
// contract: scripts and the LaunchAgent branch on them.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitDoctor   = 3 // a doctor check failed
	exitNeedRoot = 4 // the requested mode needs root
	exitRefused  = 5 // refused for safety: VPN owns the default route, captive portal, IP-level block
	// 6 is `dpb tune` finding nothing blocked on this line. It is a code of its
	// own because 4 already means "needs root", and a script that branched on 4
	// could not tell "re-run with sudo" from "there is nothing to measure".
	exitNothingBlocked = 6
)

// teardownBudget is how long a panic- or signal-driven revert gets. It runs on
// a fresh context, never the cancelled one, because the whole point is to undo
// system mutations after the reason for stopping has already happened.
const teardownBudget = 10 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	ctx, stopSignals := installSignals(stderr, os.Exit)
	defer stopSignals()

	var td teardown

	// Teardown runs on EVERY exit path, not only the panicking one.
	//
	// docs/PLAN.md's "Every exit path" table asks for a reverse-order revert on
	// a fresh context with a 10 s budget, and cliapp.Env.Push's own doc tells a
	// command to register its system reverts here. Draining the stack only from
	// inside `if r := recover()` meant that a signal — the ordinary way a user
	// stops a long-running `dpb run` — cancelled the context, returned an int,
	// found recover() nil, and dropped every registered revert on the floor,
	// leaving the system proxy pointed at a port that is about to close.
	defer func() {
		r := recover()
		td.run(stderr)
		if r != nil {
			// Re-panic AFTER the revert. A stack dump is worth nothing to a
			// user whose network is still pointed at a process that just died.
			panic(r)
		}
	}()

	return dispatch(ctx, &td, args, stdout, stderr)
}

// installSignals arms the shutdown signals and returns the context every
// command runs under.
//
// SIGHUP is in the set because closing the terminal window sends HUP, not INT,
// and a dpb that dies on HUP without reverting leaves the system proxy pointed
// at a dead port.
//
// It deliberately does not use signal.NotifyContext. That helper's goroutine
// returns as soon as the first signal cancels the context, but the signal
// remains *handled* until stop() runs, so nothing drains the channel and every
// later delivery is swallowed: measured on this tree, a second SIGINT and a
// SIGQUIT sent during the teardown budget both vanished and the process ran the
// full 10 s. A user who thinks dpb is hung then reaches for Force Quit, which
// is SIGKILL, which is the one exit that leaves residue behind. So the channel
// stays armed and a second delivery is a deliberate, documented escape hatch.
//
// exit is a parameter rather than a call to os.Exit so the force-exit path can
// be driven by a test with real signals.
func installSignals(stderr io.Writer, exit func(int)) (context.Context, func()) {
	// Buffered well past the two deliveries this cares about: signal.Notify
	// drops on a full channel, and a dropped second Ctrl-C is the bug.
	ch := make(chan os.Signal, 8)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go watchSignals(ch, done, stderr, cancel, exit)

	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			signal.Stop(ch)
			close(done)
			cancel()
		})
	}
}

// watchSignals turns the first shutdown signal into a cancellation and the
// second into an immediate exit.
func watchSignals(ch <-chan os.Signal, done <-chan struct{}, stderr io.Writer,
	cancel context.CancelFunc, exit func(int)) {
	var first os.Signal
	select {
	case first = <-ch:
	case <-done:
		return
	}
	fmt.Fprintf(stderr, "dpb: %v; reverting system changes (up to %s). "+
		"Press Ctrl-C again to give up immediately.\n", first, teardownBudget)
	cancel()

	select {
	case second := <-ch:
		// The user asked twice. Leaving is now more important than finishing,
		// so say where the unfinished work is recorded and go.
		fmt.Fprintf(stderr, "dpb: %v again; exiting without finishing the revert.\n"+
			"dpb: every system change is journalled at %s — "+
			"run `dpb doctor --repair` to undo what is left.\n", second, journalPath())
		exit(exitError)
	case <-done:
	}
}

// journalPath names the file `dpb doctor --repair` replays. It is best effort:
// this runs on the way out of a process that is already giving up, so a
// resolution failure must not stop the message being printed.
func journalPath() string {
	l, err := paths.Resolve()
	if err != nil {
		return "the dpb state directory"
	}
	return l.JournalFile()
}

// teardown is a LIFO stack of revert steps. Subsystems push onto it as they
// come up, so the exit paths can unwind them in reverse without knowing
// what they are.
type teardown struct {
	steps []func(context.Context) error
}

func (t *teardown) push(fn func(context.Context) error) { t.steps = append(t.steps, fn) }

func (t *teardown) run(stderr io.Writer) {
	if len(t.steps) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), teardownBudget)
	defer cancel()
	for i := len(t.steps) - 1; i >= 0; i-- {
		if err := t.steps[i](ctx); err != nil {
			fmt.Fprintf(stderr, "dpb: teardown step %d failed: %v\n", i, err)
		}
	}
	t.steps = nil
}

// dispatch is the seam between this file and internal/cliapp.
//
// It is one call on purpose. The command tree, its flags and its output belong
// to internal/cliapp, where they are testable without a process; the only
// things that stay here are the exit codes, the signal context and the
// teardown stack a command pushes its reverts onto.
//
// It is a var so a test can substitute a command that registers a revert and
// assert that run() actually drains the stack; no production code reassigns it.
var dispatch = func(ctx context.Context, td *teardown, args []string, stdout, stderr io.Writer) int {
	return cliapp.Execute(ctx, cliapp.Env{
		Args:   args,
		Stdout: stdout,
		Stderr: stderr,
		Push:   td.push,
	})
}
