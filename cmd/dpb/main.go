// Command dpb is the dpi-bypass-mac CLI.
//
// This file owns three things and nothing else: the process exit codes, the
// signal context, and the panic barrier that reverts system state before the
// stack dump. Everything a subcommand does lives in internal/cliapp.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/cliapp"
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
)

// teardownBudget is how long a panic- or signal-driven revert gets. It runs on
// a fresh context, never the cancelled one, because the whole point is to undo
// system mutations after the reason for stopping has already happened.
const teardownBudget = 10 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	// SIGHUP is in the set because closing the terminal window sends HUP, not
	// INT, and a dpb that dies on HUP without reverting leaves the system
	// proxy pointed at a dead port.
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer stop()

	var td teardown
	defer func() {
		if r := recover(); r != nil {
			// Revert first, then re-panic. A stack dump is worth nothing to a
			// user whose network is still pointed at a process that just died.
			td.run(stderr)
			panic(r)
		}
	}()

	return dispatch(ctx, &td, args, stdout, stderr)
}

// teardown is a LIFO stack of revert steps. Subsystems push onto it as they
// come up, so the panic barrier can unwind them in reverse without knowing
// what they are.
type teardown struct {
	steps []func(context.Context) error
}

func (t *teardown) push(fn func(context.Context) error) { t.steps = append(t.steps, fn) }

func (t *teardown) run(stderr io.Writer) {
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
func dispatch(ctx context.Context, td *teardown, args []string, stdout, stderr io.Writer) int {
	return cliapp.Execute(ctx, cliapp.Env{
		Args:   args,
		Stdout: stdout,
		Stderr: stderr,
		Push:   td.push,
	})
}
