// Package cliapp is dpb's command tree.
//
// cmd/dpb owns the process — exit codes, the signal context and the panic
// barrier — and nothing else. Everything a subcommand does lives here, so a
// command is testable by calling Execute with a pair of buffers instead of by
// spawning a binary.
package cliapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpi-bypass-mac/internal/buildinfo"
	"github.com/mumudevx/dpi-bypass-mac/internal/observ"
)

// Exit codes, as published in the CLI surface. They are part of the tool's
// contract: scripts and the LaunchAgent branch on them. cmd/dpb declares the
// same values for its own usage text; these are the ones commands return.
const (
	ExitOK       = 0
	ExitError    = 1
	ExitUsage    = 2
	ExitDoctor   = 3 // a doctor check failed
	ExitNeedRoot = 4 // the requested mode needs root
	ExitRefused  = 5 // refused for safety: VPN owns the default route, captive portal, IP-level block
)

// Env is what cmd/dpb hands the command tree.
type Env struct {
	Args   []string
	Stdout io.Writer
	Stderr io.Writer
	// Push registers a revert step on the process teardown stack owned by
	// cmd/dpb, so a command that mutates system state is unwound by the panic
	// barrier without cmd/dpb knowing what the step is. Nil is allowed, and is
	// the normal case: no command in this milestone mutates anything.
	Push func(func(context.Context) error)
}

// usageError marks an error as "the user typed something wrong", which is exit
// code 2 rather than 1. Cobra reports flag and argument problems the same way
// it reports a command that failed at runtime, so the distinction has to be
// carried by the error itself.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func usagef(format string, a ...any) error {
	return usageError{fmt.Errorf(format, a...)}
}

// refusedError is exit code 5: we understood the request and are declining for
// safety, which is a different thing from failing to carry it out.
type refusedError struct{ err error }

func (e refusedError) Error() string { return e.err.Error() }
func (e refusedError) Unwrap() error { return e.err }

// globals are the flags every command shares.
type globals struct {
	verbosity int
	logJSON   bool
	log       *observ.Logger
	env       Env
}

func (g *globals) logger() *observ.Logger {
	if g.log == nil {
		g.log = observ.NewLogger(observ.LogOptions{
			Level: observ.VerbosityLevel(g.verbosity),
			JSON:  g.logJSON,
			Out:   g.env.Stderr,
		})
	}
	return g.log
}

// logf is the func(string, ...any) sink the subsystems take. It is debug level
// because at default verbosity a one-shot command's output is its report, not
// its trace.
func (g *globals) logf(format string, a ...any) { g.logger().Debugf(format, a...) }

// Execute runs the command tree and returns a process exit code. It never
// panics on a user error and never writes to the real stdout or stderr: every
// stream comes from the Env.
func Execute(ctx context.Context, e Env) int {
	if e.Stdout == nil {
		e.Stdout = io.Discard
	}
	if e.Stderr == nil {
		e.Stderr = io.Discard
	}

	g := &globals{env: e}
	root := newRoot(g)
	root.SetArgs(e.Args)
	root.SetOut(e.Stdout)
	root.SetErr(e.Stderr)

	// With no arguments at all there is nothing to run. Printing help to stderr
	// and exiting 2 keeps `dpb | grep` from looking like it succeeded.
	if len(e.Args) == 0 {
		root.SetOut(e.Stderr)
		_ = root.Help()
		return ExitUsage
	}

	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}

	fmt.Fprintf(e.Stderr, "dpb: %v\n", err)

	var ue usageError
	var re refusedError
	switch {
	case errors.As(err, &ue), isCobraUsageError(err):
		return ExitUsage
	case errors.As(err, &re):
		return ExitRefused
	case errors.Is(err, context.Canceled):
		return ExitError
	default:
		return ExitError
	}
}

// isCobraUsageError recognises the errors cobra produces for a mistyped command
// line. They are plain fmt.Errorf values with no type to match on, so the text
// is the only handle; getting this wrong costs an exit code, never correctness.
func isCobraUsageError(err error) bool {
	s := err.Error()
	for _, p := range []string{
		"unknown command",
		"unknown flag",
		"unknown shorthand flag",
		"flag needs an argument",
		"invalid argument",
		"accepts ",
		"requires at least",
		"unknown subcommand",
	} {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func newRoot(g *globals) *cobra.Command {
	root := &cobra.Command{
		Use:   "dpb",
		Short: "dpb bypasses SNI-keyed DPI blocking on macOS",
		Long: "dpb is a DPI bypass for macOS.\n\n" +
			"It connects with no desync first and escalates only when a connection is\n" +
			"reset before any server byte arrives, so hosts that break under desync —\n" +
			"every Turkish bank measured — are never desynced at all.",
		Version:       buildinfo.Short(),
		SilenceUsage:  true,
		SilenceErrors: true,
		// A parent with no Run is a group; cobra's default would print help and
		// exit 0, which would make `dpb` look like it did something.
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SetOut(g.env.Stderr)
			_ = cmd.Help()
			return usagef("no command given")
		},
	}
	root.SetVersionTemplate("{{.Version}}\n")

	pf := root.PersistentFlags()
	pf.CountVarP(&g.verbosity, "verbose", "v", "increase log verbosity (-v debug, -vv trace)")
	pf.BoolVar(&g.logJSON, "log-json", false, "emit logs as one JSON object per line")

	root.AddCommand(newVersionCmd(g))
	root.AddCommand(newProbeCmd(g))
	root.AddCommand(newStrategyCmd(g))
	return root
}
