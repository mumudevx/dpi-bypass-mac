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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpi-bypass-mac/internal/buildinfo"
	"github.com/mumudevx/dpi-bypass-mac/internal/front/tunfe"
	"github.com/mumudevx/dpi-bypass-mac/internal/netstate"
	"github.com/mumudevx/dpi-bypass-mac/internal/netwatch"
	"github.com/mumudevx/dpi-bypass-mac/internal/observ"
	"github.com/mumudevx/dpi-bypass-mac/internal/paths"
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

	// ExitNothingBlocked is `dpb tune` finding nothing in the target set
	// blocked on this network, so there is no strategy to measure.
	//
	// docs/PLAN.md's M13 acceptance clause originally gave this case code 4,
	// which its own CLI-surface table already gives to "needs root". Both
	// codes shipped in one binary: `dpb tune` returned 4 for "nothing is
	// blocked" while `dpb service install --system` returned 4 for "re-run
	// with sudo", and a script branching on $? could not tell them apart.
	// 4 stays with "needs root" — that is the meaning the surface table
	// publishes and the one the LaunchAgent branches on — and the tune case
	// moves to a code of its own. It is documented in `dpb tune --help`,
	// which is where a person writing that script looks.
	ExitNothingBlocked = 6
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

// codedError carries an exit code a command chose deliberately, for the cases
// the two named classes above do not cover. `dpb tune` uses it for "nothing is
// blocked here", which PLAN's M13 acceptance clause gives code 4.
type codedError struct {
	code int
	err  error
}

func (e codedError) Error() string { return e.err.Error() }
func (e codedError) Unwrap() error { return e.err }
func (e codedError) ExitCode() int { return e.code }

// teardownBudget is how long a revert gets. It matches cmd/dpb's budget for the
// same reason it exists there: the revert runs after the reason for stopping has
// already happened, so it needs a bound of its own.
const teardownBudget = 10 * time.Second

// globals are the flags every command shares, plus the seams a test uses to run
// a command that would otherwise touch the machine.
//
// The seams are unexported and no production code assigns them. They exist
// because `dpb run` mutates macOS network settings, and the only honest way to
// test that it mutates the right ones in the right order — and unwinds them in
// reverse — is to give it a fake macOS to mutate.
type globals struct {
	verbosity int
	logJSON   bool
	// logMu guards the lazily built logger.
	//
	// It has to be lazy: the verbosity flags are parsed after globals is
	// built, so a logger constructed up front would freeze at the default
	// level. And it has to be guarded: g.logf is handed to subsystems that fan
	// out — resolve.Chain fires its A and AAAA lookups on two flow.Safe
	// goroutines and both log — so an unsynchronised nil-check-then-assign is a
	// genuine data race, caught by `go test -race` on `dpb doctor --full`.
	//
	// It is a POINTER rather than an embedded sync.Mutex because
	// `dpb service install` copies globals to check `dpb run`'s flags, and
	// copying a lock value is a vet failure. newRoot installs one for every
	// command tree before any goroutine exists.
	logMu *sync.Mutex
	log   *observ.Logger
	env   Env

	// layout overrides paths.Resolve, so a test never writes to the real
	// ~/.config or the real state directory.
	layout *paths.Layout
	// runner and rib replace the command runner and the kernel routing table.
	runner netstate.Runner
	rib    netstate.RIBReader
	// facts replaces CollectFacts, which reads the machine's real interfaces.
	facts *netstate.Facts
	// factsFn replaces CollectFacts with a function, so a test can move the
	// machine to a different network while a run is in flight. netwatch
	// re-collects on every routing change, and the namespace swap cannot be
	// exercised at all if the facts are a constant.
	factsFn func(context.Context, netstate.Env) *netstate.Facts
	// netwatchOpts adjusts the network watcher's options before it starts. It
	// is the single test seam for the laptop-reality layer: the shipped
	// watcher reads this machine's routing socket and dials the real
	// connectivity endpoints, and neither belongs in a unit test.
	netwatchOpts func(*netwatch.Options)
	// openLink replaces tunfe.OpenDevice, which opens a real utun and is the
	// one thing in TUN mode that genuinely cannot run without root. A test
	// hands back one end of a tunfe.NewPipe pair instead, which is the shipped
	// netstack over an in-memory link rather than a stub of it.
	openLink func(name string, mtu int, logf func(string, ...any)) (tunfe.Link, error)
	// tunSeq wraps the netstate.Manager the tunnel's bring-up applies its Ops
	// through. It is a DECORATOR rather than a replacement so production keeps
	// one manager and one journal for the whole run, while a test can watch the
	// exact Op sequence — the ordering is the contract, and on a machine with
	// no utun the real ifconfig Op cannot verify.
	tunSeq func(tunfe.Sequencer) tunfe.Sequencer
	// getenv replaces os.Getenv for the configuration's environment layer.
	getenv func(string) string
	// ready is closed once `dpb run` is listening and the banner is printed.
	ready chan struct{}
	// serveErrs receives a listener failure so run can return it.
	serveErrs chan error
	// events receives every ConnEvent. M12 wires the real bus here.
	events func(observ.ConnEvent)
	// exe resolves the binary path `dpb service install` writes into the
	// launchd property list.
	exe func() (string, error)
	// sysRoot is the filesystem root the machine-wide launchd and log
	// locations hang off — /Library/LaunchDaemons, /Library/Logs/dpb. It is ""
	// in production, meaning "/"; a test points it at a temporary directory so
	// `dpb service install --system` can be exercised without root.
	sysRoot string
}

func (g *globals) layoutOf() (paths.Layout, error) {
	if g.layout != nil {
		return *g.layout, nil
	}
	l, err := paths.Resolve()
	if err != nil {
		return paths.Layout{}, fmt.Errorf("resolve the state directories: %w", err)
	}
	return l, nil
}

func (g *globals) runnerOf() netstate.Runner {
	if g.runner != nil {
		return g.runner
	}
	return netstate.NewExecRunner(g.logf)
}

func (g *globals) ribOf() netstate.RIBReader {
	if g.rib != nil {
		return g.rib
	}
	return netstate.NewRIB()
}

// factsOf collects the machine's network identity, best effort.
//
// A failure is not fatal in proxy mode: Facts names the uplink and the gateway,
// which the verdict cache uses to namespace what it learned, and a run with no
// gateway simply learns under a less specific network identity. Refusing to
// start would trade a working proxy for a more precise cache key.
func (g *globals) factsOf(ctx context.Context, e netstate.Env) *netstate.Facts {
	if g.factsFn != nil {
		return g.factsFn(ctx, e)
	}
	if g.facts != nil {
		return g.facts
	}
	f, err := netstate.CollectFacts(ctx, e)
	if err != nil {
		g.logf("collect network facts: %v", err)
		return nil
	}
	return f
}

// openLinkOf is the utun opener. The shipped one is tunfe.OpenDevice, which is
// a wrapper around CreateTUN and the only part of TUN mode that needs root.
func (g *globals) openLinkOf() func(string, int, func(string, ...any)) (tunfe.Link, error) {
	if g.openLink != nil {
		return g.openLink
	}
	return tunfe.OpenDevice
}

// tunSeqOf is the sequencer TUN bring-up applies its Ops through: the run's own
// netstate.Manager, unless a test wrapped it.
func (g *globals) tunSeqOf(m tunfe.Sequencer) tunfe.Sequencer {
	if g.tunSeq != nil {
		return g.tunSeq(m)
	}
	return m
}

func (g *globals) getenvOf() func(string) string {
	if g.getenv != nil {
		return g.getenv
	}
	return os.Getenv
}

// exeOf returns the absolute path of the running binary.
//
// It deliberately does NOT resolve symlinks. A Homebrew install puts dpb at
// /opt/homebrew/bin/dpb, a symlink into a versioned Cellar directory that
// `brew upgrade` deletes; a launchd job pinned to the resolved path stops
// working at the next upgrade, while one pointing at the symlink follows it.
func (g *globals) exeOf() (string, error) {
	f := g.exe
	if f == nil {
		f = os.Executable
	}
	p, err := f()
	if err != nil {
		return "", fmt.Errorf("locate this binary: %w", err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", p, err)
	}
	return abs, nil
}

func (g *globals) logger() *observ.Logger {
	if mu := g.logMu; mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	// A nil logMu means this globals never went through newRoot, which is
	// single-goroutine by construction: nothing has been given g.logf yet.
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
	return exitCodeFor(err)
}

// exitCodeFor maps a command's error onto the process exit code.
//
// It is a function rather than a switch inside Execute so that a test driving
// the command tree directly — which the M12 commands must, because Execute
// resolves the REAL layout and they read and repair the machine — maps errors
// with exactly the code the shipped binary uses, instead of a second copy of
// this switch that could drift from it.
func exitCodeFor(err error) int {
	if err == nil {
		return ExitOK
	}
	var ue usageError
	var re refusedError
	var ce codedError
	switch {
	case errors.As(err, &ue), isCobraUsageError(err):
		return ExitUsage
	case errors.As(err, &re):
		return ExitRefused
	case errors.As(err, &ce):
		return ce.ExitCode()
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
	// Install the logger's mutex before anything can spawn a goroutine that
	// logs. See the logMu field comment.
	if g.logMu == nil {
		g.logMu = new(sync.Mutex)
	}
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

	root.AddCommand(newRunCmd(g))
	root.AddCommand(newScopeCmd(g))
	root.AddCommand(newVersionCmd(g))
	root.AddCommand(newProbeCmd(g))
	root.AddCommand(newStrategyCmd(g))
	root.AddCommand(newTuneCmd(g))
	root.AddCommand(newApplyCmd(g))
	root.AddCommand(newDNSCmd(g))
	root.AddCommand(newCacheCmd(g))
	root.AddCommand(newServiceCmd(g))
	root.AddCommand(newWhyCmd(g))
	root.AddCommand(newStatusCmd(g))
	root.AddCommand(newCoverageCmd(g))
	root.AddCommand(newDoctorCmd(g))
	root.AddCommand(newOnCmd(g))
	root.AddCommand(newOffCmd(g))
	root.AddCommand(newPanicCmd(g))
	root.AddCommand(newReloadCmd(g))
	root.AddCommand(newSelftestCmd(g))
	root.AddCommand(newJanitorCmd(g))
	return root
}
