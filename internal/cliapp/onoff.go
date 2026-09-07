package cliapp

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpb/internal/janitor"
	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/observ"
	"github.com/mumudevx/dpb/internal/paths"
)

// `dpb off` and `dpb panic` are the two escape hatches.
//
// They are different on purpose, and the difference is what makes the tool
// safe to run on a machine you also bank on.
//
//   - `dpb off` is the kill switch WITHOUT an exit: every host goes direct, the
//     PAC is regenerated to all-DIRECT, and the listeners and the system
//     settings stay exactly where they are. Live connections are not dropped,
//     and `dpb on` puts it back with nothing to re-apply. It is what you type
//     when something is behaving strangely and you want dpb out of the way
//     while you find out what.
//   - `dpb panic` is "get me back to normal now": revert every system change
//     and exit. It is what you type when you do not want to find out what.
//
// `dpb panic` also has to work when dpb is ALREADY dead, because that is when
// a user reaches for it — the browser stopped working and Activity Monitor
// shows nothing. With no daemon to ask, it replays the journal, which is the
// same code `dpb doctor --repair` and the SIGKILL janitor run.

func newOnCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "on",
		Short: "Resume judging in-scope hosts after `dpb off`",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return sendControl(cmd.Context(), g, observ.CmdOn)
		},
	}
}

func newOffCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "off",
		Short: "Kill switch: relay everything direct, without stopping dpb",
		Long: "off puts dpb out of the way without unwinding anything. Every host is relayed\n" +
			"directly, the PAC is regenerated to all-DIRECT, and the listeners and system\n" +
			"settings stay valid, so `dpb on` restores normal behaviour with nothing to\n" +
			"re-apply and no live connection dropped.\n\n" +
			"To make it permanent, set mode = \"never\" in the configuration; to undo every\n" +
			"system change and stop, use `dpb panic`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return sendControl(cmd.Context(), g, observ.CmdOff)
		},
	}
}

func newReloadCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Re-read the configuration and scope files in the running dpb",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return sendControl(cmd.Context(), g, observ.CmdReload)
		},
	}
}

func newPanicCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "panic",
		Short: "Undo every system change dpb made and stop",
		Long: "panic reverts everything and exits. With a dpb running it asks that process\n" +
			"to unwind in the correct order and stop. With no dpb running — the case where\n" +
			"a user actually reaches for this — it replays the journal, which undoes every\n" +
			"mutation a crashed or SIGKILLed run left behind.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPanic(cmd.Context(), g)
		},
	}
}

// sendControl issues one argument-less control command.
func sendControl(ctx context.Context, g *globals, cmd string) error {
	layout, err := g.layoutOf()
	if err != nil {
		return err
	}
	note, err := g.controlClient(layout).Command(ctx, cmd)
	if errors.Is(err, observ.ErrNotRunning) {
		return fmt.Errorf("%s: no dpb is running, so there is nothing to change. "+
			"Start one with `dpb run`, or set mode in %s to make it permanent",
			cmd, layout.ConfigFile())
	}
	if err != nil {
		return fmt.Errorf("%s: %w", cmd, err)
	}
	if note == "" {
		note = "done"
	}
	fmt.Fprintln(g.env.Stdout, note)
	return nil
}

// runPanic reverts everything, whether or not a dpb is still alive to do it.
func runPanic(ctx context.Context, g *globals) error {
	layout, err := g.layoutOf()
	if err != nil {
		return err
	}
	note, err := g.controlClient(layout).Command(ctx, observ.CmdPanic)
	switch {
	case err == nil:
		if note == "" {
			note = "system settings reverted; dpb is exiting"
		}
		fmt.Fprintln(g.env.Stdout, note)
		return nil
	case !errors.Is(err, observ.ErrNotRunning):
		// The daemon is there but could not do it. Falling through to the
		// journal replay would race its own teardown, and two processes
		// reverting the same records is the one situation the journal cannot
		// describe. Say what went wrong and name the command that is safe to
		// run once it is gone.
		return fmt.Errorf("panic: the running dpb refused to unwind: %w\n"+
			"stop it, then run `dpb doctor --repair`", err)
	}

	fmt.Fprintln(g.env.Stdout, "no dpb is running; replaying the journal instead.")
	rep, err := repairJournal(ctx, g, layout)
	if err != nil {
		return fmt.Errorf("panic: %w", err)
	}
	writeRepair(g.env.Stdout, rep)
	if !rep.Clean() {
		return codedError{code: ExitDoctor, err: errors.New(
			"panic: some system changes could not be undone; see the lines above")}
	}
	return nil
}

// repairJournal replays the journal against the real machine. It is shared by
// `dpb panic` with no daemon, `dpb doctor --repair` and the login agent, so all
// three do exactly the same thing.
//
// The replay runs on a FRESH context derived from Background, never the one
// that may already be cancelled: every Op checks ctx.Err() before it journals,
// so unwinding on a cancelled context would journal nothing and revert nothing.
func repairJournal(ctx context.Context, g *globals, layout paths.Layout) (netstate.ReplayReport, error) {
	rctx, cancel := context.WithTimeout(context.Background(), teardownBudget)
	defer cancel()
	if ctx != nil && ctx.Err() != nil {
		g.logf("repair: the caller's context is already cancelled; replaying on a fresh one")
	}

	return janitor.Replay(rctx, janitor.Options{
		JournalPath: layout.JournalFile(),
		Env: netstate.Env{
			Runner: g.runnerOf(),
			RIB:    g.ribOf(),
			Logf:   g.logf,
			// By construction: we are here because a previous run left records
			// behind, which is exactly what PriorResidue means. Without it an
			// Op restores a captured loopback setting it cannot match exactly —
			// a dead run's proxy — instead of clearing it.
			PriorResidue: true,
		},
		Logf: g.logf,
	})
}
