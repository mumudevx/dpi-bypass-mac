package cliapp

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpi-bypass-mac/internal/janitor"
	"github.com/mumudevx/dpi-bypass-mac/internal/netstate"
)

// `dpb _janitor` is the child `dpb run` spawns to survive its own SIGKILL.
//
// It is hidden because it is not a thing a user runs; it is a thing a user
// benefits from. It blocks on a kqueue EVFILT_PROC/NOTE_EXIT filter for its
// parent and, the moment the parent is gone, replays the journal — which puts
// the system proxy settings back within a second or so of a `kill -9`, with no
// login and no polling.
//
// The child must be the same dpb binary as its parent. netstate.OwnerAlive
// compares a journal record's owning process against the base name of the
// CURRENT executable, so a janitor running under any other name would decide
// that a LIVE parent's records belong to a stranger and revert them out from
// under a running proxy.

func newJanitorCmd(g *globals) *cobra.Command {
	var (
		parentPID int
		journal   string
	)
	cmd := &cobra.Command{
		Use:    janitor.JanitorCommand,
		Short:  "internal: wait for the parent dpb to exit, then undo what it left behind",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runJanitor(cmd.Context(), g, parentPID, journal)
		},
	}
	cmd.Flags().IntVar(&parentPID, "parent-pid", 0, "the dpb process to watch")
	cmd.Flags().StringVar(&journal, "journal", "", "the journal to replay once it is gone")
	return cmd
}

func runJanitor(ctx context.Context, g *globals, parentPID int, journalPath string) error {
	if parentPID <= 0 {
		return usagef("_janitor: --parent-pid is required")
	}
	if journalPath == "" {
		layout, err := g.layoutOf()
		if err != nil {
			return err
		}
		journalPath = layout.JournalFile()
	}

	rep, err := janitor.Run(ctx, janitor.Options{
		ParentPID:   parentPID,
		JournalPath: journalPath,
		Env: netstate.Env{
			Runner: g.runnerOf(),
			RIB:    g.ribOf(),
			Logf:   g.logf,
			// The parent is gone by the time anything is reverted, so a
			// captured loopback setting we cannot match exactly is its residue
			// rather than the user's own local proxy.
			PriorResidue: true,
		},
		Logf: g.logf,
	})
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// The parent stopped us on its way out cleanly. It ran UndoAll itself,
		// so there is nothing to replay and this is a successful exit.
		return nil
	case errors.Is(err, janitor.ErrNoParent):
		return usagef("%v", err)
	case err != nil:
		return fmt.Errorf("_janitor: %w", err)
	}

	// Everything the child says goes to stderr: its stdout is not connected to
	// anything a person reads, and the parent it was reporting for is gone.
	writeRepair(g.env.Stderr, rep)
	if !rep.Clean() {
		return codedError{code: ExitDoctor, err: errors.New(
			"_janitor: some system changes could not be undone")}
	}
	return nil
}
