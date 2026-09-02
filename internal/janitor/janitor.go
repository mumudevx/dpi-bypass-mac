// Package janitor is dpb's answer to SIGKILL.
//
// Every other way out of the process runs Go code on the way: SIGINT, SIGTERM
// and SIGHUP reach the signal context, a panic reaches the barrier in
// cmd/dpb, and both end in netstate.Manager.UndoAll. SIGKILL runs nothing at
// all — not a defer, not a recover, not a signal handler — and that is exactly
// the exit that leaves the macOS proxy settings pointing at a listener which no
// longer exists.
//
// docs/PLAN.md lists four overlapping defences for that case. This package is
// the second and the only one that acts immediately: a child process, spawned
// by the parent at start-up, blocked on a kqueue EVFILT_PROC/NOTE_EXIT filter
// for its parent's pid. The moment the parent dies — for any reason, including
// SIGKILL and including a kernel panic's survivors — the child wakes and
// replays the journal, which reverts every mutation the dead parent had
// recorded. No login, no polling, no timer.
//
// The child is deliberately tiny and does nothing else. It holds no sockets, it
// never reads the network, and its only writes are the ones netstate.Replay
// makes on its behalf.
package janitor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/netstate"
)

// Options configure one janitor run.
type Options struct {
	// ParentPID is the process to watch. Required.
	ParentPID int
	// JournalPath is the journal to replay once the parent is gone. Required.
	JournalPath string
	// Env is how the replayed Ops touch the world. It needs a Runner and a RIB;
	// a zero Env makes every revert fail loudly rather than silently succeed.
	Env netstate.Env
	// OwnerAlive decides whether a pending record's owner is still running.
	// Nil means netstate.OwnerAlive, which compares pid, process start time and
	// the executable's base name — which is why the janitor child must be the
	// same dpb binary as its parent.
	OwnerAlive func(pid int, started time.Time) bool
	// Wait blocks until ParentPID has exited. Nil means WaitForExit, the kqueue
	// implementation. It is a seam so the replay half can be tested without a
	// process and the wait half without a journal.
	Wait func(ctx context.Context, pid int) error
	Logf func(string, ...any)
}

func (o Options) logf(format string, a ...any) {
	if o.Logf != nil {
		o.Logf(format, a...)
	}
}

// ErrNoParent means the janitor was asked to watch a pid that cannot be one.
var ErrNoParent = errors.New("janitor: --parent-pid must name a live process")

// Run waits for the parent to exit and then replays the journal.
//
// It returns the replay report even when the report contains failures: a
// partially reverted machine is a fact the caller has to be able to print, and
// swallowing it behind an error would hide which settings are still wrong.
func Run(ctx context.Context, o Options) (netstate.ReplayReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if o.ParentPID <= 0 {
		return netstate.ReplayReport{}, fmt.Errorf("%w (got %d)", ErrNoParent, o.ParentPID)
	}
	if o.ParentPID == os.Getpid() {
		// Watching ourselves would block until we exit, which is never, and the
		// mistake is easy to make when wiring the spawn.
		return netstate.ReplayReport{}, fmt.Errorf("%w: %d is this process", ErrNoParent, o.ParentPID)
	}
	if o.JournalPath == "" {
		return netstate.ReplayReport{}, errors.New("janitor: --journal must name the journal file")
	}

	wait := o.Wait
	if wait == nil {
		wait = WaitForExit
	}
	o.logf("janitor: watching pid %d, will replay %s", o.ParentPID, o.JournalPath)
	if err := wait(ctx, o.ParentPID); err != nil {
		// A cancelled wait is the parent stopping us on its way out cleanly. It
		// already ran UndoAll itself, so there is nothing to replay and nothing
		// to report as a failure.
		return netstate.ReplayReport{}, err
	}
	o.logf("janitor: pid %d is gone; replaying the journal", o.ParentPID)
	return Replay(ctx, o)
}

// Replay opens the journal and reverts every pending record whose owner is
// gone. It is the half of Run that `dpb doctor --repair` and the login agent
// perform too, and it is exported so all three run the same code.
func Replay(ctx context.Context, o Options) (netstate.ReplayReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// The journal is opened on a FRESH context in Run's caller: every Op checks
	// ctx.Err() before it journals, so replaying on a cancelled context would
	// journal nothing and revert nothing.
	j, err := netstate.OpenJournal(o.JournalPath)
	if err != nil {
		return netstate.ReplayReport{}, fmt.Errorf("janitor: open the journal: %w", err)
	}
	defer func() {
		if cerr := j.Close(); cerr != nil {
			o.logf("janitor: close the journal: %v", cerr)
		}
	}()

	rep, err := netstate.Replay(ctx, j, o.Env, o.OwnerAlive)
	if err != nil {
		return rep, fmt.Errorf("janitor: replay: %w", err)
	}
	o.logf("janitor: replay done: %d pending, %d reverted, %d skipped, %d failed",
		len(rep.Pending), len(rep.Reverted), len(rep.Skipped), len(rep.Failed))
	return rep, nil
}
