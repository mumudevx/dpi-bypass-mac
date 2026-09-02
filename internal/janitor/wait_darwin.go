package janitor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// pollInterval is how often the kqueue wait comes up for air to look at the
// context. It is not how the parent's death is detected — that is the kernel's
// job and it is immediate — it only bounds how long a cancelled janitor takes
// to notice it should stop.
const pollInterval = 250 * time.Millisecond

// WaitForExit blocks until pid has exited, and returns nil the moment it has.
//
// It uses kqueue's EVFILT_PROC/NOTE_EXIT filter rather than polling, because
// the promise this whole package makes is that the user's proxy settings come
// back "within two seconds" of a `kill -9`, and a poll loop turns that into a
// promise about the poll interval instead. The kernel wakes us on the exit
// itself.
//
// A pid that is already gone is not an error: it is the answer. Two races make
// that essential rather than a nicety. The parent can die between the spawn and
// the registration, in which case EV_ADD fails with ESRCH; and it can die
// between a successful registration and the first kevent wait, which is why the
// registration is followed by an explicit liveness check. Treating either as an
// error would leave the journal unreplayed in exactly the case the janitor
// exists for.
func WaitForExit(ctx context.Context, pid int) error {
	if pid <= 0 {
		return fmt.Errorf("%w (got %d)", ErrNoParent, pid)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	kq, err := unix.Kqueue()
	if err != nil {
		return fmt.Errorf("janitor: kqueue: %w", err)
	}
	// Without CLOEXEC the descriptor would survive into anything this process
	// ever execs. It never execs anything today; keeping the invariant costs
	// one call and removes a class of surprise.
	unix.CloseOnExec(kq)
	defer unix.Close(kq)

	ev := unix.Kevent_t{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ONESHOT,
		Fflags: unix.NOTE_EXIT,
	}
	if _, err := unix.Kevent(kq, []unix.Kevent_t{ev}, nil, nil); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return nil // already gone
		}
		return fmt.Errorf("janitor: watch pid %d for exit: %w", pid, err)
	}

	// Close the second race. Signal 0 does not deliver anything; it only asks
	// the kernel whether the process still exists. If it died after EV_ADD
	// succeeded but before we started waiting, the NOTE_EXIT event was already
	// queued and the wait below would return it — but on a pid that was reaped
	// in between there may be nothing to return at all, and the janitor would
	// block until its context expired with the journal still pending.
	if err := unix.Kill(pid, 0); errors.Is(err, unix.ESRCH) {
		return nil
	}

	ts := unix.NsecToTimespec(int64(pollInterval))
	var out [1]unix.Kevent_t
	for {
		n, err := unix.Kevent(kq, nil, out[:], &ts)
		switch {
		case errors.Is(err, unix.EINTR):
			// A signal interrupted the wait. Nothing has changed about the
			// parent, so go round again.
		case err != nil:
			return fmt.Errorf("janitor: wait for pid %d to exit: %w", pid, err)
		case n > 0:
			return nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
	}
}
