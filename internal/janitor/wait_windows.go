//go:build windows

package janitor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

// waitSlice bounds each WaitForSingleObject call, mirroring pollInterval's job
// on the kqueue side of this package (see wait_darwin.go). Passing windows.
// INFINITE instead would make the wait uncancellable, and the one caller that
// matters — the parent's own clean shutdown, which cancels ctx precisely so
// its janitor stops watching once UndoAll has already run — would then have no
// way to make this function return.
//
// It is deliberately the SAME 250ms as wait_darwin.go's pollInterval. This
// number is not a poll rate — the parent's death wakes the wait immediately on
// both platforms — it is the worst-case delay between a cancelled context and
// this function honouring it, and there is no reason for a Windows janitor to
// take four times longer to notice than a macOS one.
const waitSlice = 250 * time.Millisecond

// WaitForExit blocks until pid has exited, and returns nil the moment it has.
//
// It opens the process with SYNCHRONIZE only — no more rights than the wait
// itself needs — and waits on the resulting handle in waitSlice-sized slices
// rather than one INFINITE call, checking ctx.Err() between slices so a
// cancelled context is honoured within about a second rather than never.
//
// A pid that is already gone is not an error: it is the answer, exactly as
// wait_darwin.go treats ESRCH from EV_ADD. On Windows that surfaces as
// OpenProcess failing with ERROR_INVALID_PARAMETER, the error Win32 returns
// when the pid names no process at all (as opposed to a process this caller
// merely lacks rights to open, which is a different, real error). Treating
// that as a failure would leave the journal unreplayed in exactly the case the
// janitor exists for: the parent died before the janitor got around to
// watching it.
func WaitForExit(ctx context.Context, pid int) error {
	if pid <= 0 {
		return fmt.Errorf("%w (got %d)", ErrNoParent, pid)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil // already gone
		}
		return fmt.Errorf("janitor: open pid %d to wait for exit: %w", pid, err)
	}
	defer windows.CloseHandle(h)

	ms := uint32(waitSlice / time.Millisecond)
	for {
		// Before the wait, not only after it. Checking only afterwards meant an
		// ALREADY-cancelled context still bought a full slice of waiting for an
		// answer nobody was going to use, which is time added to the teardown a
		// user is watching. The wait itself is what the loop exists for, so the
		// cheap question is asked first.
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		event, err := windows.WaitForSingleObject(h, ms)
		if err != nil {
			return fmt.Errorf("janitor: wait for pid %d to exit: %w", pid, err)
		}
		if event == windows.WAIT_OBJECT_0 {
			return nil
		}
		// event is WAIT_TIMEOUT: this slice elapsed with the process still
		// running. Go round again — the loop, not this call, is what makes the
		// wait cancellable.
	}
}
