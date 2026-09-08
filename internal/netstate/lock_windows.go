//go:build windows

package netstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive, non-blocking lock on the whole file.
//
// LOCKFILE_FAIL_IMMEDIATELY is not optional: without it LockFileEx BLOCKS until
// the holder releases, and `dpb status` would hang behind a running dpb instead
// of reporting that one is running. That is the same contract flock's LOCK_NB
// gives on the Unix side.
//
// The range is the maximum 64-bit length rather than the file's current size,
// because the record is rewritten and a lock over "the first N bytes" would
// stop covering the file the moment it grew.
//
// ERROR_LOCK_VIOLATION is what FAIL_IMMEDIATELY reports instead of blocking, so
// it is the platform's spelling of EWOULDBLOCK and has to reach AcquireLock as
// ErrLocked — otherwise a second dpb prints a raw Win32 error where the user
// should be told another run holds the lock.
func lockFile(f *os.File) error {
	ol := new(windows.Overlapped)
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, ^uint32(0), ^uint32(0), ol)
	if err == nil {
		return nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return fmt.Errorf("%w: %s", ErrLocked, f.Name())
	}
	return fmt.Errorf("netstate: lock %s: %w", f.Name(), err)
}

func unlockFile(f *os.File) error {
	ol := new(windows.Overlapped)
	if err := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, ^uint32(0), ^uint32(0), ol); err != nil {
		return fmt.Errorf("netstate: unlock %s: %w", f.Name(), err)
	}
	return nil
}

// openProcess opens pid with the narrowest access that answers the two
// questions this file asks of it.
//
// PROCESS_QUERY_LIMITED_INFORMATION is deliberate: it works across integrity
// levels, where PROCESS_QUERY_INFORMATION would be refused for a process we do
// not own — and being refused would look exactly like "that process is gone",
// which is the one wrong answer this file must never give.
func openProcess(pid int) (windows.Handle, error) {
	if pid <= 0 {
		return 0, windows.ERROR_INVALID_PARAMETER
	}
	return windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
}

// processCreation reports when the process behind h started, or ok=false when
// that process has already exited.
//
// The exit-time check earns its place because Windows keeps a process object
// alive as long as anyone holds a handle to it, so OpenProcess can succeed for
// a process that has already terminated. GetProcessTimes leaves lpExitTime
// zeroed while the process is running, so a non-zero exit time is positive
// knowledge that it is not — never a guess.
func processCreation(h windows.Handle) (time.Time, bool) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return time.Time{}, false
	}
	if exit.LowDateTime != 0 || exit.HighDateTime != 0 {
		return time.Time{}, false
	}
	return time.Unix(0, creation.Nanoseconds()), true
}

// ProcessStart reports when the process holding pid started.
//
// It exists for one reason: PID reuse. A lock record naming a dead process
// whose PID has been recycled must not be honoured, and comparing the recorded
// start time against the live one is what tells those apart. The Unix side
// reads it from a sysctl or from procfs; here it comes from the kernel's own
// creation timestamp, so no external command is involved at all — which
// removes the entire class of bug the LC_ALL=C pin on the Unix side exists to
// prevent, where ps reordered its columns under a Turkish locale and a live dpb
// looked dead.
//
// ok is false only when the kernel says so: a pid that cannot exist, a process
// we cannot open, or one whose exit time is set. It is never false as a default.
func ProcessStart(pid int) (time.Time, bool) {
	h, err := openProcess(pid)
	if err != nil {
		return time.Time{}, false
	}
	defer windows.CloseHandle(h)
	return processCreation(h)
}

// processIdentity is OwnerAlive's `comm=` half: the image path of the program
// running as pid.
//
// QueryFullProcessImageName is the modern spelling — it needs only
// PROCESS_QUERY_LIMITED_INFORMATION, where GetModuleFileNameEx needs
// PROCESS_VM_READ and would fail on a process running at another integrity
// level. The liveness check runs first for the reason processCreation gives:
// a terminated process can still be opened and would otherwise report a name.
func processIdentity(pid int) (string, bool) {
	h, err := openProcess(pid)
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(h)
	if _, ok := processCreation(h); !ok {
		return "", false
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", false
	}
	return windows.UTF16ToString(buf[:size]), true
}

// sameExecutable reports whether comm names the same program we are.
//
// The comparison folds case, and that is not cosmetic. Win32 paths are
// case-insensitive, and both sides of this comparison come from a process's
// recorded image path — ours from os.Executable, theirs from
// QueryFullProcessImageName — each spelled the way its command line spelled
// it. `DPB.EXE` launched from one shell and `dpb.exe` from another are the same
// binary, and a byte comparison would call the second dpb a stranger, report a
// LIVE dpb as dead, and let Replay tear down its proxy, DNS and routes.
func sameExecutable(comm string) bool {
	return strings.EqualFold(filepath.Base(comm), selfComm())
}
