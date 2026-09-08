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

// THE ASYMMETRY THIS FILE IS BUILT ON
//
// Every query below has three possible answers, not two: the process is there,
// the process is not there, and Windows would not say. The third is common, not
// exotic. PROCESS_QUERY_LIMITED_INFORMATION crosses integrity levels but it
// does NOT cross user accounts: a dpb running as SYSTEM (the service Plan 5
// ships) or under another desktop user answers ERROR_ACCESS_DENIED, and a
// pid whose handle table entry is being torn down can answer other things
// again.
//
// Collapsing "would not say" into "not there" is not a small inaccuracy. It
// makes OwnerAlive false, which makes PriorResidue true, which makes Replay
// revert a LIVE run's proxy, DNS and routes out from under a user who is using
// them. Collapsing it into "there" costs, at worst, a stale lock file that
// `dpb doctor` reports and the user clears in one command. Those two costs are
// not close, so "could not tell" is resolved as ALIVE, every time, deliberately.
//
// Only ERROR_INVALID_PARAMETER is treated as evidence of death, because it is
// the one error that is evidence: Win32 returns it from OpenProcess when the
// pid names no process at all, which is a statement about the world rather than
// about our rights. wait_windows.go leans on exactly the same distinction.

// openProcess opens pid with the access these queries need.
//
// PROCESS_QUERY_LIMITED_INFORMATION is deliberate: it works across integrity
// levels, where PROCESS_QUERY_INFORMATION would be refused for a process we do
// not own. SYNCHRONIZE is what makes the handle waitable, which is the only
// DEFINED way to ask whether the process has exited — see processExited.
//
// Asking for SYNCHRONIZE can itself be refused where QUERY_LIMITED alone would
// have been granted. That is acceptable here and nowhere near as dangerous as
// it sounds, because a refusal is "could not tell", which resolves as alive.
func openProcess(pid int) (windows.Handle, error) {
	if pid <= 0 {
		return 0, windows.ERROR_INVALID_PARAMETER
	}
	return windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
}

// noSuchProcess reports whether err is Windows saying the pid names no process,
// as opposed to Windows saying nothing useful. See the asymmetry note above:
// this predicate is the ONLY door to a "dead" verdict in this file.
func noSuchProcess(err error) bool {
	return errors.Is(err, windows.ERROR_INVALID_PARAMETER)
}

// processExited reports whether the process behind h has terminated, and
// whether Windows actually answered.
//
// The check earns its place because Windows keeps a process object alive as
// long as anyone holds a handle to it, so OpenProcess can succeed for a process
// that has already terminated and its creation time still reads back fine.
//
// It waits on the handle with a zero timeout rather than reading
// GetProcessTimes' lpExitTime, and the difference is not stylistic. A process
// handle is a synchronisation object whose signalled state is defined: it is
// signalled when, and only when, the process terminates. So WAIT_OBJECT_0 means
// exited and WAIT_TIMEOUT means running, both by contract. lpExitTime is the
// opposite: MSDN documents its value as UNDEFINED while the process has not
// exited, so the old `exit != 0 means dead` test was reading a field the
// platform does not promise to have zeroed — and reverting a working user's
// network configuration is not a decision to rest on undefined data.
//
// known=false is a query that failed, which is "could not tell" and resolves as
// alive at the call sites.
func processExited(h windows.Handle) (exited, known bool) {
	event, err := windows.WaitForSingleObject(h, 0)
	if err != nil {
		return false, false
	}
	switch event {
	case windows.WAIT_OBJECT_0:
		return true, true
	case uint32(windows.WAIT_TIMEOUT):
		return false, true
	default:
		// WAIT_ABANDONED cannot arise on a process handle, and WAIT_FAILED is
		// already an error above. Anything else is unaccounted for, so it is
		// not an answer.
		return false, false
	}
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
// ok=false does NOT mean "dead". It means "no comparable start time", which
// covers both a pid that cannot exist and a process Windows would not describe.
// That conflation is safe here and only here, because OwnerAlive reads a zero
// start time as "cannot distinguish this from the recorded owner" and resolves
// it as alive — the same direction the asymmetry note demands. The identity
// half, processIdentity, is where a false answer is destructive, and it does
// not conflate them.
func ProcessStart(pid int) (time.Time, bool) {
	h, err := openProcess(pid)
	if err != nil {
		return time.Time{}, false
	}
	defer windows.CloseHandle(h)
	if exited, known := processExited(h); known && exited {
		return time.Time{}, false
	}
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, creation.Nanoseconds()), true
}

// unknownComm is what processIdentity reports when Windows would not say who
// holds a pid: not a name, and explicitly not the absence of a process.
//
// It is empty because there is no image path to report and inventing one would
// be worse. sameExecutable is the other half of the convention and the only
// reader of it, which is why both live in this file rather than in the shared
// OwnerAlive: on Unix an empty comm really does mean "no such process", and
// nothing about that leaf changes.
const unknownComm = ""

// processIdentity is OwnerAlive's `comm=` half: the image path of the program
// running as pid.
//
// QueryFullProcessImageName is the modern spelling — it needs only
// PROCESS_QUERY_LIMITED_INFORMATION, where GetModuleFileNameEx needs
// PROCESS_VM_READ and would fail on a process running at another integrity
// level.
//
// This is the destructive one: ok=false here is what makes OwnerAlive say dead
// and Replay tear the machine's networking down. So it says false only for
// positive evidence — the pid cannot exist, or the process is known to have
// exited — and hands back unknownComm for every "could not tell".
func processIdentity(pid int) (string, bool) {
	h, err := openProcess(pid)
	if err != nil {
		if noSuchProcess(err) {
			return "", ownerGone.alive()
		}
		return unknownComm, ownerUnknown.alive()
	}
	defer windows.CloseHandle(h)
	if exited, known := processExited(h); known && exited {
		return "", ownerGone.alive()
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		// The process is there — we are holding a handle to it — and Windows
		// declined to name it. That is the textbook "could not tell".
		return unknownComm, ownerUnknown.alive()
	}
	return windows.UTF16ToString(buf[:size]), ownerPresent.alive()
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
//
// unknownComm answers true for the same reason, one step earlier: an
// unidentifiable live process must not be assumed to be a stranger, because the
// cost of being wrong about that is the teardown above, while the cost of
// treating a stranger as a peer is a lock file nobody clears until the user
// runs `dpb doctor`.
func sameExecutable(comm string) bool {
	if comm == unknownComm {
		return true
	}
	return strings.EqualFold(filepath.Base(comm), selfComm())
}
