//go:build !windows

package netstate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive, non-blocking lock on the whole file.
//
// LOCK_NB is the contract: `dpb status` reads the run lock to report who holds
// it, and a blocking acquire would leave it hanging behind the very process it
// is trying to describe. Contention comes back as ErrLocked so AcquireLock can
// tell "someone else is running" from "the lock file is broken" without knowing
// what errno this platform uses — LockFileEx reports a different one.
func lockFile(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EWOULDBLOCK) {
		return fmt.Errorf("%w: %s", ErrLocked, f.Name())
	}
	return fmt.Errorf("netstate: lock %s: %w", f.Name(), err)
}

func unlockFile(f *os.File) error {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_UN); err != nil {
		return fmt.Errorf("netstate: unlock %s: %w", f.Name(), err)
	}
	return nil
}

// processIdentity is OwnerAlive's `comm=` half: the name of the program running
// as pid, or ok=false if there is no such process.
//
// It is psInfo's first return and nothing more. psInfo also reports the start
// time, but OwnerAlive reads that through ProcessStart so that one OwnerAlive
// can serve a platform whose two answers come from two different places; the
// duplicated kernel read costs a sysctl, which is measured in microseconds.
func processIdentity(pid int) (string, bool) {
	comm, _, ok := psInfo(pid)
	return comm, ok
}

// sameExecutable reports whether comm names the same program we are.
//
// Unix paths are case-sensitive, so this is the byte comparison OwnerAlive has
// always made. Windows needs a different one, which is why this is a leaf.
func sameExecutable(comm string) bool { return filepath.Base(comm) == selfComm() }

// psRunner is the seam that lets the ps-backed helpers be tested without
// depending on which processes happen to exist on the machine. It pins LC_ALL=C
// so nothing ps prints can change shape with the user's region — see psInfo.
var psRunner Runner = newExecRunnerEnv(nil, []string{"LC_ALL=C"})

// psTimeout bounds the ps call; a hung ps must not stall teardown.
const psTimeout = 3 * time.Second

// procStarter is the seam for the kernel start-time read, so tests can drive a
// pid the machine does not have.
//
// The read itself is per-OS: lock_darwin.go asks a sysctl, lock_linux.go reads
// procfs, and there is no portable syscall for it. A Unix without one must fail
// to BUILD here rather than link against a stub that answers "this process is
// dead" — OwnerAlive is what stops Replay from reverting a RUNNING dpb's
// journal, and such a stub would make every live instance look dead and get its
// proxy, DNS and routes torn down underneath it.
var procStarter = kernelProcessStart

// ProcessStart reports when pid started, read from the kernel: sysctl
// KERN_PROC_PID on darwin, /proc/<pid>/stat on Linux — see the
// kernelProcessStart each of those files defines. ok is false if the process
// does not exist.
//
// This deliberately does NOT parse `ps -o lstart=`. ps formats that column
// through LC_TIME, and the layout is not merely translated — it is reordered:
// on a Türkçe Mac, which is the entire target audience, the same process prints
// "Çar  2 Eyl 07:50:52 2026" (day before month) where the C locale prints
// "Wed Sep  2 07:50:52 2026". Parsing that with a fixed English layout fails,
// psInfo reports the process dead, and Replay then reverts a RUNNING dpb's
// journal — deleting its routes and restoring the user's DNS while it is
// serving traffic, which is exactly what this file's opening comment calls "far
// worse than doing nothing". The kernel's own timeval has no locale.
func ProcessStart(pid int) (time.Time, bool) {
	if pid <= 0 {
		return time.Time{}, false
	}
	return procStarter(pid)
}

// psInfo reports pid's executable name and start time.
//
// It asks ps for `comm=` and nothing else. Every other column ps can print is
// either locale-formatted (lstart) or variable-width, and splitting a line on a
// field count that holds in en_US but not in tr_TR is how a live process came
// to look dead. comm is a path, so it is the same bytes in every locale.
func psInfo(pid int) (comm string, start time.Time, ok bool) {
	if pid <= 0 {
		return "", time.Time{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), psTimeout)
	defer cancel()
	res := psRunner.Run(ctx, "ps", "-o", "comm=", "-p", strconv.Itoa(pid))
	if res.Failed() {
		return "", time.Time{}, false
	}
	// Not firstLine(): that substitutes "(no output)" for an empty string, which
	// would turn "this pid does not exist" into a plausible-looking name.
	out := strings.TrimSpace(res.Combined)
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		out = out[:i]
	}
	comm = strings.TrimSpace(out)
	if comm == "" {
		return "", time.Time{}, false
	}
	start, _ = ProcessStart(pid)
	return comm, start, true
}
