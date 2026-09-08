//go:build windows

package netstate

import (
	"os"
	"testing"
	"time"
)

// A second acquire must fail while the first is held. LockFileEx with
// LOCKFILE_FAIL_IMMEDIATELY is the Windows analogue of flock(LOCK_EX|LOCK_NB);
// without FAIL_IMMEDIATELY it blocks forever instead of reporting contention.
func TestLockIsExclusive(t *testing.T) {
	path := t.TempDir() + `\dpb.lock`
	f1, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f1.Close()
	if err := lockFile(f1); err != nil {
		t.Fatalf("first lockFile() = %v, want nil", err)
	}

	f2, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	defer f2.Close()
	if err := lockFile(f2); err == nil {
		t.Fatal("second lockFile() = nil, want a contention error")
	}

	if err := unlockFile(f1); err != nil {
		t.Fatalf("unlockFile() = %v", err)
	}
	if err := lockFile(f2); err != nil {
		t.Fatalf("lockFile() after release = %v, want nil", err)
	}
	_ = unlockFile(f2)
}

// Our own PID must report a start time, and a PID that cannot exist must not.
func TestProcessStartAnswersForOurselves(t *testing.T) {
	if _, ok := ProcessStart(os.Getpid()); !ok {
		t.Error("ProcessStart(self) reported no start time")
	}
	if _, ok := ProcessStart(-1); ok {
		t.Error("ProcessStart(-1) reported a start time for an impossible pid")
	}
}

// The failure this file exists to prevent: a LIVE process reported dead makes
// Replay revert a running dpb's journal, tearing down the user's proxy, DNS and
// routes mid-session. Every Windows leaf OwnerAlive depends on is exercised
// here at once — processIdentity, sameExecutable and ProcessStart.
func TestOwnerAliveSeesThisRunningProcess(t *testing.T) {
	pid := os.Getpid()
	start, ok := ProcessStart(pid)
	if !ok {
		t.Fatal("ProcessStart(self) reported no start time")
	}
	if !OwnerAlive(pid, start) {
		t.Fatal("OwnerAlive said this very process is dead")
	}
	// The pid-reuse defence: same pid, different start time, different process.
	if OwnerAlive(pid, start.Add(-time.Hour)) {
		t.Fatal("OwnerAlive ignored a mismatched start time; pid reuse would clobber a live run")
	}
	if OwnerAlive(0, start) || OwnerAlive(-1, start) {
		t.Fatal("OwnerAlive accepted a non-positive pid")
	}
	if _, ok := processIdentity(pid); !ok {
		t.Fatal("processIdentity could not name this very process")
	}
}
