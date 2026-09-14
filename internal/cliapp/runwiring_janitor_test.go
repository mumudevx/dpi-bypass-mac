//go:build !windows

// This file tests the wiring of the janitor subsystem, which is Unix-only.
// The janitor watches for SIGKILL via kqueue on macOS, and uses Unix signal
// semantics (syscall.Kill with signal 0 as a liveness check) that have no
// Windows equivalent. See internal/janitor for the janitor implementation.

package cliapp

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeDPBBinary is a stand-in for the dpb executable the janitor child is
// spawned from. It records its pid and the arguments it was given, then stays
// alive so the test can prove the parent both started it and reaped it.
//
// It is a throwaway process on purpose: proving the janitor wiring by
// SIGKILLing a real dpb would mean a real dpb holding real system state on the
// machine running the tests, which is the one thing the janitor exists to clean
// up after.
func fakeDPBBinary(t *testing.T) (exe, logPath string) {
	t.Helper()
	// Not t.TempDir(): its path is derived from the test name and can contain
	// characters a /bin/sh script would have to quote, which has nothing to do
	// with what is under test.
	dir, err := os.MkdirTemp("", "dpbfake")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	logPath = filepath.Join(dir, "spawn.log")
	exe = filepath.Join(dir, "dpb")
	// exec replaces the shell, so the pid written here is the pid that stays
	// alive and the pid the parent's Stop must reap.
	script := "#!/bin/sh\necho \"$$ $*\" > " + logPath + "\nexec sleep 30\n"
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake dpb: %v", err)
	}
	return exe, logPath
}

// waitForFile polls until path exists and is non-empty.
func waitForFile(t *testing.T, path string, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			return string(b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never appeared within %s", path, within)
	return ""
}

func processAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// ── the janitor ─────────────────────────────────────────────────────────────

// The kqueue janitor is the only defence that survives `kill -9`, because Go
// runs no defer, no recover and no signal handler on that path. Unwired, a hard
// kill strands the user's proxy settings — the exact failure `dpb doctor`
// exists to clean up after.
func TestRunSpawnsTheJanitorAndReapsItOnTheWayOut(t *testing.T) {
	t.Parallel()
	layout := shortLayout(t)
	h := startRun(t, newFakeMac(), layout, "-v", "--proxy-style", "pac")

	line := strings.Fields(strings.TrimSpace(waitForFile(t, h.spawnLog, 10*time.Second)))
	if len(line) < 5 {
		t.Fatalf("the janitor was started with %v; want a pid and the four arguments", line)
	}
	pid, err := strconv.Atoi(line[0])
	if err != nil {
		t.Fatalf("the child did not record a pid: %v", line)
	}

	args := strings.Join(line[1:], " ")
	// The subcommand and both arguments matter: the wrong journal path means
	// the child wakes and reverts nothing, silently, on the one exit path
	// nobody tests by hand.
	if !strings.Contains(args, "_janitor") {
		t.Errorf("the child was not started as the janitor subcommand: %q", args)
	}
	if want := "--parent-pid " + strconv.Itoa(os.Getpid()); !strings.Contains(args, want) {
		t.Errorf("the janitor watches the wrong process: %q, want %q", args, want)
	}
	if want := "--journal " + layout.JournalFile(); !strings.Contains(args, want) {
		t.Errorf("the janitor was given the wrong journal: %q, want %q", args, want)
	}
	if !processAlive(pid) {
		t.Fatalf("the janitor (pid %d) is not running while dpb is", pid)
	}

	h.shutdown(t)

	// A clean exit reverts the settings itself, so the child must be reaped
	// rather than left behind: a user who sees two dpb processes in Activity
	// Monitor has no way to know which one is the real one.
	deadline := time.Now().Add(5 * time.Second)
	for processAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processAlive(pid) {
		t.Fatalf("the janitor (pid %d) outlived a clean shutdown", pid)
	}

	// And it was stopped AFTER the system settings came off. Stopping it first
	// would open a window in which a `kill -9` during the revert leaves the
	// proxy pane pointed at a port that is closing.
	assertTeardownOrder(t, h.errOut.String(),
		"close the control socket", "revert system settings", "stop the janitor")
}

// With nothing to revert there is nothing for the janitor to do, and a stray
// process per run is a cost paid for no benefit.
func TestRunSpawnsNoJanitorWhenItMutatesNothing(t *testing.T) {
	t.Parallel()
	h := startRun(t, newFakeMac(), shortLayout(t), "--proxy-style", "none")

	time.Sleep(300 * time.Millisecond)
	if b, err := os.ReadFile(h.spawnLog); err == nil && len(b) > 0 {
		t.Fatalf("--proxy-style none spawned a janitor anyway: %q", b)
	}
}
