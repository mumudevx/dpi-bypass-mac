//go:build !windows

package janitor

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeDPB is a stand-in for the dpb binary: it ignores the arguments Spawn
// passes and stays alive so the properties of the CHILD — its pid, its session,
// and whether Stop actually reaps it — can be asserted without running a real
// dpb that would hold system state.
func fakeDPB(t *testing.T) string {
	t.Helper()
	// Not t.TempDir(): a script under a path with a space in it would need
	// quoting that has nothing to do with what is under test.
	dir, err := os.MkdirTemp("", "dpbfake")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	path := filepath.Join(dir, "dpb")
	script := "#!/bin/sh\nexec sleep 30\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake dpb: %v", err)
	}
	return path
}

func TestSpawnStartsTheChildInItsOwnSession(t *testing.T) {
	child, err := Spawn(SpawnOptions{
		Exe:         fakeDPB(t),
		ParentPID:   os.Getpid(),
		JournalPath: filepath.Join(t.TempDir(), "journal.ndjson"),
	})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	t.Cleanup(func() { _ = child.Stop() })

	pid := child.PID()
	if pid <= 0 {
		t.Fatal("Spawn returned a child with no pid")
	}

	// Its own session is the load-bearing property. Sharing the parent's process
	// group means the Ctrl-C that stops dpb also kills the janitor, and the one
	// exit path it exists to cover — a kill -9 of the whole group — would take
	// the watcher with the watched.
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatalf("getpgid(%d): %v", pid, err)
	}
	if pgid != pid {
		t.Fatalf("the child's process group is %d, not its own pid %d; setsid did not take", pgid, pid)
	}
	if selfPgid, err := syscall.Getpgid(os.Getpid()); err == nil && pgid == selfPgid {
		t.Fatal("the child shares this process's group")
	}
}

func TestChildStopReapsTheProcess(t *testing.T) {
	child, err := Spawn(SpawnOptions{
		Exe:         fakeDPB(t),
		JournalPath: filepath.Join(t.TempDir(), "journal.ndjson"),
	})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	pid := child.PID()

	if err := child.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Stop is idempotent; the second call must not re-signal a reaped pid.
	if err := child.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pid %d is still alive after Stop", pid)
}

func TestSpawnNeedsAJournal(t *testing.T) {
	if _, err := Spawn(SpawnOptions{Exe: fakeDPB(t)}); err == nil {
		t.Fatal("Spawn with no journal path was accepted")
	}
}

func TestSpawnReportsAMissingBinary(t *testing.T) {
	_, err := Spawn(SpawnOptions{
		Exe:         filepath.Join(t.TempDir(), "not-a-binary"),
		JournalPath: "/tmp/journal.ndjson",
	})
	if err == nil {
		t.Fatal("Spawn of a missing binary produced no error")
	}
	if !strings.Contains(err.Error(), JanitorCommand) {
		t.Errorf("err = %v, want it to name the subcommand it tried to run", err)
	}
}

// A failed Spawn must hand back a nil Child, not a half-constructed one: the
// caller on the other end of this — Run's setup in cmd/dpb — only checks the
// error, and a non-nil Child returned alongside one would be a Child whose
// PID() and Stop() nobody has thought through for this path.
func TestSpawnReturnsNoChildOnFailure(t *testing.T) {
	child, err := Spawn(SpawnOptions{
		Exe:         filepath.Join(t.TempDir(), "not-a-binary"),
		JournalPath: "/tmp/journal.ndjson",
	})
	if err == nil {
		t.Fatal("Spawn of a missing binary produced no error")
	}
	if child != nil {
		t.Fatalf("Spawn returned a non-nil Child alongside an error: %+v", child)
	}
}

// Stop's force-kill path is the safety valve the code comment names directly:
// "a janitor that ignores SIGTERM is a bug worth reporting, not a reason to
// hold the user's network settings hostage." This pins the whole contract on
// a child that actually does ignore it: SIGTERM is sent, the child outlives
// stopBudget anyway, Stop reports the timeout instead of returning nil, and
// the child is verifiably dead — via SIGKILL — by the time Stop returns.
func TestChildStopKillsAChildThatIgnoresSIGTERM(t *testing.T) {
	dir, err := os.MkdirTemp("", "dpbstubborn")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "dpb")
	ready := filepath.Join(dir, "ready")
	// `trap '' TERM` sets SIGTERM's disposition to SIG_IGN. Unlike a caught
	// signal (which reverts to SIG_DFL across exec), SIG_IGN survives exec, so
	// the sleep this script execs into truly ignores every SIGTERM Stop sends
	// — but only once the trap has actually run. The `touch` after it, still
	// running in the same untouched shell process, is the signal to the test
	// that the trap is in effect; polling for that file rather than sleeping a
	// fixed duration is what keeps this deterministic under a loaded machine
	// (a fixed sleep here was observed to be too short under `go test ./...`'s
	// full parallel load, even at 300ms).
	script := "#!/bin/sh\ntrap '' TERM\ntouch " + ready + "\nexec sleep 30\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	child, err := Spawn(SpawnOptions{
		Exe:         path,
		JournalPath: filepath.Join(t.TempDir(), "journal.ndjson"),
	})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	pid := child.PID()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the child never reached its trap; ready marker never appeared")
		}
		time.Sleep(5 * time.Millisecond)
	}

	start := time.Now()
	stopErr := child.Stop()
	elapsed := time.Since(start)

	if stopErr == nil {
		t.Fatal("Stop on a SIGTERM-ignoring child returned nil, want the timeout reported")
	}
	if !strings.Contains(stopErr.Error(), "did not exit") {
		t.Fatalf("Stop err = %v, want it to name the timeout", stopErr)
	}
	if elapsed < stopBudget {
		t.Fatalf("Stop returned after %s, before its own %s budget could have elapsed", elapsed, stopBudget)
	}

	killDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(killDeadline) {
		if syscall.Kill(pid, 0) == syscall.ESRCH {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pid %d is still alive after Stop's force-kill", pid)
}

// A nil Child is what a caller holds when Spawn failed, and the clean exit path
// calls Stop unconditionally.
func TestNilChildIsSafe(t *testing.T) {
	var c *Child
	if c.PID() != 0 {
		t.Error("nil Child reported a pid")
	}
	if err := c.Stop(); err != nil {
		t.Errorf("nil Child Stop: %v", err)
	}
}

// Stop on a child that has already exited on its own must not report a failure:
// the clean exit path calls it unconditionally, and a janitor that raced ahead
// and finished is the normal outcome after a crash was already repaired.
func TestStopOnAnAlreadyExitedChild(t *testing.T) {
	dir, err := os.MkdirTemp("", "dpbfast")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "dpb")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	child, err := Spawn(SpawnOptions{
		Exe:         path,
		JournalPath: filepath.Join(t.TempDir(), "journal.ndjson"),
	})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	// Give it time to be gone before Stop is called.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(child.PID(), 0) == syscall.ESRCH {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := child.Stop(); err != nil {
		t.Fatalf("Stop on an exited child: %v", err)
	}
}

// The environment is passed through, because it is what carries SUDO_USER and
// therefore what makes the child resolve the same paths as its parent.
func TestSpawnPassesTheEnvironment(t *testing.T) {
	dir, err := os.MkdirTemp("", "dpbenv")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	out := filepath.Join(dir, "seen")
	path := filepath.Join(dir, "dpb")
	script := "#!/bin/sh\nprintf '%s' \"$DPB_TEST_MARKER\" > " + out + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	child, err := Spawn(SpawnOptions{
		Exe:         path,
		JournalPath: filepath.Join(t.TempDir(), "journal.ndjson"),
		Env:         []string{"DPB_TEST_MARKER=carried"},
	})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	t.Cleanup(func() { _ = child.Stop() })

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if b, rerr := os.ReadFile(out); rerr == nil && string(b) == "carried" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the child did not see the environment it was given")
}
