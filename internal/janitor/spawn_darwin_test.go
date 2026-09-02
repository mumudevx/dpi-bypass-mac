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
