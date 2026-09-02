package janitor

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// The kqueue watcher is exercised against a THROWAWAY child, never against a
// dpb that holds system state. `sleep` is the perfect subject: it does nothing,
// it survives long enough to be watched, and killing it with SIGKILL is exactly
// the event the janitor exists to detect.

// spawnSleeper starts a process that will not exit on its own.
func spawnSleeper(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleeper: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

func TestWaitForExitWakesOnSIGKILL(t *testing.T) {
	cmd := spawnSleeper(t)
	pid := cmd.Process.Pid

	done := make(chan error, 1)
	go func() { done <- WaitForExit(context.Background(), pid) }()

	// Let the watcher register before the process dies, which is the ordinary
	// ordering: the janitor is spawned first and the parent dies later.
	time.Sleep(100 * time.Millisecond)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitForExit: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Two seconds is the promise docs/PLAN.md's M12 clause makes about how
		// quickly the proxy settings come back after a kill -9.
		t.Fatal("WaitForExit did not notice the kill within 2s")
	}
}

// A pid that is already gone is the ANSWER, not an error. The parent can die
// between the spawn and the registration, and treating that as a failure would
// leave the journal unreplayed in exactly the case the janitor exists for.
func TestWaitForExitOnAnAlreadyDeadProcess(t *testing.T) {
	cmd := exec.Command("/usr/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}

	start := time.Now()
	if err := WaitForExit(context.Background(), pid); err != nil {
		t.Fatalf("WaitForExit on a reaped pid: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("WaitForExit took %s on a dead pid; it should return at once", d)
	}
}

// A janitor whose parent is exiting cleanly is stopped by its context, and must
// then say so rather than reporting success — a successful wait means "the
// parent is gone, replay now".
func TestWaitForExitHonoursCancellation(t *testing.T) {
	cmd := spawnSleeper(t)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- WaitForExit(ctx, cmd.Process.Pid) }()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("WaitForExit = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForExit ignored its cancelled context")
	}
}

func TestWaitForExitRejectsANonPID(t *testing.T) {
	for _, pid := range []int{0, -1} {
		if err := WaitForExit(context.Background(), pid); !errors.Is(err, ErrNoParent) {
			t.Errorf("WaitForExit(%d) = %v, want ErrNoParent", pid, err)
		}
	}
}

// A nil context must not panic: the janitor's own Run passes one through and a
// caller may not.
func TestWaitForExitWithANilContext(t *testing.T) {
	cmd := exec.Command("/usr/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Wait()
	//nolint:staticcheck // a nil context is exactly what is under test here
	if err := WaitForExit(nil, pid); err != nil {
		t.Fatalf("WaitForExit with a nil context: %v", err)
	}
}
