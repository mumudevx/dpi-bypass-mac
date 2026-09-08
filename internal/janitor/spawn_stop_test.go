package janitor

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// stopHelperEnv marks the re-executed test binary as the child Stop is aimed
// at, rather than an ordinary test run.
const stopHelperEnv = "DPB_JANITOR_STOP_HELPER"

// TestStopHelperProcess is not a test. It is the long-lived child
// TestStopEndsTheChildWithoutSpendingTheStopBudget stops, re-executed out of
// this same test binary so that the child is the SAME on every platform.
//
// A shell script would have been simpler and is what the Unix tests in this
// package use, but it would have made the one contract that broke on Windows —
// that Stop works there at all — untestable on Windows, which is precisely how
// the defect got in.
func TestStopHelperProcess(t *testing.T) {
	if os.Getenv(stopHelperEnv) != "1" {
		t.Skip("not the helper child")
	}
	// Far longer than stopBudget: this process must be killed, never observed
	// exiting on its own.
	time.Sleep(30 * time.Second)
}

// Stop must end the janitor and say nothing on the CLEAN exit path — the path
// every Ctrl-C takes, after the parent has already run UndoAll itself.
//
// Both halves of that are regressions. Stop used to send SIGTERM from shared
// code, and os/exec_windows.go answers every signal but Kill with
// syscall.EWINDOWS: on Windows the child was therefore never asked to exit, so
// Stop sat out its whole 2 s stopBudget waiting for a process nothing had
// touched, and then returned "not supported by windows" as the first error of
// a teardown that had in fact succeeded completely. Timing is asserted for that
// reason and not as a performance check: spending the budget is the signature
// of a stop request that was never delivered.
func TestStopEndsTheChildWithoutSpendingTheStopBudget(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestStopHelperProcess$")
	cmd.Env = append(os.Environ(), stopHelperEnv+"=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper child: %v", err)
	}
	c := &Child{cmd: cmd}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
	})

	if c.PID() <= 0 {
		t.Fatal("the helper child reported no pid")
	}

	start := time.Now()
	err := c.Stop()
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Stop on a healthy child = %v, want nil: a successful teardown must not report a failure", err)
	}
	if elapsed >= stopBudget {
		t.Fatalf("Stop took %s, the whole %s budget; the child was never asked to exit", elapsed, stopBudget)
	}
	// Wait has already run inside Stop, so the exit status is recorded. A child
	// that is merely unreferenced rather than reaped would leave this nil.
	if cmd.ProcessState == nil {
		t.Fatal("Stop returned before the child was reaped")
	}
}
