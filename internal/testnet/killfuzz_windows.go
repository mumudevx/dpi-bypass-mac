//go:build windows

package testnet

import (
	"errors"
	"os"
	"os/exec"
)

// killProcess terminates p via os.Process.Kill (TerminateProcess under the
// hood), never via p.Signal(syscall.SIGKILL): on Windows p.Signal answers
// everything except os.Kill with syscall.EWINDOWS — verified in
// $GOROOT/src/os/exec_windows.go — which is the exact defect Plan 2 found in
// the janitor's graceful stop, where a SIGTERM send blocked on EWINDOWS for
// two seconds before a successful teardown got reported as a failure.
//
// There is no signal being collapsed here. KillFuzz sends exactly one signal
// on the Unix side, SIGKILL (see its type doc) — never SIGTERM, and never a
// signal-0 liveness probe, which has no signal-based Windows equivalent at
// all (see internal/netstate/lock_windows.go's OpenProcess-based queries for
// how this codebase answers "is it alive" on Windows instead). So Windows'
// one termination primitive, TerminateProcess, loses nothing this file ever
// asked a signal to do.
//
// os.Process.Kill reports the process-already-gone race as os.ErrProcessDone
// once cmd.Wait's goroutine has reaped the process first — the Windows-side
// match for the ESRCH the Unix leaf swallows for the same reason — and
// once() tolerates exactly that race as its "Exited" outcome, so it is
// swallowed here too rather than pushed back into the portable body.
func killProcess(p *os.Process) error {
	err := p.Kill()
	if err != nil && errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

// killExitCode is the exit code a process ends with when os.Process.Kill ends
// it. Not a guess: $GOROOT/src/os/exec_windows.go's signal() calls
// syscall.TerminateProcess(handle, 1) for os.Kill, and TerminateProcess's
// second argument IS the terminated process's exit code.
const killExitCode = 1

// wasKilled reports whether waitErr is the exit of a process THIS file's
// killProcess ended.
//
// # Why it cannot ask the same question the Unix leaf asks
//
// syscall.WaitStatus on Windows carries an ExitCode and nothing else, and its
// Signaled() method is hard-coded to return false — there is no signal to
// report, because TerminateProcess is not a signal. So the Unix test
// (`st.Signaled() && st.Signal() == SIGKILL`) compiled here, read correctly,
// and was constant false: every kill fell through to "finished on its own".
// Measured on windows-latest, 2026-09-14: TestKillFuzzKillsAndReaps reported
// `{Iterations:3 Killed:0 Exited:3}` for a child that blocks forever and was
// killed all three times. The consequence is worse than a wrong number — a
// kill-fuzz report of "3 exited" says the crash window was never explored, so
// the crash-safety this fuzzer exists to prove would have been quietly
// unproven on Windows. See docs/MEASUREMENTS-windows.md.
//
// # What this costs
//
// The exit code is a weaker discriminator than a signal. A child that exits
// with status 1 ON ITS OWN, inside the window between the timer firing and
// TerminateProcess landing, is reported here as killed. That window is
// microseconds wide and the mistake is one iteration's classification, not a
// missed failure: After() still runs with the same `killed` value the caller
// then asserts against, and a child that had genuinely finished would fail
// those assertions on either platform. It is stated rather than hidden because
// a fuzzer's own report is the last place to round a number up.
func wasKilled(waitErr error) bool {
	var exit *exec.ExitError
	if !errors.As(waitErr, &exit) {
		return false
	}
	return exit.ExitCode() == killExitCode
}
