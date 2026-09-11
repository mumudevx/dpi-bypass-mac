//go:build windows

package testnet

import (
	"errors"
	"os"
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
