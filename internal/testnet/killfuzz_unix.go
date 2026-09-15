//go:build !windows

package testnet

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// killProcess sends SIGKILL to p — the only signal KillFuzz ever needs; see
// the type doc on KillFuzz for why SIGTERM, SIGINT and a liveness probe (a
// signal-0 send) have no place in this file.
//
// It goes through the raw pid via syscall.Kill rather than p.Signal, because
// the raw syscall reports the race where the process already exited as a
// plain ESRCH errno — cheap and unambiguous to recognise here, where
// once() tolerates exactly that race as its "Exited" outcome rather than a
// failure.
func killProcess(p *os.Process) error {
	err := syscall.Kill(p.Pid, syscall.SIGKILL)
	if err != nil && errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

// wasKilled reports whether waitErr is the exit of a process THIS file's
// killProcess ended.
//
// The wait status carries the signal, so the answer is exact: SIGKILL is the
// only signal killProcess ever sends, so a status that was signalled with
// SIGKILL is our kill and nothing else is. A child that exited on its own in
// the window between the timer firing and the kill landing has an exit code
// instead and is reported honestly as "exited" — overstating kills would
// overstate how much of the crash window the suite has explored.
func wasKilled(waitErr error) bool {
	var exit *exec.ExitError
	if !errors.As(waitErr, &exit) {
		return false
	}
	st, ok := exit.Sys().(syscall.WaitStatus)
	return ok && st.Signaled() && st.Signal() == syscall.SIGKILL
}
