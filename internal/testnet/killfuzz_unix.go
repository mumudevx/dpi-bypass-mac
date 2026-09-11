//go:build !windows

package testnet

import (
	"errors"
	"os"
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
