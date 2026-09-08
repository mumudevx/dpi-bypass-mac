//go:build windows

package janitor

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// detachAttrs makes the janitor outlive the dpb that spawned it.
//
// Setsid is the Unix mechanism; DETACHED_PROCESS is the one that carries the
// weight here. It gives the child no console at all, so the Ctrl-C in the
// terminal that started dpb — the case the janitor exists to clean up after —
// has nowhere to be delivered, and closing that terminal does not take the
// janitor with it either.
//
// CREATE_NEW_PROCESS_GROUP is belt and braces rather than a second mechanism:
// a process with no console is already outside every console's control-event
// group, so on its own it changes nothing. It is kept because it is what would
// still hold if this child ever grew a console, and it costs a bit in a flags
// word. What it does NOT buy is a graceful stop — see requestStop.
func detachAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
}

// requestStop ends the janitor, immediately, with TerminateProcess.
//
// There is no graceful phase being skipped here for convenience: on Windows
// there is none to skip. A termination signal has to reach the child somehow,
// and neither route exists for this child.
//
//   - os.Process.Signal handles exactly one value, os.Kill, and answers every
//     other signal with syscall.Errno(syscall.EWINDOWS) — "not supported by
//     windows" (see $GOROOT/src/os/exec_windows.go). So a SIGTERM would not be
//     delivered late or partially; it would not be delivered at all, and Stop
//     would report that non-delivery as the failure of an otherwise perfect
//     teardown.
//   - The console-control route, GenerateConsoleCtrlEvent with CTRL_BREAK_EVENT,
//     needs the target to be attached to a console. detachAttrs deliberately
//     gives this child none, because a console is exactly what would let the
//     user's Ctrl-C kill the watcher along with the watched. A janitor we could
//     ask politely to stop would be a janitor that dies with its parent.
//
// So Kill is not the fallback, it is the mechanism. Child.Stop still waits for
// the child to actually go away and still reports it if it does not.
func requestStop(p *os.Process) error { return p.Kill() }
