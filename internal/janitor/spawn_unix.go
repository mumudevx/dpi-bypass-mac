//go:build !windows

package janitor

import (
	"os"
	"syscall"
)

// detachAttrs puts the janitor in its OWN session with setsid. Without it the
// janitor shares the parent's process group, so the Ctrl-C that stops dpb is
// delivered to the janitor too — and the one exit path it exists to cover, a
// `kill -9` of the whole group, would kill the watcher along with the watched.
func detachAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// requestStop asks the janitor to exit, gracefully, with SIGTERM.
//
// The graceful phase is real here and worth having: the janitor gets to run
// its own shutdown path, and Child.Stop escalates to Kill only if the child is
// still there after stopBudget — a janitor that ignores SIGTERM is a bug worth
// reporting, not a reason to hold the user's network settings hostage.
func requestStop(p *os.Process) error { return p.Signal(syscall.SIGTERM) }
