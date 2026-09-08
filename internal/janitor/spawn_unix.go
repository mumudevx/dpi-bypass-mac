//go:build !windows

package janitor

import "syscall"

// detachAttrs puts the janitor in its OWN session with setsid. Without it the
// janitor shares the parent's process group, so the Ctrl-C that stops dpb is
// delivered to the janitor too — and the one exit path it exists to cover, a
// `kill -9` of the whole group, would kill the watcher along with the watched.
func detachAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
