//go:build windows

package janitor

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// detachAttrs makes the janitor outlive the dpb that spawned it.
//
// Setsid is the Unix mechanism; Windows has two flags and needs both.
// DETACHED_PROCESS gives the child no console, so closing the terminal that
// started dpb does not take the janitor with it. CREATE_NEW_PROCESS_GROUP stops
// a Ctrl-C in that terminal from being delivered to the janitor — which matters
// precisely because Ctrl-C is the case the janitor exists to clean up after.
func detachAttrs() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
}
