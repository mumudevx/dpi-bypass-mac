//go:build windows

package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows/svc"

	"github.com/mumudevx/dpb/internal/cliapp"
)

// serviceStop carries the service control manager's stop control into the
// signal channel installSignals arms.
//
// It is created before the service's work starts, and buffered, so that a stop
// arriving before run() has called armServiceStop is held rather than dropped —
// a dropped stop is a service that never reverts. It stays nil in an
// interactive run, and armServiceStop then does nothing, which is why a normal
// `dpb run` on Windows pays no goroutine for this.
var serviceStop chan os.Signal

// armServiceStop relays the SCM's stop into ch, the channel signal.Notify feeds.
//
// Delivering it as a signal rather than cancelling anything directly is the
// point: watchSignals then runs exactly as it does for a Ctrl-C, and the
// teardown that reverts the user's proxy, DNS and routes is the one run()
// already drains on its way out. SIGTERM is the signal used because it is
// already in installSignals' Notify set and because it is what it means.
func armServiceStop(ch chan<- os.Signal) {
	if serviceStop == nil {
		return
	}
	go func() {
		for s := range serviceStop {
			ch <- s
		}
	}()
}

// runAsWindowsService hands the process to the SCM when the SCM started it, and
// reports whether it did.
func runAsWindowsService() (int, bool) {
	// svc.IsWindowsService is the authority on this — it is how the Go runtime
	// itself distinguishes the two cases, and internal/paths reads it the same
	// way. An error means "not a service", which is the safe reading: a CLI run
	// that mistakenly registered with the SCM would hang for 30 s and then be
	// killed, while a service that mistakenly ran as a CLI merely fails to find
	// a console and exits.
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return 0, false
	}

	serviceStop = make(chan os.Signal, 8)
	code := cliapp.RunWindowsService(cliapp.WindowsService{
		// os.Stdout and os.Stderr are read HERE, inside the closure, so they
		// are the files RunWindowsService redirected them to rather than the
		// unusable handles this process started with. os.Args[1:] is the tail
		// of the ImagePath `dpb service install --system` wrote, i.e. "run"
		// followed by whatever came after the `--`.
		Body:       func() int { return run(os.Args[1:], os.Stdout, os.Stderr) },
		Stop:       func() { serviceStop <- syscall.SIGTERM },
		StopBudget: teardownBudget,
	})
	return code, true
}
