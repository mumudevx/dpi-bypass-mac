//go:build windows

package cliapp

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/mumudevx/dpb/internal/paths"
)

// This file is the other side of service_windows.go: not the installer, but the
// process the service control manager starts.
//
// A Windows service is not a background copy of the CLI. The SCM starts the
// binary with no console, no standard handles and no signals, then talks to it
// over a control callback, and it expects the process to register within
// roughly 30 seconds or it declares the start failed. Two consequences shape
// everything below.
//
// The first is that stdout and stderr have to be created rather than inherited
// — see redirectServiceOutput.
//
// The second is that the SCM's stop control has to end up driving dpb's
// EXISTING shutdown, not a second one. dpb's teardown restores the user's
// system proxy, their DNS and their routes; two implementations of that will
// drift, and the day they do, one of them leaves a machine with its network
// pointed at a process that no longer exists. So WindowsService.Stop is wired
// in cmd/dpb to deliver a signal into the very channel signal.Notify feeds,
// which means the SCM's stop travels the SIGINT path unmodified: the
// "reverting system changes" notice, the context cancel, dispatch returning,
// and the teardown stack run()'s defer drains on the way out. Nothing in this
// file reverts anything.

// WindowsService is how cmd/dpb hands this process to the SCM.
//
// The three fields are deliberately all supplied by cmd/dpb rather than
// reconstructed here, because all three are things cmd/dpb owns: the command
// dispatch, the signal channel, and the revert budget.
type WindowsService struct {
	// Body runs the command exactly as an interactive run would — the same
	// dispatch, under the same signal context, wrapped in the same deferred
	// teardown — and returns the process exit code. It is called after the
	// standard streams have been redirected, and it must read os.Stdout and
	// os.Stderr when it is CALLED rather than capturing them earlier; see
	// redirectServiceOutput for why that matters.
	Body func() int

	// Stop asks Body to shut down the way a Ctrl-C asks it to. It must be the
	// same path, not an equivalent one.
	Stop func()

	// StopBudget is how long Body may reasonably take to return once Stop has
	// been called, i.e. dpb's teardown budget. It becomes the WaitHint this
	// service reports to the SCM, so the two cannot drift into the SCM giving
	// up on a revert that was still running.
	StopBudget time.Duration
}

// winServiceStopSlack is added to StopBudget when reporting the stop WaitHint.
// The budget covers the revert itself; the slack covers the scheduling and the
// unwinding around it, so a revert that uses its whole budget is not killed a
// millisecond before it finishes.
const winServiceStopSlack = 5 * time.Second

// winServiceStopTick is how often the stop path re-reports SERVICE_STOP_PENDING
// with a higher checkpoint. Comfortably inside the WaitHint, because the point
// is to keep telling the SCM that progress is being made.
const winServiceStopTick = 2 * time.Second

// RunWindowsService redirects the standard streams, registers with the SCM and
// blocks until the service stops. It returns the process exit code.
func RunWindowsService(ws WindowsService) int {
	closeLogs, err := redirectServiceOutput()
	if err != nil {
		// There is nowhere to print this: the failure IS that there is nowhere
		// to print. Returning non-zero at least puts a failed start in the
		// Windows event log, which is the only channel left. Pressing on
		// regardless would run `dpb run` — a command whose whole job is to
		// mutate the machine's network — with no record anyone can audit.
		return 1
	}
	defer closeLogs()

	h := &winServiceHandler{ws: ws}
	if err := svc.Run(serviceName, h); err != nil {
		// StartServiceCtrlDispatcher failed. svc.IsWindowsService said this
		// process was started by the SCM, so this is not the "someone ran it
		// from a shell" case; it is a real registration failure and belongs in
		// the log the redirect above just opened.
		fmt.Fprintf(os.Stderr, "dpb: the service control manager refused this process: %v\n", err)
		return 1
	}
	return h.code
}

// redirectServiceOutput points os.Stdout and os.Stderr at the two files
// `dpb service logs` reads.
//
// This has no launchd counterpart because it needs none: launchd redirects a
// job's streams FOR it, from the StandardOutPath and StandardErrorPath keys
// service_darwin.go writes into the plist. The SCM has no equivalent — there is
// no SERVICE_CONFIG_* level for a service's standard streams, and a service is
// started with no console and no parent to inherit handles from, so
// GetStdHandle returns nothing usable and every write to os.Stdout fails with
// ERROR_INVALID_HANDLE. The service therefore has to redirect itself, before
// anything writes.
//
// Reassigning the os.Stdout and os.Stderr *variables* is the whole mechanism,
// and it is why cmd/dpb passes a Body closure instead of writers: Windows has
// no dup2, and windows.SetStdHandle only changes what GetStdHandle returns for
// later callers — it cannot re-point the *os.File already built from the
// handle syscall.Stdout captured at process start. So the redirect must happen
// before anything reads os.Stdout, and Body reads it when called.
//
// The practical gap this leaves is small, because `dpb run` writes its real
// record to the NDJSON event log in the same directory through internal/emit.
// It is not zero: anything written before this returns is lost, which includes
// a failure of this function itself. serviceLogs' comment in service.go states
// that difference where someone reading the logs will meet it.
func redirectServiceOutput() (func(), error) {
	// paths.Resolve inside a service returns the machine-wide %ProgramData%
	// layout — paths_windows.go asks svc.IsWindowsService the same question
	// cmd/dpb just asked — which is the same directory
	// serviceScopeFor(true) computed for the installer via paths.SystemLayout.
	// That is why `dpb service logs --system` finds these files.
	l, err := paths.Resolve()
	if err != nil {
		return nil, fmt.Errorf("service: resolve the log directory: %w", err)
	}
	if err := os.MkdirAll(l.LogDir, 0o755); err != nil {
		return nil, fmt.Errorf("service: create %s: %w", l.LogDir, err)
	}
	out, err := openServiceLog(filepath.Join(l.LogDir, serviceOutLog))
	if err != nil {
		return nil, err
	}
	errf, err := openServiceLog(filepath.Join(l.LogDir, serviceErrLog))
	if err != nil {
		_ = out.Close()
		return nil, err
	}
	os.Stdout, os.Stderr = out, errf
	return func() { _ = out.Close(); _ = errf.Close() }, nil
}

// openServiceLog opens one of the two stream files.
func openServiceLog(path string) (*os.File, error) {
	// O_APPEND rather than O_TRUNC: the SCM restarts a crashed service (see
	// serviceRecoveryActions), and the log of the crash that caused the restart
	// is precisely the one worth keeping.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("service: open %s: %w", path, err)
	}
	return f, nil
}

// winServiceHandler is the svc.Handler the SCM drives.
type winServiceHandler struct {
	ws WindowsService
	// code is the exit code Body returned, kept for RunWindowsService to
	// return as the process's own.
	code int
}

// Execute is the SCM's view of `dpb run`.
//
// Reporting Running before Body has finished starting is deliberate and is what
// MSDN asks for: the SCM's start timeout applies to reaching a reported state,
// and a `dpb run` that is still probing is running as far as the SCM is
// concerned. The alternative — holding StartPending until the tunnel is up —
// would make a slow line look like a failed service.
func (h *winServiceHandler) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{
		State:    svc.StartPending,
		WaitHint: uint32(serviceStartWait / time.Millisecond),
	}

	done := make(chan int, 1)
	go func() { done <- h.ws.Body() }()

	// Only Stop and Shutdown are accepted. Pause and Continue are not: there is
	// no coherent "paused" state for a process holding the machine's default
	// route, and an accepted control that does nothing is worse than one the
	// SCM refuses on the service's behalf.
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case code := <-done:
			// Body returned on its own: `dpb run` refused for safety, hit an
			// error, or finished. Its teardown has already run — it is the same
			// deferred revert the CLI path unwinds — so reporting Stopped now
			// is truthful rather than merely convenient.
			return h.finish(code)

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				// MSDN requires SERVICE_CONTROL_INTERROGATE to be answered
				// promptly; echoing back the status the SCM last saw is the
				// answer, and it must not wait on anything. This arm exists so
				// that a `sc interrogate` during a long revert still gets a
				// reply.
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// Shutdown is treated identically to Stop. The system is going
				// down, but the proxy settings and DNS overrides dpb wrote are
				// persistent machine state that would still be wrong at the
				// next boot, so they have to be reverted here too.
				return h.stop(r, changes, done)
			default:
				// The SCM checks ControlsAccepted before delivering, so nothing
				// dpb did not ask for should arrive. Ignoring it is correct;
				// blocking on it would hang the control handler.
			}
		}
	}
}

// stop drives dpb's ordinary shutdown and keeps the SCM informed while it runs.
func (h *winServiceHandler) stop(r <-chan svc.ChangeRequest, changes chan<- svc.Status, done <-chan int) (bool, uint32) {
	// The one line that matters in this file. It asks for exactly the shutdown
	// a Ctrl-C asks for; Body's own deferred revert then restores the proxy,
	// DNS and routes on its way out. Nothing here duplicates that work.
	h.ws.Stop()

	// StopPending with a WaitHint, refreshed with a rising CheckPoint, is how
	// MSDN says a service asks for more time: the SCM waits WaitHint
	// milliseconds for the next status carrying a larger CheckPoint before
	// deciding the service has hung. The hint is dpb's own revert budget rather
	// than a number invented here, so the SCM cannot give up on a teardown that
	// is still inside its budget.
	hint := uint32((h.ws.StopBudget + winServiceStopSlack) / time.Millisecond)
	check := uint32(0)
	report := func() {
		check++
		changes <- svc.Status{State: svc.StopPending, WaitHint: hint, CheckPoint: check}
	}
	report()

	tick := time.NewTicker(winServiceStopTick)
	defer tick.Stop()
	for {
		select {
		case code := <-done:
			return h.finish(code)
		case <-tick.C:
			report()
		case c := <-r:
			if c.Cmd == svc.Interrogate {
				changes <- c.CurrentStatus
			}
			// A second Stop while stopping is neither an error nor a reason to
			// call Stop again: cmd/dpb's signal watcher already treats a repeat
			// delivery as the user's give-up-now escape hatch, and calling it
			// twice from here would trip that on the SCM's behalf.
		}
	}
}

// finish records the exit code and reports it to the SCM.
func (h *winServiceHandler) finish(code int) (bool, uint32) {
	h.code = code
	// Reported as service-specific. A dpb exit code is not a Win32 error
	// number — 5 means "refused for safety: a VPN owns the default route", not
	// ERROR_ACCESS_DENIED — and the SCM has a field for exactly this
	// distinction: SERVICE_STATUS.dwServiceSpecificExitCode, used when
	// dwWin32ExitCode is ERROR_SERVICE_SPECIFIC_ERROR. x/sys' svc package
	// arranges both from this bool. Reporting a dpb code as a Win32 code would
	// put a plausible lie in the event log.
	//
	// Reporting Stopped at all, rather than letting the process die quietly, is
	// also what keeps the recovery actions honest: they fire only for a service
	// that vanishes WITHOUT reporting Stopped, so a deliberate `dpb run` exit is
	// left alone and only a crash is restarted. See serviceRecoveryReset.
	return code != 0, uint32(code)
}
