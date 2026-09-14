//go:build windows

package cliapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/mumudevx/dpb/internal/paths"
)

// dpb installs itself as a Windows service so it survives logout and reboot.
// This file is service_darwin.go's opposite number for HALF of Windows: the
// SCM (winService, --system, LocalSystem) mechanism. The other half —
// winLogonTask, a Scheduled Task running as the interactive user, which is
// what proxy mode needs — lives in service_task_windows.go, along with the
// reasoning for why Windows needs two mechanisms where darwin needs one.
// Read that file's header first; this one assumes it. service.go's five
// mechanism calls (installMechanism, uninstallMechanism, startMechanism,
// stopMechanism, statusMechanism) are defined once, here, and dispatch to
// service_task_windows.go's functions when a scope's mech is winLogonTask —
// they are not duplicated per mechanism.
//
// Two things about the SCM mechanism specifically are deliberate.
//
// First, the scope. --system here means a LocalSystem service, which is the
// scope TUN mode needs anyway — creating the wintun adapter and editing the
// route table both require administrator — and it is the scope the SCM is
// actually for. It is not the scope for proxy mode; see
// service_task_windows.go for why that is a different mechanism rather than
// a different flag to this one.
//
// Second, the verification. Every mutation in this tool is confirmed through a
// different subsystem than it was applied with (see netstate's package
// comment). Everything below writes through the SCM — CreateService, Start,
// Delete — so asking the SCM again would only prove the SCM agrees with
// itself. The second observer is the registry key the SCM persists the
// definition into, HKLM\SYSTEM\CurrentControlSet\Services\dpb, read through
// RegOpenKeyEx/RegQueryValueEx. Two observers, neither of them a parsed
// command-line tool: on darwin the equivalent split is plutil plus `launchctl
// print`, and service_darwin.go's header explains why that is the best launchd
// allows. Windows allows better, so this takes it — and the registry read also
// works without elevation, which OpenSCManager's usual ALL_ACCESS does not.
//
// Third, what a status verb is allowed to claim. readServiceRegistry and
// queryWinService each distinguish "not there" from "I could not look", and
// statusMechanism reports the second as the third return value rather than
// folding it into "not installed". See service.go's serviceStatus for the two
// real defects that rule comes from. service_task_windows.go's statusLogonTask
// makes the identical distinction for its own two observers plus the process
// snapshot that answers "is it running".

// serviceName is the name the SCM knows dpb by, and therefore the name of the
// registry subkey under HKLM\SYSTEM\CurrentControlSet\Services. It is short and
// lowercase rather than the reverse-DNS serviceLabel launchd uses, because it
// is what a user types at `sc.exe query` and reads in services.msc, and because
// the registry key is named after it. Like serviceLabel it is not a value to
// change lightly: a rename orphans the service an older dpb installed.
const serviceName = "dpb"

// serviceDisplayName and serviceDescription are what services.msc shows. They
// are the only place a human meets this service without having typed `dpb`, so
// they say what it does to the machine rather than just naming the binary.
const (
	serviceDisplayName = "dpb (DPI bypass)"
	serviceDescription = "Runs dpb's DPI-bypass proxy or tunnel as a LocalSystem service. " +
		"Logs to %ProgramData%\\dpb\\logs; `dpb service logs --system` prints them."
)

// serviceRegKey is the second observer's address. The SCM writes every
// service's definition here (MSDN, "Service Record List"), which is what makes
// reading it a genuinely independent check rather than a second opinion from
// the same source.
const serviceRegKey = `SYSTEM\CurrentControlSet\Services\` + serviceName

// serviceInstallHint, serviceFollowHint, serviceHelp and serviceLogNote are
// four of the five platform-provided identifiers service.go's header lists
// (serviceName above is the fifth).
//
// The install hint carries --system because the plain form refuses here, and it
// says "elevated" because requireRoot would otherwise be the first thing the
// user hit. The follow hint is PowerShell's because Windows has no tail(1).
const serviceInstallHint = "dpb service install --system (from an Administrator prompt)"

func serviceFollowHint(path string) string {
	return "follow with: powershell -Command \"Get-Content -Wait -Tail 20 '" + path + "'\""
}

// serviceHelp is Windows' half of service.go's help text.
//
// Every string here has to describe TWO mechanisms, because that is what this
// platform has: a logon Scheduled Task for the scope with no flag, and an SCM
// service for --system. Help text is static, so it cannot resolve a scope the
// way kind() does — it names both and says which is which, which is also the
// distinction a user most needs before they type either one. The wording
// follows the README's Windows section deliberately: a user who has read one
// should not have to re-learn the split from the other.
var serviceHelp = serviceHelpText{
	cmdShort: "Install, remove and inspect dpb as a logon task or a Windows service",
	cmdLong: "service manages dpb's background job, which on Windows is one of two\n" +
		"mechanisms — they are not interchangeable.\n\n" +
		"By default it installs a Scheduled Task with a logon trigger, running as YOU.\n" +
		"That is the right choice for proxy mode and needs no Administrator: the proxy\n" +
		"environment variables and Internet Settings it writes are per-user, and only a\n" +
		"process inside your own logon can put them where your applications will read\n" +
		"them.\n\n" +
		"--system creates a LocalSystem service in the service control manager instead.\n" +
		"That needs Administrator, and it is the right choice for --tun, which needs\n" +
		"Administrator anyway for the wintun adapter and the route table. A LocalSystem\n" +
		"service cannot write your HKCU hive, so it is NOT a way to run proxy mode.",
	scopeFlag:    "act on the machine-wide LocalSystem service instead of your login session's Scheduled Task",
	installShort: "Register the logon task (or, with --system, create the service) and start it",
	installLong: "install registers the job, confirms it through two independent observers, and\n" +
		"starts it.\n\n" +
		"With no flag that is a Scheduled Task with a logon trigger, running as you: it\n" +
		"is registered with schtasks, read back from the definition Task Scheduler\n" +
		"persists, and started immediately — a logon trigger alone fires only at your\n" +
		"NEXT logon, which would leave your proxy dark until then.\n\n" +
		"Anything after `--` is appended to the `dpb run` command line the job runs.\n" +
		"Those flags are parsed here, before anything is registered, so a typo is a\n" +
		"usage error now rather than a job that fails at every logon.\n\n" +
		"For scripts: --system creates a LocalSystem service, which the service control\n" +
		"manager refuses to an unelevated token, so without Administrator it stops\n" +
		"before touching anything and returns exit 4. That code means \"re-run this\n" +
		"elevated\" and nothing else — `dpb tune` reports \"nothing is blocked here\" as\n" +
		"exit 6, not 4, so a caller can branch on the two.",
	installExample: "  dpb service install\n" +
		"  dpb service install -- --profile turkey --port 8081\n" +
		"  dpb service install --system   (from an Administrator prompt)",
	uninstallShort: "Delete the logon task, or with --system the service",
	stopShort:      "End the running job, leaving it installed",
	stopLong: "stop ends the job's process and leaves the job itself registered, so the\n" +
		"logon task still fires at your next logon and the service still starts at the\n" +
		"next boot. `dpb service start` runs it again now; `dpb service uninstall` is\n" +
		"what removes it.",
}

// serviceLogNote is why `dpb service logs` may have nothing to print here.
//
// The two files it reads are real for the SCM mechanism — svcrun_windows.go
// redirects the service process's own os.Stdout and os.Stderr into them — and
// are never written at all for the logon task, which has no console and no
// redirect. Saying so is the whole point: without it the command answers "(no
// such file — the job has not written to it yet)" twice for a task that is
// running perfectly, and a tester reasonably concludes their install is
// broken. See logonTaskRecordHint in service_task_windows.go for what the
// logon task's record actually is, and why wrapping its action in `cmd /c` to
// manufacture these files was declined.
func serviceLogNote(s serviceScope) string {
	if s.mech != winLogonTask {
		return ""
	}
	return "Note: a Scheduled Task action gets no console and no output redirection, so\n" +
		"the two files below are not written by this mechanism at all — only\n" +
		"`dpb service install --system`'s service writes them (it redirects its own\n" +
		"streams). This job's record is Task Scheduler's own:\n  " + logonTaskRecordHint
}

// Timings. The SCM is asynchronous everywhere: Start, Control and Delete all
// return once the request is accepted, not once it has taken effect, so every
// one of them is followed by a poll rather than believed.
const (
	serviceStartWait  = 30 * time.Second
	serviceStopWait   = 30 * time.Second
	serviceDeleteWait = 10 * time.Second
	servicePoll       = 250 * time.Millisecond
)

// serviceRecoveryReset is MSDN's SERVICE_FAILURE_ACTIONS.dwResetPeriod: the
// span of failure-free running after which the SCM forgets earlier failures, in
// seconds.
//
// It is deliberately NOT paired with SetRecoveryActionsOnNonCrashFailures(true).
// Left at the Windows default of false, the recovery actions fire only when the
// process dies WITHOUT reporting SERVICE_STOPPED — a crash. A `dpb run` that
// exits 5 because a full-tunnel VPN owns the default route reports Stopped with
// that exit code (svcrun_windows.go's finish) and is left alone. That is
// precisely the discrimination service.go's serviceThrottle comment says
// launchd cannot express — "restart unless the exit code was 5" — so on Windows
// dpb gets it for free and must not throw it away by flipping the flag.
const serviceRecoveryReset = 24 * 60 * 60

// serviceScopeFor resolves the scope for this invocation.
//
// The log directory for --system is NOT taken from the invoking user's layout,
// for the same reason service_darwin.go's serviceScopeFor gives: the service
// runs as LocalSystem with no user profile, so paths.Resolve() inside it
// returns the machine-wide %ProgramData% layout. Pointing this scope at the
// installing user's %LOCALAPPDATA% would split the service's own event log from
// the stdout it redirects for itself, and `dpb service logs --system` would
// then read the wrong half. paths.SystemLayout exists so both halves compute
// that directory from one piece of code.
func (g *globals) serviceScopeFor(system bool) (serviceScope, error) {
	l, err := g.layoutOf()
	if err != nil {
		return serviceScope{}, err
	}
	s := serviceScope{system: system, uid: l.UID, layout: l}
	if system {
		s.mech = winService
		sys, err := paths.SystemLayout()
		if err != nil {
			return serviceScope{}, fmt.Errorf("service: locate the machine-wide log directory: %w", err)
		}
		s.logDir = sys.LogDir
	} else {
		// The user scope: winLogonTask, implemented in service_task_windows.go.
		// l.LogDir is already the invoking user's own %LOCALAPPDATA%\dpb\logs
		// (paths_windows.go's resolve), which is exactly right here — unlike
		// the --system branch above, this mechanism runs AS the invoking user,
		// so there is no LocalSystem/interactive-session split to route around.
		s.mech = winLogonTask
		s.logDir = l.LogDir
	}
	s.outLog = filepath.Join(s.logDir, serviceOutLog)
	s.errLog = filepath.Join(s.logDir, serviceErrLog)
	return s, nil
}

// ── install / uninstall ─────────────────────────────────────────────────────

// installMechanism creates the service, sets its recovery actions, confirms the
// definition through both observers, and starts it. It is what
// `dpb service install --system` does once service.go's generic checks (root,
// run flags, the binary's own path) have passed.
func installMechanism(ctx context.Context, g *globals, s serviceScope, args []string) error {
	if s.mech == winLogonTask {
		return installLogonTask(ctx, g, s, args)
	}
	// service.go builds args as {exe, "run", ...extra}. CreateService takes the
	// executable and its arguments separately and escapes each itself.
	exe, runArgs := args[0], args[1:]

	// The service writes here as LocalSystem; creating it now, from the
	// elevated installer, means a first-run failure to create it cannot be the
	// reason the service has no log to explain itself with.
	if err := os.MkdirAll(s.logDir, 0o755); err != nil {
		return fmt.Errorf("service install: create %s: %w", s.logDir, err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service install: connect to the service control manager: %w", err)
	}
	defer m.Disconnect()

	// Make a reinstall idempotent, exactly as the darwin path boots the job out
	// before bootstrapping it: CreateService fails with ERROR_SERVICE_EXISTS,
	// and the user asked for "install", not "fail because you already did this".
	if err := deleteExistingService(ctx, m); err != nil {
		return fmt.Errorf("service install: %w", err)
	}

	cfg := mgr.Config{
		ServiceType: windows.SERVICE_WIN32_OWN_PROCESS,
		// StartAutomatic is launchd's RunAtLoad: the service comes back after a
		// reboot without anyone logging in, which is the whole point of
		// --system.
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		// Spelled out rather than left to CreateService's NULL default, which
		// also means LocalSystem: the account this runs as belongs in the
		// source, and the registry read-back below needs an exact string to
		// compare against.
		ServiceStartName: "LocalSystem",
		DisplayName:      serviceDisplayName,
		Description:      serviceDescription,
	}
	h, err := m.CreateService(serviceName, exe, cfg, runArgs...)
	if err != nil {
		return fmt.Errorf("service install: create the %q service: %w", serviceName, err)
	}
	defer h.Close()

	if err := h.SetRecoveryActions(serviceRecoveryActions(), serviceRecoveryReset); err != nil {
		return winServiceRollback(h, fmt.Errorf("service install: set the recovery actions: %w", err))
	}

	want := winServiceImagePath(exe, runArgs)
	if err := verifyWinService(want); err != nil {
		return winServiceRollback(h, fmt.Errorf("service install: %w", err))
	}

	if err := h.Start(); err != nil {
		return winServiceRollback(h,
			fmt.Errorf("service install: the %q service was created but would not start: %w", serviceName, err))
	}
	st, err := waitForState(ctx, h, svc.Running, serviceStartWait)
	if err != nil {
		return winServiceRollback(h, fmt.Errorf("service install: %w", err))
	}

	w := g.env.Stdout
	fmt.Fprintf(w, "installed  %s (%s)\n", serviceName, s.kind())
	fmt.Fprintf(w, "  registry HKLM\\%s\n", serviceRegKey)
	fmt.Fprintf(w, "  command  %s\n", want)
	fmt.Fprintf(w, "  account  LocalSystem\n")
	fmt.Fprintf(w, "  logs     %s\n           %s\n", s.outLog, s.errLog)
	fmt.Fprintf(w, "  state    %s\n", winStatusText(st))
	// Said out loud for the same reason service_darwin.go says it of a
	// LaunchDaemon: a silently reduced coverage surface is exactly the failure
	// this tool exists to avoid. A LocalSystem service sets HTTP(S)_PROXY in
	// its own environment block, which the interactive desktop session does not
	// inherit, so proxy mode's environment lever does not reach the
	// applications running there. TUN mode does not depend on that lever, which
	// is why this scope exists.
	fmt.Fprintf(w, "\nnote: a LocalSystem service sets HTTP(S)_PROXY only in its own environment,\n"+
		"      which your desktop session does not inherit. This scope is for TUN mode\n"+
		"      (`-- --tun`), which needs administrator for the adapter and routes anyway.\n")
	return nil
}

// winServiceRollback undoes a half-finished install so the machine is never
// left with a service the SCM will start at the next boot and a user who was
// told the install failed. It mirrors service_darwin.go's serviceRollback.
func winServiceRollback(h *mgr.Service, cause error) error {
	_, _ = h.Control(svc.Stop)
	_ = h.Delete()
	return fmt.Errorf("%w (the service was removed again, nothing is installed)", cause)
}

// deleteExistingService removes a service left by an earlier install.
func deleteExistingService(ctx context.Context, m *mgr.Mgr) error {
	h, err := m.OpenService(serviceName)
	if err != nil {
		// ERROR_SERVICE_DOES_NOT_EXIST is the state this is trying to reach.
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return fmt.Errorf("open the existing %q service: %w", serviceName, err)
	}
	stopErr := stopWinService(ctx, h)
	delErr := h.Delete()
	h.Close()
	if stopErr != nil {
		return stopErr
	}
	if delErr != nil && !errors.Is(delErr, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return fmt.Errorf("delete the existing %q service: %w", serviceName, delErr)
	}
	return waitForServiceGone(ctx, m)
}

// waitForServiceGone waits for the name to actually become free.
//
// DeleteService only MARKS a service for deletion; MSDN is explicit that "the
// service is not removed from the database until all open handles to the
// service have been closed" — including handles held by services.msc or an
// sc.exe someone left running. Until then CreateService still fails with
// ERROR_SERVICE_EXISTS, so waiting here turns a confusing "already exists" a
// second after a successful delete into either success or a message that names
// the real cause.
func waitForServiceGone(ctx context.Context, m *mgr.Mgr) error {
	deadline := time.Now().Add(serviceDeleteWait)
	for {
		h, err := m.OpenService(serviceName)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("check whether the previous %q service is gone: %w", serviceName, err)
		}
		h.Close()
		if time.Now().After(deadline) {
			return fmt.Errorf("the previous %q service is still marked for deletion after %s; "+
				"close services.msc (an open handle keeps the name reserved) and try again",
				serviceName, serviceDeleteWait)
		}
		if err := sleepCtx(ctx, servicePoll); err != nil {
			return err
		}
	}
}

// uninstallMechanism stops and deletes the service, then confirms it is gone.
func uninstallMechanism(ctx context.Context, g *globals, s serviceScope) error {
	if s.mech == winLogonTask {
		return uninstallLogonTask(ctx, g, s)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service uninstall: connect to the service control manager: %w", err)
	}
	defer m.Disconnect()

	h, err := m.OpenService(serviceName)
	switch {
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		// Already gone: the state uninstall is trying to reach. Fall through to
		// the read-back, which is what the absence is judged on — the same
		// reasoning as service_darwin.go ignoring bootout's exit status.
	case err != nil:
		return fmt.Errorf("service uninstall: open the %q service: %w", serviceName, err)
	default:
		stopErr := stopWinService(ctx, h)
		delErr := h.Delete()
		h.Close()
		if stopErr != nil {
			return fmt.Errorf("service uninstall: %w", stopErr)
		}
		if delErr != nil && !errors.Is(delErr, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return fmt.Errorf("service uninstall: delete the %q service: %w", serviceName, delErr)
		}
	}

	// Confirmed through the registry, not through the SCM that performed the
	// delete. This is also the check that catches the marked-for-deletion case
	// the comment on waitForServiceGone describes.
	if err := waitForRegistryGone(ctx); err != nil {
		return fmt.Errorf("service uninstall: %w", err)
	}
	fmt.Fprintf(g.env.Stdout, "removed  %s (%s)\n", serviceName, s.kind())
	fmt.Fprintf(g.env.Stdout, "  logs are left in place: %s\n", s.logDir)
	return nil
}

// waitForRegistryGone polls the second observer until the definition is gone.
func waitForRegistryGone(ctx context.Context) error {
	deadline := time.Now().Add(serviceDeleteWait)
	for {
		_, installed, err := readServiceRegistry()
		if err != nil {
			return fmt.Errorf("cannot confirm %q is gone: %w", serviceName, err)
		}
		if !installed {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("HKLM\\%s still exists %s after the delete; "+
				"the SCM removes a service's name only when the last open handle to it closes",
				serviceRegKey, serviceDeleteWait)
		}
		if err := sleepCtx(ctx, servicePoll); err != nil {
			return err
		}
	}
}

// ── start / stop ────────────────────────────────────────────────────────────

// startMechanism starts an installed service.
func startMechanism(ctx context.Context, g *globals, s serviceScope) error {
	if s.mech == winLogonTask {
		return startLogonTask(ctx, g, s)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service start: connect to the service control manager: %w", err)
	}
	defer m.Disconnect()

	h, err := m.OpenService(serviceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return fmt.Errorf("service start: %s is not installed; run `%s` first",
				serviceName, serviceInstallHint)
		}
		return fmt.Errorf("service start: open the %q service: %w", serviceName, err)
	}
	defer h.Close()

	st, err := h.Query()
	if err != nil {
		return fmt.Errorf("service start: query the %q service: %w", serviceName, err)
	}
	if st.State != svc.Running && st.State != svc.StartPending {
		if err := h.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			// ALREADY_RUNNING means something else won the race between the
			// query above and this call, which is the state start wanted.
			return fmt.Errorf("service start: %w", err)
		}
	}

	st, err = waitForState(ctx, h, svc.Running, serviceStartWait)
	if err != nil {
		return fmt.Errorf("service start: %s is installed but did not reach running; "+
			"`dpb service logs --system` will say why: %w", serviceName, err)
	}
	fmt.Fprintf(g.env.Stdout, "started  %s (%s), %s\n", serviceName, s.kind(), winStatusText(st))
	return nil
}

// stopMechanism stops the service, leaving it installed.
//
// Unlike the darwin path, this really is a stop rather than an unload. launchd
// has to be booted out because KeepAlive would bring a signalled job straight
// back; the SCM's recovery actions fire only for a process that dies WITHOUT
// reporting SERVICE_STOPPED, and svcrun_windows.go always reports it, so a
// requested stop stays stopped. The service is still marked StartAutomatic and
// will come back at the next boot — `dpb service uninstall --system` is what
// removes it.
func stopMechanism(ctx context.Context, g *globals, s serviceScope) error {
	if s.mech == winLogonTask {
		return stopLogonTask(ctx, g, s)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service stop: connect to the service control manager: %w", err)
	}
	defer m.Disconnect()

	h, err := m.OpenService(serviceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return fmt.Errorf("service stop: %s is not installed", serviceName)
		}
		return fmt.Errorf("service stop: open the %q service: %w", serviceName, err)
	}
	defer h.Close()

	if err := stopWinService(ctx, h); err != nil {
		return fmt.Errorf("service stop: %w", err)
	}
	st, err := h.Query()
	if err != nil {
		return fmt.Errorf("service stop: query the %q service: %w", serviceName, err)
	}
	if st.State != svc.Stopped {
		return fmt.Errorf("service stop: %s is %s, not stopped", serviceName, winStateName(st.State))
	}
	fmt.Fprintf(g.env.Stdout, "stopped  %s (%s), still installed\n", serviceName, s.kind())
	return nil
}

// stopWinService sends the stop control and waits for the service to reach it.
func stopWinService(ctx context.Context, h *mgr.Service) error {
	st, err := h.Control(svc.Stop)
	if err != nil {
		// ERROR_SERVICE_NOT_ACTIVE is the state stop is trying to reach.
		// mgr.Control returns it as an error alongside a usable status rather
		// than as success, so it is filtered here and not treated as failure.
		if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return nil
		}
		return fmt.Errorf("stop the %q service: %w", serviceName, err)
	}
	if st.State == svc.Stopped {
		return nil
	}
	_, err = waitForState(ctx, h, svc.Stopped, serviceStopWait)
	return err
}

// waitForState polls the SCM until the service reaches want or the budget runs
// out. Start, Control and Delete are all asynchronous — they report that the
// request was accepted — so believing their return value is how a caller ends
// up telling a user something started when it did not.
func waitForState(ctx context.Context, h *mgr.Service, want svc.State, budget time.Duration) (svc.Status, error) {
	deadline := time.Now().Add(budget)
	var st svc.Status
	for {
		var err error
		st, err = h.Query()
		if err != nil {
			return st, fmt.Errorf("query the %q service: %w", serviceName, err)
		}
		if st.State == want {
			return st, nil
		}
		if time.Now().After(deadline) {
			return st, fmt.Errorf("the %q service is %s after %s, not %s",
				serviceName, winStateName(st.State), budget, winStateName(want))
		}
		if err := sleepCtx(ctx, servicePoll); err != nil {
			return st, err
		}
	}
}

// The polls above wait with probe.go's sleepCtx, which already returns early on
// a cancelled context. A second copy of five lines is still a second copy.

// ── recovery actions ────────────────────────────────────────────────────────

// serviceRecoveryActions is the SCM's equivalent of launchd's KeepAlive plus
// ThrottleInterval.
//
// The delay is serviceThrottle, and service.go's comment on that constant is
// the reason rather than any property of Windows: the exits worth respawning
// through are transient, and restarting instantly into a network that is still
// broken is not recovery, it is a hot loop. The SCM's own default delay is 0,
// so this has to be said explicitly here just as ThrottleInterval has to be
// said explicitly in the plist.
//
// Three entries rather than one: MSDN's SERVICE_FAILURE_ACTIONS says the SCM
// performs element [N-1] on the Nth failure and repeats the last element once N
// exceeds the array, so a three-element array of ServiceRestart is an unbounded
// retry at a 30 s floor — the same shape as launchd's KeepAlive — while a
// one-element array would also work but reads as if it meant "once".
func serviceRecoveryActions() []mgr.RecoveryAction {
	d := time.Duration(serviceThrottle) * time.Second
	return []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: d},
		{Type: mgr.ServiceRestart, Delay: d},
		{Type: mgr.ServiceRestart, Delay: d},
	}
}

// ── the two observers ───────────────────────────────────────────────────────

// winServiceReg is the service's own definition as the registry holds it.
type winServiceReg struct {
	imagePath  string
	start      uint64
	objectName string
	typ        uint64
}

// readServiceRegistry reads HKLM\SYSTEM\CurrentControlSet\Services\dpb.
//
// The second return says whether the service is installed. A missing key is an
// ANSWER, not a failure. Any other error is not that answer, and is returned as
// one: "I could not read it" reported as "it is not there" is the defect class
// service.go's serviceStatus comment names.
func readServiceRegistry() (winServiceReg, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, serviceRegKey, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return winServiceReg{}, false, nil
		}
		return winServiceReg{}, false, fmt.Errorf("read HKLM\\%s: %w", serviceRegKey, err)
	}
	defer k.Close()

	var r winServiceReg
	// ImagePath is REG_EXPAND_SZ for most services and REG_SZ for some;
	// registry.GetStringValue accepts either and returns the stored text
	// unexpanded, which is exactly what CreateService wrote.
	if r.imagePath, _, err = k.GetStringValue("ImagePath"); err != nil {
		return r, true, fmt.Errorf("read HKLM\\%s\\ImagePath: %w", serviceRegKey, err)
	}
	if r.start, _, err = k.GetIntegerValue("Start"); err != nil {
		return r, true, fmt.Errorf("read HKLM\\%s\\Start: %w", serviceRegKey, err)
	}
	if r.typ, _, err = k.GetIntegerValue("Type"); err != nil {
		return r, true, fmt.Errorf("read HKLM\\%s\\Type: %w", serviceRegKey, err)
	}
	// ObjectName is absent for a service left on CreateService's NULL account
	// default. dpb sets it, so its absence is a mismatch worth reporting rather
	// than a shrug.
	if r.objectName, _, err = k.GetStringValue("ObjectName"); err != nil {
		return r, true, fmt.Errorf("read HKLM\\%s\\ObjectName: %w", serviceRegKey, err)
	}
	return r, true, nil
}

// winServiceImagePath reproduces the command line CreateService stores.
//
// mgr.CreateService builds it as syscall.EscapeArg(exepath) followed by each
// argument, also escaped, joined with single spaces
// (golang.org/x/sys@v0.43.0/windows/svc/mgr/mgr.go). Reproducing it here rather
// than reading the value back and matching it loosely is what turns the
// registry check into an equality test: the command line the SCM persisted
// either is the one dpb asked for or it is not, and "close enough" is how a
// wrong --profile survives an install.
func winServiceImagePath(exe string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, syscall.EscapeArg(exe))
	for _, a := range args {
		parts = append(parts, syscall.EscapeArg(a))
	}
	return strings.Join(parts, " ")
}

// verifyWinService confirms a fresh install through both observers.
func verifyWinService(wantImagePath string) error {
	reg, installed, err := readServiceRegistry()
	if err != nil {
		return fmt.Errorf("the service was created but its definition could not be read back: %w", err)
	}
	if !installed {
		return fmt.Errorf("the SCM reported success but HKLM\\%s does not exist", serviceRegKey)
	}
	if reg.imagePath != wantImagePath {
		return fmt.Errorf("HKLM\\%s\\ImagePath is %q, not the %q dpb asked for",
			serviceRegKey, reg.imagePath, wantImagePath)
	}
	if reg.start != windows.SERVICE_AUTO_START {
		return fmt.Errorf("HKLM\\%s\\Start is %d (%s), not automatic; it would not come back after a reboot",
			serviceRegKey, reg.start, winStartTypeName(reg.start))
	}
	if reg.typ != windows.SERVICE_WIN32_OWN_PROCESS {
		return fmt.Errorf("HKLM\\%s\\Type is %#x, not SERVICE_WIN32_OWN_PROCESS (%#x)",
			serviceRegKey, reg.typ, windows.SERVICE_WIN32_OWN_PROCESS)
	}
	// EqualFold because the SCM normalises some well-known account names and
	// the comparison is about identity, not spelling.
	if !strings.EqualFold(reg.objectName, "LocalSystem") {
		return fmt.Errorf("HKLM\\%s\\ObjectName is %q, not LocalSystem", serviceRegKey, reg.objectName)
	}

	// And now the other observer, answering a different question: the registry
	// says what is written down, the SCM says whether it has loaded it. A green
	// install therefore means "the definition on disk is the one dpb asked for
	// AND the SCM admits to knowing the service", which is strictly more than
	// "CreateService returned a handle".
	_, known, err := queryWinService()
	if err != nil {
		return fmt.Errorf("the definition was written but the SCM could not be asked about %q: %w", serviceName, err)
	}
	if !known {
		return fmt.Errorf("the definition was written but the SCM does not know %q", serviceName)
	}
	return nil
}

// queryWinService asks the SCM for the service's live state.
//
// The second return says whether the SCM knows the service; a nil error means
// the answer is trustworthy either way. It opens its own least-privilege
// handles rather than going through mgr.Connect/mgr.OpenService, both of which
// request ALL_ACCESS (x/sys mgr.go) and are therefore refused to an unelevated
// token. A `dpb service status` that only worked for administrators is a status
// command nobody runs. The raw handles are wrapped back into mgr.Mgr and
// mgr.Service — whose Handle fields are exported for exactly this — so Query
// itself is still x/sys's own code.
func queryWinService() (svc.Status, bool, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return svc.Status{}, false, fmt.Errorf("connect to the service control manager: %w", err)
	}
	m := &mgr.Mgr{Handle: scm}
	defer m.Disconnect()

	name, err := syscall.UTF16PtrFromString(serviceName)
	if err != nil {
		return svc.Status{}, false, err
	}
	sh, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return svc.Status{}, false, nil
		}
		return svc.Status{}, false, fmt.Errorf("open the %q service: %w", serviceName, err)
	}
	h := &mgr.Service{Name: serviceName, Handle: sh}
	defer h.Close()

	st, err := h.Query()
	if err != nil {
		return svc.Status{}, true, fmt.Errorf("query the %q service: %w", serviceName, err)
	}
	return st, true, nil
}

// ── status ──────────────────────────────────────────────────────────────────

// statusMechanism reports and prints one scope's state, asking both observers.
//
// The third return is the mechanism saying "I could not look" — see the unsure
// slice in service.go's serviceStatus. Unlike launchd, Windows really can leave
// the question open: an unelevated caller reads the registry fine and is
// refused by the SCM, so dpb can know the service exists and honestly not know
// whether it is running.
func statusMechanism(ctx context.Context, g *globals, s serviceScope) (found, running bool, cannotTell error) {
	if s.mech == winLogonTask {
		return statusLogonTask(ctx, g, s)
	}
	w := g.env.Stdout

	reg, regKnown, regErr := readServiceRegistry()
	st, scmKnown, scmErr := queryWinService()

	found = (regErr == nil && regKnown) || (scmErr == nil && scmKnown)
	if !found {
		if regErr != nil || scmErr != nil {
			// At most one observer answered, and it said nothing is there. That
			// is not enough to claim "not installed": the other one may have
			// been about to say otherwise.
			return false, false, errors.Join(regErr, scmErr)
		}
		return false, false, nil
	}

	fmt.Fprintf(w, "%s  (%s)\n", serviceName, s.kind())
	if regErr != nil {
		fmt.Fprintf(w, "  registry unreadable — %v\n", regErr)
		cannotTell = errors.Join(cannotTell, regErr)
	} else if !regKnown {
		fmt.Fprintf(w, "  registry HKLM\\%s is missing, but the SCM still knows the service\n", serviceRegKey)
	} else {
		fmt.Fprintf(w, "  registry HKLM\\%s\n", serviceRegKey)
		fmt.Fprintf(w, "  command  %s\n", reg.imagePath)
		fmt.Fprintf(w, "  account  %s\n", reg.objectName)
		fmt.Fprintf(w, "  startup  %s\n", winStartTypeName(reg.start))
	}

	switch {
	case scmErr != nil:
		// Printed as unknown, and reported as unknown. Saying "not running"
		// here would be the lie this whole return value exists to prevent.
		fmt.Fprintf(w, "  state    unknown — %v\n", scmErr)
		cannotTell = errors.Join(cannotTell, scmErr)
	case !scmKnown:
		fmt.Fprintf(w, "  state    the SCM does not know this service; the registry key is stale\n")
	default:
		fmt.Fprintf(w, "  state    %s\n", winStatusText(st))
		if st.ProcessId > 0 {
			fmt.Fprintf(w, "  pid      %d\n", st.ProcessId)
		}
		running = st.State == svc.Running
	}
	fmt.Fprintf(w, "  logs     %s\n           %s\n", s.outLog, s.errLog)
	return found, running, cannotTell
}

// ── naming ──────────────────────────────────────────────────────────────────

// winStateName spells a SERVICE_STATUS.dwCurrentState. The numbers appear in
// `sc query` output and in the event log, so an unknown one is printed rather
// than hidden behind "unknown".
func winStateName(st svc.State) string {
	switch st {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "resuming"
	case svc.PausePending:
		return "pausing"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("state %d", uint32(st))
	}
}

// winStatusText is winStateName plus the exit code a stopped service left
// behind, which is the difference between "someone stopped it" and "it refused
// to run". svcrun_windows.go reports dpb's own exit codes in
// ServiceSpecificExitCode, so that one is preferred when it is set.
func winStatusText(st svc.Status) string {
	name := winStateName(st.State)
	if st.State != svc.Stopped {
		return name
	}
	switch {
	case st.ServiceSpecificExitCode != 0:
		return fmt.Sprintf("%s (dpb exit %d)", name, st.ServiceSpecificExitCode)
	case st.Win32ExitCode != 0 && st.Win32ExitCode != uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR):
		return fmt.Sprintf("%s (win32 error %d)", name, st.Win32ExitCode)
	default:
		return name
	}
}

// winStartTypeName spells the registry's Start value.
func winStartTypeName(v uint64) string {
	switch v {
	case windows.SERVICE_AUTO_START:
		return "automatic (starts at boot)"
	case windows.SERVICE_DEMAND_START:
		return "manual"
	case windows.SERVICE_DISABLED:
		return "disabled"
	default:
		return fmt.Sprintf("start type %d", v)
	}
}
