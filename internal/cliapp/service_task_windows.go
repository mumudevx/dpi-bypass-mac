//go:build windows

package cliapp

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/netstate"
)

// dpb installs proxy mode as a Windows Scheduled Task with a logon trigger,
// running as the interactive user. This is the other half of Windows service
// support — service_windows.go's header covers the SCM half (winService,
// --system, LocalSystem) — and this file, not that one, is where the reason
// for the split belongs, because it is the mechanism that exists only because
// a Windows service cannot do this job.
//
// Why two mechanisms at all. A Windows service runs in session 0 as
// LocalSystem. It can neither write the interactive user's HKCU hive — which
// is where WinINET's proxy settings live — nor deliver
// INTERNET_OPTION_SETTINGS_CHANGED into that user's session; both are
// operations that only make sense inside a real interactive logon. So:
//
//   - proxy mode, which is per-user by construction (it sets environment
//     variables and WinINET settings for one desktop session), installs as
//     the logon task this file implements.
//   - TUN mode, which needs administrator rights anyway for the wintun
//     adapter and the route table, installs as the LocalSystem service
//     service_windows.go implements.
//
// This is the split WireGuard uses for the same reason: wireguard-windows
// runs its tunnel service as SYSTEM and leaves the per-user UI/config surface
// to a process in the user's own session, because SYSTEM cannot reach that
// session either.
//
// Verification follows the same two-observer rule service.go's header states
// for every mutation this tool makes, adapted to what Task Scheduler actually
// offers:
//
//   - Observer 1 is the filesystem: Task Scheduler persists every task's
//     definition as an XML file under %WINDIR%\System32\Tasks\<name>, written
//     by the Task Scheduler service itself (not by dpb — see
//     writeStagingXML), and readLogonTaskFile reads that file back and parses
//     it as XML.
//   - Observer 2 is schtasks itself, asked again by EXIT STATUS ONLY.
//     schtasks prints its result in the system UI language and there is no
//     LC_ALL=C on Windows — the exact hazard this project already paid for on
//     macOS, where `ps` reordered its columns under tr_TR and made a live dpb
//     look dead (see internal/netstate's lock_unix.go). So nothing here ever
//     branches on schtasks' stdout text; sysport.Result.Failed() with no
//     "schtasks" entry in its liar table reduces to exactly "exit code
//     non-zero", which is what "Consult its exit status and nothing else"
//     means in code.
//
// The same hazard rules out using schtasks' own /query output — even in CSV
// or LIST form — to learn whether the task is currently RUNNING: its Status
// column ("Ready"/"Running"/"Disabled") is translated same as any other
// display text, and the classic schtasks verb set has no query filter to
// sidestep that the way tasklist's /FI does for STATUS. So "is it running"
// is answered a third way, through winProcessRunning: a CreateToolhelp32Snapshot
// walk of the process list, which carries no text a locale can touch at all
// (see that function's own comment for the API-verification this project
// requires before a new Windows call is trusted).
//
// What is NOT attempted here: Task Scheduler's own <RestartOnFailure> element
// (Interval/Count), even though the design notes for this port list it as the
// mechanism's restart throttle. It is left out on purpose. <RestartOnFailure>
// restarts the task whenever its action exits non-zero — full stop. It has no
// equivalent of the SCM's crash-only recovery actions (which fire only when
// the process dies WITHOUT reporting SERVICE_STOPPED, letting svcrun_windows.go's
// explicit "stopped" report suppress a restart) or launchd's KeepAlive
// SuccessfulExit=false. `dpb run` reports exit 5 on purpose when a full-tunnel
// VPN owns the default route or a captive portal is up — precisely the case
// service.go's serviceThrottle comment says must NOT be retried into — and
// Task Scheduler's restart-on-failure cannot tell that exit apart from a
// crash. Wiring it up would reintroduce the hot loop this project has
// designed around on every other platform, so it stays unconfigured until (if
// ever) a task takes on solving that mismatch deliberately.

// logonTaskName is the Scheduled Task's name. It is deliberately the same
// string as serviceName ("dpb"): from a user's perspective this is still "the
// dpb job", just carried by a different mechanism, and giving the two
// different names would be one more thing to remember for no benefit. Task
// Scheduler names live in their own namespace from service names, so the
// reuse cannot collide with the SCM's "dpb".
//
// It carries no folder, so the name is also the task's full path ("\dpb"),
// which is what `schtasks /tn dpb` and Task Scheduler's UI both show, and what
// makes %WINDIR%\System32\Tasks\dpb (no subdirectory) the file
// logonTaskFile below expects.
const logonTaskName = serviceName

// logonTaskDescription is what Task Scheduler's UI shows for the task. Unlike
// serviceDescription it says nothing about administrator rights, because this
// scope deliberately has none.
const logonTaskDescription = "Runs dpb's DPI-bypass proxy in your login session, so its " +
	"HTTP(S)_PROXY environment variables and WinINET settings land where your " +
	"applications actually run. `dpb service logs` prints its output."

// logonInstallHint is this mechanism's own install command, distinct from
// serviceInstallHint (which is specifically the SCM's --system, elevated
// phrasing). service.go's header describes serviceInstallHint as one of three
// strings a platform provides ONCE — true when a platform has one mechanism,
// not true for Windows now that it has two with different privilege
// requirements. Rather than bend one shared constant to mean two different
// commands, the logon task's own messages use this instead and
// serviceInstallHint keeps meaning exactly what service_windows.go already
// says it means.
const logonInstallHint = "dpb service install"

// installLogonTask writes the task definition, asks schtasks to register it,
// confirms the registration through both observers, and runs it now. It is
// what `dpb service install` (no --system) does once service.go's generic
// checks (run flags, the binary's own path) have passed — the same shape
// installMechanism uses for the SCM in service_windows.go, and
// service_darwin.go's installMechanism before that.
//
// "Runs it now" is not optional polish: a LogonTrigger fires only on a FUTURE
// logon event. Creating one while the installing user is already logged in —
// the overwhelmingly common case, since `dpb service install` is typed
// interactively — does NOT retroactively run it, unlike launchd's
// bootstrap-plus-RunAtLoad or (after installMechanism's explicit h.Start())
// the SCM. Skipping the explicit `schtasks /run` here would compile, look
// correct, and leave the user's proxy dark until their next logon — exactly
// the class of bug this project watches for.
func installLogonTask(ctx context.Context, g *globals, s serviceScope, args []string) error {
	exe, runArgs := args[0], args[1:]

	if err := os.MkdirAll(s.logDir, 0o755); err != nil {
		return fmt.Errorf("service install: create %s: %w", s.logDir, err)
	}

	sid, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("service install: %w", err)
	}

	run := g.runnerOf()

	// Make a reinstall idempotent, exactly as deleteExistingService does for
	// the SCM: schtasks /create without /F fails outright on a task that
	// already exists, and the user asked for "install", not "fail because you
	// already did this". Both calls are best-effort — ending a task that is
	// not running, or deleting one that is not there, are the states this is
	// trying to reach, not failures to act on.
	_ = run.Run(ctx, "schtasks", "/end", "/tn", logonTaskName)
	_ = run.Run(ctx, "schtasks", "/delete", "/tn", logonTaskName, "/f")

	xmlPath, cleanup, err := writeStagingXML(logonTaskXML(sid, exe, runArgs))
	if err != nil {
		return fmt.Errorf("service install: %w", err)
	}
	defer cleanup()

	// Consult schtasks' exit status and nothing else — see the package
	// comment.
	if res := run.Run(ctx, "schtasks", "/create", "/tn", logonTaskName, "/xml", xmlPath, "/f"); res.Failed() {
		return fmt.Errorf("service install: %s", res.Reason())
	}

	wantArgs := logonTaskArguments(runArgs)
	if err := verifyLogonTask(ctx, run, exe, wantArgs); err != nil {
		return rollbackLogonTask(ctx, run, fmt.Errorf("service install: %w", err))
	}

	if res := run.Run(ctx, "schtasks", "/run", "/tn", logonTaskName); res.Failed() {
		return rollbackLogonTask(ctx, run,
			fmt.Errorf("service install: the task is registered but would not run: %s", res.Reason()))
	}
	running, err := waitForLogonTaskProcess(ctx, exe, true, serviceStartWait)
	if err != nil {
		return rollbackLogonTask(ctx, run, fmt.Errorf("service install: %w", err))
	}
	if !running {
		return rollbackLogonTask(ctx, run, fmt.Errorf(
			"service install: %s is registered but did not start within %s; `dpb service logs` will say why",
			logonTaskName, serviceStartWait))
	}

	w := g.env.Stdout
	file, _ := logonTaskFile()
	fmt.Fprintf(w, "installed  %s (%s)\n", logonTaskName, s.kind())
	fmt.Fprintf(w, "  task     %s\n", file)
	fmt.Fprintf(w, "  command  %s %s\n", exe, wantArgs)
	fmt.Fprintf(w, "  account  %s\n", sid)
	fmt.Fprintf(w, "  logs     %s\n           %s\n", s.outLog, s.errLog)
	fmt.Fprintf(w, "\nIt starts at your next logon and is running now. `dpb service stop` ends it.\n")
	return nil
}

// rollbackLogonTask undoes a half-finished install so the machine is never
// left with a task Task Scheduler will run at the next logon and a user who
// was told the install failed. It mirrors service_windows.go's
// winServiceRollback and service_darwin.go's serviceRollback.
func rollbackLogonTask(ctx context.Context, run netstate.Runner, cause error) error {
	_ = run.Run(ctx, "schtasks", "/end", "/tn", logonTaskName)
	_ = run.Run(ctx, "schtasks", "/delete", "/tn", logonTaskName, "/f")
	return fmt.Errorf("%w (the task was removed again, nothing is installed)", cause)
}

// writeStagingXML writes the definition dpb generated to a temp file schtasks
// can read, and returns a cleanup func removing it.
//
// This is only ever a STAGING copy. schtasks /create /xml cannot take a
// definition on stdin, so dpb has to put it somewhere on disk — but the copy
// Task Scheduler actually runs from, at %WINDIR%\System32\Tasks\<name>, is
// written by the Task Scheduler service itself once /create succeeds, not by
// this process. Confusing the two would make readLogonTaskFile a test of
// dpb's own os.WriteFile rather than of what got registered.
func writeStagingXML(doc string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "dpb-task-*.xml")
	if err != nil {
		return "", nil, fmt.Errorf("create a staging file for the task definition: %w", err)
	}
	path = f.Name()
	cleanup = func() { _ = os.Remove(path) }

	if _, err := f.WriteString(doc); err != nil {
		_ = f.Close()
		cleanup()
		return "", nil, fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("close %s: %w", path, err)
	}
	return path, cleanup, nil
}

// verifyLogonTask confirms a fresh registration through both observers named
// in the package comment.
func verifyLogonTask(ctx context.Context, run netstate.Runner, wantExe, wantArgs string) error {
	def, found, err := readLogonTaskFile()
	if err != nil {
		return fmt.Errorf("the task was created but its definition could not be read back: %w", err)
	}
	if !found {
		file, _ := logonTaskFile()
		return fmt.Errorf("schtasks reported success but %s does not exist", file)
	}
	if def.command != wantExe {
		return fmt.Errorf("the task's Command is %q, not the %q dpb asked for", def.command, wantExe)
	}
	if def.arguments != wantArgs {
		return fmt.Errorf("the task's Arguments is %q, not the %q dpb asked for", def.arguments, wantArgs)
	}
	if !def.hasLogonTrigger {
		return errors.New("the task has no LogonTrigger; it would never run at your next logon")
	}

	// And now the other observer, exactly as verifyWinService asks the SCM
	// after reading the registry: the file says what got written down,
	// schtasks says whether Task Scheduler's own database agrees. Exit status
	// only — see the package comment.
	if res := run.Run(ctx, "schtasks", "/query", "/tn", logonTaskName); res.Failed() {
		return fmt.Errorf("the task's definition file exists but schtasks does not know %q", logonTaskName)
	}
	return nil
}

// ── uninstall ───────────────────────────────────────────────────────────────

// uninstallLogonTask ends any running instance, deletes the task, and
// confirms it is gone through the filesystem observer — the same asymmetry
// service_darwin.go's uninstallMechanism and service_windows.go's
// uninstallMechanism both use: what the job's absence is judged on is the
// read-back, not the exit status of the command that tried to cause it.
func uninstallLogonTask(ctx context.Context, g *globals, s serviceScope) error {
	run := g.runnerOf()
	_ = run.Run(ctx, "schtasks", "/end", "/tn", logonTaskName)
	_ = run.Run(ctx, "schtasks", "/delete", "/tn", logonTaskName, "/f")

	if err := waitForLogonTaskFileGone(ctx); err != nil {
		return fmt.Errorf("service uninstall: %w", err)
	}
	fmt.Fprintf(g.env.Stdout, "removed  %s (%s)\n", logonTaskName, s.kind())
	fmt.Fprintf(g.env.Stdout, "  logs are left in place: %s\n", s.logDir)
	return nil
}

// waitForLogonTaskFileGone polls the filesystem observer until the
// definition is gone.
//
// schtasks /delete is documented as a synchronous call, unlike the SCM's
// DeleteService (which only marks a service for deletion — see
// waitForServiceGone in service_windows.go). A short, bounded poll costs
// nothing when the delete really was immediate, and this project's rule for
// anything that looks asynchronous is to confirm it rather than assume it.
func waitForLogonTaskFileGone(ctx context.Context) error {
	deadline := time.Now().Add(serviceDeleteWait)
	for {
		_, found, err := readLogonTaskFile()
		if err != nil {
			return fmt.Errorf("cannot confirm %s is gone: %w", logonTaskName, err)
		}
		if !found {
			return nil
		}
		if time.Now().After(deadline) {
			file, _ := logonTaskFile()
			return fmt.Errorf("%s still exists %s after the delete", file, serviceDeleteWait)
		}
		if err := sleepCtx(ctx, servicePoll); err != nil {
			return err
		}
	}
}

// ── start / stop ────────────────────────────────────────────────────────────

// startLogonTask runs an installed task now.
func startLogonTask(ctx context.Context, g *globals, s serviceScope) error {
	_, found, err := readLogonTaskFile()
	if err != nil {
		return fmt.Errorf("service start: %w", err)
	}
	if !found {
		return fmt.Errorf("service start: %s is not installed; run `%s` first", logonTaskName, logonInstallHint)
	}

	run := g.runnerOf()
	if res := run.Run(ctx, "schtasks", "/run", "/tn", logonTaskName); res.Failed() {
		return fmt.Errorf("service start: %s", res.Reason())
	}

	exe, err := g.exeOf()
	if err != nil {
		return fmt.Errorf("service start: %w", err)
	}
	running, err := waitForLogonTaskProcess(ctx, exe, true, serviceStartWait)
	if err != nil {
		return fmt.Errorf("service start: %w", err)
	}
	if !running {
		return fmt.Errorf("service start: %s is installed but did not start within %s; "+
			"`dpb service logs` will say why", logonTaskName, serviceStartWait)
	}
	fmt.Fprintf(g.env.Stdout, "started  %s (%s)\n", logonTaskName, s.kind())
	return nil
}

// stopLogonTask ends the running instance, leaving the task installed so it
// still fires at the next logon. `dpb service uninstall` is what removes it.
func stopLogonTask(ctx context.Context, g *globals, s serviceScope) error {
	_, found, err := readLogonTaskFile()
	if err != nil {
		return fmt.Errorf("service stop: %w", err)
	}
	if !found {
		return fmt.Errorf("service stop: %s is not installed", logonTaskName)
	}

	run := g.runnerOf()
	if res := run.Run(ctx, "schtasks", "/end", "/tn", logonTaskName); res.Failed() {
		return fmt.Errorf("service stop: %s", res.Reason())
	}

	exe, err := g.exeOf()
	if err != nil {
		return fmt.Errorf("service stop: %w", err)
	}
	running, err := waitForLogonTaskProcess(ctx, exe, false, serviceStopWait)
	if err != nil {
		return fmt.Errorf("service stop: %w", err)
	}
	if running {
		return fmt.Errorf("service stop: dpb is still running %s after %s", logonTaskName, serviceStopWait)
	}
	fmt.Fprintf(g.env.Stdout, "stopped  %s (%s), still installed\n", logonTaskName, s.kind())
	return nil
}

// ── status ──────────────────────────────────────────────────────────────────

// logonTaskFound combines the two observers' answers into the single "found"
// signal statusLogonTask reports, plus the error that means "an observer
// could not be consulted" rather than "it looked and said no".
//
// Factored out of statusLogonTask so this specific combination — the exact
// place a "no" vs. "I cannot tell" bug likes to hide, per service.go's
// serviceStatus comment on the two real defects that rule already cost this
// project — can be checked directly, without a live filesystem or schtasks.
//
// found is true the moment EITHER observer says yes: two independent
// observers exist so that one being unreachable does not cost the answer,
// mirroring service_windows.go's statusMechanism (`found = (regErr == nil &&
// regKnown) || (scmErr == nil && scmKnown)`). notFoundErr is only ever
// non-nil when found is false: reported cannotTell detail once something HAS
// been found belongs to the caller (statusLogonTask keeps looking and prints
// per-observer detail), not to this combinator.
func logonTaskFound(fileFound bool, fileErr error, schtasksKnows bool) (found bool, notFoundErr error) {
	found = fileFound || schtasksKnows
	if found {
		return true, nil
	}
	if fileErr != nil {
		// The file observer could not answer (a real read/parse failure, not
		// "the file does not exist"), and schtasks also said no. At most one
		// observer gave a trustworthy answer and it was not "yes", so this is
		// not enough to claim "not installed" — the other one may have been
		// about to say otherwise.
		return false, fileErr
	}
	return false, nil
}

// statusLogonTask reports and prints one scope's state, asking both
// observers, plus the process snapshot for liveness. The third return is the
// mechanism saying "I could not look" — see the unsure slice in service.go's
// serviceStatus, and service_windows.go's own statusMechanism for the
// analogous SCM case this mirrors.
func statusLogonTask(ctx context.Context, g *globals, s serviceScope) (found, running bool, cannotTell error) {
	w := g.env.Stdout

	def, fileFound, fileErr := readLogonTaskFile()

	run := g.runnerOf()
	queryRes := run.Run(ctx, "schtasks", "/query", "/tn", logonTaskName)
	schtasksKnows := !queryRes.Failed()

	var notFoundErr error
	found, notFoundErr = logonTaskFound(fileFound, fileErr, schtasksKnows)
	if !found {
		return false, false, notFoundErr
	}

	fmt.Fprintf(w, "%s  (%s)\n", logonTaskName, s.kind())
	switch {
	case fileErr != nil:
		fmt.Fprintf(w, "  task     unreadable — %v\n", fileErr)
		cannotTell = errors.Join(cannotTell, fileErr)
	case !fileFound:
		fmt.Fprintf(w, "  task     %s is missing, but schtasks still knows the task\n", mustLogonTaskFile())
	default:
		file, _ := logonTaskFile()
		fmt.Fprintf(w, "  task     %s\n", file)
		fmt.Fprintf(w, "  command  %s %s\n", def.command, def.arguments)
	}
	if !schtasksKnows {
		fmt.Fprintf(w, "  schtasks does not know %q; the file above may be stale\n", logonTaskName)
	}

	exe, err := g.exeOf()
	if err != nil {
		fmt.Fprintf(w, "  state    unknown — %v\n", err)
		cannotTell = errors.Join(cannotTell, err)
		fmt.Fprintf(w, "  logs     %s\n           %s\n", s.outLog, s.errLog)
		return found, false, cannotTell
	}
	live, err := winProcessRunning(filepath.Base(exe))
	switch {
	case err != nil:
		fmt.Fprintf(w, "  state    unknown — %v\n", err)
		cannotTell = errors.Join(cannotTell, err)
	case live:
		fmt.Fprintf(w, "  state    running\n")
		running = true
	default:
		fmt.Fprintf(w, "  state    not running\n")
	}
	fmt.Fprintf(w, "  logs     %s\n           %s\n", s.outLog, s.errLog)
	return found, running, cannotTell
}

// ── observer 1: the file Task Scheduler persisted ──────────────────────────

// logonTaskFile returns the path Task Scheduler persists the task definition
// to.
//
// Built from GetWindowsDirectory rather than %WINDIR%: a process can run with
// an environment block that strips it (a Scheduled Task's own action is
// launched by the Task Scheduler service, not by a shell, and inherits
// whatever environment that service constructs), while GetWindowsDirectory is
// the Win32 call schtasks itself is built on to find the same answer.
// Verified against golang.org/x/sys@v0.43.0/windows/security_windows.go before
// use: it wraps a real GetWindowsDirectoryW syscall, not a stub.
func logonTaskFile() (string, error) {
	dir, err := windows.GetWindowsDirectory()
	if err != nil {
		return "", fmt.Errorf("locate the Windows directory: %w", err)
	}
	return filepath.Join(dir, "System32", "Tasks", logonTaskName), nil
}

// mustLogonTaskFile is logonTaskFile without the error, for messages where a
// GetWindowsDirectory failure has already been folded into a different
// return value and printing a second, redundant error would only be noise.
func mustLogonTaskFile() string {
	p, err := logonTaskFile()
	if err != nil {
		return `%WINDIR%\System32\Tasks\` + logonTaskName
	}
	return p
}

// winTaskDef is the fields of a persisted Task Scheduler definition dpb cares
// about verifying — the Task Scheduler equivalent of service_windows.go's
// winServiceReg.
type winTaskDef struct {
	command         string
	arguments       string
	hasLogonTrigger bool
}

// readLogonTaskFile reads back %WINDIR%\System32\Tasks\<name> from the
// filesystem — the first of the two observers the package comment describes.
//
// The second return says whether the task is installed. A missing file is an
// ANSWER, not a failure — matching readServiceRegistry's own contract in
// service_windows.go: "I could not read it" reported as "it is not there" is
// the defect class this whole project organises its status code around.
func readLogonTaskFile() (winTaskDef, bool, error) {
	path, err := logonTaskFile()
	if err != nil {
		return winTaskDef{}, false, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return winTaskDef{}, false, nil
		}
		return winTaskDef{}, false, fmt.Errorf("read %s: %w", path, err)
	}

	def, err := parseTaskXML(raw)
	if err != nil {
		return winTaskDef{}, true, fmt.Errorf("%s: %w", path, err)
	}
	return def, true, nil
}

// winTaskXMLDoc is the shape parseTaskXML unmarshals into: only the fields
// verifyLogonTask and statusLogonTask actually check, named after the Task
// Scheduler schema's own elements so a struct-tag typo is easy to spot
// against the schema rather than against another Go name.
type winTaskXMLDoc struct {
	Principals struct {
		Principal []struct {
			UserId string `xml:"UserId"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Triggers struct {
		LogonTrigger *struct {
			UserId string `xml:"UserId"`
		} `xml:"LogonTrigger"`
	} `xml:"Triggers"`
	Actions struct {
		Exec struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

// parseTaskXML decodes and unmarshals the raw bytes of a persisted task
// definition into a winTaskDef. Split out of readLogonTaskFile so the
// decode-and-parse step — the part with no filesystem or Windows API call in
// it — can be tested directly against synthetic byte slices, the same way
// service_windows.go's winServiceImagePath is tested apart from the registry
// read that uses it.
func parseTaskXML(raw []byte) (winTaskDef, error) {
	text, err := decodeTaskXML(raw)
	if err != nil {
		return winTaskDef{}, fmt.Errorf("decode: %w", err)
	}
	var doc winTaskXMLDoc
	if err := xml.Unmarshal([]byte(stripXMLProlog(text)), &doc); err != nil {
		return winTaskDef{}, fmt.Errorf("parse: %w", err)
	}
	return winTaskDef{
		command:         doc.Actions.Exec.Command,
		arguments:       doc.Actions.Exec.Arguments,
		hasLogonTrigger: doc.Triggers.LogonTrigger != nil,
	}, nil
}

// decodeTaskXML converts the bytes Task Scheduler persisted into a Go string.
//
// Every Task Scheduler file this project has observed is UTF-16LE with a
// byte-order mark — Windows' native text encoding. Decoding it needs no new
// dependency: the standard library's unicode/utf16 does the code-unit-to-rune
// step and BOM detection is two bytes. golang.org/x/text/encoding/unicode
// would do this too, but adding a module this codebase does not otherwise
// depend on, for two bytes of BOM-sniffing, is not a trade worth making.
func decodeTaskXML(b []byte) (string, error) {
	if len(b) < 2 || b[0] != 0xFF || b[1] != 0xFE {
		// No little-endian BOM: assume the bytes are already UTF-8, which is
		// what dpb itself writes to the staging file (see writeStagingXML). If
		// a future Windows release changes how the persisted copy is encoded,
		// this produces an XML parse error rather than silently misreading it
		// as something else.
		return string(b), nil
	}
	b = b[2:]
	if len(b)%2 != 0 {
		return "", fmt.Errorf("%d bytes after the byte-order mark is not a whole number of UTF-16 code units", len(b))
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(units)), nil
}

// stripXMLProlog removes a leading <?xml ...?> declaration.
//
// encoding/xml.Unmarshal refuses any declared encoding other than "utf-8" or
// "us-ascii" unless a CharsetReader is set (encoding/xml's own doc comment on
// Decoder.CharsetReader) — and the text decodeTaskXML returns still reads
// encoding="UTF-16" in its declaration even though the string itself has
// already been converted to native UTF-8. Removing the declaration entirely
// sidesteps that check rather than fighting it with a second
// dependency-free workaround.
func stripXMLProlog(s string) string {
	t := strings.TrimLeft(s, "\ufeff \t\r\n")
	if !strings.HasPrefix(t, "<?xml") {
		return s
	}
	if i := strings.Index(t, "?>"); i >= 0 {
		return t[i+2:]
	}
	return s
}

// ── the identity the task runs as ───────────────────────────────────────────

// currentUserSID identifies the account the logon task's Principal and
// LogonTrigger run as: the token of the process typing `dpb service install`,
// which is deliberately NOT elevated (see logonTaskXML's RunLevel comment).
//
// A SID rather than "DOMAIN\User" text: Task Scheduler accepts either, but a
// SID needs no XML- or locale-escaping and identifies the account even if it
// is later renamed — the same preference for identity over spelling
// winServiceImagePath's comment states for the SCM's command line.
//
// windows.OpenCurrentProcessToken and Token.GetTokenUser are already used
// this way in this package (internal/paths/paths_windows.go's isElevated
// uses the sibling Token.IsElevated call on the same handle type), so this
// follows that established pattern rather than the alternative no-close
// pseudo-token (GetCurrentProcessToken).
func currentUserSID() (string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", fmt.Errorf("open the current process token: %w", err)
	}
	defer token.Close()

	u, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read the token's user SID: %w", err)
	}
	sid := u.User.Sid.String()
	if sid == "" {
		// SID.String swallows ConvertSidToStringSid's own error and returns
		// "" (golang.org/x/sys@v0.43.0/windows/security_windows.go) — checked
		// here rather than trusted, since a blank UserId in the XML would be a
		// task nothing could ever run as.
		return "", errors.New("convert the token's SID to a string")
	}
	return sid, nil
}

// ── observer 3: is it actually running right now ───────────────────────────

// winProcessRunning reports whether a process named exeBase (a bare file
// name, e.g. "dpb.exe") currently exists, by walking a process snapshot.
//
// This exists because nothing schtasks prints gives a locale-independent
// answer to "is the action running right now" — see the package comment.
// CreateToolhelp32Snapshot carries no text at all: ProcessEntry32.ExeFile is
// a fixed-size UTF-16 buffer holding a literal file name, immune to locale by
// construction. The walk below is x/sys's own pattern, read before use per
// this project's rule for any Windows API new to this package: it matches
// getProcessEntry in golang.org/x/sys@v0.43.0/windows/syscall_windows.go
// (used there to implement Getppid), confirming CreateToolhelp32Snapshot,
// Process32First and Process32Next are real syscalls in this module version,
// not stubs.
//
// Matching by base name only, not the full path, is a known, accepted
// imprecision: a second, unrelated dpb.exe elsewhere on the machine would
// count. Task Scheduler's action exposes no PID to key off of instead, and
// layering a full-path check on top would mean trusting
// QueryFullProcessImageName's access checks not to fail quietly for a process
// this caller has every right to see — one more Windows API this project has
// not yet had reason to lean on.
func winProcessRunning(exeBase string) (bool, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false, fmt.Errorf("snapshot the process list: %w", err)
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	err = windows.Process32First(snap, &entry)
	for ; err == nil; err = windows.Process32Next(snap, &entry) {
		name := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(name, exeBase) {
			return true, nil
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return false, fmt.Errorf("walk the process list: %w", err)
	}
	return false, nil
}

// waitForLogonTaskProcess polls winProcessRunning until it matches want or
// the budget runs out — this mechanism's equivalent of waitForState in
// service_windows.go, needed for the identical reason: schtasks /run and
// /end both return once the Task Scheduler service has accepted the request,
// not once the action has actually started or exited.
func waitForLogonTaskProcess(ctx context.Context, exe string, want bool, budget time.Duration) (bool, error) {
	exeBase := filepath.Base(exe)
	deadline := time.Now().Add(budget)
	for {
		running, err := winProcessRunning(exeBase)
		if err != nil {
			return false, fmt.Errorf("check whether %s is running: %w", exeBase, err)
		}
		if running == want {
			return running, nil
		}
		if time.Now().After(deadline) {
			return running, nil
		}
		if err := sleepCtx(ctx, servicePoll); err != nil {
			return running, err
		}
	}
}

// ── the task definition ─────────────────────────────────────────────────────

// logonTaskArguments joins runArgs into the single string Task Scheduler's
// <Arguments> element expects, each argument escaped exactly as
// winServiceImagePath escapes the SCM's command line — same syscall function,
// same reasoning: CreateProcess parses one string, and "close enough" is how
// an argument containing a space survives wrong.
func logonTaskArguments(runArgs []string) string {
	parts := make([]string, 0, len(runArgs))
	for _, a := range runArgs {
		parts = append(parts, syscall.EscapeArg(a))
	}
	return strings.Join(parts, " ")
}

// logonTaskXML renders the Task Scheduler task definition schtasks /create
// /xml consumes.
//
// Three settings below exist only because their defaults are traps for a
// long-running process, and Task Scheduler applies the trap silently:
//
//   - ExecutionTimeLimit defaults to PT72H (72 hours) when the element is
//     absent, and the Task Scheduler engine kills the action when that limit
//     is reached. A proxy meant to run for the length of a login session
//     would be silently terminated three days in. PT0S turns the limit off.
//   - DisallowStartIfOnBatteries and StopIfGoingOnBatteries both default to
//     true. dpb exists to keep a connection open on whatever hardware it is
//     asked to run on; a proxy that stops the moment a laptop is unplugged is
//     not that.
//
// RunLevel is LeastPrivilege, not HighestAvailable: this mechanism exists
// precisely because proxy mode does NOT need administrator (see the package
// comment), and asking for elevation here would make Task Scheduler prompt
// UAC at every logon for no reason this scope has.
//
// MultipleInstancesPolicy is IgnoreNew: a second logon (fast user switching,
// or logging in again before logging out) must not start a second copy
// competing for the same listener port.
func logonTaskXML(userSID, exe string, runArgs []string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` + "\n")

	b.WriteString("  <RegistrationInfo>\n")
	b.WriteString("    <Description>" + xmlText(logonTaskDescription) + "</Description>\n")
	b.WriteString("  </RegistrationInfo>\n")

	b.WriteString("  <Triggers>\n")
	b.WriteString("    <LogonTrigger>\n")
	b.WriteString("      <Enabled>true</Enabled>\n")
	b.WriteString("      <UserId>" + xmlText(userSID) + "</UserId>\n")
	b.WriteString("    </LogonTrigger>\n")
	b.WriteString("  </Triggers>\n")

	b.WriteString("  <Principals>\n")
	b.WriteString("    <Principal id=\"Author\">\n")
	b.WriteString("      <UserId>" + xmlText(userSID) + "</UserId>\n")
	b.WriteString("      <LogonType>InteractiveToken</LogonType>\n")
	b.WriteString("      <RunLevel>LeastPrivilege</RunLevel>\n")
	b.WriteString("    </Principal>\n")
	b.WriteString("  </Principals>\n")

	b.WriteString("  <Settings>\n")
	b.WriteString("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n")
	b.WriteString("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n")
	b.WriteString("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n")
	b.WriteString("    <AllowHardTerminate>true</AllowHardTerminate>\n")
	b.WriteString("    <StartWhenAvailable>false</StartWhenAvailable>\n")
	b.WriteString("    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n")
	b.WriteString("    <IdleSettings>\n")
	b.WriteString("      <StopOnIdleEnd>false</StopOnIdleEnd>\n")
	b.WriteString("      <RestartOnIdle>false</RestartOnIdle>\n")
	b.WriteString("    </IdleSettings>\n")
	b.WriteString("    <AllowStartOnDemand>true</AllowStartOnDemand>\n")
	b.WriteString("    <Enabled>true</Enabled>\n")
	b.WriteString("    <Hidden>false</Hidden>\n")
	b.WriteString("    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n")
	b.WriteString("    <WakeToRun>false</WakeToRun>\n")
	b.WriteString("    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n")
	b.WriteString("    <Priority>7</Priority>\n")
	b.WriteString("  </Settings>\n")

	b.WriteString("  <Actions Context=\"Author\">\n")
	b.WriteString("    <Exec>\n")
	b.WriteString("      <Command>" + xmlText(exe) + "</Command>\n")
	b.WriteString("      <Arguments>" + xmlText(logonTaskArguments(runArgs)) + "</Arguments>\n")
	b.WriteString("    </Exec>\n")
	b.WriteString("  </Actions>\n")

	b.WriteString("</Task>\n")
	return b.String()
}

// xmlText escapes a string for an XML text node — service_darwin.go's
// plistText, unavailable here across the darwin/windows build-tag boundary,
// re-implemented against the same stdlib call for the same reason: a home
// directory or account name can contain an ampersand, and without this the
// task XML would be silently invalid.
func xmlText(s string) string {
	var buf bytes.Buffer
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		// EscapeText writes to a bytes.Buffer, which never fails.
		return s
	}
	return buf.String()
}
