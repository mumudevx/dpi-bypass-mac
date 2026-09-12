//go:build darwin

package cliapp

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/mumudevx/dpb/internal/netstate"
)

// dpb installs itself as a launchd job so it survives logout and reboot.
//
// Two things about this mechanism are deliberate and easy to get wrong.
//
// First, the verbs. launchd's `load -w` / `unload -w` have been deprecated
// since 10.10 and lie in ways that matter: `load` on an already-loaded job
// prints nothing useful, and `-w` silently rewrites the persistent disabled
// database, so a job can end up disabled with no record of who did it. The
// modern triple — `enable`, `bootstrap`, `bootout` — separates "may this run"
// from "is this loaded", and each one reports a real failure. docs/PLAN.md's
// CLI surface names them explicitly: never `load -w`.
//
// Second, the verification. Every other mutation in this tool is verified
// through a different subsystem than it was applied with (see netstate's
// package comment). launchd has no second observer for its own job table, so
// this command splits the difference the same way netstate's launchenv Op does:
// the half that CAN be independently checked — the plist we wrote — is checked
// with plutil(1) and a read-back, and only the load itself is confirmed with
// `launchctl print`. A green install therefore means "the file on disk is a
// valid property list AND launchd admits to knowing the job", which is strictly
// more than "launchctl exited 0".
//
// Everything in this file runs only when a serviceScope's mech is launchdAgent
// or launchdDaemon — service.go's six verbs call into it exactly once each
// (installMechanism, uninstallMechanism, startMechanism, stopMechanism,
// statusMechanism) and never touch launchctl, plutil or a plist path
// themselves.

// serviceScopeFor resolves the scope for this invocation.
//
// The log directory is NOT taken from the invoking user's layout when --system
// is given. A LaunchDaemon runs as root with no SUDO_USER, so paths.Resolve()
// inside it returns the machine-wide layout; pointing the plist at the invoking
// user's ~/Library/Logs would split the daemon's own event log from the stdout
// launchd captures for it, and `dpb service logs` would then read the wrong
// half.
func (g *globals) serviceScopeFor(system bool) (serviceScope, error) {
	l, err := g.layoutOf()
	if err != nil {
		return serviceScope{}, err
	}
	s := serviceScope{system: system, uid: l.UID, layout: l}
	if system {
		s.mech = launchdDaemon
		root := g.sysRoot
		if root == "" {
			root = string(filepath.Separator)
		}
		s.domain = "system"
		s.plist = filepath.Join(root, "Library", "LaunchDaemons", serviceLabel+".plist")
		s.logDir = filepath.Join(root, "Library", "Logs", "dpb")
	} else {
		s.mech = launchdAgent
		if l.Home == "" {
			return serviceScope{}, usagef(
				"there is no login session to install into (root with no SUDO_USER); use --system")
		}
		s.domain = "gui/" + strconv.Itoa(l.UID)
		s.plist = filepath.Join(l.Home, "Library", "LaunchAgents", serviceLabel+".plist")
		s.logDir = l.LogDir
	}
	s.outLog = filepath.Join(s.logDir, serviceOutLog)
	s.errLog = filepath.Join(s.logDir, serviceErrLog)
	return s, nil
}

// target is the service target `launchctl enable/bootout/kickstart/print` take.
func (s serviceScope) target() string { return s.domain + "/" + serviceLabel }

// installMechanism writes the property list, enables the job, and bootstraps
// it into launchd, then confirms launchd knows about it. It is what
// `dpb service install` does once service.go's generic checks (root, run
// flags, the binary's own path) have passed.
func installMechanism(ctx context.Context, g *globals, s serviceScope, args []string) error {
	if err := os.MkdirAll(filepath.Dir(s.plist), 0o755); err != nil {
		return fmt.Errorf("service install: create %s: %w", filepath.Dir(s.plist), err)
	}
	if err := os.MkdirAll(s.logDir, 0o755); err != nil {
		return fmt.Errorf("service install: create %s: %w", s.logDir, err)
	}
	// Under sudo the plist is written by root into the invoking user's
	// LaunchAgents directory; hand both back or the user cannot remove their
	// own service without sudo either. Chown is a no-op when unprivileged.
	_ = s.layout.Chown(filepath.Dir(s.plist))
	_ = s.layout.Chown(s.logDir)

	if err := os.WriteFile(s.plist, []byte(servicePlist(args, s)), 0o644); err != nil {
		return fmt.Errorf("service install: write %s: %w", s.plist, err)
	}
	_ = s.layout.Chown(s.plist)

	run := g.runnerOf()

	// Verify the file before launchd ever sees it. plutil is a different
	// reader than the writer above, and an invalid plist is the one failure
	// launchd reports so badly (a bare "Bootstrap failed: 5: Input/output
	// error") that it is worth spending a process to rule out.
	if res := run.Run(ctx, "plutil", "-lint", s.plist); res.Failed() {
		_ = os.Remove(s.plist)
		return fmt.Errorf("service install: the property list dpb generated is not valid: %s", res.Reason())
	}

	// Make a reinstall idempotent. A job that is already loaded makes
	// bootstrap fail, and the user asked for "install", not "fail because you
	// already did this".
	_ = run.Run(ctx, "launchctl", "bootout", s.target())

	if res := run.Run(ctx, "launchctl", "enable", s.target()); res.Failed() {
		return serviceRollback(ctx, run, s, fmt.Errorf("service install: %s", res.Reason()))
	}
	if res := run.Run(ctx, "launchctl", "bootstrap", s.domain, s.plist); res.Failed() {
		return serviceRollback(ctx, run, s, fmt.Errorf("service install: %s", res.Reason()))
	}

	st := serviceStateOf(ctx, run, s)
	if !st.loaded {
		return serviceRollback(ctx, run, s,
			errors.New("service install: launchctl reported success but launchd does not know the job"))
	}

	w := g.env.Stdout
	fmt.Fprintf(w, "installed  %s (%s)\n", serviceLabel, s.kind())
	fmt.Fprintf(w, "  plist    %s\n", s.plist)
	fmt.Fprintf(w, "  command  %s\n", strings.Join(args, " "))
	fmt.Fprintf(w, "  logs     %s\n           %s\n", s.outLog, s.errLog)
	fmt.Fprintf(w, "  state    %s\n", st.describe())
	if s.system {
		// Said out loud because a silently reduced coverage surface is exactly
		// the failure this tool exists to avoid. `launchctl setenv` sets the
		// variables in the domain of the process that calls it; a daemon runs
		// in the system domain, and GUI applications inherit from their own
		// gui/<uid> domain, so the HTTP(S)_PROXY lever that reaches Electron's
		// in-process updater does not reach it from here.
		fmt.Fprintf(w, "\nnote: a system daemon sets HTTP(S)_PROXY in launchd's system domain, which\n"+
			"      GUI applications do not inherit. For proxy mode, the user agent\n"+
			"      (`dpb service install` with no --system) covers more of your machine.\n")
	} else {
		fmt.Fprintf(w, "\nIt starts at login and is running now. `dpb service stop` unloads it.\n")
	}
	return nil
}

// serviceRollback undoes a half-finished install so the machine is never left
// with a plist launchd will pick up at the next login and a user who was told
// the install failed.
func serviceRollback(ctx context.Context, run netstate.Runner, s serviceScope, cause error) error {
	_ = run.Run(ctx, "launchctl", "bootout", s.target())
	_ = os.Remove(s.plist)
	return fmt.Errorf("%w (the job was removed again, nothing is installed)", cause)
}

// uninstallMechanism unloads the launchd job and deletes its property list.
func uninstallMechanism(ctx context.Context, g *globals, s serviceScope) error {
	run := g.runnerOf()

	// bootout's result is deliberately ignored: it fails with "Could not find
	// service" for a job that is not loaded, which is the state uninstall is
	// trying to reach. What the job's absence is judged on is the check below,
	// not this command's exit status.
	_ = run.Run(ctx, "launchctl", "bootout", s.target())

	if err := os.Remove(s.plist); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("service uninstall: remove %s: %w", s.plist, err)
	}

	st := serviceStateOf(ctx, run, s)
	if st.loaded {
		return fmt.Errorf("service uninstall: %s is still loaded in %s after bootout; "+
			"run `launchctl print %s` to see why", serviceLabel, s.domain, s.target())
	}
	if _, err := os.Stat(s.plist); err == nil {
		return fmt.Errorf("service uninstall: %s still exists", s.plist)
	}
	fmt.Fprintf(g.env.Stdout, "removed  %s (%s)\n", serviceLabel, s.kind())
	fmt.Fprintf(g.env.Stdout, "  logs are left in place: %s\n", s.logDir)
	return nil
}

// startMechanism loads and starts an installed job.
func startMechanism(ctx context.Context, g *globals, s serviceScope) error {
	if _, err := os.Stat(s.plist); err != nil {
		return fmt.Errorf("service start: %s is not installed (no %s); run `dpb service install` first",
			serviceLabel, s.plist)
	}
	run := g.runnerOf()

	if st := serviceStateOf(ctx, run, s); !st.loaded {
		// stop unloads rather than signalling, because the job has KeepAlive
		// set and a signalled job comes straight back. So start's first move
		// is to load it again.
		if res := run.Run(ctx, "launchctl", "enable", s.target()); res.Failed() {
			return fmt.Errorf("service start: %s", res.Reason())
		}
		if res := run.Run(ctx, "launchctl", "bootstrap", s.domain, s.plist); res.Failed() {
			return fmt.Errorf("service start: %s", res.Reason())
		}
	}
	if res := run.Run(ctx, "launchctl", "kickstart", s.target()); res.Failed() {
		return fmt.Errorf("service start: %s", res.Reason())
	}

	st := serviceStateOf(ctx, run, s)
	if !st.running {
		return fmt.Errorf("service start: %s is loaded but not running (%s); `dpb service logs` will say why",
			serviceLabel, st.describe())
	}
	fmt.Fprintf(g.env.Stdout, "started  %s (%s), %s\n", serviceLabel, s.kind(), st.describe())
	return nil
}

// stopMechanism unloads the job, leaving it installed.
func stopMechanism(ctx context.Context, g *globals, s serviceScope) error {
	run := g.runnerOf()
	_ = run.Run(ctx, "launchctl", "bootout", s.target())

	if st := serviceStateOf(ctx, run, s); st.loaded {
		return fmt.Errorf("service stop: %s is still loaded in %s", serviceLabel, s.domain)
	}
	fmt.Fprintf(g.env.Stdout, "stopped  %s (%s), still installed at %s\n", serviceLabel, s.kind(), s.plist)
	return nil
}

// statusMechanism reports and prints one scope's launchd state. It returns
// whether the job was found (installed or loaded) and whether it is running.
func statusMechanism(ctx context.Context, g *globals, s serviceScope) (found, running bool) {
	run := g.runnerOf()
	w := g.env.Stdout

	_, statErr := os.Stat(s.plist)
	st := serviceStateOf(ctx, run, s)
	if statErr != nil && !st.loaded {
		return false, false
	}

	fmt.Fprintf(w, "%s  (%s)\n", serviceLabel, s.kind())
	fmt.Fprintf(w, "  plist    %s%s\n", s.plist, existsNote(statErr))
	fmt.Fprintf(w, "  state    %s\n", st.describe())
	if st.pid > 0 {
		fmt.Fprintf(w, "  pid      %d\n", st.pid)
	}
	fmt.Fprintf(w, "  logs     %s\n           %s\n", s.outLog, s.errLog)
	return true, st.running
}

// ── launchctl print, read as evidence rather than as an exit code ───────────

// serviceState is what `launchctl print` says about a job.
type serviceState struct {
	loaded  bool
	running bool
	state   string
	pid     int
}

func (st serviceState) describe() string {
	switch {
	case !st.loaded:
		return "not loaded"
	case st.state != "":
		return st.state
	case st.running:
		return "running"
	default:
		return "loaded"
	}
}

var (
	// launchctl print's body is an indented block of `key = value` lines.
	// Captured from this machine (macOS 26.3.1) on 2026-09-02:
	//
	//   gui/501/com.apple.Finder = {
	//   	active count = 7
	//   	state = running
	//   	pid = 430
	//
	// A job that is loaded but idle prints `state = not running` and no pid at
	// all, which is why "running" is decided by the state line and not by the
	// presence of a pid.
	reServiceState = regexp.MustCompile(`(?m)^\s*state\s*=\s*(.+?)\s*$`)
	reServicePID   = regexp.MustCompile(`(?m)^\s*pid\s*=\s*(\d+)\s*$`)
)

// serviceStateOf asks launchd about the job.
//
// A failure is reported as "not loaded" rather than as an error, because that
// is what launchctl's failure means here: `launchctl print` on an unknown job
// exits 113 with "Could not find service ... in domain for ...". Any other
// failure — a missing launchctl, a permission problem — also leaves us unable
// to claim the job is loaded, and every caller treats "not loaded" as the
// conservative answer.
func serviceStateOf(ctx context.Context, run netstate.Runner, s serviceScope) serviceState {
	res := run.Run(ctx, "launchctl", "print", s.target())
	if res.Failed() {
		return serviceState{}
	}
	st := serviceState{loaded: true}
	if m := reServiceState.FindStringSubmatch(res.Combined); m != nil {
		st.state = m[1]
		st.running = m[1] == "running"
	}
	if m := reServicePID.FindStringSubmatch(res.Combined); m != nil {
		st.pid, _ = strconv.Atoi(m[1])
	}
	return st
}

// ── the property list ───────────────────────────────────────────────────────

// servicePlist renders the job description.
//
// Two omissions are deliberate. There is no PATH in EnvironmentVariables:
// launchd's default is /usr/bin:/bin:/usr/sbin:/sbin (confirmed by reading
// `launchctl print`'s "default environment" on this machine), which already
// contains every tool netstate shells out to — networksetup and scutil in
// /usr/sbin, route and ifconfig in /sbin, launchctl and ps in /bin. And there
// is no UserName key for the daemon: `dpb run` needs root for nothing in proxy
// mode, but the --system form exists precisely for the cases that do.
func servicePlist(argv []string, s serviceScope) string {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")

	b.WriteString("\t<key>Label</key>\n\t<string>" + plistText(serviceLabel) + "</string>\n")

	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, a := range argv {
		b.WriteString("\t\t<string>" + plistText(a) + "</string>\n")
	}
	b.WriteString("\t</array>\n")

	b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")

	// KeepAlive as a dictionary rather than <true/>: SuccessfulExit=false means
	// "respawn only when it exited non-zero", so `dpb panic` and a deliberate
	// `dpb service stop` do not fight launchd.
	b.WriteString("\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n")
	b.WriteString(fmt.Sprintf("\t<key>ThrottleInterval</key>\n\t<integer>%d</integer>\n", serviceThrottle))

	// Interactive keeps launchd from applying background-task CPU and I/O
	// throttling to a process every TCP connection on the machine waits behind.
	b.WriteString("\t<key>ProcessType</key>\n\t<string>Interactive</string>\n")

	b.WriteString("\t<key>StandardOutPath</key>\n\t<string>" + plistText(s.outLog) + "</string>\n")
	b.WriteString("\t<key>StandardErrorPath</key>\n\t<string>" + plistText(s.errLog) + "</string>\n")

	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

// plistText escapes a string for an XML text node. A home directory can contain
// an ampersand; without this the plist would be silently invalid and launchd
// would report only "Input/output error".
func plistText(s string) string {
	var b bytes.Buffer
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		// EscapeText writes to a bytes.Buffer, which never fails.
		return s
	}
	return b.String()
}
