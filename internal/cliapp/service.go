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

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/paths"
)

// `dpb service` installs dpb as a launchd job so it survives logout and reboot.
//
// Two things about this command are deliberate and easy to get wrong.
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
func newServiceCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Install, remove and inspect dpb as a launchd job",
		Long: "service manages dpb's launchd job.\n\n" +
			"By default it installs a LaunchAgent in your own login session, which is the\n" +
			"right choice for proxy mode: it needs no root, it starts when you log in, and\n" +
			"the proxy environment variables it sets land in the session your applications\n" +
			"actually run in.\n\n" +
			"--system installs a LaunchDaemon instead. That needs root, and it is only the\n" +
			"right choice when dpb must run before or without a login session.",
	}
	cmd.AddCommand(
		newServiceInstallCmd(g),
		newServiceUninstallCmd(g),
		newServiceStartCmd(g),
		newServiceStopCmd(g),
		newServiceStatusCmd(g),
		newServiceLogsCmd(g),
	)
	return cmd
}

// serviceLabel is the launchd job name. It is also the file name of the plist
// and half of every service target, so it is not a value to change lightly:
// a rename orphans the job an older dpb installed.
const serviceLabel = "com.mumudevx.dpb"

const (
	serviceOutLog = "service.out.log"
	serviceErrLog = "service.err.log"

	// serviceThrottle is launchd's minimum seconds between respawns.
	//
	// launchd's own floor is 10 s. 30 s is deliberately slower, because the
	// exits worth respawning through are transient (a listener losing its port
	// to a race at login) while the exit that is NOT worth respawning through
	// is `dpb run` refusing for safety — a full-tunnel VPN owns the default
	// route, or a captive portal is up. launchd has no way to express "restart
	// unless the exit code was 5", so the honest compromise is to keep the
	// retry loop cheap enough to leave running and loud enough to find in the
	// log.
	serviceThrottle = 30
)

// serviceScope is where one launchd job lives: which launchd domain owns it,
// which file describes it, and where its output goes.
type serviceScope struct {
	system bool
	uid    int
	// domain is a launchd domain target: "system", or "gui/<uid>".
	domain string
	plist  string
	logDir string
	outLog string
	errLog string
	layout paths.Layout
}

// target is the service target `launchctl enable/bootout/kickstart/print` take.
func (s serviceScope) target() string { return s.domain + "/" + serviceLabel }

func (s serviceScope) kind() string {
	if s.system {
		return "system daemon"
	}
	return "user agent"
}

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
		root := g.sysRoot
		if root == "" {
			root = string(filepath.Separator)
		}
		s.domain = "system"
		s.plist = filepath.Join(root, "Library", "LaunchDaemons", serviceLabel+".plist")
		s.logDir = filepath.Join(root, "Library", "Logs", "dpb")
	} else {
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

// requireRoot turns "you need sudo" into exit code 4 rather than a launchctl
// permission error the user has to decode.
func requireRoot(s serviceScope, verb string) error {
	if !s.system || s.layout.Elevated {
		return nil
	}
	return codedError{
		code: ExitNeedRoot,
		err: fmt.Errorf("service %s --system writes %s and bootstraps into launchd's system domain: re-run with sudo",
			verb, s.plist),
	}
}

func systemFlag(cmd *cobra.Command, v *bool) {
	cmd.Flags().BoolVar(v, "system", false,
		"act on the machine-wide LaunchDaemon instead of your login session's LaunchAgent")
}

// ── install ─────────────────────────────────────────────────────────────────

func newServiceInstallCmd(g *globals) *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:   "install [-- RUN FLAGS...]",
		Short: "Write the launchd job and load it",
		Long: "install writes the property list, enables the job, and bootstraps it into\n" +
			"launchd, then confirms launchd knows about it.\n\n" +
			"Anything after `--` is appended to the `dpb run` command line the job runs.\n" +
			"Those flags are parsed here, before the plist is written, so a typo is a\n" +
			"usage error now rather than a job launchd respawns and kills forever.\n\n" +
			"For scripts: --system writes into /Library/LaunchDaemons and bootstraps into\n" +
			"launchd's system domain, so without root it stops before writing anything and\n" +
			"returns exit 4. That code means \"re-run this with sudo\" and nothing else —\n" +
			"`dpb tune` reports \"nothing is blocked here\" as exit 6, not 4, so a caller can\n" +
			"branch on the two.",
		Example: "  dpb service install\n" +
			"  dpb service install -- --profile turkey --port 8081\n" +
			"  sudo dpb service install --system",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return serviceInstall(cmd.Context(), g, system, args)
		},
	}
	systemFlag(cmd, &system)
	return cmd
}

func serviceInstall(ctx context.Context, g *globals, system bool, extra []string) error {
	s, err := g.serviceScopeFor(system)
	if err != nil {
		return err
	}
	if err := requireRoot(s, "install"); err != nil {
		return err
	}
	if err := checkRunFlags(g, extra); err != nil {
		return err
	}

	exe, err := g.exeOf()
	if err != nil {
		return err
	}

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

	args := append([]string{exe, "run"}, extra...)
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

// checkRunFlags parses extra against the real `dpb run` flag set.
//
// It runs against a copy of globals so parsing "-v" here does not raise the
// verbosity of the install command itself.
func checkRunFlags(g *globals, extra []string) error {
	if len(extra) == 0 {
		return nil
	}
	tmp := *g
	root := newRoot(&tmp)
	argv := append([]string{"run"}, extra...)
	cmd, flags, err := root.Find(argv)
	if err != nil || cmd.Name() != "run" {
		return usagef("service install: cannot check the run flags: %v", err)
	}
	if err := cmd.ParseFlags(flags); err != nil {
		return usagef("service install: `dpb run %s` would not start: %v", strings.Join(extra, " "), err)
	}
	if rest := cmd.Flags().Args(); len(rest) > 0 {
		return usagef("service install: `dpb run` takes no positional arguments, got %q", rest[0])
	}
	return nil
}

// ── uninstall ───────────────────────────────────────────────────────────────

func newServiceUninstallCmd(g *globals) *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Unload the launchd job and delete its property list",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serviceUninstall(cmd.Context(), g, system)
		},
	}
	systemFlag(cmd, &system)
	return cmd
}

func serviceUninstall(ctx context.Context, g *globals, system bool) error {
	s, err := g.serviceScopeFor(system)
	if err != nil {
		return err
	}
	if err := requireRoot(s, "uninstall"); err != nil {
		return err
	}
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

// ── start / stop ────────────────────────────────────────────────────────────

func newServiceStartCmd(g *globals) *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Load and start an installed job",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serviceStart(cmd.Context(), g, system)
		},
	}
	systemFlag(cmd, &system)
	return cmd
}

func serviceStart(ctx context.Context, g *globals, system bool) error {
	s, err := g.serviceScopeFor(system)
	if err != nil {
		return err
	}
	if err := requireRoot(s, "start"); err != nil {
		return err
	}
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

func newServiceStopCmd(g *globals) *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Unload the job, leaving it installed",
		Long: "stop boots the job out of launchd rather than signalling it. The job is\n" +
			"configured to come back after an unclean exit, so a signal would only\n" +
			"restart it; `dpb service start` loads it again.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serviceStop(cmd.Context(), g, system)
		},
	}
	systemFlag(cmd, &system)
	return cmd
}

func serviceStop(ctx context.Context, g *globals, system bool) error {
	s, err := g.serviceScopeFor(system)
	if err != nil {
		return err
	}
	if err := requireRoot(s, "stop"); err != nil {
		return err
	}
	run := g.runnerOf()
	_ = run.Run(ctx, "launchctl", "bootout", s.target())

	if st := serviceStateOf(ctx, run, s); st.loaded {
		return fmt.Errorf("service stop: %s is still loaded in %s", serviceLabel, s.domain)
	}
	fmt.Fprintf(g.env.Stdout, "stopped  %s (%s), still installed at %s\n", serviceLabel, s.kind(), s.plist)
	return nil
}

// ── status ──────────────────────────────────────────────────────────────────

func newServiceStatusCmd(g *globals) *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Report whether the job is installed, loaded and running",
		Long: "status with no --system looks in your login session first and then in the\n" +
			"system domain, so it finds the job wherever it was installed. Exit status is\n" +
			"0 only when a job is actually running.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serviceStatus(cmd.Context(), g, system, cmd.Flags().Changed("system"))
		},
	}
	systemFlag(cmd, &system)
	return cmd
}

func serviceStatus(ctx context.Context, g *globals, system, pinned bool) error {
	scopes := []bool{system}
	if !pinned {
		// Checking both is what makes `sudo dpb service install --system &&
		// dpb service status` report the daemon it just installed. Reading the
		// system domain needs no privilege.
		scopes = []bool{false, true}
	}

	run := g.runnerOf()
	w := g.env.Stdout
	found := false
	running := false

	for _, sys := range scopes {
		s, err := g.serviceScopeFor(sys)
		if err != nil {
			// A root shell has no login session to report on; that is not an
			// error when the system domain is still to be checked.
			if len(scopes) > 1 {
				continue
			}
			return err
		}
		_, statErr := os.Stat(s.plist)
		st := serviceStateOf(ctx, run, s)
		if statErr != nil && !st.loaded {
			continue
		}
		found = true
		running = running || st.running

		fmt.Fprintf(w, "%s  (%s)\n", serviceLabel, s.kind())
		fmt.Fprintf(w, "  plist    %s%s\n", s.plist, existsNote(statErr))
		fmt.Fprintf(w, "  state    %s\n", st.describe())
		if st.pid > 0 {
			fmt.Fprintf(w, "  pid      %d\n", st.pid)
		}
		fmt.Fprintf(w, "  logs     %s\n           %s\n", s.outLog, s.errLog)
	}

	if !found {
		fmt.Fprintf(w, "%s is not installed\n", serviceLabel)
		fmt.Fprintf(w, "  install it with `dpb service install`\n")
		return errors.New("service status: not installed")
	}
	if !running {
		return errors.New("service status: installed but not running")
	}
	return nil
}

func existsNote(statErr error) string {
	if statErr == nil {
		return ""
	}
	// A loaded job whose plist is gone is a real state: someone deleted the
	// file without booting the job out, and it will not come back at login.
	return "  (missing)"
}

// ── logs ────────────────────────────────────────────────────────────────────

func newServiceLogsCmd(g *globals) *cobra.Command {
	var system bool
	var lines int
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Print the tail of the job's stdout and stderr",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return serviceLogs(g, system, lines)
		},
	}
	systemFlag(cmd, &system)
	cmd.Flags().IntVarP(&lines, "lines", "n", 50, "lines to print from the end of each file")
	return cmd
}

func serviceLogs(g *globals, system bool, lines int) error {
	if lines <= 0 {
		return usagef("service logs: --lines must be positive, got %d", lines)
	}
	s, err := g.serviceScopeFor(system)
	if err != nil {
		return err
	}
	w := g.env.Stdout
	for _, f := range []string{s.outLog, s.errLog} {
		fmt.Fprintf(w, "==> %s\n", f)
		b, err := os.ReadFile(f)
		switch {
		case errors.Is(err, os.ErrNotExist):
			// Not an error: launchd creates these on the job's first write, so
			// their absence usually means the job has never run.
			fmt.Fprintf(w, "    (no such file — the job has not written to it yet)\n")
			continue
		case err != nil:
			return fmt.Errorf("service logs: read %s: %w", f, err)
		}
		out := tailLines(string(b), lines)
		if out == "" {
			fmt.Fprintf(w, "    (empty)\n")
			continue
		}
		fmt.Fprintln(w, out)
	}
	fmt.Fprintf(w, "\nfollow with: tail -f %s\n", s.errLog)
	return nil
}

// tailLines returns the last n lines of s, without a trailing newline.
func tailLines(s string, n int) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	all := strings.Split(s, "\n")
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return strings.Join(all, "\n")
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
