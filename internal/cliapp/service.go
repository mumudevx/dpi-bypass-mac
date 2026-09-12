package cliapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpb/internal/paths"
)

// `dpb service` installs dpb as a background service so it survives logout
// and reboot, using whichever mechanism its serviceMech is bound to.
//
// This file is the platform-free half: the six verbs (install, uninstall,
// start, stop, status, logs) and the generic checks every mechanism needs
// (needs-root, are the run flags well-formed, where do the logs live). What
// each verb actually DOES to the machine — writing a launchd plist and
// calling launchctl today; a Windows Task Scheduler entry or a Windows
// service once Plan 5's Tasks 2 and 3 land — is one platform call per verb:
// installMechanism, uninstallMechanism, startMechanism, stopMechanism,
// statusMechanism. See service_darwin.go for launchd's implementation of
// those, including why its verbs are `enable`/`bootstrap`/`bootout` rather
// than the deprecated `load -w`/`unload -w`, and how an install is verified
// against two independent readers.
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

	// serviceThrottle is the minimum seconds between respawns.
	//
	// launchd's own floor is 10 s. 30 s is deliberately slower, because the
	// exits worth respawning through are transient (a listener losing its port
	// to a race at login) while the exit that is NOT worth respawning through
	// is `dpb run` refusing for safety — a full-tunnel VPN owns the default
	// route, or a captive portal is up. launchd has no way to express "restart
	// unless the exit code was 5", so the honest compromise is to keep the
	// retry loop cheap enough to leave running and loud enough to find in the
	// log. The Windows service mechanism (Plan 5 Task 3) needs the identical
	// reasoning for its own recovery-action delay, which is why this constant
	// and its comment live here rather than in service_darwin.go.
	serviceThrottle = 30
)

// serviceMech is the platform mechanism a serviceScope is bound to.
type serviceMech int

const (
	launchdAgent  serviceMech = iota // darwin, gui/<uid>
	launchdDaemon                    // darwin, system
	winLogonTask                     // windows, the interactive user
	winService                       // windows, LocalSystem
)

// serviceScope is where one service instance lives: which mechanism owns it,
// and where its output goes. system and uid identify the scope every
// mechanism understands; the fields below mech are consulted only by that
// mechanism's own code.
type serviceScope struct {
	system bool
	uid    int
	// mech is which platform mechanism owns this scope. See serviceMech.
	mech serviceMech

	// domain and plist are launchd's own vocabulary for locating and
	// describing the job — see service_darwin.go. They are meaningful only
	// when mech is launchdAgent or launchdDaemon; a mechanism with no use for
	// them (a Windows scheduled task, a Windows service) leaves them empty.
	domain string
	plist  string

	logDir string
	outLog string
	errLog string
	layout paths.Layout
}

func (s serviceScope) kind() string {
	if s.system {
		return "system daemon"
	}
	return "user agent"
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

	args := append([]string{exe, "run"}, extra...)
	return installMechanism(ctx, g, s, args)
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
	return uninstallMechanism(ctx, g, s)
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
	return startMechanism(ctx, g, s)
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
	return stopMechanism(ctx, g, s)
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
		f, r := statusMechanism(ctx, g, s)
		found = found || f
		running = running || r
	}

	if !found {
		fmt.Fprintf(g.env.Stdout, "%s is not installed\n", serviceLabel)
		fmt.Fprintf(g.env.Stdout, "  install it with `dpb service install`\n")
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

// serviceLogs needs no platform call: whatever mechanism produced s.outLog
// and s.errLog, reading their tails back is the same file I/O regardless.
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
