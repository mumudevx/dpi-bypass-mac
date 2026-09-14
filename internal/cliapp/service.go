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
// each verb actually DOES to the machine — writing a launchd plist and calling
// launchctl on darwin; creating a LocalSystem service in the Windows service
// control manager on Windows — is one platform call per verb:
// installMechanism, uninstallMechanism, startMechanism, stopMechanism,
// statusMechanism. See service_darwin.go for launchd's implementation of
// those, including why its verbs are `enable`/`bootstrap`/`bootout` rather
// than the deprecated `load -w`/`unload -w`, and how an install is verified
// against two independent readers; see service_windows.go for the SCM's, whose
// two readers are the registry and the SCM itself.
//
// Five more identifiers are platform-provided, and they exist because a
// message that names the wrong mechanism is a message that sends a user
// somewhere that does not exist:
//
//	serviceName         what the user sees the job called
//	serviceInstallHint  the command that installs it here
//	serviceFollowHint   how to tail a growing log file here
//	serviceHelp         every help string whose truth is mechanism-specific
//	serviceLogNote      why s.outLog and s.errLog may never appear, or ""
//
// Each platform file defines all five. serviceHelp and serviceLogNote were
// added when `dpb service --help` was found still explaining launchd to
// Windows users after `doctor` and the README had been corrected. A help text
// is the surface a user meets FIRST, so naming a mechanism their machine does
// not have is not a cosmetic wrong — and the same applies to promising log
// files that a mechanism never writes, which is what serviceLogNote is for.
// serviceLabel below is launchd's own and stays launchd's own.
func newServiceCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: serviceHelp.cmdShort,
		Long:  serviceHelp.cmdLong,
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

// serviceHelpText is the set of help strings whose wording depends on which
// mechanism the platform binds a scope to. One struct rather than a dozen
// loose constants: it keeps the per-platform definitions side by side, so the
// next person to add a verb cannot half-define it, and the fields are the
// exact set of places this file used to name launchd unconditionally.
type serviceHelpText struct {
	cmdShort       string
	cmdLong        string
	scopeFlag      string
	installShort   string
	installLong    string
	installExample string
	uninstallShort string
	stopShort      string
	stopLong       string
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
	// log. The Windows service mechanism needs the identical reasoning for its
	// own recovery-action delay — see serviceRecoveryActions in
	// service_windows.go, which uses this constant — which is why it and this
	// comment live here rather than in service_darwin.go.
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

// kind is the one-phrase name for this scope's mechanism, printed in every
// install, stop, remove and status line.
//
// It switches on mech rather than on system alone because "user agent" and
// "system daemon" are launchd's words, and a Windows install printing
// "installed dpb (user agent)" names something that does not exist on the
// machine the user is reading it on. The two launchd mechanisms keep their
// exact previous strings, which is why the switch falls through to the
// system/agent pair rather than listing them.
func (s serviceScope) kind() string {
	switch s.mech {
	case winLogonTask:
		return "logon task"
	case winService:
		return "Windows service"
	}
	if s.system {
		return "system daemon"
	}
	return "user agent"
}

// requireRoot turns "you need sudo" into exit code 4 rather than a launchctl
// permission error the user has to decode.
//
// The sentence differs by mechanism because the privileged operation does.
// launchd needs root to write into /Library/LaunchDaemons and bootstrap into
// the system domain; the SCM needs an elevated token before it will accept
// CreateService, Start or Delete, and there is no sudo on Windows to re-run
// with. Advice that cannot be followed is worse than no advice, so the two are
// not merged into one string.
func requireRoot(s serviceScope, verb string) error {
	if !s.system || s.layout.Elevated {
		return nil
	}
	if s.mech == winService {
		return codedError{
			code: ExitNeedRoot,
			err: fmt.Errorf("service %s --system creates a LocalSystem service, which the service control manager refuses to an unelevated token: re-run from an Administrator prompt",
				verb),
		}
	}
	return codedError{
		code: ExitNeedRoot,
		err: fmt.Errorf("service %s --system writes %s and bootstraps into launchd's system domain: re-run with sudo",
			verb, s.plist),
	}
}

func systemFlag(cmd *cobra.Command, v *bool) {
	cmd.Flags().BoolVar(v, "system", false, serviceHelp.scopeFlag)
}

// ── install ─────────────────────────────────────────────────────────────────

func newServiceInstallCmd(g *globals) *cobra.Command {
	var system bool
	cmd := &cobra.Command{
		Use:     "install [-- RUN FLAGS...]",
		Short:   serviceHelp.installShort,
		Long:    serviceHelp.installLong,
		Example: serviceHelp.installExample,
		Args:    cobra.ArbitraryArgs,
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
		Short: serviceHelp.uninstallShort,
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
		Short: serviceHelp.stopShort,
		Long:  serviceHelp.stopLong,
		Args:  cobra.NoArgs,
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
		Long: "status with no --system looks in your own login session first and then\n" +
			"machine-wide, so it finds the job wherever it was installed. Exit status is\n" +
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

	// unsure collects the mechanisms that could not be consulted at all.
	//
	// It is kept apart from found/running because "I could not look" is a
	// different answer from "I looked and it is not there", and reporting the
	// second when the first is true is the defect class this tree has already
	// paid for twice: a ProcessStart that read a failed lookup as "the process
	// is dead" would have had Replay tear down a running user's network, and an
	// envCtl.Get that read a failed read as "unset" would have deleted a
	// pre-existing HTTPS_PROXY. Nothing ever lands here on darwin — launchctl's
	// failure IS the answer, as serviceStateOf explains — but it does on
	// Windows, where the SCM refuses a connection to an unelevated caller while
	// the registry still says plainly whether the service exists.
	var unsure []error

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
		f, r, cannotTell := statusMechanism(ctx, g, s)
		found = found || f
		running = running || r
		if cannotTell != nil {
			unsure = append(unsure, cannotTell)
		}
	}

	if !found {
		if len(unsure) > 0 {
			return fmt.Errorf("service status: cannot tell whether %s is installed: %w",
				serviceName, errors.Join(unsure...))
		}
		fmt.Fprintf(g.env.Stdout, "%s is not installed\n", serviceName)
		fmt.Fprintf(g.env.Stdout, "  install it with `%s`\n", serviceInstallHint)
		return errors.New("service status: not installed")
	}
	if !running {
		if len(unsure) > 0 {
			return fmt.Errorf("service status: %s is installed, but whether it is running could not be determined: %w",
				serviceName, errors.Join(unsure...))
		}
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
//
// What is NOT the same is WHO wrote them — or whether anybody did — and that
// changes what this command is able to show.
//
// launchd redirects a job's stdout and stderr into these two paths itself,
// from the StandardOutPath and StandardErrorPath keys service_darwin.go puts
// in the plist, so on darwin the files exist from the job's first write no
// matter what the job does. The Windows SCM has no equivalent key and gives a
// service no console and no parent to inherit handles from, so there the
// service process redirects its OWN os.Stdout and os.Stderr into the same two
// files as its first act (svcrun_windows.go). Two consequences follow for that
// mechanism: anything the service writes before the redirect — a failure to
// resolve the log directory, most of all — has nowhere to go and is lost, and
// the streams are ordinary buffered file writes, so a service the SCM kills
// leaves their tail unwritten.
//
// A Windows Scheduled Task action gets the same nothing as a service and has
// no redirect at all, so for that mechanism these two files are never written
// by anyone. That is what serviceLogNote says, in the mechanism's own words,
// before this command prints "(no such file)" twice and leaves a tester
// concluding their task is broken.
func serviceLogs(g *globals, system bool, lines int) error {
	if lines <= 0 {
		return usagef("service logs: --lines must be positive, got %d", lines)
	}
	s, err := g.serviceScopeFor(system)
	if err != nil {
		return err
	}
	w := g.env.Stdout
	if note := serviceLogNote(s); note != "" {
		fmt.Fprintf(w, "%s\n\n", note)
	}
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
	fmt.Fprintf(w, "\n%s\n", serviceFollowHint(s.errLog))
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
