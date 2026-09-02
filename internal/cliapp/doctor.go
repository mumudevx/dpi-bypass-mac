package cliapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpi-bypass-mac/internal/buildinfo"
	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/netstate"
	"github.com/mumudevx/dpi-bypass-mac/internal/ops"
	"github.com/mumudevx/dpi-bypass-mac/internal/paths"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
)

// `dpb doctor` audits the machine and, with --repair, puts it back.
//
// It is the answer to "nothing works". The single most valuable thing it can
// say is the one a user will never work out alone: the system proxy is still
// pointing at a dpb that is not there. macOS treats an unfetchable auto-proxy
// URL as DIRECT, so PAC residue merely costs a little latency — but an explicit
// web/secure proxy pointing at a dead port is a TOTAL outage with no error
// message anywhere, and the browser simply says the site cannot be reached.
// Diagnosing that needs no network at all: `scutil --proxy` says where macOS is
// pointed, and the run lock says whether anything is there.
//
// --repair replays the journal. Its correctness is the difference between a
// crash being recoverable and a user losing their network settings, so it is
// the same netstate.Replay the SIGKILL janitor and the login agent run, called
// through the same janitor.Replay wrapper, on a fresh context.

// checkState is one check's verdict.
type checkState string

const (
	stateOK   checkState = "ok"
	stateWarn checkState = "warn"
	stateFail checkState = "fail"
)

// check is one audited fact.
type check struct {
	Name   string     `json:"name"`
	State  checkState `json:"state"`
	Detail string     `json:"detail"`
	// Remedy is what the user should do. A finding without one is noise, and
	// noise is how the finding that mattered gets scrolled past.
	Remedy string `json:"remedy,omitempty"`
}

// repairSummary is what a --repair pass actually did.
type repairSummary struct {
	Ran      bool     `json:"ran"`
	Pending  int      `json:"pending"`
	Reverted []string `json:"reverted,omitempty"`
	Skipped  []string `json:"skipped,omitempty"`
	Failed   []string `json:"failed,omitempty"`
	Err      string   `json:"error,omitempty"`
}

// doctorReport is the whole audit.
type doctorReport struct {
	Version  string        `json:"version"`
	Elevated bool          `json:"elevated"`
	Layout   layoutReport  `json:"paths"`
	Repair   repairSummary `json:"repair"`
	Checks   []check       `json:"checks"`
	Failed   int           `json:"failed"`
	Warned   int           `json:"warned"`
}

type layoutReport struct {
	Config  string `json:"config_dir"`
	State   string `json:"state_dir"`
	Log     string `json:"log_dir"`
	Owner   string `json:"owner"`
	System  bool   `json:"system"`
	Journal string `json:"journal"`
	Socket  string `json:"control_socket"`
}

func newDoctorCmd(g *globals) *cobra.Command {
	var (
		repair       bool
		full         bool
		asJSON       bool
		quiet        bool
		installAgent bool
		removeAgent  bool
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Audit this machine, and with --repair put back what a crash left behind",
		Long: "doctor checks the things that break dpb and the things dpb can break: where\n" +
			"its files are and who owns them, whether the configuration loads, whether the\n" +
			"configured strategies can be emitted by an ordinary socket, whether a previous\n" +
			"run left the system proxy pointing at a port nobody is listening on, and\n" +
			"whether the journal holds unfinished system changes.\n\n" +
			"--repair replays the journal, undoing every mutation left behind by a dpb that\n" +
			"is gone. It never touches records owned by a dpb that is still running.\n" +
			"--full additionally probes the DNS chain, which is the only check that uses\n" +
			"the network.",
		Example: "  dpb doctor\n  dpb doctor --repair\n  dpb doctor --full --json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if installAgent && removeAgent {
				return usagef("doctor: --install-agent and --remove-agent do opposite things")
			}
			switch {
			case installAgent:
				return runInstallAgent(cmd.Context(), g)
			case removeAgent:
				return runRemoveAgent(cmd.Context(), g)
			}
			return runDoctor(cmd.Context(), g, doctorFlags{
				repair: repair, full: full, asJSON: asJSON, quiet: quiet,
			})
		},
	}
	fl := cmd.Flags()
	fl.BoolVar(&repair, "repair", false, "replay the journal, undoing what a crashed run left behind")
	fl.BoolVar(&full, "full", false, "also probe the DNS chain (the only check that uses the network)")
	fl.BoolVar(&asJSON, "json", false, "emit the audit as JSON")
	fl.BoolVar(&quiet, "quiet", false, "print only warnings and failures; used by the login repair agent")
	fl.BoolVar(&installAgent, "install-agent", false,
		"install the login LaunchAgent that runs `dpb doctor --repair --quiet` at every login")
	fl.BoolVar(&removeAgent, "remove-agent", false, "remove the login repair LaunchAgent")
	return cmd
}

type doctorFlags struct {
	repair bool
	full   bool
	asJSON bool
	quiet  bool
}

func runDoctor(ctx context.Context, g *globals, f doctorFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	layout, err := g.layoutOf()
	if err != nil {
		return err
	}

	rep := doctorReport{
		Version:  buildinfo.Short(),
		Elevated: layout.Elevated,
		Layout: layoutReport{
			Config:  layout.ConfigDir,
			State:   layout.StateDir,
			Log:     layout.LogDir,
			Owner:   layout.User,
			System:  layout.System,
			Journal: layout.JournalFile(),
			Socket:  layout.ControlSocket(),
		},
	}

	// Repair runs FIRST so every check below reports the state the machine is
	// actually in when the command returns, not the one it was in when it
	// started. A doctor that repairs and then prints the pre-repair audit
	// teaches the user to distrust it.
	if f.repair {
		rep.Repair = runRepair(ctx, g, layout)
	}

	rep.Checks = collectChecks(ctx, g, layout, f.full)
	for _, c := range rep.Checks {
		switch c.State {
		case stateFail:
			rep.Failed++
		case stateWarn:
			rep.Warned++
		}
	}

	if f.asJSON {
		enc := json.NewEncoder(g.env.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return fmt.Errorf("doctor: write JSON: %w", err)
		}
	} else if err := renderDoctor(g.env.Stdout, rep, f.quiet); err != nil {
		return err
	}

	if rep.Repair.Err != "" || len(rep.Repair.Failed) > 0 {
		return codedError{code: ExitDoctor, err: errors.New(
			"doctor: the journal could not be fully replayed; see the lines above")}
	}
	if rep.Failed > 0 {
		return codedError{code: ExitDoctor, err: fmt.Errorf(
			"doctor: %d check(s) failed", rep.Failed)}
	}
	return nil
}

// runRepair replays the journal and summarises what it did.
func runRepair(ctx context.Context, g *globals, layout paths.Layout) repairSummary {
	sum := repairSummary{Ran: true}
	rep, err := repairJournal(ctx, g, layout)
	if err != nil {
		sum.Err = err.Error()
		return sum
	}
	sum.Pending = len(rep.Pending)
	for _, r := range rep.Reverted {
		sum.Reverted = append(sum.Reverted, recordLabel(r))
	}
	for _, r := range rep.Skipped {
		sum.Skipped = append(sum.Skipped, recordLabel(r))
	}
	for _, r := range rep.Failed {
		sum.Failed = append(sum.Failed, recordLabel(r))
	}
	return sum
}

func recordLabel(r netstate.Record) string {
	label := fmt.Sprintf("%s %s", r.Kind, r.ID)
	if r.Adopted {
		label += " (adopted: it was never ours, so nothing was changed)"
	}
	return label
}

// writeRepair prints a repair summary. It is shared with `dpb panic`.
func writeRepair(w io.Writer, rep netstate.ReplayReport) {
	if len(rep.Pending) == 0 {
		fmt.Fprintln(w, "the journal was already empty; nothing needed undoing.")
		return
	}
	for _, r := range rep.Reverted {
		fmt.Fprintf(w, "undone:  %s\n", recordLabel(r))
	}
	for _, r := range rep.Skipped {
		fmt.Fprintf(w, "left:    %s\n", recordLabel(r))
	}
	for _, r := range rep.Failed {
		fmt.Fprintf(w, "FAILED:  %s\n", recordLabel(r))
	}
}

// collectChecks runs the audit.
func collectChecks(ctx context.Context, g *globals, layout paths.Layout, full bool) []check {
	var out []check
	add := func(c check) { out = append(out, c) }

	add(checkPaths(layout))

	cfg, cfgErr := scopeConfig(g)
	add(checkConfig(cfg, cfgErr))
	if cfgErr == nil {
		add(checkStrategies(cfg))
	}

	running, lockCheck := checkRunLock(layout)
	add(lockCheck)
	add(checkControlSocket(ctx, g, layout, running))
	add(checkJournal(layout))
	add(checkSystemProxy(ctx, g, running))
	add(checkProxyEnv(ctx, g, running))

	if cfgErr == nil {
		netID, _ := g.networkIdentity(ctx, cfg)
		add(checkStore(layout, cfg, netID))
		add(checkTuned(layout, netID))
		if full {
			add(checkDNS(ctx, g, cfg))
		}
	}
	return out
}

// checkPaths verifies the state directory exists, is writable, and is not owned
// by root while we are not.
//
// A root-owned state directory is the classic sudo trap this whole layout
// exists to avoid: one `sudo dpb run --tun` writes the journal as root, and
// every unprivileged command afterwards — including the repair that would fix
// it — cannot read its own files.
func checkPaths(layout paths.Layout) check {
	c := check{Name: "paths", State: stateOK}
	c.Detail = fmt.Sprintf("state %s, config %s, logs %s", layout.StateDir, layout.ConfigDir, layout.LogDir)

	if err := layout.EnsureDirs(); err != nil {
		c.State = stateFail
		c.Detail = err.Error()
		c.Remedy = "create the directory by hand, or check the permissions on its parent"
		return c
	}
	probe := filepath.Join(layout.StateDir, ".dpb-doctor-write-probe")
	if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
		c.State = stateFail
		c.Detail = fmt.Sprintf("%s is not writable: %v", layout.StateDir, err)
		if !layout.Elevated {
			c.Remedy = fmt.Sprintf("a previous `sudo dpb` may own it: sudo chown -R %s %s",
				layout.User, layout.StateDir)
		} else {
			c.Remedy = "check the permissions on " + layout.StateDir
		}
		return c
	}
	// The probe file is litter the moment it has answered the question.
	if err := os.Remove(probe); err != nil {
		c.State = stateWarn
		c.Detail = fmt.Sprintf("%s is writable but the probe file could not be removed: %v", layout.StateDir, err)
		c.Remedy = "delete " + probe
	}
	return c
}

// checkConfig reports whether the configuration loads at all.
func checkConfig(cfg *config.Loaded, err error) check {
	c := check{Name: "config", State: stateOK}
	if err != nil {
		c.State = stateFail
		c.Detail = err.Error()
		c.Remedy = "fix or remove the file named above; an unknown key is rejected on purpose, " +
			"because a typo that is silently ignored is a setting that silently does nothing"
		return c
	}
	c.Detail = fmt.Sprintf("profile %s from %s", cfg.Profile, strings.Join(cfg.Sources, ", "))
	return c
}

// checkStrategies is the capability report: can an ordinary kernel socket
// actually emit every rung of the configured ladder?
//
// This is validation gate 3 from docs/PLAN.md, run as a diagnostic. A profile
// naming a strategy the transport cannot satisfy must refuse to load rather
// than start up and silently ship the SNI unfragmented, and `dpb doctor` is
// where a user finds out why their profile is being refused.
func checkStrategies(cfg *config.Loaded) check {
	c := check{Name: "strategies", State: stateOK}
	ops.Install()
	specs, err := cfg.LadderSpecs()
	if err != nil {
		c.State = stateFail
		c.Detail = err.Error()
		c.Remedy = "correct the ladder in the configuration; `dpb strategy list` shows what exists"
		return c
	}
	if err := cfg.CheckStrategies(proxyCaps); err != nil {
		c.State = stateFail
		c.Detail = err.Error()
		c.Remedy = "choose a strategy this transport can emit; `dpb strategy explain SPEC` " +
			"names the capability each one needs"
		return c
	}
	c.Detail = fmt.Sprintf("ladder %s, all emittable by a kernel socket (%s)",
		strings.Join(ladderLabels(specs), " -> "), proxyCaps)
	return c
}

// checkRunLock reports whether a dpb holds the run lock, and whether the last
// one exited cleanly.
func checkRunLock(layout paths.Layout) (running bool, c check) {
	c = check{Name: "run lock", State: stateOK}
	info, err := netstate.ReadLock(layout.LockFile())
	if errors.Is(err, os.ErrNotExist) || (err != nil && os.IsNotExist(errors.Unwrap(err))) {
		c.Detail = "no run lock; dpb has not run on this machine, or it cleaned up after itself"
		return false, c
	}
	if err != nil {
		c.State = stateWarn
		c.Detail = err.Error()
		// The flock sidecar is a separate file and is the one that fails to
		// open; naming only run.lock leaves the user deleting the wrong thing.
		c.Remedy = "delete " + layout.LockFile() + " and " + layout.LockFile() + ".flock if no dpb is running"
		return false, c
	}
	if netstate.OwnerAlive(info.PID, info.StartedAt) {
		c.Detail = fmt.Sprintf("held by a live dpb (pid %d)", info.PID)
		return true, c
	}
	c.Detail = fmt.Sprintf("last held by pid %d, which is gone", info.PID)
	return false, c
}

// checkControlSocket reports whether the running dpb can be talked to.
func checkControlSocket(ctx context.Context, g *globals, layout paths.Layout, running bool) check {
	c := check{Name: "control socket", State: stateOK}
	path := layout.ControlSocket()
	reachable := g.controlClient(layout).Running(ctx)
	switch {
	case reachable:
		c.Detail = "answering at " + path
	case running:
		c.State = stateWarn
		c.Detail = "a dpb holds the run lock but nothing answers at " + path
		c.Remedy = "stop that process and start it again; `dpb status`, `dpb why` and " +
			"`dpb off` need this socket"
	default:
		c.Detail = "no dpb is running, so there is nothing to answer at " + path
	}
	return c
}

// checkJournal reports unfinished system mutations.
func checkJournal(layout paths.Layout) check {
	c := check{Name: "journal", State: stateOK}
	js := journalStatus(layout)
	switch {
	case js.Err != "":
		c.State = stateFail
		c.Detail = js.Err
		c.Remedy = "the journal is how dpb undoes what it did; if it cannot be read, " +
			"check the permissions on " + js.Path
	case js.Residue > 0:
		c.State = stateFail
		c.Detail = fmt.Sprintf("%d unfinished system change(s) from a dpb that is gone", js.Residue)
		c.Remedy = "run `dpb doctor --repair` to undo them"
	case js.OwnedByLive > 0:
		c.Detail = fmt.Sprintf("%d change(s) held by the running dpb", js.OwnedByLive)
	default:
		c.Detail = "empty; no system change is outstanding"
	}
	return c
}

// checkSystemProxy is the highest-value diagnosis this command makes.
//
// It needs no network and no daemon: `scutil --proxy` reports where macOS is
// actually pointed, and the run lock reports whether anything is there. An
// explicit web or secure proxy on loopback with no dpb running is a total
// outage and is reported as a failure; a PAC URL in the same state costs a
// little latency, because macOS treats an unfetchable auto-proxy URL as DIRECT,
// and is reported as a warning.
func checkSystemProxy(ctx context.Context, g *globals, running bool) check {
	c := check{Name: "system proxy", State: stateOK}
	env := netstate.Env{Runner: g.runnerOf(), RIB: g.ribOf(), Logf: g.logf}
	st, err := netstate.ReadProxyState(ctx, env)
	if err != nil {
		c.State = stateWarn
		c.Detail = err.Error()
		c.Remedy = "run `scutil --proxy` by hand to see what macOS is pointed at"
		return c
	}

	var set []string
	var dead []string
	note := func(kind, value string, failsClosed bool) {
		set = append(set, kind+" "+value)
		if running || !isLoopbackTarget(value) {
			return
		}
		if failsClosed {
			dead = append(dead, kind+" "+value+" (this fails CLOSED: nothing can connect)")
			return
		}
		dead = append(dead, kind+" "+value)
	}

	if st.On("ProxyAutoConfigEnable") {
		note("auto-proxy URL", st.Str("ProxyAutoConfigURLString"), false)
	}
	if st.On("HTTPEnable") {
		note("web proxy", proxyTarget(st, "HTTPProxy", "HTTPPort"), true)
	}
	if st.On("HTTPSEnable") {
		note("secure proxy", proxyTarget(st, "HTTPSProxy", "HTTPSPort"), true)
	}
	if st.On("SOCKSEnable") {
		note("SOCKS proxy", proxyTarget(st, "SOCKSProxy", "SOCKSPort"), true)
	}

	switch {
	case len(set) == 0:
		c.Detail = "no system proxy is set"
	case len(dead) == 0:
		c.Detail = strings.Join(set, "; ")
	default:
		c.State = stateWarn
		for _, d := range dead {
			if strings.Contains(d, "fails CLOSED") {
				c.State = stateFail
			}
		}
		c.Detail = "macOS is pointed at a dpb that is not running: " + strings.Join(dead, "; ")
		c.Remedy = "run `dpb doctor --repair` to put the previous settings back, " +
			"or `dpb run` to make them true again"
	}
	return c
}

func proxyTarget(st netstate.ProxyState, hostKey, portKey string) string {
	host := st.Str(hostKey)
	if port, ok := st.Int(portKey); ok {
		return fmt.Sprintf("%s:%d", host, port)
	}
	return host
}

// isLoopbackTarget reports whether a proxy value names this machine.
//
// It accepts every shape scutil and launchctl produce: a bare host, host:port,
// a bracketed IPv6 literal, and a full URL — the PAC is reported as a URL while
// the explicit proxies are reported as separate host and port keys, and the
// environment variables are URLs again.
func isLoopbackTarget(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexByte(v, '/'); i >= 0 {
		v = v[:i]
	}
	host := v
	if h, _, err := net.SplitHostPort(v); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	// netip decides, rather than a string prefix: 127.0.0.0/8 is all loopback,
	// and so is ::1, and neither is spelled one way.
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// proxyEnvVars are the variables `launchctl setenv` exports. GT24: Discord's
// updater is an in-process reqwest addon whose ONLY proxy sources are these.
var proxyEnvVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"}

// checkProxyEnv reports the launchd session environment, which is the half of
// the coverage story the proxy pane cannot show.
func checkProxyEnv(ctx context.Context, g *globals, running bool) check {
	c := check{Name: "proxy environment", State: stateOK}
	env := netstate.Env{Runner: g.runnerOf(), RIB: g.ribOf(), Logf: g.logf}

	var set []string
	var stale []string
	for _, name := range proxyEnvVars {
		v, err := netstate.ReadLaunchEnv(ctx, env, name)
		if err != nil {
			c.State = stateWarn
			c.Detail = err.Error()
			c.Remedy = "run `launchctl getenv HTTPS_PROXY` by hand to see what is exported"
			return c
		}
		if v == "" {
			continue
		}
		set = append(set, name+"="+v)
		if !running && isLoopbackTarget(v) {
			stale = append(stale, name+"="+v)
		}
	}

	switch {
	case len(set) == 0:
		c.Detail = "no proxy variables are exported to the login session"
	case len(stale) == 0:
		c.Detail = strings.Join(set, "; ")
	default:
		c.State = stateFail
		c.Detail = "the login session still exports a dead dpb: " + strings.Join(stale, "; ")
		c.Remedy = "run `dpb doctor --repair`; until then, every program that reads these " +
			"variables — curl, Go, Python, Node, Discord's updater — connects to nothing"
	}
	return c
}

// checkStore reports what the verdict cache holds for this network.
func checkStore(layout paths.Layout, cfg *config.Loaded, netID policy.NetworkID) check {
	c := check{Name: "verdict cache", State: stateOK}
	cs := cacheStatus(layout, cfg, netID)
	switch {
	case cs.Err != "":
		c.State = stateWarn
		c.Detail = cs.Err
		c.Remedy = "delete " + cs.Path + "; losing the cache costs one extra round trip per host"
	case !cs.Enabled:
		c.Detail = "learning is disabled (learn = false)"
	default:
		c.Detail = fmt.Sprintf("%d host(s) under network %s — %d plain, %d desync",
			cs.Hosts, netID.Key(), cs.Plain, cs.Desync)
	}
	return c
}

// checkTuned reports the measured profile's age and whether it belongs to this
// network at all.
func checkTuned(layout paths.Layout, netID policy.NetworkID) check {
	c := check{Name: "tuned profile", State: stateOK}
	ts := tunedStatus(layout, netID.Key())
	switch {
	case ts.Err != "":
		c.State = stateWarn
		c.Detail = ts.Err
		c.Remedy = "run `dpb tune` to write a fresh one"
	case !ts.Present:
		c.Detail = "none; the shipped ladder is in use"
		c.Remedy = "run `dpb tune` (~3 min) to measure this line"
	case !ts.SameNetwork:
		c.State = stateWarn
		c.Detail = fmt.Sprintf("measured on a different network %s ago, so it is not being used",
			ts.Age.Round(time.Minute))
		c.Remedy = "run `dpb tune` to measure the network you are on now"
	default:
		c.Detail = fmt.Sprintf("%s, confidence %s, measured %s ago",
			specLabel(ts.Strategy), ts.Confidence, ts.Age.Round(time.Minute))
	}
	return c
}

// doctorControlName is the name the DNS check resolves.
//
// It MUST be one that is not blocked on the line under test, or a perfectly
// healthy resolver is reported as broken. MEASUREMENTS.md §2 uses exactly this
// pair of names for that reason.
const doctorControlName = "cloudflare.com"

// checkDNS probes the resolver chain. It is the only check that uses the
// network, which is why it is behind --full.
func checkDNS(ctx context.Context, g *globals, cfg *config.Loaded) check {
	c := check{Name: "dns", State: stateOK}
	resolvers, err := buildResolvers(cfg)
	if err != nil {
		c.State = stateFail
		c.Detail = err.Error()
		c.Remedy = "correct the resolver chain in the configuration"
		return c
	}
	chain := resolve.NewChain(resolve.Options{
		Resolvers: resolvers,
		AAAA:      cfg.AAAAMode(),
		Detector:  resolve.NewDetector(nil, nil),
		PerTry:    cfg.DNS.PerTry.D(),
		Logf:      g.logf,
	})

	// The chain has five rungs and PerTry defaults to four seconds, so a fully
	// dead network costs twenty seconds without a deadline of our own.
	qctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	addrs, rerr := chain.Resolve(qctx, doctorControlName)

	var rows []string
	for _, h := range chain.Health() {
		state := "untried"
		switch {
		case h.Signal.Sinkhole:
			state = "POISONED"
		case h.OK:
			state = "ok"
		case h.Err != nil:
			state = "failed"
		}
		rows = append(rows, h.Label+"="+state)
	}

	switch {
	case errors.Is(rerr, resolve.ErrNoCleanTransport):
		c.State = stateFail
		c.Detail = "every DNS transport on this network is dropped or poisoned: " + strings.Join(rows, " ")
		c.Remedy = "no packet strategy fixes a poisoned resolver. Try another network, " +
			"or add a resolver with --dns-doh"
	case rerr != nil:
		c.State = stateFail
		c.Detail = fmt.Sprintf("%s did not resolve: %v — %s", doctorControlName, rerr, strings.Join(rows, " "))
		c.Remedy = "run `dpb dns check` for the full transport matrix"
	default:
		c.Detail = fmt.Sprintf("%s resolved to %v — %s", doctorControlName, addrs, strings.Join(rows, " "))
	}
	return c
}

// renderDoctor prints the human form. --quiet drops the ok lines, which is what
// the login agent wants: a repair that found nothing should say nothing.
func renderDoctor(w io.Writer, rep doctorReport, quiet bool) error {
	var b strings.Builder

	if rep.Repair.Ran {
		switch {
		case rep.Repair.Err != "":
			fmt.Fprintf(&b, "repair:    FAILED: %s\n", rep.Repair.Err)
		case rep.Repair.Pending == 0:
			if !quiet {
				b.WriteString("repair:    the journal was already empty; nothing needed undoing.\n")
			}
		default:
			fmt.Fprintf(&b, "repair:    %d pending record(s)\n", rep.Repair.Pending)
			for _, s := range rep.Repair.Reverted {
				fmt.Fprintf(&b, "  undone   %s\n", s)
			}
			for _, s := range rep.Repair.Skipped {
				fmt.Fprintf(&b, "  left     %s\n", s)
			}
			for _, s := range rep.Repair.Failed {
				fmt.Fprintf(&b, "  FAILED   %s\n", s)
			}
		}
	}

	if !quiet {
		fmt.Fprintf(&b, "%s\n", rep.Version)
		fmt.Fprintf(&b, "state:     %s (owner %s)\n", rep.Layout.State, rep.Layout.Owner)
	}
	for _, c := range rep.Checks {
		if quiet && c.State == stateOK {
			continue
		}
		mark := "ok  "
		if c.State == stateWarn {
			mark = "warn"
		} else if c.State == stateFail {
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "[%s] %-18s %s\n", mark, c.Name, c.Detail)
		if c.Remedy != "" && c.State != stateOK {
			fmt.Fprintf(&b, "                          -> %s\n", c.Remedy)
		}
	}
	if !quiet {
		fmt.Fprintf(&b, "\n%d check(s), %d failed, %d warning(s)\n",
			len(rep.Checks), rep.Failed, rep.Warned)
	}

	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("doctor: write: %w", err)
	}
	return nil
}

// ── the login repair LaunchAgent ────────────────────────────────────────────

// AgentLabel is the launchd label of the login repair agent.
const AgentLabel = "com.mumudevx.dpb.repair"

// agentPlist renders the LaunchAgent.
//
// RunAtLoad with no KeepAlive is exactly the shape wanted: run once per login,
// exit, and never be restarted. It is defence (c) of docs/PLAN.md's four
// against SIGKILL — the backstop for the case where even the janitor child died
// with its parent, which is what a power loss or a Force Quit of the whole
// process group produces.
func agentPlist(exe, logPath string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + AgentLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEscape(exe) + `</string>
		<string>doctor</string>
		<string>--repair</string>
		<string>--quiet</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<false/>
	<key>ProcessType</key>
	<string>Background</string>
	<key>StandardOutPath</key>
	<string>` + xmlEscape(logPath) + `</string>
	<key>StandardErrorPath</key>
	<string>` + xmlEscape(logPath) + `</string>
</dict>
</plist>
`
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// agentPath is where the plist goes. It is a per-user LaunchAgent even when dpb
// is run with sudo, because the settings it repairs are the invoking user's.
func agentPath(layout paths.Layout) string {
	home := layout.Home
	if home == "" {
		home = "/Library"
		return filepath.Join(home, "LaunchAgents", AgentLabel+".plist")
	}
	return filepath.Join(home, "Library", "LaunchAgents", AgentLabel+".plist")
}

func runInstallAgent(ctx context.Context, g *globals) error {
	layout, err := g.layoutOf()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("doctor: find this executable: %w", err)
	}
	if err := layout.EnsureDirs(); err != nil {
		return fmt.Errorf("doctor: create the state directories: %w", err)
	}

	path := agentPath(layout)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("doctor: create %s: %w", filepath.Dir(path), err)
	}
	logPath := filepath.Join(layout.LogDir, "repair.log")
	if err := os.WriteFile(path, []byte(agentPlist(exe, logPath)), 0o644); err != nil {
		return fmt.Errorf("doctor: write %s: %w", path, err)
	}
	if err := layout.Chown(path); err != nil {
		g.logf("doctor: chown the agent plist: %v", err)
	}

	// Modern verbs only. `launchctl load -w` is deprecated, mutates the user's
	// overrides database as a side effect, and reports success for a plist it
	// never actually loaded.
	env := netstate.Env{Runner: g.runnerOf(), Logf: g.logf}
	domain := fmt.Sprintf("gui/%d", layout.UID)
	_ = env.Runner.Run(ctx, "launchctl", "bootout", domain+"/"+AgentLabel)
	res := env.Runner.Run(ctx, "launchctl", "bootstrap", domain, path)
	if err := res.Error(); err != nil {
		return fmt.Errorf("doctor: bootstrap %s into %s: %w", path, domain, err)
	}
	fmt.Fprintf(g.env.Stdout, "installed %s\n", path)
	fmt.Fprintln(g.env.Stdout,
		"at every login it runs `dpb doctor --repair --quiet`, which undoes anything a\n"+
			"crashed run left behind. It is the backstop for the case where even the janitor\n"+
			"child died with its parent.")
	return nil
}

func runRemoveAgent(ctx context.Context, g *globals) error {
	layout, err := g.layoutOf()
	if err != nil {
		return err
	}
	path := agentPath(layout)
	env := netstate.Env{Runner: g.runnerOf(), Logf: g.logf}
	domain := fmt.Sprintf("gui/%d", layout.UID)
	// bootout is best effort: the agent may already be gone, and the plist is
	// the thing that actually has to disappear.
	_ = env.Runner.Run(ctx, "launchctl", "bootout", domain+"/"+AgentLabel)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("doctor: remove %s: %w", path, err)
	}
	fmt.Fprintf(g.env.Stdout, "removed %s\n", path)
	return nil
}
