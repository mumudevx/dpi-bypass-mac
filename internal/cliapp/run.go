package cliapp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/mumudevx/dpi-bypass-mac/internal/config"
	"github.com/mumudevx/dpi-bypass-mac/internal/emit"
	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/front/proxyfe"
	"github.com/mumudevx/dpi-bypass-mac/internal/janitor"
	"github.com/mumudevx/dpi-bypass-mac/internal/netstate"
	"github.com/mumudevx/dpi-bypass-mac/internal/observ"
	"github.com/mumudevx/dpi-bypass-mac/internal/ops"
	"github.com/mumudevx/dpi-bypass-mac/internal/paths"
	"github.com/mumudevx/dpi-bypass-mac/internal/policy"
	"github.com/mumudevx/dpi-bypass-mac/internal/resolve"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// proxyCaps is what an ordinary kernel socket grants in proxy mode. It is a
// constant rather than a probe because it is a property of emit.SockTransport,
// and it is checked against the configured ladder BEFORE anything starts, so a
// profile naming a strategy this transport cannot emit refuses to load rather
// than starting up and silently shipping the SNI unfragmented.
const proxyCaps = strategy.CapStreamWrite | strategy.CapNoDelay | strategy.CapSockTTL | strategy.CapOOB

type runFlags struct {
	profile   string
	configs   []string
	listen    string
	port      int
	socksPort int

	proxyStyle string
	mode       string
	strategy   string
	ladder     string

	maxAttempts   int
	attemptBudget time.Duration
	maxSegments   int
	inspectPorts  []int

	bypass     []string
	bypassFile string
	include    []string

	dnsDoH []string
	dnsUDP []string
	ipv6   string

	noLearn bool
	dryRun  bool
}

func newRunCmd(g *globals) *cobra.Command {
	var f runFlags

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the bypass: proxy listeners, PAC, and the system proxy settings",
		Long: "run is the product.\n\n" +
			"It starts an HTTP CONNECT / plaintext HTTP / SOCKS5 proxy on loopback, serves\n" +
			"a PAC that sends bypassed hosts DIRECT, and points macOS at both. Every system\n" +
			"change is journalled before it is attempted and verified through a different\n" +
			"subsystem than it was written with, and every one of them is reverted on the\n" +
			"way out — including on SIGINT, SIGTERM, SIGHUP and a panic.\n\n" +
			"No sudo. Connections are sent with no desync first and escalated only when one\n" +
			"is reset before any server byte arrives, so the Turkish banks and .gov.tr sites\n" +
			"measured breaking under desync are never desynced at all.",
		Example: "  dpb run --profile turkey\n" +
			"  dpb run --proxy-style none            # listen, but change no system setting\n" +
			"  dpb run --dry-run                     # print every mutation, apply none",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRun(cmd.Context(), g, cmd, f)
		},
	}

	fl := cmd.Flags()
	fl.StringVar(&f.profile, "profile", "", "profile name or path (default: turkey on a TR locale, else global)")
	fl.StringSliceVar(&f.configs, "config", nil, "extra config file(s), applied last")
	fl.StringVar(&f.listen, "listen", "", "address to listen on")
	fl.IntVar(&f.port, "port", 0, "HTTP proxy port, which also serves "+proxyfe.PACPath+" (0 disables it)")
	fl.IntVar(&f.socksPort, "socks-port", 0, "SOCKS5 port (0 disables it)")
	fl.StringVar(&f.proxyStyle, "proxy-style", "", "pac | explicit | env | both | none")
	fl.StringVar(&f.mode, "mode", "", "watch | always | never")
	fl.StringVar(&f.strategy, "strategy", "", "force one strategy for every in-scope host")
	fl.StringVar(&f.ladder, "ladder", "", "ladder name, or a comma-separated list of specs")
	fl.IntVar(&f.maxAttempts, "max-attempts", 0, "upstream connections one client connection may cost")
	fl.DurationVar(&f.attemptBudget, "attempt-budget", 0, "budget for one ladder walk")
	fl.IntVar(&f.maxSegments, "max-segments", 0, "XNU small-write guard: segments per plan")
	fl.IntSliceVar(&f.inspectPorts, "inspect-ports", nil, "ports whose first message is judged")
	fl.StringSliceVar(&f.bypass, "bypass", nil, "add names or CIDRs to the hard-veto list")
	fl.StringVar(&f.bypassFile, "bypass-file", "", "file of bypass entries, one per line")
	fl.StringSliceVar(&f.include, "include", nil, "if set, ONLY these names are ever escalated")
	fl.StringSliceVar(&f.dnsDoH, "dns-doh", nil, "prepend a DoH resolver URL")
	fl.StringSliceVar(&f.dnsUDP, "dns-udp", nil, "prepend a plaintext UDP resolver ip:port")
	fl.StringVar(&f.ipv6, "ipv6", "", "auto | allow | suppress")
	fl.BoolVar(&f.noLearn, "no-learn", false, "do not read or write the per-host verdict cache")
	fl.BoolVar(&f.dryRun, "dry-run", false,
		"print every system mutation that WOULD be applied and apply none; the listeners still run")

	return cmd
}

// stack is run's own LIFO of teardown steps.
//
// It exists rather than pushing each step onto cmd/dpb's stack directly because
// run owns the ORDER, and the order is the whole contract: system settings come
// off first, while the listeners they point at are still up, and the run lock
// comes off last. One drain function is registered with the process teardown
// stack so a signal or a panic unwinds exactly the same sequence, and the same
// function runs on the ordinary return path; sync.Once makes running it twice
// impossible.
type stack struct {
	steps []step
	once  sync.Once
}

type step struct {
	what string
	fn   func(context.Context) error
}

func (s *stack) push(what string, fn func(context.Context) error) {
	s.steps = append(s.steps, step{what: what, fn: fn})
}

func (s *stack) drain(ctx context.Context, logf func(string, ...any)) error {
	var firstErr error
	s.once.Do(func() {
		for i := len(s.steps) - 1; i >= 0; i-- {
			st := s.steps[i]
			// The order is the contract, so it is logged rather than only
			// asserted: "the settings came off before the listeners" is the
			// kind of claim that has to be checkable on a user's machine with
			// -v, not only in a test.
			logf("run: teardown %s", st.what)
			if err := st.fn(ctx); err != nil {
				logf("run: teardown %s: %v", st.what, err)
				if firstErr == nil {
					firstErr = fmt.Errorf("run: teardown %s: %w", st.what, err)
				}
			}
		}
	})
	return firstErr
}

// killSwitch is what `dpb off` and `dpb on` move.
//
// It is one flag read by every surface that can escalate — the scope engine and
// the served PAC — because a kill switch that half of the process honours is
// worse than none: the user is told dpb is out of the way while it is still
// mangling handshakes. Its zero value is "on", and mode = "never" starts it off.
type killSwitch struct {
	mu     sync.RWMutex
	off    bool
	reason string
}

func (k *killSwitch) suspended() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.off
}

func (k *killSwitch) state() (bool, string) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.off, k.reason
}

func (k *killSwitch) set(off bool, reason string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.off, k.reason = off, reason
}

func runRun(ctx context.Context, g *globals, cmd *cobra.Command, f runFlags) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	layout, err := g.layoutOf()
	if err != nil {
		return err
	}
	if err := layout.EnsureDirs(); err != nil {
		return fmt.Errorf("run: create state directories: %w", err)
	}

	cfg, err := loadConfig(g, layout, cmd, f)
	if err != nil {
		return err
	}

	// Installing the op set is what makes a spec parseable, and the capability
	// gate below is validation gate 3 from docs/PLAN.md.
	ops.Install()
	if err := cfg.CheckStrategies(proxyCaps); err != nil {
		return err
	}
	ladderSpecs, err := cfg.LadderSpecs()
	if err != nil {
		return err
	}

	var st stack
	// Teardown runs on a FRESH context. Every netstate Op checks ctx.Err()
	// before it journals, so unwinding on the cancelled context that stopped us
	// would journal nothing and revert nothing.
	drain := func(context.Context) error {
		tctx, cancel := context.WithTimeout(context.Background(), teardownBudget)
		defer cancel()
		return st.drain(tctx, g.logf)
	}
	if g.env.Push != nil {
		g.env.Push(drain)
	}
	defer func() {
		if derr := drain(ctx); derr != nil && err == nil {
			err = derr
		}
	}()

	// The run lock first: two dpb processes writing the same journal and the
	// same proxy settings is the one situation the journal cannot describe.
	lock, err := netstate.AcquireLock(layout.LockFile())
	if err != nil {
		if errors.Is(err, netstate.ErrLocked) {
			return fmt.Errorf("run: %w — stop it, or run `dpb doctor --repair` if it is gone", err)
		}
		return fmt.Errorf("run: take the run lock: %w", err)
	}
	st.push("release the run lock", func(context.Context) error { return lock.Release() })

	journal, err := netstate.OpenJournal(layout.JournalFile())
	if err != nil {
		return fmt.Errorf("run: open the journal: %w", err)
	}
	st.push("close the journal", func(context.Context) error { return journal.Close() })
	if err := layout.Chown(journal.Path()); err != nil {
		g.logf("run: chown journal: %v", err)
	}

	// The janitor goes up BEFORE the first mutation and comes down AFTER the
	// revert, which is why it is pushed here and not later: it is the only
	// defence that survives `kill -9`, where Go runs no defer, no recover and
	// no signal handler, and the window it has to cover is exactly the window
	// in which the journal has records in it.
	preNotes := startJanitor(g, cfg, journal, &st, f)

	// PriorResidue must be read BEFORE any Op is prepared: it is the only thing
	// that lets an Op recognise a loopback proxy setting as a dead previous
	// run's rather than as the user's own local proxy.
	residue := netstate.PriorResidue(ctx, journal, layout.LockFile())
	env := netstate.Env{
		Runner:       g.runnerOf(),
		RIB:          g.ribOf(),
		Logf:         g.logf,
		DryRun:       f.dryRun,
		PriorResidue: residue,
	}
	env.Facts = g.factsOf(ctx, env)

	// The sockets are bound BEFORE the datapath is built, because the PAC has
	// to name the port that is actually bound: --port 0 is a real thing to ask
	// for, and a PAC naming the configured port would then point at nothing.
	// Binding first also means the PAC is complete before a single connection
	// can read it, rather than being filled in underneath the listener.
	bound, err := bindListeners(cfg)
	if err != nil {
		return err
	}
	if len(bound) == 0 {
		return usagef("run: both --port and --socks-port are 0, so nothing would listen")
	}
	closeBound := func() {
		for _, b := range bound {
			_ = b.ln.Close()
		}
	}

	// The counters are built before the datapath because the datapath's OnConn
	// hook is what feeds them. Without this the drift detector — the only way a
	// user learns their ISP changed tactics rather than that one site broke —
	// observes nothing at all.
	counters := observ.NewCounters(observ.CountersOptions{
		OnDrift: func(ev observ.DriftEvent) {
			g.logger().Warn(ev.Remedy, "%s (%d of %d in-scope hosts in the last %s)",
				ev.Suspected, ev.Escalated, ev.Hosts, ev.Window)
		},
	})
	ks := &killSwitch{}
	if cfg.Mode == config.ModeNever {
		ks.set(true, `mode = "never"`)
	}

	sub, err := buildSubsystems(g, layout, cfg, ladderSpecs, env, addrOfBound(bound, "http"), counters, ks)
	if err != nil {
		closeBound()
		return err
	}
	st.push("close the verdict store", func(context.Context) error { return sub.store.Close() })

	listeners := startListeners(bound, sub.server, &st, g)

	applied, notes, sys := applySystemState(ctx, g, layout, cfg, sub, listeners, &st, env, journal)
	notes = append(preNotes, notes...)

	// The control socket goes up LAST and comes down FIRST. Everything it
	// reports — the ports that are bound, the settings that were actually
	// confirmed — has to be true before a `dpb status` can read it, and once
	// teardown starts the honest answer is no answer rather than a report of a
	// machine that is being dismantled underneath the reader.
	live := &liveState{
		started:   time.Now(),
		cfg:       cfg,
		layout:    layout,
		ladder:    ladderSpecs,
		listeners: listeners,
		applied:   applied,
		notes:     notes,
		sub:       sub,
		ks:        ks,
		counters:  counters,
		sys:       sys,
	}
	stopRun := make(chan struct{})
	live.stop = sync.OnceFunc(func() { close(stopRun) })
	// Reload re-runs the whole configuration resolution, flags included, and
	// swaps the result into the running scope engine. It deliberately does NOT
	// touch the listeners or the system settings: `dpb reload` is for the
	// scoping rules, and a reload that re-bound a port would drop every live
	// connection to fix a typo in a bypass list.
	live.reload = func(context.Context) error {
		nc, err := loadConfig(g, layout, cmd, f)
		if err != nil {
			return err
		}
		rules, err := nc.Rules()
		if err != nil {
			return err
		}
		ipRules, err := nc.IPRules()
		if err != nil {
			return err
		}
		matcher, err := policy.NewMatcher(rules)
		if err != nil {
			return err
		}
		ipset, err := policy.NewIPSet(ipRules)
		if err != nil {
			return err
		}
		sub.engine.Reload(matcher, ipset)
		g.logf("run: reloaded %d name rules and %d address rules", len(rules), len(ipRules))
		return nil
	}
	notes = append(notes, serveControlSocket(g, layout, live, &st)...)
	live.setNotes(notes)

	b := banner{
		Config:    cfg,
		Sources:   cfg.Sources,
		Listeners: listeners,
		Ladder:    ladderSpecs,
		Resolvers: sub.chain.Labels(),
		Applied:   applied,
		Notes:     notes,
		DryRun:    f.dryRun,
		Journal:   journal.Path(),
	}
	b.write(g.env.Stdout)

	if g.ready != nil {
		close(g.ready)
	}

	select {
	case <-ctx.Done():
		return nil
	case <-stopRun:
		// `dpb panic` reverted the system half itself and then asked us to go,
		// so the reply reaches the client before the process does anything
		// else. The teardown below is idempotent and finishes the rest.
		return nil
	case serr := <-sub.serveErr:
		return serr
	}
}

// startJanitor spawns the kqueue child that undoes this run's system changes if
// the process is SIGKILLed, and registers its shutdown.
//
// It is skipped when this run will not mutate anything: with --proxy-style none
// or --dry-run the journal stays empty, so the child would wake to an empty
// file and exit — a stray process in Activity Monitor bought for nothing.
//
// A failure to spawn is NOT fatal. It costs the SIGKILL defence, which is one
// of four overlapping ones (the others are the signal handlers, the panic
// barrier and `dpb doctor --repair`), and taking away a working proxy to punish
// a missing child would be the wrong trade. It is reported instead.
func startJanitor(g *globals, cfg *config.Loaded, journal netstate.Journal,
	st *stack, f runFlags) (notes []string) {
	if f.dryRun || cfg.ProxyStyle == config.StyleNone {
		return nil
	}
	exe, err := g.exeOf()
	if err != nil {
		return []string{fmt.Sprintf(
			"the SIGKILL janitor was not started (%v); a `kill -9` would leave "+
				"the proxy settings behind until `dpb doctor --repair`", err)}
	}
	child, err := janitor.Spawn(janitor.SpawnOptions{
		Exe:         exe,
		ParentPID:   os.Getpid(),
		JournalPath: journal.Path(),
	})
	if err != nil {
		return []string{fmt.Sprintf(
			"the SIGKILL janitor was not started (%v); a `kill -9` would leave "+
				"the proxy settings behind until `dpb doctor --repair`", err)}
	}
	g.logf("run: janitor %d is watching %d for %s", child.PID(), os.Getpid(), journal.Path())
	st.push("stop the janitor", func(context.Context) error { return child.Stop() })
	return nil
}

// serveControlSocket binds the control socket and serves it until teardown.
//
// A failure to bind is NOT fatal, for the same reason a failed networksetup is
// not: the proxy still works, and refusing to run because `dpb status` would be
// blind would take away the half that matters. It is returned as a note so the
// banner says so rather than the user discovering it when `dpb why` reports
// "no dpb is running" about a dpb that is.
func serveControlSocket(g *globals, layout paths.Layout, live *liveState, st *stack) (notes []string) {
	srv, err := observ.NewControlServer(observ.ControlOptions{
		Path:    layout.ControlSocket(),
		Handler: live.handler(),
		Chown:   layout.Chown,
		Logf:    g.logf,
	})
	if err != nil {
		return []string{fmt.Sprintf(
			"the control socket at %s is not available (%v), so `dpb status`, `dpb why`, "+
				"`dpb on` and `dpb off` cannot reach this process",
			layout.ControlSocket(), err)}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	flow.Safe("cliapp/control", g.logf, func() {
		defer close(done)
		if err := srv.Serve(ctx); err != nil {
			g.logf("run: control socket: %v", err)
		}
	})
	st.push("close the control socket", func(context.Context) error {
		cancel()
		<-done
		return nil
	})
	g.logf("run: control socket at %s", srv.Path())
	return nil
}

// loadConfig resolves the configuration and then applies the flags the user
// actually typed. cobra's Changed is the only honest source for "typed": a flag
// left alone carries its zero value, and treating that as an override would let
// --port's default silently replace a configured port.
func loadConfig(g *globals, layout paths.Layout, cmd *cobra.Command, f runFlags) (*config.Loaded, error) {
	files := []string{scopeFile(layout)}
	files = append(files, f.configs...)
	loaded, err := config.Load(config.Options{
		Profile: f.profile,
		System:  config.DefaultSystemFile,
		User:    layout.ConfigFile(),
		Files:   files,
		Env:     g.getenvOf(),
	})
	if err != nil {
		return nil, usagef("%v", err)
	}
	c := loaded.Config

	fl := cmd.Flags()
	set := func(name string, apply func()) {
		if fl.Changed(name) {
			apply()
		}
	}
	set("listen", func() { c.Listen = f.listen })
	set("port", func() { c.Port = f.port })
	set("socks-port", func() { c.SOCKSPort = f.socksPort })
	set("proxy-style", func() { c.ProxyStyle = config.ProxyStyle(f.proxyStyle) })
	set("mode", func() { c.Mode = config.Mode(f.mode) })
	set("strategy", func() { c.Strategy = f.strategy })
	set("ladder", func() { c.Ladder = f.ladder })
	set("max-attempts", func() { c.MaxAttempts = f.maxAttempts })
	set("attempt-budget", func() { c.AttemptBudget = config.Duration(f.attemptBudget) })
	set("max-segments", func() { c.MaxSegments = f.maxSegments })
	set("inspect-ports", func() { c.InspectPorts = f.inspectPorts })
	set("bypass", func() { c.Bypass = append(c.Bypass, f.bypass...) })
	set("include", func() { c.Include = append(c.Include, f.include...) })
	set("dns-doh", func() { c.DNS.PrependDoH = append(c.DNS.PrependDoH, f.dnsDoH...) })
	set("dns-udp", func() { c.DNS.PrependUDP = append(c.DNS.PrependUDP, f.dnsUDP...) })
	set("ipv6", func() { c.DNS.AAAA = f.ipv6 })
	set("no-learn", func() { c.Learn = !f.noLearn })

	if f.bypassFile != "" {
		extra, err := readBypassFile(f.bypassFile)
		if err != nil {
			return nil, usagef("%v", err)
		}
		c.Bypass = append(c.Bypass, extra...)
	}

	// The flags went in after Load validated, so validate again. A flag is just
	// the last layer, and it gets the same scrutiny as the file layers.
	if err := c.Validate(); err != nil {
		return nil, usagef("%v", err)
	}
	return loaded, nil
}

// readBypassFile reads one entry per line, ignoring blanks and # comments.
func readBypassFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("run: read --bypass-file: %w", err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

// subsystems is everything the datapath needs, built once.
type subsystems struct {
	chain *resolve.Chain
	store policy.Store
	scope policy.Scope
	// engine is the same object scope wraps. The control socket's `why` needs
	// the concrete engine — Explain is not on the Scope interface — and
	// `reload` needs somewhere to put the new rules.
	engine    *policy.Engine
	netID     policy.NetworkID
	resolvers []resolve.Resolver
	server    *proxyfe.Server
	pac       *proxyfe.PAC
	serveErr  chan error
	bypasses  []string
}

func buildSubsystems(g *globals, layout paths.Layout, cfg *config.Loaded,
	ladderSpecs []string, env netstate.Env, httpAddr string,
	counters *observ.Counters, ks *killSwitch) (*subsystems, error) {
	rules, err := cfg.Rules()
	if err != nil {
		return nil, usagef("%v", err)
	}
	ipRules, err := cfg.IPRules()
	if err != nil {
		return nil, usagef("%v", err)
	}
	matcher, err := policy.NewMatcher(rules)
	if err != nil {
		return nil, usagef("%v", err)
	}
	ipset, err := policy.NewIPSet(ipRules)
	if err != nil {
		return nil, usagef("%v", err)
	}

	resolvers, err := buildResolvers(cfg)
	if err != nil {
		return nil, err
	}
	reverse := policy.NewReverseMap(policy.HostCap)
	chain := resolve.NewChain(resolve.Options{
		Resolvers: resolvers,
		AAAA:      cfg.AAAAMode(),
		// A nil Detector would approve everything. The default carries the
		// measured sinkhole sentinels (MEASUREMENTS.md §2, GT19).
		Detector: resolve.NewDetector(nil, nil),
		Reverse:  reverse,
		PerTry:   cfg.DNS.PerTry.D(),
		Logf:     g.logf,
	})

	store := policy.NopStore()
	if cfg.Learn {
		s, err := policy.OpenStore(layout.VerdictFile(), time.Now)
		if err != nil {
			return nil, fmt.Errorf("run: open the verdict store: %w", err)
		}
		if err := layout.Chown(layout.VerdictFile()); err != nil {
			g.logf("run: chown verdict store: %v", err)
		}
		store = s
	}

	netID := networkID(env.Facts, resolvers)
	engine := policy.NewEngine(policy.EngineOptions{
		Rules:        matcher,
		IPs:          ipset,
		IncludeOnly:  cfg.IncludeOnly(),
		Store:        store,
		NetID:        func() policy.NetworkID { return netID },
		InspectPorts: cfg.InspectPorts,
		Ladder:       ladderSpecs,
		// mode = "never" is `dpb off` written into a file: everything relays
		// directly and nothing is judged, while the listeners and the system
		// settings stay valid so nothing has to be re-applied to turn it back on.
		// The runtime switch and the configured one are the same flag, so
		// `dpb on` can lift a configured "never" for this run only.
		Suspended: ks.suspended,
		// Recent is where the counters reach `dpb why`: the last few outcomes
		// for a host, printed under the verdict that produced them.
		Recent: func(host string) []policy.ConnSummary {
			return connSummaries(counters.Recent(host))
		},
	})
	var scope policy.Scope = engine
	if cfg.Mode == config.ModeAlways {
		scope = alwaysScope{Scope: engine, spec: forcedSpec(cfg, ladderSpecs)}
	}

	// ONE governor for the process. GT13 is a process-wide write-volume defect,
	// so a per-connection governor would guard nothing.
	gov := emit.NewGovernor(cfg.SmallWriteRate, cfg.SmallWriteBurst)
	budget := strategy.DefaultBudget()
	budget.MaxSegments = cfg.MaxSegments

	runner := &flow.LadderRunner{
		Dial:   &flow.NetDialer{Resolve: chain.Resolve, Logf: g.logf},
		Sender: &emit.Sender{Gov: gov, Logf: g.logf},
		Store:  store,
		NetID:  func() policy.NetworkID { return netID },
		// One sinkhole table for the whole process, shared with the resolver
		// chain, so "this answer proves nothing" cannot mean two things.
		Sinkholes:   resolve.DefaultSinkholes,
		Single:      policy.NewSingleflight(),
		RTT:         flow.NewRTTTracker(),
		Budget:      budget,
		MaxAttempts: cfg.MaxAttempts,
		TotalBudget: cfg.AttemptBudget.D(),
		Logf:        g.logf,
	}

	pacHost, pacPort := cfg.Listen, cfg.Port
	if httpAddr != "" {
		h, p, err := net.SplitHostPort(httpAddr)
		if err != nil {
			return nil, fmt.Errorf("run: parse the bound address %q: %w", httpAddr, err)
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("run: parse the bound port %q: %w", p, err)
		}
		pacHost, pacPort = h, n
	}
	pac := &proxyfe.PAC{
		Host:      pacHost,
		Port:      pacPort,
		Bypass:    bypassPatterns(rules, ipRules),
		Suspended: ks.suspended,
	}

	server, err := proxyfe.New(proxyfe.Options{
		Scope:   scope,
		Ladder:  runner,
		Dial:    runner.Dial,
		Resolve: chain.Resolve,
		PAC:     pac,
		FirstMsg: flow.FirstMsgOpts{
			FirstByteWait: cfg.FirstByteWait.D(),
			CompleteWait:  cfg.CompleteWait.D(),
			MaxAssembly:   cfg.MaxAssembly.D(),
			Max:           cfg.FirstMsgMax,
		},
		RelayIdle: cfg.IdleTimeout.D(),
		// Every finished flow goes to the counters FIRST and to the log
		// second. The counters are what `dpb status`, `dpb why` and the drift
		// detector read; a log line nobody parses is not telemetry.
		OnConn: func(ev observ.ConnEvent) {
			counters.Observe(ev)
			g.onConn(ev)
		},
		Logf: g.logf,
	})
	if err != nil {
		return nil, err
	}
	return &subsystems{
		chain:     chain,
		store:     store,
		scope:     scope,
		engine:    engine,
		netID:     netID,
		resolvers: resolvers,
		server:    server,
		pac:       pac,
		serveErr:  make(chan error, 2),
		bypasses:  pac.Bypass,
	}, nil
}

// connSummaries converts the counters' view of a host's history into policy's,
// which is what `dpb why` renders. The two types are deliberately separate —
// observ sits below policy in the import graph — and this is the one place they
// meet.
func connSummaries(in []observ.ConnStat) []policy.ConnSummary {
	if len(in) == 0 {
		return nil
	}
	out := make([]policy.ConnSummary, 0, len(in))
	for _, c := range in {
		out = append(out, policy.ConnSummary{
			At: c.At, Spec: c.Spec, Attempts: c.Attempts, OK: c.OK, Latency: c.Latency,
		})
	}
	return out
}

// alwaysScope implements mode = "always": every host that would be watched is
// desynced on attempt one instead.
//
// It is a decorator rather than a policy.EngineOptions field because it is a
// statement about this run's configuration, not about the host: the engine's
// job is to say what is known about a name, and forcing a strategy onto
// everything is the operator overriding that.
type alwaysScope struct {
	policy.Scope
	spec string
}

func (a alwaysScope) ForName(host string, port int) policy.Verdict {
	return a.force(a.Scope.ForName(host, port))
}

func (a alwaysScope) ForAddr(ap netip.AddrPort) policy.Verdict {
	return a.force(a.Scope.ForAddr(ap))
}

func (a alwaysScope) force(v policy.Verdict) policy.Verdict {
	if v.Class != policy.ScopeWatch || a.spec == "" {
		return v
	}
	v.Class = policy.ScopeDesync
	v.Spec = a.spec
	v.Reason = "mode = always"
	v.RuleFrom = "config"
	return v
}

// forcedSpec is the strategy mode = "always" applies. An explicit --strategy
// wins; otherwise it is the ladder's first non-plain rung, because rung 1 is
// plain by construction and forcing plain would mean forcing nothing.
func forcedSpec(cfg *config.Loaded, ladder []string) string {
	if cfg.Strategy != "" {
		return cfg.Strategy
	}
	for _, s := range ladder {
		if s != "" {
			return s
		}
	}
	return ""
}

func buildResolvers(cfg *config.Loaded) ([]resolve.Resolver, error) {
	eps := cfg.Endpoints()
	out := make([]resolve.Resolver, 0, len(eps))
	for _, e := range eps {
		r, err := e.New(nil, nil)
		if err != nil {
			return nil, usagef("run: resolver %q: %v", e.Label, err)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, usagef("run: the resolver chain is empty")
	}
	return out, nil
}

// networkID namespaces the verdict cache. A verdict learned on a censored line
// must not be trusted on a different network, and the gateway plus the resolver
// set is what tells one from the other without asking anybody's permission.
func networkID(facts *netstate.Facts, resolvers []resolve.Resolver) policy.NetworkID {
	id := policy.NetworkID{Kind: "unknown"}
	if facts != nil {
		id.Gateway = facts.Gateway
		id.GatewayMAC = facts.UplinkMAC
		if facts.VPN.Present {
			id.Kind = "vpn"
		}
	}
	labels := make([]string, 0, len(resolvers))
	for _, r := range resolvers {
		labels = append(labels, r.Label())
	}
	id.ResolverSet = policy.ResolverSetHash(labels)
	return id
}

// bypassPatterns is what the PAC sends DIRECT: every hard-veto rule, names and
// addresses alike. A host in this list never reaches the proxy at all, which is
// the strongest form the veto can take.
func bypassPatterns(rules, ips []policy.Rule) []string {
	var out []string
	for _, set := range [][]policy.Rule{rules, ips} {
		for _, r := range set {
			if r.Class == policy.ScopeBypass {
				out = append(out, r.Pattern)
			}
		}
	}
	return out
}

// listener is one bound socket, reported by the banner.
type listener struct {
	Kind string
	Addr string
}

// boundListener is a socket that is listening but not yet being served.
type boundListener struct {
	kind string
	ln   net.Listener
}

func bindListeners(cfg *config.Loaded) ([]boundListener, error) {
	var out []boundListener
	for _, want := range []struct {
		kind string
		port int
	}{{"http", cfg.Port}, {"socks5", cfg.SOCKSPort}} {
		if want.port == 0 {
			continue
		}
		addr := net.JoinHostPort(cfg.Listen, strconv.Itoa(want.port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, b := range out {
				_ = b.ln.Close()
			}
			return nil, fmt.Errorf("run: listen on %s: %w", addr, err)
		}
		out = append(out, boundListener{kind: want.kind, ln: ln})
	}
	return out, nil
}

func addrOfBound(bound []boundListener, kind string) string {
	for _, b := range bound {
		if b.kind == kind {
			return b.ln.Addr().String()
		}
	}
	return ""
}

func startListeners(bound []boundListener, srv *proxyfe.Server, st *stack, g *globals) []listener {
	out := make([]listener, 0, len(bound))
	for _, b := range bound {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		ln, kind := b.ln, b.kind
		flow.Safe("cliapp/serve-"+kind, g.logf, func() {
			defer close(done)
			if err := srv.Serve(ctx, ln); err != nil {
				g.serveFailed(err)
			}
		})
		st.push("stop the "+kind+" listener", func(context.Context) error {
			cancel()
			<-done
			return nil
		})
		out = append(out, listener{Kind: kind, Addr: ln.Addr().String()})
	}
	return out
}

// applySystemState points macOS at the listeners.
//
// The order is the bring-up order and UndoAll reverses it: the PAC file is on
// disk before anything is pointed at its URL, and the environment is exported
// last because it is the mechanism with the widest blast radius. Everything
// goes through netstate.Manager, so every step is journalled with an fsync
// BEFORE it is attempted and verified through a different subsystem than it was
// written with.
//
// A failure here is NOT fatal. A machine where networksetup refuses is a
// machine where the listeners still work and the user can configure their
// browser by hand; exiting instead would take away the working half. Every
// refusal is returned as a note and the banner prints it, so nothing is ever
// claimed that did not happen.
// systemHalf is the applied system state, kept so the control socket can act on
// it after start-up: `dpb coverage --fix` re-asserts it and `dpb panic` unwinds
// it. Nil when this run changes nothing.
type systemHalf struct {
	// revert runs UndoAll exactly once, however many callers ask. The teardown
	// stack and `dpb panic` are both callers, and two processes' worth of
	// reverts against one journal is the situation the journal cannot describe.
	revert func(context.Context) error
	// reapply re-runs the same mutations. netstate's adopt detection makes a
	// setting that is already correct a no-op, so this is the cheap answer to
	// "something else overwrote the proxy pane".
	reapply func(context.Context) (applied []string, notes []string)
}

func applySystemState(ctx context.Context, g *globals, layout paths.Layout, cfg *config.Loaded,
	sub *subsystems, listeners []listener, st *stack, env netstate.Env,
	journal netstate.Journal) (applied []string, notes []string, half *systemHalf) {
	style := cfg.ProxyStyle
	if style == config.StyleNone {
		return nil, []string{"--proxy-style none: no system setting was changed"}, nil
	}
	httpAddr := addrOf(listeners, "http")
	if httpAddr == "" && (style.SetsPAC() || style.SetsExplicit() || style.SetsEnv()) {
		return nil, []string{"the HTTP listener is disabled, so no system proxy setting was applied"}, nil
	}

	mgr := netstate.NewManager(journal, env)
	var revertOnce sync.Once
	var revertErr error
	revert := func(c context.Context) error {
		revertOnce.Do(func() { revertErr = errors.Join(mgr.UndoAll(c)...) })
		return revertErr
	}
	st.push("revert system settings", revert)

	host, portStr, _ := net.SplitHostPort(httpAddr)
	port, _ := strconv.Atoi(portStr)

	// The op list is rebuilt on every pass rather than captured once, because
	// the PAC's bytes depend on the kill switch: re-asserting a stale
	// all-DIRECT PAC after `dpb on` would put the settings back wrong.
	apply := func(c context.Context) (applied []string, notes []string) {
		do := func(what string, op netstate.Op) {
			if err := mgr.Do(c, op); err != nil {
				notes = append(notes, fmt.Sprintf("%s: %v", what, err))
				return
			}
			applied = append(applied, op.Describe())
		}
		if style.SetsPAC() {
			do("write the PAC file", netstate.NewPACFile(layout.PACFile(), sub.pac.Active()))
			if err := layout.Chown(layout.PACFile()); err != nil {
				g.logf("run: chown PAC file: %v", err)
			}
			do("set the auto-proxy URL", netstate.NewPAC(env.Runner, sub.pac.URL(), nil))
		}
		if style.SetsExplicit() {
			do("set the web and secure proxies", netstate.NewWebProxy(env.Runner, host, port, nil))
		}
		if style.SetsEnv() {
			do("export the proxy environment",
				netstate.NewLaunchEnv(env.Runner, "http://"+httpAddr, noProxyList(sub.bypasses)))
		}
		return applied, notes
	}

	applied, notes = apply(ctx)
	return applied, notes, &systemHalf{revert: revert, reapply: apply}
}

func addrOf(ls []listener, kind string) string {
	for _, l := range ls {
		if l.Kind == kind {
			return l.Addr
		}
	}
	return ""
}

// noProxyList is NO_PROXY for the processes that read the environment rather
// than the proxy pane. It carries the same hard-veto names the PAC does, which
// is what keeps a reqwest-based updater and a browser agreeing about which
// hosts never touch dpb.
func noProxyList(bypasses []string) []string {
	out := []string{"localhost", "127.0.0.1", "::1"}
	for _, p := range bypasses {
		p = strings.TrimPrefix(strings.TrimPrefix(p, "="), "*.")
		if p != "" && !strings.Contains(p, "/") {
			out = append(out, p)
		}
	}
	return out
}

// scopeFile is the config layer `dpb scope` owns and rewrites. Keeping the
// tool's own edits out of the user's hand-written file means a scope change can
// never eat a comment or reorder a setting somebody cared about.
func scopeFile(l paths.Layout) string { return filepath.Join(l.ConfigDir, "scope.toml") }

// serveFailed reports a listener that died while running.
func (g *globals) serveFailed(err error) {
	if g.serveErrs != nil {
		select {
		case g.serveErrs <- err:
		default:
		}
	}
}

// onConn reports one finished flow.
//
// M12 replaces this with the event bus and the control socket. Until then the
// debug log is the only way a user can see what the ladder decided for a host,
// and "run it with -v and read the line" has to be an answer we can give: a
// tool that silently escalates is a tool nobody can tell is misbehaving.
func (g *globals) onConn(ev observ.ConnEvent) {
	if g.events != nil {
		g.events(ev)
		return
	}
	g.logf("flow %d %s:%d %s scope=%s strategy=%s attempts=%d escalations=%d up=%d down=%d in %s%s",
		ev.ID, ev.Host, ev.Port, ev.Outcome, ev.Scope, specLabel(ev.Strategy),
		ev.Attempts, ev.Rung, ev.BytesUp, ev.BytesDown, ev.Duration.Round(time.Millisecond),
		errSuffix(ev.Err))
}

func specLabel(s string) string {
	if s == "" {
		return "plain"
	}
	return s
}

func errSuffix(s string) string {
	if s == "" {
		return ""
	}
	return ": " + s
}
