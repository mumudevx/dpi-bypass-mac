package cliapp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/mumudevx/dpb/internal/config"
	"github.com/mumudevx/dpb/internal/front/tunfe"
	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/observ"
	"github.com/mumudevx/dpb/internal/ops"
	"github.com/mumudevx/dpb/internal/paths"
	"github.com/mumudevx/dpb/internal/resolve"
)

// The safety half of `--tun`: the guards that only matter on the paths nobody
// exercises by hand. Every test here is about a defence, not a feature, which
// is why each one names the failure it is standing in front of.

// ── Y1: the SIGKILL janitor under --tun --proxy-style none ──────────────────

// TestWillMutateCountsTheTunnel.
//
// The janitor's spawn condition used to read "--proxy-style none means nothing
// was changed". That was true until --tun existed. Under
// `sudo dpb run --tun --proxy-style none` the run installs a utun, both
// capture-route halves, a /32 per system nameserver, an interface-scoped
// default route and (by default) a resolver-list rewrite — and every one of
// them is journalled. The question the janitor turns on is "will this run
// journal a mutation", never "which proxy style is it".
func TestWillMutateCountsTheTunnel(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		style config.ProxyStyle
		tun   bool
		dry   bool
		want  bool
	}{
		{"pac in proxy mode", config.StylePAC, false, false, true},
		{"proxy-style none changes nothing", config.StyleNone, false, false, false},
		{"the tunnel mutates whatever the proxy style", config.StyleNone, true, false, true},
		{"the tunnel and the proxy settings together", config.StylePAC, true, false, true},
		{"--dry-run applies nothing", config.StylePAC, false, true, false},
		{"--tun --dry-run opens no device and installs no route", config.StyleNone, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Loaded{Config: config.Defaults()}
			cfg.ProxyStyle = tc.style
			got := willMutate(cfg, runFlags{tun: tc.tun, dryRun: tc.dry})
			if got != tc.want {
				t.Fatalf("willMutate(style=%s tun=%v dry=%v) = %v, want %v",
					tc.style, tc.tun, tc.dry, got, tc.want)
			}
		})
	}
}

// TestRunSpawnsTheJanitorUnderTunWithProxyStyleNone.
//
// This is the wiring the unit test above cannot prove. `kill -9` runs no defer,
// no recover and no signal handler, so the janitor child is the ONLY thing that
// takes the capture routes back out of the kernel. Without it the user is left
// with 0.0.0.0/1 and 128.0.0.0/1 pointing at a utun that no longer exists —
// every name on the machine unreachable — and no process left that knows it.
//
// The janitor is spawned from a throwaway script, never from a real dpb: the
// point of the defence is what happens to real system state, which is the last
// thing a test should be holding.
func TestRunSpawnsTheJanitorUnderTunWithProxyStyleNone(t *testing.T) {
	t.Parallel()
	layout := tempLayout(t)
	layout.Elevated = true

	seq := &recordingSeq{started: make(chan struct{})}
	dev, _ := tunfe.NewPipe(tunfe.DefaultMTU)
	dev.SetName("utun7")
	link := &spyLink{Link: dev, seq: seq}

	h := startRunTweak(t, newFakeMac(), layout, func(g *globals) {
		g.facts = &netstate.Facts{
			Uplink:   tunFixtureUplink,
			Gateway:  netip.MustParseAddr("192.0.2.1"),
			Services: []string{"Wi-Fi"},
		}
		g.openLink = func(string, int, func(string, ...any)) (tunfe.Link, error) { return link, nil }
		g.tunSeq = func(tunfe.Sequencer) tunfe.Sequencer { return seq }
		// -v: the teardown order is asserted below out of the debug log, which
		// is where a user has to be able to check the same claim on their own
		// machine.
	}, "-v", "--tun", "--proxy-style", "none")

	seq.awaitStart(t)
	// The routes are in the kernel by now, so the window the janitor covers is
	// open and it has to already be watching.
	if len(seq.kinds()) == 0 {
		t.Fatal("the tunnel applied no Ops, so this test is not standing in front of anything")
	}

	line := strings.Fields(strings.TrimSpace(waitForFile(t, h.spawnLog, 10*time.Second)))
	if len(line) < 5 {
		t.Fatalf("the janitor was started with %v; want a pid and the four arguments", line)
	}
	pid, err := strconv.Atoi(line[0])
	if err != nil {
		t.Fatalf("the child did not record a pid: %v", line)
	}
	args := strings.Join(line[1:], " ")
	if !strings.Contains(args, "_janitor") {
		t.Errorf("the child was not started as the janitor subcommand: %q", args)
	}
	if want := "--journal " + layout.JournalFile(); !strings.Contains(args, want) {
		t.Errorf("the janitor was given the wrong journal: %q, want %q", args, want)
	}
	if !processAlive(pid) {
		t.Fatalf("the janitor (pid %d) is not running while the tunnel is up", pid)
	}

	h.shutdown(t)
	deadline := time.Now().Add(5 * time.Second)
	for processAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processAlive(pid) {
		t.Fatalf("the janitor (pid %d) outlived a clean shutdown", pid)
	}
	// It is stopped AFTER the tunnel came down. Stopping it first would open a
	// window in which a `kill -9` mid-teardown leaves the capture routes
	// pointing at a device that is closing.
	assertTeardownOrder(t, h.errOut.String(), "tear down the tunnel", "stop the janitor")
}

// A --tun --dry-run applies nothing, so there is still nothing for the janitor
// to clean up and a stray process per run is a cost paid for no benefit.
func TestTunDryRunSpawnsNoJanitor(t *testing.T) {
	t.Parallel()
	h := startRun(t, newFakeMac(), shortLayout(t), "--tun", "--dry-run", "--proxy-style", "none")

	time.Sleep(300 * time.Millisecond)
	if b, err := os.ReadFile(h.spawnLog); err == nil && len(b) > 0 {
		t.Fatalf("--tun --dry-run spawned a janitor anyway: %q", b)
	}
}

// ── Y2: the recursion guard ─────────────────────────────────────────────────

// TestTunResolverChainCannotEscapeTheUplinkPin is the mechanical gate for the
// property "every resolver dial under --tun is uplink-bound".
//
// Under --tun the capture routes cover the whole address space. A resolver
// socket that is not pinned to the physical uplink is routed back into dpb's
// own netstack and answered by the in-process DNS server that issued the query:
// not a detour but unbounded recursion, and the tool deadlocks against itself.
// It is the same class of defect as MEASUREMENTS.md §5.4 — a dial escaping the
// tool's own resolution path — which is why §5.4's no-hostname-dial gate exists
// at all.
//
// The gate works by making the pin FATAL: the uplink names an interface that
// cannot be bound, so a dial that honours the pin cannot leave the process at
// all. Every rung is aimed at a loopback decoy that counts what reaches it. A
// rung that ignores the pin lands on its decoy and the count is not zero.
func TestTunResolverChainCannotEscapeTheUplinkPin(t *testing.T) {
	t.Parallel()
	tcp, udp := newResolverDecoys(t)

	// An interface no machine has. flow's bind hook resolves the name with
	// net.InterfaceByName BEFORE connect, so a pinned dial fails without a
	// packet leaving the process — which is what makes this hermetic.
	const noSuchUplink = "dpbnope0"

	cfgTOML := fmt.Sprintf(`
[dns]
chain = "custom"

[[dns.endpoint]]
label = "doh-decoy"
transport = "doh"
target = "https://decoy.invalid:%d/dns-query"
bootstrap = ["127.0.0.1"]

[[dns.endpoint]]
label = "dot-decoy"
transport = "dot"
target = "%s"

[[dns.endpoint]]
label = "udp-decoy"
transport = "udp"
target = "%s"

[[dns.endpoint]]
label = "udp-alt-decoy"
transport = "udp-alt"
target = "%s"
`, tcp.port, tcp.addr, udp.addr, udp.addr)

	fx := newRunSubsystems(t, true, noSuchUplink, cfgTOML)

	// A rung added to the shipped chain with a transport this fixture does not
	// build escapes the gate silently. Fail instead.
	covered := map[string]bool{}
	for _, e := range fx.cfg.Endpoints() {
		covered[e.Transport] = true
	}
	for _, e := range resolve.DefaultEndpoints() {
		if !covered[e.Transport] {
			t.Fatalf("the shipped chain ships transport %q and this gate never dials one; "+
				"add an endpoint for it to the fixture above", e.Transport)
		}
	}
	if len(fx.sub.resolvers) != len(fx.cfg.Endpoints()) {
		t.Fatalf("built %d resolvers for %d endpoints", len(fx.sub.resolvers), len(fx.cfg.Endpoints()))
	}

	query, err := resolve.NewQuery("example.invalid", dns.TypeA)
	if err != nil {
		t.Fatalf("build a query: %v", err)
	}
	for _, r := range fx.sub.resolvers {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := r.Exchange(ctx, query)
		cancel()
		if err == nil {
			t.Errorf("rung %s answered over an uplink that cannot be bound, so it is not pinned", r.Label())
			continue
		}
		// The refusal must be the PIN. A rung that failed for some other
		// reason would make this test pass while protecting nothing.
		if !strings.Contains(err.Error(), noSuchUplink) {
			t.Errorf("rung %s failed for a reason other than the uplink pin: %v", r.Label(), err)
		}
	}
	if n := tcp.hits(); n != 0 {
		t.Errorf("%d resolver dial(s) reached the TCP decoy despite the uplink pin; "+
			"under --tun those sockets are captured by dpb's own routes and answered by dpb itself", n)
	}
	if n := udp.hits(); n != 0 {
		t.Errorf("%d resolver datagram(s) reached the UDP decoy despite the uplink pin; "+
			"under --tun that is the recursion: dpb's own DNS query answered by dpb's own DNS server", n)
	}

	// The control. Proxy mode installs no capture routes, so nothing there is
	// pinned — and the decoys must be reachable, or the assertions above would
	// hold for a chain that simply cannot dial anything.
	proxy := newRunSubsystems(t, false, noSuchUplink, cfgTOML)
	for _, r := range proxy.sub.resolvers {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = r.Exchange(ctx, query)
		cancel()
	}
	if tcp.hits() == 0 || udp.hits() == 0 {
		t.Fatalf("the unpinned chain reached the decoys %d time(s) over TCP and %d over UDP; "+
			"with nothing reachable the pinned half above proves nothing", tcp.hits(), udp.hits())
	}
}

// decoy counts what reaches it and answers nothing.
type decoy struct {
	addr string
	port int
	n    atomic.Int64
}

func (d *decoy) hits() int64 { return d.n.Load() }

// newResolverDecoys stands up one TCP and one UDP loopback socket for the
// resolver chain to aim at. They are on loopback so that a rung which escapes
// the pin still cannot reach the network from a unit test.
func newResolverDecoys(t *testing.T) (tcp, udp *decoy) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp decoy: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tcp = &decoy{addr: ln.Addr().String(), port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tcp.n.Add(1)
			_ = c.Close()
		}
	}()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp decoy: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	udp = &decoy{addr: pc.LocalAddr().String(), port: pc.LocalAddr().(*net.UDPAddr).Port}
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			udp.n.Add(1)
		}
	}()
	return tcp, udp
}

// ── Y3: a listener that dies must reach the process ─────────────────────────

// TestAListenerFailureStopsTheRunWithNoTestSeam.
//
// g.serveErrs is assigned only in _test.go. A production `dpb run` therefore
// had a nil channel, and a proxy listener that died was reported to nobody: the
// process kept printing Ready, the system proxy settings kept pointing at a
// port serving nothing, and every request on the machine failed with no
// attribution. A seam that makes the production path silent is worse than no
// seam, so this test runs with the seam explicitly nil.
func TestAListenerFailureStopsTheRunWithNoTestSeam(t *testing.T) {
	t.Parallel()
	fx := newRunSubsystems(t, false, "en0", "")
	fx.g.serveErrs = nil // production

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var st stack
	startListeners([]boundListener{{kind: "http", ln: ln}}, fx.sub.server, &st, fx.g, fx.sub.serveErr)

	// The listener dies underneath the server, which is what a revoked
	// interface or an fd exhaustion looks like from Accept.
	_ = ln.Close()

	select {
	case err := <-fx.sub.serveErr:
		if err == nil {
			t.Fatal("a dead listener reported a nil error")
		}
		if !strings.Contains(err.Error(), "http") {
			t.Errorf("the failure does not name the listener that died: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a dead proxy listener never reached the run; dpb would keep reporting Ready " +
			"while the system proxy settings point at a port serving nothing")
	}

	ctx, cancel := context.WithTimeout(context.Background(), teardownBudget)
	defer cancel()
	_ = st.drain(ctx, t.Logf)
}

// ── Y4: --set-dns on without --tun ──────────────────────────────────────────

// TestSetDNSOnWithoutTunIsRefused.
//
// resolveSetDNS has always had the right usage-error branch, and its only call
// site was inside startTun — which runs only under --tun. So `dpb run
// --set-dns on` was accepted, ignored, and the user was told nothing: exactly
// the trap this project keeps removing. The validation has to happen on the
// path every run takes.
func TestSetDNSOnWithoutTunIsRefused(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	// A run that gets past the validation LISTENS, so the context is what
	// bounds this test rather than the command. That is also the assertion:
	// an ignored flag reaches the banner and exits 0 when the context expires,
	// a refused one exits 2 before anything is bound.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := c.execCtx(t, ctx, "run", "--set-dns", "on", "--proxy-style", "none",
		"--port", "0", "--socks-port", strconv.Itoa(freePort(t)))

	if r.code != ExitUsage {
		t.Fatalf("`dpb run --set-dns on` exited %d, want %d (usage)\nstdout:\n%s\nstderr:\n%s",
			r.code, ExitUsage, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "--set-dns") {
		t.Fatalf("the refusal does not name the flag it refused:\n%s", r.stderr)
	}
	// And it is refused BEFORE anything is bound, journalled or mutated: a
	// usage error that arrives after half a bring-up is one the user pays for.
	if strings.TrimSpace(r.stdout) != "" {
		t.Fatalf("the refused run got as far as printing its banner:\n%s", r.stdout)
	}
	if snap := c.mac.proxySnapshot(); strings.Contains(snap, "ProxyAutoConfigEnable : 1") {
		t.Fatalf("the refused run changed a system setting:\n%s", snap)
	}
}

// ── the fixture ─────────────────────────────────────────────────────────────

// runFixture is `dpb run`'s subsystems, built exactly the way runRun builds
// them: the command's own flag parsing, the shipped configuration resolution
// and buildSubsystems. Nothing here binds a port or mutates the machine.
type runFixture struct {
	g      *globals
	cfg    *config.Loaded
	sub    *subsystems
	layout paths.Layout
}

func newRunSubsystems(t *testing.T, tun bool, uplink, configTOML string) *runFixture {
	t.Helper()
	ops.Install()

	layout := tempLayout(t)
	if err := layout.EnsureDirs(); err != nil {
		t.Fatalf("state dirs: %v", err)
	}
	if configTOML != "" {
		if err := os.WriteFile(layout.ConfigFile(), []byte(configTOML), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
	}

	mac := newFakeMac()
	facts := &netstate.Facts{Uplink: uplink, Services: []string{"Wi-Fi"}}
	g := &globals{
		env:    Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}},
		layout: &layout,
		runner: mac,
		rib:    mac,
		facts:  facts,
		getenv: func(string) string { return "" },
	}

	cmd := newRunCmd(g)
	// A port that is never bound — the fixture builds the subsystems and stops
	// short of listening — but the configuration refuses a run in which nothing
	// would listen at all, so it has to be a real number.
	args := []string{"--proxy-style", "none", "--port", "0",
		"--socks-port", strconv.Itoa(freePort(t))}
	if tun {
		args = append(args, "--tun")
	}
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	f := runFlagsOf(t, cmd)

	cfg, err := loadConfig(g, layout, cmd, f)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	ladder, err := cfg.LadderSpecs()
	if err != nil {
		t.Fatalf("ladder: %v", err)
	}
	env := netstate.Env{Runner: mac, RIB: mac, Facts: facts, Logf: t.Logf}
	sub, err := buildSubsystems(g, layout, cfg, ladder, env, "",
		observ.NewCounters(observ.CountersOptions{}), &killSwitch{}, tun)
	if err != nil {
		t.Fatalf("build subsystems: %v", err)
	}
	t.Cleanup(func() { _ = sub.store.Close() })
	return &runFixture{g: g, cfg: cfg, sub: sub, layout: layout}
}
