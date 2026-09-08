package cliapp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/config"
	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/netwatch"
	"github.com/mumudevx/dpb/internal/paths"
	"github.com/mumudevx/dpb/internal/policy"
)

// runHarness starts `dpb run` against a fake macOS and a temporary state
// directory, and gives the test the address it actually bound.
type runHarness struct {
	mac    *fakeMac
	layout paths.Layout
	out    *bytes.Buffer
	errOut *bytes.Buffer

	port    int
	done    chan error
	stop    context.CancelFunc
	steps   []func(context.Context) error
	stopped bool

	// fakeDPB stands in for the dpb binary the janitor child is spawned from,
	// and spawnLog is the file it writes its pid and arguments to.
	fakeDPB  string
	spawnLog string
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func tempLayout(t *testing.T) paths.Layout {
	t.Helper()
	dir := t.TempDir()
	return paths.Layout{
		ConfigDir: filepath.Join(dir, "config"),
		StateDir:  filepath.Join(dir, "state"),
		CacheDir:  filepath.Join(dir, "cache"),
		LogDir:    filepath.Join(dir, "log"),
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		Home:      dir,
	}
}

func startRun(t *testing.T, mac *fakeMac, layout paths.Layout, args ...string) *runHarness {
	t.Helper()
	return startRunTweak(t, mac, layout, nil, args...)
}

// startRunTweak is startRun with a hook that adjusts the globals before the
// command tree is built. M15's network watcher needs it: a test must be able
// to hand `dpb run` a routing-change source and a captive-portal prober it
// controls, because the real ones read the kernel and dial the internet.
func startRunTweak(t *testing.T, mac *fakeMac, layout paths.Layout,
	tweak func(*globals), args ...string) *runHarness {
	t.Helper()
	h := &runHarness{
		mac:    mac,
		layout: layout,
		out:    &bytes.Buffer{},
		errOut: &bytes.Buffer{},
		port:   freePort(t),
		done:   make(chan error, 1),
	}
	h.fakeDPB, h.spawnLog = fakeDPBBinary(t)
	ready := make(chan struct{})
	g := &globals{
		env: Env{
			Stdout: h.out,
			Stderr: h.errOut,
			Push:   func(fn func(context.Context) error) { h.steps = append(h.steps, fn) },
		},
		layout:    &layout,
		runner:    mac,
		rib:       mac,
		facts:     &netstate.Facts{Uplink: "en0", Services: []string{"Wi-Fi"}},
		getenv:    func(string) string { return "" },
		ready:     ready,
		serveErrs: make(chan error, 2),
		// `dpb run` spawns the SIGKILL janitor from its own executable, and
		// under `go test` that is this test binary. Pointing it at a throwaway
		// script means the janitor wiring is exercised by the real
		// janitor.Spawn against a process that holds no system state.
		exe: func() (string, error) { return h.fakeDPB, nil },
		// Every run test drives the network watcher, so both of its outside
		// edges are stubbed by default: an inert routing source (the real one
		// reads this machine's kernel) and a prober that reaches no verdict
		// (the real one dials captive.apple.com). A test that wants either
		// replaces it in tweak.
		netwatchOpts: func(o *netwatch.Options) {
			o.Source = inertSource{}
			o.Portal = inertProber{}
		},
	}
	if tweak != nil {
		tweak(g)
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.stop = cancel
	full := append([]string{"run", "--port", fmt.Sprint(h.port), "--socks-port", "0"}, args...)
	root := newRoot(g)
	root.SetArgs(full)
	root.SetOut(h.out)
	root.SetErr(h.errOut)
	go func() { h.done <- root.ExecuteContext(ctx) }()

	select {
	case <-ready:
	case err := <-h.done:
		t.Fatalf("run exited before it was ready: %v\nstdout:\n%s\nstderr:\n%s", err, h.out, h.errOut)
	case <-time.After(20 * time.Second):
		t.Fatalf("run never became ready\nstdout:\n%s\nstderr:\n%s", h.out, h.errOut)
	}
	t.Cleanup(func() { h.shutdown(t) })
	return h
}

// shutdown is idempotent: a test that stops the run to assert on the reverted
// state must not have the cleanup wait on a channel that has already been read.
func (h *runHarness) shutdown(t *testing.T) {
	t.Helper()
	if h.stopped {
		return
	}
	h.stopped = true
	h.stop()
	select {
	case err := <-h.done:
		if err != nil {
			t.Errorf("run returned %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("run did not return after its context was cancelled")
	}
}

func (h *runHarness) addr() string { return fmt.Sprintf("127.0.0.1:%d", h.port) }

// The offline half of the M11 acceptance: a real request through the listener
// the shipped command bound, using the shipped datapath end to end. The live
// half — `curl -x http://127.0.0.1:8080 https://discord.com/` on a Türk Telekom
// line — cannot run here, and --proxy-style none is what makes the rest of it
// runnable without touching the machine.
func TestRunProxiesAPlaintextRequest(t *testing.T) {
	t.Parallel()
	origin := newTestOrigin(t)
	mac := newFakeMac()
	h := startRun(t, mac, tempLayout(t), "--proxy-style", "none")

	body := fetchThrough(t, h.addr(), "http://"+origin+"/hello")
	if !strings.Contains(body, "origin answered /hello") {
		t.Fatalf("body = %q", body)
	}
	if snap := mac.proxySnapshot(); strings.Contains(snap, "ProxyAutoConfigEnable : 1") {
		t.Fatalf("--proxy-style none changed a system setting:\n%s", snap)
	}
}

// CONNECT through the shipped listener, to a loopback origin. The destination
// is an address literal, so policy's compiled-in private-address table makes it
// a hard bypass and it is relayed with nothing buffered — which is the path a
// browser takes to a host on the bypass list.
func TestRunTunnelsCONNECT(t *testing.T) {
	t.Parallel()
	origin := newTestOrigin(t)
	mac := newFakeMac()
	h := startRun(t, mac, tempLayout(t), "--proxy-style", "none")

	c, err := net.Dial("tcp", h.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", origin, origin)
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("status = %q", line)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(l) == "" {
			break
		}
	}
	fmt.Fprintf(c, "GET /tunnel HTTP/1.1\r\nHost: %s\r\n\r\n", origin)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(payload), "/tunnel") {
		t.Fatalf("body = %q", payload)
	}
}

// The PAC is served from the port that is actually bound, not the one that was
// configured. A PAC naming a port nothing is listening on is worse than none.
func TestRunServesThePACFromTheBoundPort(t *testing.T) {
	t.Parallel()
	mac := newFakeMac()
	h := startRun(t, mac, tempLayout(t), "--proxy-style", "none")

	body := fetchDirect(t, "http://"+h.addr()+"/dpb.pac")
	if !strings.Contains(body, fmt.Sprintf(`return "PROXY 127.0.0.1:%d"`, h.port)) {
		t.Fatalf("the PAC does not name the bound listener:\n%s", body)
	}
	// The compiled-in bypasses must be in it: those hosts have to reach DIRECT
	// without entering dpb at all.
	if !strings.Contains(body, `"isbank.com.tr"`) {
		t.Fatalf("the PAC carries no compiled-in bypass:\n%s", body)
	}
}

// The acceptance clause, offline: after Ctrl-C, `scutil --proxy` is
// byte-identical to the snapshot taken before the run.
func TestRunRevertsEverySystemSettingOnShutdown(t *testing.T) {
	t.Parallel()
	mac := newFakeMac()
	layout := tempLayout(t)
	before := mac.proxySnapshot()
	beforeEnv := mac.environment()

	h := startRun(t, mac, layout, "--proxy-style", "both")

	during := mac.proxySnapshot()
	if !strings.Contains(during, "ProxyAutoConfigEnable : 1") {
		t.Fatalf("the auto-proxy URL was never applied:\n%s\nbanner:\n%s", during, h.out)
	}
	if !strings.Contains(during, fmt.Sprintf("ProxyAutoConfigURLString : http://127.0.0.1:%d/dpb.pac", h.port)) {
		t.Fatalf("the PAC URL does not name the bound listener:\n%s", during)
	}
	if got := mac.environment()["HTTPS_PROXY"]; got != fmt.Sprintf("http://127.0.0.1:%d", h.port) {
		t.Fatalf("HTTPS_PROXY = %q", got)
	}
	// The PAC file is on disk, and it is the same bytes the listener serves.
	onDisk, err := os.ReadFile(layout.PACFile())
	if err != nil {
		t.Fatalf("read the PAC file: %v", err)
	}
	served := fetchDirect(t, "http://"+h.addr()+"/dpb.pac")
	if string(onDisk) != served {
		t.Fatal("the PAC on disk is not the PAC being served")
	}

	h.shutdown(t)

	if after := mac.proxySnapshot(); after != before {
		t.Fatalf("scutil --proxy is not byte-identical to the pre-run snapshot.\nbefore:\n%s\nafter:\n%s",
			before, after)
	}
	// Comparing lengths let a revert that replaced one variable with another
	// pass — the same defect class TestRunRevertsSystemSettingsBeforeItStops-
	// Listening was rewritten to remove. Compare the state, not its size.
	after := mac.environment()
	if len(after) != len(beforeEnv) {
		t.Fatalf("the proxy environment was left behind: before %v, after %v", beforeEnv, after)
	}
	for k, want := range beforeEnv {
		if got, ok := after[k]; !ok || got != want {
			t.Fatalf("environment %q = %q (present %v), want %q", k, got, ok, want)
		}
	}
	for k := range after {
		if _, ok := beforeEnv[k]; !ok {
			t.Fatalf("environment %q was added by the run and never removed", k)
		}
	}
}

// Teardown order is the contract: the system settings come off FIRST, while the
// listeners they point at are still up, and the run lock comes off last.
// Reverting in the other order leaves a window where macOS is pointed at a port
// nothing is listening on.
func TestRunRevertsSystemSettingsBeforeItStopsListening(t *testing.T) {
	t.Parallel()
	mac := newFakeMac()
	before := mac.proxySnapshot()
	h := startRun(t, mac, tempLayout(t), "--proxy-style", "pac")
	addr := h.addr()

	// Without this, "the state came back" is satisfied by a run that never
	// changed anything, and the test below would pass against a no-op.
	during := mac.proxySnapshot()
	if !strings.Contains(during, "ProxyAutoConfigEnable : 1") {
		t.Fatalf("the PAC setting was never applied, so reverting it proves nothing:\n%s\nbanner:\n%s",
			during, h.out)
	}

	// Watch teardown from inside the fake macOS. The watch is installed AFTER
	// startRun returns, so every -setautoproxy* it sees is a revert: the apply
	// finished before the banner was written. Dialling the listener from inside
	// the command is the only honest observation of the order — the call log
	// records which commands ran, never what was still listening when they did.
	var mu sync.Mutex
	var whileListening, afterClose int
	mac.watchCalls(func(argv string) {
		if !strings.HasPrefix(argv, "networksetup -setautoproxy") {
			return
		}
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if c != nil {
			c.Close()
		}
		mu.Lock()
		defer mu.Unlock()
		if err == nil {
			whileListening++
		} else {
			afterClose++
		}
	})

	h.shutdown(t)
	mac.watchCalls(nil)

	// The reverted STATE, read back through the other subsystem — not a count of
	// the commands that were issued. A revert that runs and achieves nothing is
	// the failure this test exists to catch.
	if after := mac.proxySnapshot(); after != before {
		t.Fatalf("the PAC setting was applied and never reverted; `scutil --proxy` is not the pre-run snapshot.\nbefore:\n%s\nafter:\n%s",
			before, after)
	}

	mu.Lock()
	defer mu.Unlock()
	if whileListening == 0 {
		t.Fatalf("no PAC revert command ran at all (%d ran after the listener was gone)", afterClose)
	}
	if afterClose != 0 {
		t.Fatalf("%d PAC revert command(s) ran after the listener had already closed: for that window macOS was pointed at a dead port", afterClose)
	}
	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Fatal("the listener is still up after teardown")
	}
}

// A system mutation that fails must not take the listeners down with it: a
// machine where networksetup refuses is a machine where the user can still
// point their browser at the proxy by hand. What must never happen is claiming
// it worked.
func TestRunSurvivesASystemMutationFailureAndSaysSo(t *testing.T) {
	t.Parallel()
	mac := newFakeMac()
	mac.failNext("networksetup -setautoproxyurl", 3)
	h := startRun(t, mac, tempLayout(t), "--proxy-style", "pac")

	out := h.out.String()
	if !strings.Contains(out, "!") {
		t.Fatalf("a refused mutation was not reported:\n%s", out)
	}
	if strings.Contains(out, "    - set auto-proxy URL") {
		t.Fatalf("a mutation that failed was listed as applied:\n%s", out)
	}
	// The listener is still serving.
	if body := fetchDirect(t, "http://"+h.addr()+"/dpb.pac"); !strings.Contains(body, "FindProxyForURL") {
		t.Fatalf("the listener died with the failed mutation: %q", body)
	}
}

// --dry-run is the killfuzz subject docs/PLAN.md amendment A6 names. It has to
// bring the whole thing up and mutate nothing.
func TestRunDryRunMutatesNothing(t *testing.T) {
	t.Parallel()
	mac := newFakeMac()
	before := mac.proxySnapshot()
	h := startRun(t, mac, tempLayout(t), "--proxy-style", "both", "--dry-run")

	if after := mac.proxySnapshot(); after != before {
		t.Fatalf("--dry-run changed a setting:\n%s", after)
	}
	if len(mac.environment()) != 0 {
		t.Fatalf("--dry-run exported %v", mac.environment())
	}
	if !strings.Contains(h.out.String(), "--dry-run") {
		t.Fatalf("the banner does not say it was a dry run:\n%s", h.out)
	}
	// It is still a running proxy, which is what makes it a useful fuzz subject.
	if body := fetchDirect(t, "http://"+h.addr()+"/dpb.pac"); !strings.Contains(body, "FindProxyForURL") {
		t.Fatalf("--dry-run did not start the listener: %q", body)
	}
}

// A second run must not clobber the first one's journal and settings.
func TestRunRefusesWhenAnotherRunHoldsTheLock(t *testing.T) {
	t.Parallel()
	mac := newFakeMac()
	layout := tempLayout(t)
	_ = startRun(t, mac, layout, "--proxy-style", "none")

	g := &globals{
		env:    Env{Stdout: io.Discard, Stderr: io.Discard},
		layout: &layout,
		runner: mac,
		rib:    mac,
		facts:  &netstate.Facts{Uplink: "en0"},
		getenv: func(string) string { return "" },
	}
	root := newRoot(g)
	root.SetArgs([]string{"run", "--port", fmt.Sprint(freePort(t)), "--proxy-style", "none"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("a second run started while the first held the lock")
	}
	if !strings.Contains(err.Error(), "lock") {
		t.Fatalf("err = %v, want it to name the lock", err)
	}
}

func TestRunRejectsAnUnsatisfiableStrategyBeforeListening(t *testing.T) {
	t.Parallel()
	mac := newFakeMac()
	layout := tempLayout(t)
	g := &globals{
		env:    Env{Stdout: io.Discard, Stderr: io.Discard},
		layout: &layout,
		runner: mac,
		rib:    mac,
		facts:  &netstate.Facts{},
		getenv: func(string) string { return "" },
	}
	root := newRoot(g)
	root.SetArgs([]string{"run", "--strategy", "fake:size=4", "--proxy-style", "none"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err == nil {
		t.Fatal("a strategy this transport can never emit was accepted")
	}
}

// A flag assigns an enum field directly, bypassing the TOML unmarshaller, so
// the value has to be checked again by Validate. An unrecognised proxy style
// would otherwise make every SetsX predicate false and dpb would start up
// having changed nothing while reporting success.
func TestRunRejectsAnUnknownProxyStyleFlag(t *testing.T) {
	t.Parallel()
	layout := tempLayout(t)
	g := &globals{
		env:    Env{Stdout: io.Discard, Stderr: io.Discard},
		layout: &layout,
		runner: newFakeMac(),
		rib:    newFakeMac(),
		facts:  &netstate.Facts{},
		getenv: func(string) string { return "" },
	}
	root := newRoot(g)
	root.SetArgs([]string{"run", "--proxy-style", "sock", "--port", fmt.Sprint(freePort(t))})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("an unknown --proxy-style started a run")
	}
	if !strings.Contains(err.Error(), "proxy_style") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunRejectsAnUnknownConfigKey(t *testing.T) {
	t.Parallel()
	layout := tempLayout(t)
	if err := os.MkdirAll(layout.ConfigDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(layout.ConfigFile(), []byte("sni_match = \"x\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	g := &globals{
		env:    Env{Stdout: io.Discard, Stderr: io.Discard},
		layout: &layout,
		runner: newFakeMac(),
		rib:    newFakeMac(),
		facts:  &netstate.Facts{},
		getenv: func(string) string { return "" },
	}
	root := newRoot(g)
	root.SetArgs([]string{"run", "--proxy-style", "none"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "sni_match") {
		t.Fatalf("err = %v, want the unknown key named", err)
	}
}

// The banner may print only what happened. A run whose PAC was refused must not
// claim the PAC is set, and a run with --proxy-style none must not imply the
// system was touched.
func TestBannerPrintsOnlyVerifiedFacts(t *testing.T) {
	t.Parallel()
	mac := newFakeMac()
	h := startRun(t, mac, tempLayout(t), "--proxy-style", "none")
	out := h.out.String()

	if !strings.Contains(out, "no system setting was changed") {
		t.Fatalf("the banner does not say the system was untouched:\n%s", out)
	}
	if strings.Contains(out, "auto-proxy") {
		t.Fatalf("the banner claims a proxy setting that was never applied:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf("127.0.0.1:%d", h.port)) {
		t.Fatalf("the banner does not report the bound address:\n%s", out)
	}
	// The ladder is printed with the plain rung named, not as a gap.
	if !strings.Contains(out, "plain → tlsfrag:pos=snimid") {
		t.Fatalf("the banner does not print the ladder:\n%s", out)
	}
	if !strings.Contains(out, "doctor --repair") {
		t.Fatalf("the banner does not say how to recover from a hard kill:\n%s", out)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// newTestOrigin is a loopback HTTP server that names the path it answered.
func newTestOrigin(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "origin answered %s", r.URL.RequestURI())
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// fetchThrough sends an absolute-form request to the proxy, which is what a
// client configured with an HTTP proxy does.
func fetchThrough(t *testing.T, proxyAddr, url string) string {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial the proxy: %v", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	host := strings.TrimPrefix(url, "http://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", url, host)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// fetchDirect fetches a URL from the proxy's own listener, which is how macOS
// fetches the PAC.
func fetchDirect(t *testing.T, url string) string {
	t.Helper()
	rest := strings.TrimPrefix(url, "http://")
	addr, path, _ := strings.Cut(rest, "/")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	fmt.Fprintf(c, "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", path, addr)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// mode = "always" applies a strategy on attempt one instead of waiting for
// evidence. It must never override a hard veto: the ten measured regressors
// stay on plain whatever the mode says.
func TestAlwaysModeForcesOnlyWatchedFlows(t *testing.T) {
	t.Parallel()
	base := fixedScope{
		byName: map[string]policy.Verdict{
			"discord.com":   {Class: policy.ScopeWatch},
			"isbank.com.tr": {Class: policy.ScopeBypass},
			"cached.test":   {Class: policy.ScopeDesync, Spec: "chunk:size=12"},
		},
	}
	s := alwaysScope{Scope: base, spec: "tlsfrag:pos=snimid"}

	if v := s.ForName("discord.com", 443); v.Class != policy.ScopeDesync || v.Spec != "tlsfrag:pos=snimid" {
		t.Fatalf("a watched host was not forced: %+v", v)
	}
	if v := s.ForName("isbank.com.tr", 443); v.Class != policy.ScopeBypass {
		t.Fatalf("mode=always overrode a hard veto: %+v", v)
	}
	if v := s.ForName("cached.test", 443); v.Spec != "chunk:size=12" {
		t.Fatalf("mode=always overwrote a learned winner: %+v", v)
	}
	if v := s.ForAddr(netip.MustParseAddrPort("192.0.2.1:443")); v.Class != policy.ScopeDirect {
		t.Fatalf("ForAddr = %+v", v)
	}
}

func TestForcedSpecPrefersTheExplicitStrategy(t *testing.T) {
	t.Parallel()
	cfg := &config.Loaded{Config: config.Defaults()}
	cfg.Strategy = "oob:pos=1"
	if got := forcedSpec(cfg, []string{"", "tlsfrag:pos=snimid"}); got != "oob:pos=1" {
		t.Fatalf("forcedSpec = %q", got)
	}
	cfg.Strategy = ""
	// Rung 1 is plain by construction, so forcing it would force nothing.
	if got := forcedSpec(cfg, []string{"", "tlsfrag:pos=snimid"}); got != "tlsfrag:pos=snimid" {
		t.Fatalf("forcedSpec = %q", got)
	}
	if got := forcedSpec(cfg, []string{""}); got != "" {
		t.Fatalf("forcedSpec = %q", got)
	}
}

// fixedScope is a policy.Scope with canned answers.
type fixedScope struct{ byName map[string]policy.Verdict }

func (f fixedScope) ForName(host string, _ int) policy.Verdict {
	if v, ok := f.byName[host]; ok {
		return v
	}
	return policy.Verdict{Class: policy.ScopeWatch}
}

func (f fixedScope) ForAddr(netip.AddrPort) policy.Verdict {
	return policy.Verdict{Class: policy.ScopeDirect}
}

func (f fixedScope) Explain(host string) policy.Explanation {
	return policy.Explanation{Input: host}
}

func TestRunReadsABypassFile(t *testing.T) {
	t.Parallel()
	layout := tempLayout(t)
	if err := layout.EnsureDirs(); err != nil {
		t.Fatalf("dirs: %v", err)
	}
	path := filepath.Join(layout.ConfigDir, "extra.txt")
	body := "# hosts my employer blocks anyway\nintranet.example  # trailing comment\n\n203.0.113.0/24\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	h := startRun(t, newFakeMac(), layout, "--proxy-style", "none", "--bypass-file", path)
	pac := fetchDirect(t, "http://"+h.addr()+"/dpb.pac")
	if !strings.Contains(pac, `"intranet.example"`) {
		t.Fatalf("the bypass file's name is not in force:\n%s", pac)
	}
	if !strings.Contains(pac, `isInNet(host, "203.0.113.0", "255.255.255.0")`) {
		t.Fatalf("the bypass file's CIDR is not in force:\n%s", pac)
	}
}

func TestRunRejectsAMissingBypassFile(t *testing.T) {
	t.Parallel()
	layout := tempLayout(t)
	g := &globals{
		env:    Env{Stdout: io.Discard, Stderr: io.Discard},
		layout: &layout,
		runner: newFakeMac(),
		rib:    newFakeMac(),
		facts:  &netstate.Facts{},
		getenv: func(string) string { return "" },
	}
	root := newRoot(g)
	root.SetArgs([]string{"run", "--proxy-style", "none", "--bypass-file", filepath.Join(layout.ConfigDir, "nope")})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.ExecuteContext(context.Background()); err == nil {
		t.Fatal("a missing --bypass-file was ignored")
	}
}

// A listener that dies while running has to reach the command, or `dpb run`
// sits there reporting success with nothing listening.
//
// Both sinks are checked. serveErrs is the test seam; fail is sub.serveErr,
// the channel the production run loop selects on — and it is the one that has
// to work, because serveErrs is nil in every shipped binary.
func TestServeFailureReachesTheCommand(t *testing.T) {
	t.Parallel()
	var errOut bytes.Buffer
	g := &globals{env: Env{Stderr: &errOut}, serveErrs: make(chan error, 1)}
	fail := make(chan error, 1)
	g.serveFailed(fail, errors.New("listener died"))
	for name, ch := range map[string]chan error{"the run loop": fail, "the test seam": g.serveErrs} {
		select {
		case err := <-ch:
			if err == nil || !strings.Contains(err.Error(), "listener died") {
				t.Fatalf("%s got err = %v", name, err)
			}
		default:
			t.Fatalf("the failure never reached %s", name)
		}
	}
	// It is also reported to the user, at a level a default run prints: the
	// process is about to stop and the reason has to be attributable.
	if !strings.Contains(errOut.String(), "listener died") {
		t.Errorf("the failure was not reported to the user:\n%s", errOut.String())
	}
	// A second failure must not block: the first one is the one that matters
	// and the channel is deliberately small.
	g.serveFailed(fail, errors.New("and again"))
	g.serveFailed(nil, errors.New("and with no run loop at all"))
}

// inertSource never reports a routing change.
type inertSource struct{}

func (inertSource) Run(ctx context.Context, _ chan<- struct{}) error {
	<-ctx.Done()
	return nil
}

// inertProber reaches no verdict, which netwatch treats as "keep doing what
// you were doing" rather than as a portal.
type inertProber struct{}

func (inertProber) Probe(context.Context) netwatch.Portal {
	return netwatch.Portal{Err: errors.New("no probe in tests")}
}
