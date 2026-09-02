package cliapp

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/netstate"
	"github.com/mumudevx/dpi-bypass-mac/internal/paths"
	"github.com/mumudevx/dpi-bypass-mac/internal/testnet"
)

// ── a launchd that behaves like the one on this machine ─────────────────────

// launchctl output captured from macOS 26.3.1 on 2026-09-02, from read-only
// `launchctl print` calls against Apple's own jobs. The shapes matter: a loaded
// but idle job prints `state = not running` and NO pid line at all, so code
// that infers "running" from the presence of a pid gets it wrong, and an
// unknown job prints on stdout and exits 113 rather than printing nothing.
const (
	launchctlPrintRunning = `%[1]s = {
	active count = 7
	path = %[2]s
	type = LaunchAgent
	state = running

	program = /opt/homebrew/bin/dpb
	domain = gui/501 [100002]
	runs = 1
	pid = 4242
	immediate reason = speculative
	forks = 0
}
`
	launchctlPrintIdle = `%[1]s = {
	active count = 0
	path = %[2]s
	type = LaunchAgent
	state = not running

	program = /opt/homebrew/bin/dpb
	runs = 0
}
`
	launchctlPrintMissing = "Bad request.\nCould not find service \"" + serviceLabel + "\" in domain for %s"
)

// fakeLaunchd is launchd's job table, driven through testnet.ScriptRunner so
// every argv the command runs is still recorded and assertable.
//
// It is a state machine rather than a set of canned replies because the
// properties worth testing — install is idempotent, stop then start works, a
// bootstrap that fails leaves nothing behind — are properties of the
// transitions, and a canned reply cannot get them wrong.
type fakeJob struct {
	running bool
	plist   string
}

type fakeLaunchd struct {
	*testnet.ScriptRunner

	// jobs is keyed by service target ("gui/501/com.mumudevx.dpb",
	// "system/com.mumudevx.dpb"). launchd's domains are separate registries —
	// a job loaded in a login session is invisible in the system domain — and
	// a fake with one global flag would let `service status --system` report a
	// user agent as a daemon.
	jobs map[string]*fakeJob

	// failEnable / failBootstrap make those verbs report failure while still
	// exiting 0, which is what the netstate liar table exists for.
	failEnable    bool
	failBootstrap bool
	// silentBootstrap exits 0, prints nothing, and loads nothing: the tool
	// must not believe it.
	silentBootstrap bool
	// silentBootout is the same lie for the other direction — bootout exits 0
	// and the job stays loaded.
	silentBootout bool
	// lintFails rejects the generated property list.
	lintFails bool
	// neverRuns loads the job but never lets it reach "running", the way a
	// binary that exits immediately on a taken port behaves.
	neverRuns bool
}

func (f *fakeLaunchd) loaded(target string) bool {
	_, ok := f.jobs[target]
	return ok
}

func (f *fakeLaunchd) running(target string) bool {
	j, ok := f.jobs[target]
	return ok && j.running
}

func newFakeLaunchd() *fakeLaunchd {
	f := &fakeLaunchd{ScriptRunner: testnet.NewScriptRunner(), jobs: map[string]*fakeJob{}}

	// plutil genuinely parses the file, so a plist this code generates with a
	// broken escape fails the test instead of passing it.
	f.OnFunc("plutil -lint", func(argv []string) netstate.Result {
		path := argv[len(argv)-1]
		if f.lintFails {
			return netstate.Result{Combined: path + ": Unexpected character b at line 1", Code: 1}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return netstate.Result{Combined: path + ": " + err.Error(), Code: 1}
		}
		if err := xml.Unmarshal(b, new(struct {
			XMLName xml.Name
			Inner   string `xml:",innerxml"`
		})); err != nil {
			return netstate.Result{Combined: path + ": " + err.Error(), Code: 1}
		}
		return netstate.Result{Combined: path + ": OK"}
	})

	f.OnFunc("launchctl print", func(argv []string) netstate.Result {
		target := argv[2]
		j, ok := f.jobs[target]
		if !ok {
			return netstate.Result{Combined: fmt.Sprintf(launchctlPrintMissing, target), Code: 113}
		}
		tpl := launchctlPrintIdle
		if j.running {
			tpl = launchctlPrintRunning
		}
		return netstate.Result{Combined: fmt.Sprintf(tpl, target, j.plist)}
	})

	f.OnFunc("launchctl enable", func([]string) netstate.Result {
		if f.failEnable {
			return netstate.Result{Combined: "Could not enable service: 150: Operation not permitted while System Integrity Protection is engaged", Code: 150}
		}
		return netstate.Result{}
	})

	f.OnFunc("launchctl bootstrap", func(argv []string) netstate.Result {
		if f.failBootstrap {
			// Exit status ZERO on purpose. netstate's liar table lists
			// `^Bootstrap failed` precisely because launchctl's exit status is
			// not the thing to trust; a test that also returned a non-zero
			// code would pass even if the liar table were deleted.
			return netstate.Result{Combined: "Bootstrap failed: 5: Input/output error"}
		}
		if f.silentBootstrap {
			return netstate.Result{}
		}
		target := argv[2] + "/" + serviceLabel
		if f.loaded(target) {
			return netstate.Result{Combined: "Bootstrap failed: 37: Operation already in progress", Code: 37}
		}
		f.jobs[target] = &fakeJob{running: !f.neverRuns, plist: argv[3]} // RunAtLoad
		return netstate.Result{}
	})

	f.OnFunc("launchctl bootout", func(argv []string) netstate.Result {
		if f.silentBootout {
			return netstate.Result{}
		}
		if !f.loaded(argv[2]) {
			return netstate.Result{Combined: "Boot-out failed: 3: No such process", Code: 113}
		}
		delete(f.jobs, argv[2])
		return netstate.Result{}
	})

	f.OnFunc("launchctl kickstart", func(argv []string) netstate.Result {
		j, ok := f.jobs[argv[2]]
		if !ok {
			return netstate.Result{Combined: fmt.Sprintf(launchctlPrintMissing, argv[2]), Code: 113}
		}
		j.running = !f.neverRuns
		return netstate.Result{}
	})
	return f
}

// ── harness ─────────────────────────────────────────────────────────────────

type serviceHarness struct {
	g       *globals
	mac     *fakeLaunchd
	layout  paths.Layout
	sysRoot string
	exe     string
	out     *bytes.Buffer
}

func newServiceHarness(t *testing.T) *serviceHarness {
	t.Helper()
	layout := tempLayout(t)
	h := &serviceHarness{
		mac:     newFakeLaunchd(),
		layout:  layout,
		sysRoot: t.TempDir(),
		exe:     "/opt/homebrew/bin/dpb",
		out:     &bytes.Buffer{},
	}
	// A real login session has a Library directory; the fake layout's home is
	// a fresh temp dir, so create it the way macOS would.
	if err := os.MkdirAll(filepath.Join(layout.Home, "Library"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.g = &globals{
		env:     Env{Stdout: h.out, Stderr: h.out},
		layout:  &h.layout,
		runner:  h.mac,
		getenv:  func(string) string { return "" },
		exe:     func() (string, error) { return h.exe, nil },
		sysRoot: h.sysRoot,
	}
	return h
}

// elevate makes the layout look like a root process, which is what
// `sudo dpb service install --system` produces.
func (h *serviceHarness) elevate() { h.layout.Elevated = true }

func (h *serviceHarness) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	h.out.Reset()
	root := newRoot(h.g)
	root.SetArgs(append([]string{"service"}, args...))
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.ExecuteContext(context.Background())
	return h.out.String(), err
}

func (h *serviceHarness) agentPlist() string {
	return filepath.Join(h.layout.Home, "Library", "LaunchAgents", serviceLabel+".plist")
}

func (h *serviceHarness) daemonPlist() string {
	return filepath.Join(h.sysRoot, "Library", "LaunchDaemons", serviceLabel+".plist")
}

func (h *serviceHarness) agentTarget() string {
	return "gui/" + strconv.Itoa(h.layout.UID) + "/" + serviceLabel
}

// loaded and running report the state of the LOGIN SESSION's job, which is what
// every test that does not pass --system is about.
func (h *serviceHarness) loaded() bool  { return h.mac.loaded(h.agentTarget()) }
func (h *serviceHarness) running() bool { return h.mac.running(h.agentTarget()) }

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// ── install ─────────────────────────────────────────────────────────────────

func TestServiceInstallWritesThePlistAndLoadsIt(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)

	out, err := h.run(t, "install", "--", "--profile", "turkey", "--port", "8081")
	if err != nil {
		t.Fatalf("service install: %v\n%s", err, out)
	}

	plist := mustRead(t, h.agentPlist())
	for _, want := range []string{
		"<key>Label</key>",
		"<string>" + serviceLabel + "</string>",
		"<string>/opt/homebrew/bin/dpb</string>",
		"<string>run</string>",
		"<string>--profile</string>",
		"<string>turkey</string>",
		"<string>8081</string>",
		"<key>RunAtLoad</key>",
		filepath.Join(h.layout.LogDir, serviceOutLog),
		filepath.Join(h.layout.LogDir, serviceErrLog),
	} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist is missing %q:\n%s", want, plist)
		}
	}
	if !h.loaded() || !h.running() {
		t.Errorf("launchd state after install: loaded=%v running=%v, want both true", h.loaded(), h.running())
	}
	if !strings.Contains(out, "installed") || !strings.Contains(out, h.agentPlist()) {
		t.Errorf("install said nothing useful:\n%s", out)
	}
}

// KeepAlive is a dictionary, not <true/>. A bare <true/> respawns the job after
// a clean exit too, so `dpb panic` — the "get me back to normal now" button —
// would be undone by launchd within ThrottleInterval.
func TestServiceInstallKeepAliveDoesNotRespawnACleanExit(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "install"); err != nil {
		t.Fatalf("service install: %v", err)
	}
	plist := mustRead(t, h.agentPlist())

	var doc struct {
		Dict struct {
			Inner string `xml:",innerxml"`
		} `xml:"dict"`
	}
	if err := xml.Unmarshal([]byte(plist), &doc); err != nil {
		t.Fatalf("plist does not parse: %v\n%s", err, plist)
	}
	i := strings.Index(doc.Dict.Inner, "<key>KeepAlive</key>")
	if i < 0 {
		t.Fatalf("no KeepAlive key:\n%s", plist)
	}
	rest := doc.Dict.Inner[i+len("<key>KeepAlive</key>"):]
	if !strings.Contains(rest[:min(len(rest), 120)], "SuccessfulExit") {
		t.Errorf("KeepAlive is not conditioned on SuccessfulExit:\n%s", plist)
	}
}

// docs/PLAN.md's CLI surface: "launchctl enable / bootout / bootstrap — never
// load -w". load -w silently rewrites launchd's persistent disabled database,
// so a job can end up disabled with nothing recording who did it.
func TestServiceUsesModernLaunchctlVerbsOnly(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, err := h.run(t, "stop"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := h.run(t, "start"); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := h.run(t, "uninstall"); err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	for _, argv := range h.mac.Calls() {
		if argv[0] != "launchctl" {
			continue
		}
		switch argv[1] {
		case "enable", "disable", "bootstrap", "bootout", "kickstart", "print":
		default:
			t.Errorf("deprecated or unreviewed launchctl verb: %v", argv)
		}
		for _, a := range argv {
			if a == "-w" {
				t.Errorf("-w rewrites launchd's persistent disabled database: %v", argv)
			}
		}
	}
}

func TestServiceInstallIsIdempotent(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "install"); err != nil {
		t.Fatalf("first install: %v", err)
	}
	out, err := h.run(t, "install")
	if err != nil {
		t.Fatalf("second install: %v\n%s", err, out)
	}
	if !h.loaded() {
		t.Error("the job is not loaded after reinstalling")
	}
}

func TestServiceInstallRejectsRunFlagsThatWouldNotStart(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)

	out, err := h.run(t, "install", "--", "--port", "eight-thousand")
	var ue usageError
	if !errors.As(err, &ue) {
		t.Fatalf("error = %v (%T), want a usage error\n%s", err, err, out)
	}
	if _, statErr := os.Stat(h.agentPlist()); statErr == nil {
		t.Error("a plist was written for a command line dpb run would reject")
	}
	if len(h.mac.Calls()) != 0 {
		t.Errorf("launchd was touched before the flags were checked: %v", h.mac.Calls())
	}
}

func TestServiceInstallRejectsPositionalArgsForRun(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "install", "--", "discord.com"); !errors.As(err, new(usageError)) {
		t.Fatalf("error = %v, want a usage error", err)
	}
}

// A bootstrap failure must leave nothing behind. A plist with RunAtLoad that
// survives a failed install is loaded at the next login anyway, so the user is
// told the install failed and then gets the job regardless.
func TestServiceInstallRollsBackWhenBootstrapFails(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	h.mac.failBootstrap = true

	_, err := h.run(t, "install")
	if err == nil {
		t.Fatal("install reported success after a failed bootstrap")
	}
	if !strings.Contains(err.Error(), "Bootstrap failed") {
		t.Errorf("error does not name the failure: %v", err)
	}
	if _, statErr := os.Stat(h.agentPlist()); statErr == nil {
		t.Error("the plist survived a failed install")
	}
}

func TestServiceInstallRollsBackWhenEnableFails(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	h.mac.failEnable = true

	if _, err := h.run(t, "install"); err == nil {
		t.Fatal("install reported success after a failed enable")
	}
	if _, err := os.Stat(h.agentPlist()); err == nil {
		t.Error("the plist survived a failed install")
	}
	if h.mac.Ran("launchctl bootstrap") {
		t.Error("bootstrap was attempted after enable failed")
	}
}

// The install is judged on what launchd admits to knowing, not on launchctl's
// exit status. This is the same rule netstate applies to route(8).
func TestServiceInstallDisbelievesASilentBootstrap(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	h.mac.silentBootstrap = true

	_, err := h.run(t, "install")
	if err == nil {
		t.Fatal("install believed a bootstrap that exited 0 and loaded nothing")
	}
	if !strings.Contains(err.Error(), "does not know the job") {
		t.Errorf("error = %v, want it to say launchd does not know the job", err)
	}
	if _, statErr := os.Stat(h.agentPlist()); statErr == nil {
		t.Error("the plist survived an install launchd did not honour")
	}
}

func TestServiceInstallSystemNeedsRoot(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)

	_, err := h.run(t, "install", "--system")
	var ce codedError
	if !errors.As(err, &ce) {
		t.Fatalf("error = %v (%T), want a coded error", err, err)
	}
	if ce.ExitCode() != ExitNeedRoot {
		t.Errorf("exit code = %d, want %d (needs root)", ce.ExitCode(), ExitNeedRoot)
	}
	if _, statErr := os.Stat(h.daemonPlist()); statErr == nil {
		t.Error("a LaunchDaemon plist was written without root")
	}
}

// A LaunchDaemon runs as root with no SUDO_USER, so paths.Resolve() inside it
// returns the machine-wide layout. Pointing its stdout at the invoking user's
// ~/Library/Logs would split the daemon's own event log from the output launchd
// captures for it.
func TestServiceInstallSystemUsesTheMachineWideLocations(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	h.elevate()

	out, err := h.run(t, "install", "--system")
	if err != nil {
		t.Fatalf("install --system: %v\n%s", err, out)
	}
	plist := mustRead(t, h.daemonPlist())
	wantLog := filepath.Join(h.sysRoot, "Library", "Logs", "dpb", serviceOutLog)
	if !strings.Contains(plist, wantLog) {
		t.Errorf("daemon plist does not log to %s:\n%s", wantLog, plist)
	}
	if strings.Contains(plist, h.layout.LogDir) {
		t.Errorf("daemon plist logs into the invoking user's log directory:\n%s", plist)
	}
	if !h.mac.Ran("launchctl bootstrap system") {
		t.Errorf("did not bootstrap into the system domain: %v", h.mac.Calls())
	}
	// The coverage caveat has to be visible where the user makes the choice.
	if !strings.Contains(out, "system domain") {
		t.Errorf("install --system did not warn about the launchd domain:\n%s", out)
	}
}

func TestServiceInstallRefusesWithNoLoginSession(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	// Root with no SUDO_USER: paths returns the system layout, which has no
	// home directory, so there is no gui/<uid> domain to install into.
	h.layout.Home = ""
	h.layout.System = true
	h.layout.Elevated = true

	if _, err := h.run(t, "install"); !errors.As(err, new(usageError)) {
		t.Fatalf("error = %v, want a usage error naming --system", err)
	}
}

func TestServiceInstallFailsWhenTheBinaryCannotBeLocated(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	h.g.exe = func() (string, error) { return "", errors.New("no such process") }

	if _, err := h.run(t, "install"); err == nil {
		t.Fatal("install wrote a plist with no program path")
	}
	if len(h.mac.Calls()) != 0 {
		t.Errorf("launchd was touched anyway: %v", h.mac.Calls())
	}
}

// ── the plist itself ────────────────────────────────────────────────────────

func TestServicePlistEscapesTheHomeDirectory(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	// Legal in a macOS user name, and fatal to an unescaped XML document.
	h.layout.LogDir = filepath.Join(h.layout.Home, "Ben & Co", "Logs")

	if _, err := h.run(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}
	plist := mustRead(t, h.agentPlist())
	if strings.Contains(plist, "Ben & Co") {
		t.Error("the ampersand reached the plist unescaped")
	}
	if !strings.Contains(plist, "Ben &amp; Co") {
		t.Errorf("the log path is not in the plist at all:\n%s", plist)
	}
	if err := xml.Unmarshal([]byte(plist), new(struct {
		XMLName xml.Name
		Inner   string `xml:",innerxml"`
	})); err != nil {
		t.Errorf("plist does not parse: %v", err)
	}
}

// The generated plist is handed to the real plutil(1) — the same reader launchd
// uses. A fake that parses XML cannot tell us the DOCTYPE and plist envelope
// are acceptable; this can. Read-only: it lints a file in a temp directory.
func TestServicePlistPassesRealPlutil(t *testing.T) {
	t.Parallel()
	plutil, err := exec.LookPath("plutil")
	if err != nil {
		t.Skipf("no plutil on this machine: %v", err)
	}
	s := serviceScope{
		system: false,
		domain: "gui/501",
		outLog: "/Users/ben & co/Library/Logs/dpb/" + serviceOutLog,
		errLog: "/Users/ben & co/Library/Logs/dpb/" + serviceErrLog,
	}
	path := filepath.Join(t.TempDir(), serviceLabel+".plist")
	body := servicePlist([]string{"/opt/homebrew/bin/dpb", "run", "--profile", "turkey"}, s)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(plutil, "-lint", path).CombinedOutput()
	if err != nil {
		t.Fatalf("plutil -lint rejected the generated plist: %v\n%s\n%s", err, out, body)
	}
}

// ── status ──────────────────────────────────────────────────────────────────

// PLAN's M14 acceptance clause is `sudo dpb service install --system && dpb
// service status` — with no --system on the status call. Status therefore has
// to look in both domains, and reading the system domain needs no privilege.
func TestServiceStatusFindsTheSystemDaemonWithoutTheFlag(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	h.elevate()
	if _, err := h.run(t, "install", "--system"); err != nil {
		t.Fatalf("install --system: %v", err)
	}

	h.layout.Elevated = false // status is run back as the ordinary user
	out, err := h.run(t, "status")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if !strings.Contains(out, "system daemon") || !strings.Contains(out, "running") {
		t.Errorf("status did not report the running daemon:\n%s", out)
	}
	if !strings.Contains(out, "pid      4242") {
		t.Errorf("status did not report the pid:\n%s", out)
	}
}

func TestServiceStatusIsNonZeroWhenNotInstalled(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)

	out, err := h.run(t, "status")
	if err == nil {
		t.Fatalf("status exited 0 with nothing installed:\n%s", out)
	}
	if !strings.Contains(out, "not installed") {
		t.Errorf("status did not say it is not installed:\n%s", out)
	}
}

// Installed but unloaded is a real state and must not read as healthy: a script
// that trusts the exit code should keep dpb out of the path.
func TestServiceStatusIsNonZeroWhenInstalledButStopped(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, err := h.run(t, "stop"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	out, err := h.run(t, "status")
	if err == nil {
		t.Fatalf("status exited 0 for a stopped job:\n%s", out)
	}
	if !strings.Contains(out, "not loaded") {
		t.Errorf("status did not report the job as unloaded:\n%s", out)
	}
}

// ── start / stop ────────────────────────────────────────────────────────────

func TestServiceStopUnloadsAndStartLoadsAgain(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}

	out, err := h.run(t, "stop")
	if err != nil {
		t.Fatalf("stop: %v\n%s", err, out)
	}
	if h.loaded() {
		t.Error("the job is still loaded after stop")
	}
	if _, statErr := os.Stat(h.agentPlist()); statErr != nil {
		t.Error("stop deleted the plist; that is uninstall's job")
	}

	out, err = h.run(t, "start")
	if err != nil {
		t.Fatalf("start: %v\n%s", err, out)
	}
	if !h.loaded() || !h.running() {
		t.Errorf("after start: loaded=%v running=%v", h.loaded(), h.running())
	}
}

func TestServiceStartWithoutAnInstallSaysSo(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)

	_, err := h.run(t, "start")
	if err == nil {
		t.Fatal("start reported success with nothing installed")
	}
	if !strings.Contains(err.Error(), "not installed") {
		t.Errorf("error = %v, want it to say the job is not installed", err)
	}
	if len(h.mac.Calls()) != 0 {
		t.Errorf("launchd was touched for a job that does not exist: %v", h.mac.Calls())
	}
}

// ── uninstall ───────────────────────────────────────────────────────────────

func TestServiceUninstallRemovesBothTheJobAndThePlist(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}

	out, err := h.run(t, "uninstall")
	if err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	if h.loaded() {
		t.Error("the job is still loaded")
	}
	if _, statErr := os.Stat(h.agentPlist()); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the plist is still there: %v", statErr)
	}
}

// bootout on a job that is not loaded exits 113 with "Boot-out failed: 3: No
// such process". That is the state uninstall wants, not a failure.
func TestServiceUninstallToleratesAnAlreadyUnloadedJob(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, err := h.run(t, "stop"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := h.run(t, "uninstall"); err != nil {
		t.Fatalf("uninstall after stop: %v", err)
	}
}

func TestServiceUninstallOfNothingIsNotAnError(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "uninstall"); err != nil {
		t.Fatalf("uninstall with nothing installed: %v", err)
	}
}

// If launchd still has the job after bootout, saying "removed" would be a lie
// the user only discovers at the next reboot.
func TestServiceUninstallReportsAJobItCouldNotUnload(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}
	// A bootout that exits 0 and unloads nothing.
	h.mac.silentBootout = true

	_, err := h.run(t, "uninstall")
	if err == nil {
		t.Fatal("uninstall claimed success while the job was still loaded")
	}
	if !strings.Contains(err.Error(), "still loaded") {
		t.Errorf("error = %v, want it to say the job is still loaded", err)
	}
}

// ── logs ────────────────────────────────────────────────────────────────────

func TestServiceLogsTailsBothStreams(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if err := os.MkdirAll(h.layout.LogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for i := 1; i <= 10; i++ {
		lines = append(lines, fmt.Sprintf("out line %d", i))
	}
	if err := os.WriteFile(filepath.Join(h.layout.LogDir, serviceOutLog),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.layout.LogDir, serviceErrLog),
		[]byte("refused: a VPN owns the default route\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := h.run(t, "logs", "-n", "3")
	if err != nil {
		t.Fatalf("logs: %v\n%s", err, out)
	}
	if strings.Contains(out, "out line 7") || !strings.Contains(out, "out line 8") {
		t.Errorf("-n 3 did not tail three lines:\n%s", out)
	}
	if !strings.Contains(out, "a VPN owns the default route") {
		t.Errorf("stderr was not printed:\n%s", out)
	}
}

// launchd creates these files on the job's first write, so their absence is the
// normal state before the job has ever run, not a failure.
func TestServiceLogsWithNoFilesYetIsNotAnError(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)

	out, err := h.run(t, "logs")
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
	if !strings.Contains(out, "no such file") {
		t.Errorf("logs did not explain the missing files:\n%s", out)
	}
}

func TestServiceLogsRejectsANonPositiveCount(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "logs", "-n", "0"); !errors.As(err, new(usageError)) {
		t.Fatalf("error = %v, want a usage error", err)
	}
}

func TestTailLines(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"", 5, ""},
		{"\n\n", 5, ""},
		{"a\nb\nc\n", 2, "b\nc"},
		{"a\nb\nc", 5, "a\nb\nc"},
		{"only\n", 1, "only"},
	} {
		if got := tailLines(tc.in, tc.n); got != tc.want {
			t.Errorf("tailLines(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

// ── parsing launchctl print ─────────────────────────────────────────────────

func TestServiceStateOfReadsRealLaunchctlOutput(t *testing.T) {
	t.Parallel()
	s := serviceScope{domain: "gui/501"}

	for _, tc := range []struct {
		name string
		res  netstate.Result
		want serviceState
	}{
		{
			name: "running",
			res:  netstate.Result{Combined: fmt.Sprintf(launchctlPrintRunning, s.target(), "/x.plist")},
			want: serviceState{loaded: true, running: true, state: "running", pid: 4242},
		},
		{
			// The pid line is absent, and "not running" contains the word
			// "running": a substring test on the body gets this backwards.
			name: "loaded but idle",
			res:  netstate.Result{Combined: fmt.Sprintf(launchctlPrintIdle, s.target(), "/x.plist")},
			want: serviceState{loaded: true, running: false, state: "not running"},
		},
		{
			name: "unknown job",
			res:  netstate.Result{Combined: fmt.Sprintf(launchctlPrintMissing, s.target()), Code: 113},
			want: serviceState{},
		},
		{
			// launchctl absent or unrunnable. Anything we cannot read is "not
			// loaded", which is the conservative answer for every caller.
			name: "launchctl could not run",
			res:  netstate.Result{Err: errors.New("exec: launchctl: not found")},
			want: serviceState{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := testnet.NewScriptRunner()
			r.On("launchctl print", tc.res)
			got := serviceStateOf(context.Background(), r, s)
			if got != tc.want {
				t.Errorf("serviceStateOf = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestServiceStateDescribe(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		st   serviceState
		want string
	}{
		{serviceState{}, "not loaded"},
		{serviceState{loaded: true}, "loaded"},
		{serviceState{loaded: true, state: "not running"}, "not running"},
		{serviceState{loaded: true, running: true, state: "running"}, "running"},
	} {
		if got := tc.st.describe(); got != tc.want {
			t.Errorf("%+v.describe() = %q, want %q", tc.st, got, tc.want)
		}
	}
}

// ── scope resolution ────────────────────────────────────────────────────────

func TestServiceScopeTargets(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	h.layout.UID = 501

	agent, err := h.g.serviceScopeFor(false)
	if err != nil {
		t.Fatal(err)
	}
	if agent.target() != "gui/501/"+serviceLabel {
		t.Errorf("agent target = %q", agent.target())
	}
	if agent.domain != "gui/501" {
		t.Errorf("agent domain = %q, want the gui domain of the invoking user", agent.domain)
	}

	daemon, err := h.g.serviceScopeFor(true)
	if err != nil {
		t.Fatal(err)
	}
	if daemon.target() != "system/"+serviceLabel {
		t.Errorf("daemon target = %q", daemon.target())
	}
	if daemon.plist != h.daemonPlist() {
		t.Errorf("daemon plist = %q, want %q", daemon.plist, h.daemonPlist())
	}
}

// ── the plist is checked before launchd ever sees it ────────────────────────

// launchd's report for an unparseable plist is "Bootstrap failed: 5:
// Input/output error", which says nothing about the file. plutil is asked
// first so the failure is legible and nothing is left on disk.
func TestServiceInstallStopsWhenTheGeneratedPlistDoesNotLint(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	h.mac.lintFails = true

	_, err := h.run(t, "install")
	if err == nil {
		t.Fatal("install handed launchd a plist plutil had rejected")
	}
	if !strings.Contains(err.Error(), "not valid") {
		t.Errorf("error = %v, want it to name the invalid property list", err)
	}
	if _, statErr := os.Stat(h.agentPlist()); statErr == nil {
		t.Error("the rejected plist was left on disk")
	}
	for _, argv := range h.mac.Calls() {
		if argv[0] == "launchctl" {
			t.Errorf("launchd was touched after the lint failed: %v", argv)
		}
	}
}

// ── start and stop report what actually happened ────────────────────────────

// A job that loads and then dies immediately — a port already taken, a config
// file that no longer parses — must not be reported as started.
func TestServiceStartRefusesToClaimAJobThatIsNotRunning(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, err := h.run(t, "stop"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	h.mac.neverRuns = true // loads, but never reaches "running"

	_, err := h.run(t, "start")
	if err == nil {
		t.Fatal("start claimed success for a job that is loaded but not running")
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Errorf("error = %v, want it to say the job is not running", err)
	}
}

func TestServiceStopReportsAJobItCouldNotUnload(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}
	h.mac.silentBootout = true

	if _, err := h.run(t, "stop"); err == nil {
		t.Fatal("stop claimed success while the job was still loaded")
	}
}

// ── status pinned to one domain ─────────────────────────────────────────────

// With --system, status reports only the system domain — so an agent running
// in the login session cannot make a missing daemon look installed.
func TestServiceStatusWithSystemIgnoresTheUserAgent(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}
	out, err := h.run(t, "status", "--system")
	if err == nil {
		t.Fatalf("status --system exited 0 with only a user agent installed:\n%s", out)
	}
	if !strings.Contains(out, "not installed") {
		t.Errorf("status --system did not report the daemon as absent:\n%s", out)
	}
}

// A job launchd still knows about whose plist has been deleted will not come
// back at the next login; status has to say so rather than print a path that
// does not exist.
func TestServiceStatusFlagsALoadedJobWithNoPlist(t *testing.T) {
	t.Parallel()
	h := newServiceHarness(t)
	if _, err := h.run(t, "install"); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := os.Remove(h.agentPlist()); err != nil {
		t.Fatal(err)
	}
	out, err := h.run(t, "status")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if !strings.Contains(out, "(missing)") {
		t.Errorf("status did not flag the missing plist:\n%s", out)
	}
}
