package cliapp

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/observ"
)

// findCheck returns one audited check by name.
func findCheck(t *testing.T, rep doctorReport, name string) check {
	t.Helper()
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check named %q in %+v", name, rep.Checks)
	return check{}
}

func doctorJSON(t *testing.T, c *cli, args ...string) (doctorReport, result) {
	t.Helper()
	r := c.exec(t, append([]string{"doctor", "--json"}, args...)...)
	var rep doctorReport
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("decode doctor JSON: %v\n%s%s", err, r.stdout, r.stderr)
	}
	return rep, r
}

func TestDoctorOnACleanMachine(t *testing.T) {
	c := newCLI(t)
	rep, r := doctorJSON(t, c)
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	if rep.Failed != 0 {
		t.Fatalf("a clean machine failed %d check(s): %+v", rep.Failed, rep.Checks)
	}
	for _, name := range []string{
		"paths", "config", "strategies", "run lock", "control socket",
		"journal", "system proxy", "proxy environment", "verdict cache", "tuned profile",
	} {
		findCheck(t, rep, name)
	}
}

// The DNS check is the only one that uses the network, so it must be absent
// without --full. A `dpb doctor` that quietly resolved a name would be a
// diagnostic that cannot be run on a broken line.
func TestDoctorDoesNotTouchTheNetworkWithoutFull(t *testing.T) {
	c := newCLI(t)
	rep, _ := doctorJSON(t, c)
	for _, ch := range rep.Checks {
		if ch.Name == "dns" {
			t.Fatal("the DNS check ran without --full")
		}
	}
}

// The highest-value diagnosis in the tool: macOS is pointed at a dpb that is
// not there. A PAC URL fails OPEN, so it is a warning; an explicit secure proxy
// fails CLOSED into a total outage, so it is a failure and exit code 3.
func TestDoctorFindsAProxyPointingAtADeadDPB(t *testing.T) {
	t.Run("pac residue is a warning", func(t *testing.T) {
		c := newCLI(t)
		c.mac.Run(t.Context(), "networksetup", "-setautoproxyurl", "Wi-Fi", "http://127.0.0.1:8080/dpb.pac")

		rep, r := doctorJSON(t, c)
		ch := findCheck(t, rep, "system proxy")
		if ch.State != stateWarn {
			t.Fatalf("state = %q, want warn: %+v", ch.State, ch)
		}
		if !strings.Contains(ch.Detail, "not running") {
			t.Errorf("detail = %q", ch.Detail)
		}
		if !strings.Contains(ch.Remedy, "doctor --repair") {
			t.Errorf("remedy = %q, want it to name the command that fixes it", ch.Remedy)
		}
		if r.code != ExitOK {
			t.Errorf("exit code = %d; PAC residue fails open and must not be fatal", r.code)
		}
	})

	t.Run("an explicit proxy is a failure", func(t *testing.T) {
		c := newCLI(t)
		c.mac.Run(t.Context(), "networksetup", "-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "8080")

		rep, r := doctorJSON(t, c)
		ch := findCheck(t, rep, "system proxy")
		if ch.State != stateFail {
			t.Fatalf("state = %q, want fail: %+v", ch.State, ch)
		}
		if !strings.Contains(ch.Detail, "fails CLOSED") {
			t.Errorf("detail = %q, want it to say the outage is total", ch.Detail)
		}
		if r.code != ExitDoctor {
			t.Errorf("exit code = %d, want %d", r.code, ExitDoctor)
		}
	})
}

// The launchd half of the coverage story. GT24: an in-process reqwest addon
// reads only these variables, so residue here is invisible in the proxy pane
// and total for the programs that read it.
func TestDoctorFindsStaleProxyEnvironment(t *testing.T) {
	c := newCLI(t)
	c.mac.Run(t.Context(), "launchctl", "setenv", "HTTPS_PROXY", "http://127.0.0.1:8080")

	rep, r := doctorJSON(t, c)
	ch := findCheck(t, rep, "proxy environment")
	if ch.State != stateFail {
		t.Fatalf("state = %q, want fail: %+v", ch.State, ch)
	}
	if !strings.Contains(ch.Detail, "HTTPS_PROXY") {
		t.Errorf("detail = %q, want it to name the variable", ch.Detail)
	}
	if r.code != ExitDoctor {
		t.Errorf("exit code = %d, want %d", r.code, ExitDoctor)
	}
}

// A proxy that points somewhere else is the USER'S, not ours. Reporting it as
// residue would send them to delete their own corporate proxy.
func TestDoctorLeavesAnOffMachineProxyAlone(t *testing.T) {
	c := newCLI(t)
	c.mac.Run(t.Context(), "networksetup", "-setsecurewebproxy", "Wi-Fi", "proxy.corp.example", "3128")

	rep, r := doctorJSON(t, c)
	ch := findCheck(t, rep, "system proxy")
	if ch.State != stateOK {
		t.Fatalf("state = %q, want ok: %+v", ch.State, ch)
	}
	if r.code != ExitOK {
		t.Errorf("exit code = %d", r.code)
	}
}

// Unfinished journal records are a failure with a named remedy: they are
// changes sitting on the machine right now that nothing else will undo.
func TestDoctorReportsJournalResidue(t *testing.T) {
	c := newCLI(t)
	seedPendingPAC(t, c.layout, deadPID)

	rep, r := doctorJSON(t, c)
	ch := findCheck(t, rep, "journal")
	if ch.State != stateFail {
		t.Fatalf("state = %q, want fail: %+v", ch.State, ch)
	}
	if !strings.Contains(ch.Remedy, "doctor --repair") {
		t.Errorf("remedy = %q", ch.Remedy)
	}
	if r.code != ExitDoctor {
		t.Errorf("exit code = %d, want %d", r.code, ExitDoctor)
	}
}

// This is the clause the milestone turns on: --repair replays the journal, the
// mutation is undone, and the journal file ends up empty.
func TestDoctorRepairUndoesWhatACrashLeftBehind(t *testing.T) {
	c := newCLI(t)
	pacPath := seedPendingPAC(t, c.layout, deadPID)
	if _, err := os.Stat(pacPath); err != nil {
		t.Fatalf("the fixture mutation was not applied: %v", err)
	}

	rep, r := doctorJSON(t, c, "--repair")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !rep.Repair.Ran || rep.Repair.Pending != 1 || len(rep.Repair.Reverted) != 1 {
		t.Fatalf("repair = %+v", rep.Repair)
	}
	if _, err := os.Stat(pacPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the PAC file survived the repair: %v", err)
	}

	// The journal file must end up EMPTY, not merely logically drained: `dpb
	// status` and the janitor both read its size as the answer to "is anything
	// outstanding".
	fi, err := os.Stat(c.layout.JournalFile())
	if err != nil {
		t.Fatalf("stat journal: %v", err)
	}
	if fi.Size() != 0 {
		b, _ := os.ReadFile(c.layout.JournalFile())
		t.Fatalf("the journal is %d bytes after repair:\n%s", fi.Size(), b)
	}

	// And the audit printed afterwards must describe the REPAIRED machine. A
	// doctor that repairs and then prints the pre-repair state teaches the user
	// to distrust it.
	if ch := findCheck(t, rep, "journal"); ch.State != stateOK {
		t.Fatalf("the post-repair journal check = %+v", ch)
	}
}

// A record whose owner is still running is left alone, so `dpb doctor --repair`
// is safe to type while a dpb is up.
func TestDoctorRepairSkipsALiveOwnersRecords(t *testing.T) {
	c := newCLI(t)
	pacPath := seedPendingPAC(t, c.layout, os.Getpid())

	rep, r := doctorJSON(t, c, "--repair")
	if len(rep.Repair.Reverted) != 0 || len(rep.Repair.Skipped) != 1 {
		t.Fatalf("repair = %+v, want the record skipped", rep.Repair)
	}
	if _, err := os.Stat(pacPath); err != nil {
		t.Fatalf("a live owner's PAC file was removed: %v", err)
	}
	// The record is still pending, so the journal check still reports it — but
	// as held by a live dpb rather than as residue.
	ch := findCheck(t, rep, "journal")
	if ch.State != stateOK || !strings.Contains(ch.Detail, "running dpb") {
		t.Fatalf("journal check = %+v", ch)
	}
	if r.code != ExitOK {
		t.Errorf("exit code = %d", r.code)
	}
}

func TestDoctorRepairOnAnEmptyJournalSaysSo(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "doctor", "--repair")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "already empty") {
		t.Errorf("output:\n%s", r.stdout)
	}
}

// --quiet is what the login LaunchAgent runs. A repair that found nothing must
// say nothing at all, or every login writes a log nobody reads.
func TestDoctorQuietIsSilentWhenThereIsNothingToSay(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "doctor", "--repair", "--quiet")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	if strings.TrimSpace(r.stdout) != "" {
		t.Fatalf("--quiet printed on a clean machine:\n%s", r.stdout)
	}
}

func TestDoctorQuietStillPrintsFailures(t *testing.T) {
	c := newCLI(t)
	c.mac.Run(t.Context(), "networksetup", "-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "8080")
	r := c.exec(t, "doctor", "--quiet")
	if r.code != ExitDoctor {
		t.Fatalf("exit code = %d, want %d", r.code, ExitDoctor)
	}
	if !strings.Contains(r.stdout, "FAIL") {
		t.Fatalf("--quiet swallowed a failure:\n%s", r.stdout)
	}
}

// The capability report is validation gate 3 as a diagnostic: a ladder this
// transport cannot emit must be named as a failure, with the command that
// explains why.
func TestDoctorReportsAnUnsatisfiableLadder(t *testing.T) {
	c := newCLI(t)
	cfgPath := c.layout.ConfigFile()
	if err := os.WriteFile(cfgPath, []byte("ladder = \"seqovl:pos=1\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	rep, r := doctorJSON(t, c)
	ch := findCheck(t, rep, "strategies")
	if ch.State != stateFail {
		t.Fatalf("state = %q, want fail: %+v", ch.State, ch)
	}
	if r.code != ExitDoctor {
		t.Errorf("exit code = %d, want %d", r.code, ExitDoctor)
	}
}

func TestDoctorReportsAnUnloadableConfig(t *testing.T) {
	c := newCLI(t)
	if err := os.WriteFile(c.layout.ConfigFile(), []byte("sni_match = true\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	rep, r := doctorJSON(t, c)
	ch := findCheck(t, rep, "config")
	if ch.State != stateFail {
		t.Fatalf("state = %q, want fail: %+v", ch.State, ch)
	}
	if !strings.Contains(ch.Detail, "sni_match") {
		t.Errorf("detail = %q, want it to name the offending key", ch.Detail)
	}
	if r.code != ExitDoctor {
		t.Errorf("exit code = %d, want %d", r.code, ExitDoctor)
	}
}

// A dpb holding the run lock with an unreachable control socket is a real and
// distinct state: the process is up but nothing can talk to it.
func TestDoctorReportsALiveRunWithNoSocket(t *testing.T) {
	c := newCLI(t)
	lock, err := netstate.AcquireLock(c.layout.LockFile())
	if err != nil {
		t.Fatalf("acquire lock: %v", err)
	}
	defer lock.Release()

	rep, _ := doctorJSON(t, c)
	if ch := findCheck(t, rep, "run lock"); !strings.Contains(ch.Detail, "live dpb") {
		t.Fatalf("run lock check = %+v", ch)
	}
	ch := findCheck(t, rep, "control socket")
	if ch.State != stateWarn {
		t.Fatalf("control socket check = %+v", ch)
	}
}

func TestDoctorSeesTheControlSocket(t *testing.T) {
	c := newCLI(t)
	startControl(t, c.layout, observ.Handler{})
	rep, _ := doctorJSON(t, c)
	ch := findCheck(t, rep, "control socket")
	if ch.State != stateOK || !strings.Contains(ch.Detail, "answering") {
		t.Fatalf("control socket check = %+v", ch)
	}
}

func TestDoctorRejectsContradictoryAgentFlags(t *testing.T) {
	c := newCLI(t)
	if r := c.exec(t, "doctor", "--install-agent", "--remove-agent"); r.code != ExitUsage {
		t.Fatalf("exit code = %d, want %d", r.code, ExitUsage)
	}
}

// The LaunchAgent plist must name the repair command and use RunAtLoad with no
// KeepAlive: run once per login, exit, never be restarted.
func TestAgentPlistShape(t *testing.T) {
	p := agentPlist("/usr/local/bin/dpb", "/tmp/repair.log")
	for _, want := range []string{
		"<string>" + AgentLabel + "</string>",
		"<string>/usr/local/bin/dpb</string>",
		"<string>doctor</string>",
		"<string>--repair</string>",
		"<string>--quiet</string>",
		"<key>RunAtLoad</key>\n\t<true/>",
		"<key>KeepAlive</key>\n\t<false/>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("the plist does not contain %q:\n%s", want, p)
		}
	}
	// A path with an ampersand in it must not produce invalid XML: launchd
	// would refuse the plist and the backstop would silently not exist.
	if got := agentPlist("/Users/a&b/dpb", "/tmp/l"); !strings.Contains(got, "a&amp;b") {
		t.Errorf("the executable path was not XML-escaped:\n%s", got)
	}
}

func TestIsLoopbackTarget(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.1:8080", true},
		{"http://127.0.0.1:8080/dpb.pac", true},
		{"localhost", true},
		{"http://localhost:8080/dpb.pac", true},
		{"[::1]:8080", true},
		{"::1", true},
		{"127.53.1.9", true},
		// Somebody else's proxy. Reporting it as our residue would send the user
		// to delete their own corporate configuration.
		{"proxy.corp.example:3128", false},
		{"http://proxy.corp.example/proxy.pac", false},
		{"10.0.0.1:3128", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isLoopbackTarget(tc.in); got != tc.want {
			t.Errorf("isLoopbackTarget(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// The DNS check is the only one that touches the network, and its job is to
// distinguish "this resolver is broken" from "every transport here is
// poisoned". Pointing the chain at a loopback port nothing is bound to keeps
// the whole exchange on this machine while still exercising the real chain.
func TestDoctorFullReportsABrokenResolverChain(t *testing.T) {
	c := newCLI(t)
	cfg := "[dns]\nchain = \"custom\"\nper_try = \"200ms\"\n\n" +
		"[[dns.endpoint]]\nlabel = \"dead\"\ntransport = \"udp\"\ntarget = \"127.0.0.1:1\"\n"
	if err := os.WriteFile(c.layout.ConfigFile(), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	rep, r := doctorJSON(t, c, "--full")
	ch := findCheck(t, rep, "dns")
	if ch.State != stateFail {
		t.Fatalf("a chain with one dead resolver = %+v", ch)
	}
	if !strings.Contains(ch.Detail, doctorControlName) {
		t.Errorf("detail = %q, want it to name the control it tried", ch.Detail)
	}
	if ch.Remedy == "" {
		t.Error("the DNS failure carries no remedy")
	}
	if r.code != ExitDoctor {
		t.Errorf("exit code = %d, want %d", r.code, ExitDoctor)
	}
}

// A resolver chain that cannot even be built is a configuration failure, not a
// network one, and must be reported as such without a single packet.
func TestDoctorFullReportsAnUnbuildableChain(t *testing.T) {
	c := newCLI(t)
	cfg := "[dns]\nchain = \"custom\"\n\n" +
		"[[dns.endpoint]]\nlabel = \"bad\"\ntransport = \"udp\"\ntarget = \"not-an-address\"\n"
	if err := os.WriteFile(c.layout.ConfigFile(), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	rep, _ := doctorJSON(t, c, "--full")
	// Either the config layer rejects it or the chain builder does; both are
	// failures with a name, and neither is allowed to be a silent pass.
	dns, cfgCheck := checkOrZero(rep, "dns"), findCheck(t, rep, "config")
	if dns.State != stateFail && cfgCheck.State != stateFail {
		t.Fatalf("an unbuildable resolver chain was not reported: dns=%+v config=%+v", dns, cfgCheck)
	}
}

func checkOrZero(rep doctorReport, name string) check {
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	return check{}
}

// The login LaunchAgent is defence (c) of docs/PLAN.md's four against SIGKILL.
// Installing it writes a plist into the INVOKING USER's LaunchAgents directory
// and bootstraps it with the modern verbs; both halves are driven here against
// a fake launchd and a temporary home.
func TestInstallAgentWritesThePlistAndUsesModernVerbs(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "doctor", "--install-agent")

	path := agentPath(c.layout)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the plist was not written to %s: %v", path, err)
	}
	if !strings.Contains(string(b), AgentLabel) {
		t.Errorf("the plist does not carry the label:\n%s", b)
	}

	calls := strings.Join(c.mac.callsMatching("launchctl"), "\n")
	if !strings.Contains(calls, "launchctl bootstrap gui/") {
		t.Errorf("bootstrap was not used:\n%s", calls)
	}
	if strings.Contains(calls, "launchctl load") {
		t.Errorf("the deprecated `load -w` was used:\n%s", calls)
	}
	// The fake launchd does not implement bootstrap, so the command reports the
	// failure rather than claiming success — which is the behaviour that
	// matters: an agent that was never loaded must not be reported as installed.
	if r.code == ExitOK {
		t.Errorf("a failed bootstrap was reported as success:\n%s", r.stdout)
	}
}

func TestRemoveAgentDeletesThePlist(t *testing.T) {
	c := newCLI(t)
	path := agentPath(c.layout)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(agentPlist("/bin/true", "/tmp/l")), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	r := c.exec(t, "doctor", "--remove-agent")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the plist survived: %v", err)
	}
	// bootout is best effort — the plist disappearing is what actually matters —
	// but it must still have been attempted, or an already-loaded agent keeps
	// running from a file that no longer exists.
	if !strings.Contains(strings.Join(c.mac.callsMatching("launchctl"), "\n"), "bootout") {
		t.Error("bootout was not attempted")
	}
}

// Removing an agent that was never installed is not an error: the login agent
// is optional, and `--remove-agent` has to be safe to type.
func TestRemoveAgentIsIdempotent(t *testing.T) {
	c := newCLI(t)
	if r := c.exec(t, "doctor", "--remove-agent"); r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
}
