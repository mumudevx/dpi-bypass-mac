package cliapp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/observ"
)

func findMechanism(t *testing.T, rep coverageReport, name string) mechanism {
	t.Helper()
	for _, m := range rep.Mechanisms {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("no mechanism named %q in %+v", name, rep.Mechanisms)
	return mechanism{}
}

func coverageJSON(t *testing.T, c *cli, args ...string) (coverageReport, result) {
	t.Helper()
	r := c.exec(t, append([]string{"coverage", "--json"}, args...)...)
	var rep coverageReport
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("decode: %v\n%s%s", err, r.stdout, r.stderr)
	}
	return rep, r
}

// The two mechanisms cover DIFFERENT classes of program, and the report has to
// say which. "PAC is on" means nothing to a user trying to work out why
// Discord's updater still cannot connect (GT24).
func TestCoverageReportsBothMechanismsAndWhoTheyCover(t *testing.T) {
	c := newCLI(t)
	c.mac.Run(t.Context(), "networksetup", "-setautoproxyurl", "Wi-Fi", "http://127.0.0.1:8080/dpb.pac")
	c.mac.Run(t.Context(), "launchctl", "setenv", "HTTPS_PROXY", "http://127.0.0.1:8080")

	rep, r := coverageJSON(t, c)
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	pac := findMechanism(t, rep, "auto-proxy URL (PAC)")
	if !pac.Set || pac.Value != "http://127.0.0.1:8080/dpb.pac" {
		t.Fatalf("PAC mechanism = %+v", pac)
	}
	if !strings.Contains(pac.Covers, "CFNetwork") {
		t.Errorf("the PAC mechanism does not say who it covers: %q", pac.Covers)
	}
	env := findMechanism(t, rep, "launchd HTTPS_PROXY")
	if !env.Set {
		t.Fatalf("the environment mechanism = %+v", env)
	}
	if !strings.Contains(env.Covers, "updater") {
		t.Errorf("the environment mechanism does not name the program it exists for: %q", env.Covers)
	}
}

// Setting one lever and not the other leaves a whole class of program
// uncovered, and the report has to make that visible side by side.
func TestCoverageShowsOneLeverSetAndTheOtherNot(t *testing.T) {
	c := newCLI(t)
	c.mac.Run(t.Context(), "networksetup", "-setautoproxyurl", "Wi-Fi", "http://127.0.0.1:8080/dpb.pac")

	rep, _ := coverageJSON(t, c)
	if !findMechanism(t, rep, "auto-proxy URL (PAC)").Set {
		t.Error("the PAC was reported as unset")
	}
	if findMechanism(t, rep, "launchd HTTPS_PROXY").Set {
		t.Error("an unset environment variable was reported as set")
	}
}

// With no dpb, the ports are the CONFIGURED ones rather than bound ones, and
// saying so is the difference between a report about the machine and a report
// about a file.
func TestCoverageSaysThePortsAreOnlyConfigured(t *testing.T) {
	c := newCLI(t)
	rep, _ := coverageJSON(t, c)
	if rep.Running {
		t.Error("coverage reported a running dpb")
	}
	joined := strings.Join(rep.Notes, " ")
	if !strings.Contains(joined, "CONFIGURED") {
		t.Errorf("notes = %v", rep.Notes)
	}
}

func TestCoverageUsesTheBoundPortsFromTheDaemon(t *testing.T) {
	c := newCLI(t)
	startControl(t, c.layout, observ.Handler{
		Status: func(context.Context) (observ.Status, error) {
			return observ.Status{
				PID:       os.Getpid(),
				Listeners: []observ.Listener{{Kind: "http", Addr: "127.0.0.1:54321"}},
			}, nil
		},
	})
	rep, _ := coverageJSON(t, c)
	if !rep.Running {
		t.Fatal("coverage did not see the running dpb")
	}
	if len(rep.Listeners) != 1 || rep.Listeners[0] != 54321 {
		t.Fatalf("listener ports = %v, want the bound one", rep.Listeners)
	}
}

// --fix has nothing it can honestly do without the process that owns the
// settings, and the message has to say why rather than failing obscurely.
func TestCoverageFixWithNoDaemonExplainsItself(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "coverage", "--fix")
	if r.code != ExitError {
		t.Fatalf("exit code = %d, want %d", r.code, ExitError)
	}
	if !strings.Contains(r.stderr, "only the process that owns them can restore them") {
		t.Errorf("stderr = %q", r.stderr)
	}
}

func TestCoverageFixReachesTheDaemon(t *testing.T) {
	c := newCLI(t)
	called := make(chan struct{}, 1)
	startControl(t, c.layout, observ.Handler{
		Reapply: func(context.Context) error {
			called <- struct{}{}
			return nil
		},
	})
	if r := c.exec(t, "coverage", "--fix"); r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	select {
	case <-called:
	default:
		t.Fatal("Reapply was never called")
	}
}

// The absence of clients is ambiguous on its own, and the human output must say
// so — that ambiguity is the whole reason --watch exists.
func TestCoverageExplainsAnEmptyClientList(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "coverage")
	if !strings.Contains(r.stdout, "--watch 30s") {
		t.Fatalf("an empty client list was reported without saying what to do:\n%s", r.stdout)
	}
}

// parseLsof reads the -F field format because a command name with a space in it
// — "Google Chrome Helper" — makes column splitting wrong in exactly the case a
// user cares about.
func TestParseLsofFieldFormat(t *testing.T) {
	out := strings.Join([]string{
		"p501",
		"cGoogle Chrome Helper",
		"n127.0.0.1:55123->127.0.0.1:8080",
		"p777",
		"cdpb",
		"n127.0.0.1:8080->127.0.0.1:55123", // dpb's own accepted side
		"p888",
		"ccurl",
		"n127.0.0.1:55999->127.0.0.1:9999", // a different port
		"p999",
		"cbroken",
		"nnot-a-pair",
	}, "\n")

	got := parseLsof(out, 8080, 0)
	if len(got) != 1 {
		t.Fatalf("got %+v, want only the client side of the connection to 8080", got)
	}
	if got[0].Command != "Google Chrome Helper" {
		t.Errorf("command = %q; a name with spaces must survive", got[0].Command)
	}
	if got[0].PID != 501 || got[0].Port != 8080 {
		t.Errorf("client = %+v", got[0])
	}
}

// dpb must not report itself as one of its own users.
func TestParseLsofExcludesTheDaemonItself(t *testing.T) {
	out := "p4242\ncdpb\nn127.0.0.1:55123->127.0.0.1:8080\n"
	if got := parseLsof(out, 8080, 4242); len(got) != 0 {
		t.Fatalf("got %+v, want dpb's own pid excluded", got)
	}
}

func TestPortOf(t *testing.T) {
	if p, err := portOf("127.0.0.1:8080"); err != nil || p != 8080 {
		t.Errorf("portOf = %d, %v", p, err)
	}
	if _, err := portOf("no-port-here"); err == nil {
		t.Error("portOf accepted an address with no port")
	}
}

// stubRunner answers one command with a canned result, so the lsof cases can be
// driven without depending on what happens to be listening on this machine.
type stubRunner struct {
	out   string
	code  int
	err   error
	calls [][]string
}

func (r *stubRunner) Run(_ context.Context, name string, args ...string) netstate.Result {
	r.calls = append(r.calls, append([]string{name}, args...))
	return netstate.Result{
		Argv:     append([]string{name}, args...),
		Combined: r.out,
		Code:     r.code,
		Err:      r.err,
	}
}

// lsof exits 1 when nothing matches, which is the ordinary case on a quiet
// machine. Treating that as a failure would make the command useless exactly
// when it has nothing alarming to report.
func TestSampleClientsToleratesLsofFindingNothing(t *testing.T) {
	r := &stubRunner{code: 1}
	got, note := sampleClients(context.Background(), r, []int{8080}, 0, 0)
	if len(got) != 0 {
		t.Fatalf("clients = %+v", got)
	}
	if note != "" {
		t.Fatalf("an empty result was reported as an error: %q", note)
	}
	if len(r.calls) != 1 || r.calls[0][0] != "lsof" {
		t.Fatalf("calls = %v", r.calls)
	}
}

func TestSampleClientsReadsTheFieldFormat(t *testing.T) {
	r := &stubRunner{out: "p501\ncSafari\nn127.0.0.1:55123->127.0.0.1:8080\n"}
	got, note := sampleClients(context.Background(), r, []int{8080}, 0, 0)
	if note != "" {
		t.Fatalf("note = %q", note)
	}
	if len(got) != 1 || got[0].Command != "Safari" {
		t.Fatalf("clients = %+v", got)
	}
	// -F is what makes a command name with a space survive; asserting the flag
	// is what stops it being dropped in a later edit.
	joined := strings.Join(r.calls[0], " ")
	if !strings.Contains(joined, "-Fcpn") {
		t.Errorf("lsof was not asked for the field format: %s", joined)
	}
}

// A command that could not be RUN is a real failure and is reported, rather
// than being folded into "nothing is connected".
func TestSampleClientsReportsARealFailure(t *testing.T) {
	r := &stubRunner{err: errors.New("exec: \"lsof\": executable file not found")}
	_, note := sampleClients(context.Background(), r, []int{8080}, 0, 0)
	if !strings.Contains(note, "lsof") {
		t.Fatalf("note = %q, want the failure reported", note)
	}
}

func TestSampleClientsWithNoPorts(t *testing.T) {
	_, note := sampleClients(context.Background(), &stubRunner{}, nil, 0, 0)
	if note == "" {
		t.Fatal("no note was produced for a report with no ports to attribute to")
	}
}
