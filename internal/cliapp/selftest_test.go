package cliapp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/emit"
	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/ops"
	"github.com/mumudevx/dpi-bypass-mac/internal/testcensor"
)

// The M12 acceptance clause: `dpb selftest` runs the full censor matrix and
// exits 0.
//
// It is a real end-to-end run of the shipped datapath — the real registry, the
// real strategy compiler, the real emit.Sender and a real TLS handshake with
// full certificate verification — against an in-process censor. Nothing here is
// stubbed except the middlebox.
func TestSelftestRunsTheMatrixAndExitsZero(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "selftest")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "0 failed") {
		t.Fatalf("the matrix did not come back clean:\n%s", r.stdout)
	}
}

// Every row must be a claim with a measurement attached. A matrix of numbers
// nobody can trace back to a sentence in MEASUREMENTS.md is a matrix that
// cannot be argued with when it fails.
func TestSelftestCasesCiteTheirMeasurement(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "selftest", "--json")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	var rep selftestReport
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("decode: %v\n%s", err, r.stdout)
	}
	if len(rep.Cases) < 5 || rep.Failed != 0 {
		t.Fatalf("report = %+v", rep)
	}
	for _, tc := range rep.Cases {
		if !strings.Contains(tc.Because, "§") {
			t.Errorf("case %s/%s/%s cites no measurement: %q", tc.Model, tc.Spec, tc.Host, tc.Because)
		}
		if tc.Want == "" || tc.Got == "" {
			t.Errorf("case %+v has no verdicts", tc)
		}
	}
}

// The two claims the whole architecture rests on, asserted by name rather than
// by counting rows: tlsfrag defeats the measured DPI, and the same emitter
// breaks a bank that plain reaches.
func TestSelftestCoversBothAxes(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "selftest", "--json")
	var rep selftestReport
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}

	var sawBypass, sawFragile, sawControl bool
	for _, tc := range rep.Cases {
		switch {
		case tc.Model == "tt2026" && tc.Spec == "tlsfrag:pos=snimid" && tc.Want == "PASS":
			sawBypass = true
		case tc.Model == "fragile" && tc.Spec == "tlsfrag:pos=snimid" && tc.Want != "PASS":
			sawFragile = true
		case tc.Model == "tt2026" && tc.Spec == "plain" && tc.Host == selftestControl && tc.Want == "PASS":
			sawControl = true
		}
	}
	if !sawBypass {
		t.Error("no case asserts that tlsfrag:pos=snimid defeats the measured DPI")
	}
	if !sawFragile {
		t.Error("no case asserts that the same emitter breaks a fragile bank — " +
			"that is the finding the default-direct architecture exists for")
	}
	if !sawControl {
		t.Error("no case asserts the benign-SNI control, so a total failure would look like a pass")
	}
}

func TestSelftestModelFilter(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "selftest", "--model", "fragile", "--json")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	var rep selftestReport
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rep.Cases) == 0 {
		t.Fatal("the filter selected nothing")
	}
	for _, tc := range rep.Cases {
		if tc.Model != "fragile" {
			t.Errorf("case %+v survived the fragile filter", tc)
		}
	}
}

func TestSelftestUnknownModelListsTheRealOnes(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "selftest", "--model", "nonsense")
	if r.code != ExitUsage {
		t.Fatalf("exit code = %d, want %d", r.code, ExitUsage)
	}
	if !strings.Contains(r.stderr, "tt2026") {
		t.Errorf("the error does not name the models that exist: %q", r.stderr)
	}
}

// The claims table is the part a reviewer reads, so it must be well formed
// independently of whether a run happens to be green.
func TestSelftestClaimsAreWellFormed(t *testing.T) {
	for _, c := range selftestClaims() {
		if c.model.Name == "" {
			t.Errorf("claim %+v has an unnamed model", c)
		}
		if c.host == "" {
			t.Errorf("claim %+v has no host", c)
		}
		if len(c.because) < 20 {
			t.Errorf("claim %s/%s cites too little to argue with: %q", c.model.Name, c.spec, c.because)
		}
	}
}

// boxTransport is the one piece of the datapath selftest substitutes, and every
// capability it advertises must actually work: an emitter that silently skips
// its OOB byte or its TTL change would make the whole matrix meaningless while
// every case still reported PASS.
func TestBoxTransportImplementsWhatItAdvertises(t *testing.T) {
	ops.Install()
	line, err := newCensorLine()
	if err != nil {
		t.Fatalf("censor line: %v", err)
	}
	defer line.close()

	box := testcensor.New(testcensor.TT2026(selftestBlocked), testcensor.Options{Port: 443})
	conn, err := boxDialer{box: box, addr: line.origin.Addr()}.DialTCP(
		context.Background(), flow.Target{Name: selftestBlocked})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	tp, err := newBoxTransport(conn, proxyCaps)
	if err != nil {
		t.Fatalf("newBoxTransport: %v", err)
	}
	defer tp.Close()

	if got := tp.Caps(); got != proxyCaps {
		t.Errorf("caps = %s, want the kernel-socket set %s", got, proxyCaps)
	}
	if _, err := tp.Write([]byte("x")); err != nil {
		t.Errorf("Write: %v", err)
	}
	if _, err := tp.WriteOOB([]byte("!")); err != nil {
		t.Errorf("WriteOOB: %v", err)
	}
	if err := tp.SetTTL(1); err != nil {
		t.Errorf("SetTTL: %v", err)
	}
	if err := tp.ResetTTL(); err != nil {
		t.Errorf("ResetTTL: %v", err)
	}
	// Raw injection needs a capability an in-process fixture cannot have, and
	// saying so is better than pretending: a plan that needs it must be
	// downgraded, not silently emitted as something else.
	if err := tp.InjectRaw([]byte("x")); !errors.Is(err, emit.ErrCapUnavailable) {
		t.Errorf("InjectRaw = %v, want ErrCapUnavailable", err)
	}
	if _, ok := tp.SeqState(); ok {
		t.Error("SeqState reported a sequence state the fixture cannot know")
	}
	if !tp.Local().IsValid() || !tp.Remote().IsValid() {
		t.Errorf("local %v remote %v; both must name the loopback socket", tp.Local(), tp.Remote())
	}
}

func TestBoxTransportRefusesAConnItCannotDrive(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := newBoxTransport(a, proxyCaps); err == nil {
		t.Fatal("a plain net.Conn was accepted as a censor transport")
	}
}
