package netstate

import (
	"context"
	"fmt"
	"testing"

	"github.com/mumudevx/dpb/internal/sysport"
	"github.com/mumudevx/dpb/internal/testport"
)

// launchEnvPAC is this Op's own value, spelled here rather than borrowed from
// ops_test.go so that this file stays free of the macOS tool fake.
const launchEnvPAC = "http://127.0.0.1:8080/dpb.pac"

// unreadable is the error a Port reports for a variable it could not read at
// all: on macOS, a `launchctl getenv` that exits non-zero and prints nothing.
var unreadable = fmt.Errorf("netstate: launchctl getenv HTTPS_PROXY: exit status 1: %w", sysport.ErrEnvUnreadable)

// The capture must refuse a variable it could not read, never record it as
// unset.
//
// prevSet is what Revert acts on: a name recorded as unset is UNSET on the way
// out (op_launchenv.go:180). So a prepare that answers "not set" for a variable
// it merely failed to read deletes the user's own HTTPS_PROXY when dpb exits —
// a machine that was never touched by us losing configuration because a read
// failed. Refusing the apply is what this tool shipped with (46e30d6,
// op_launchenv.go:105).
func TestLaunchEnvCaptureRefusesAnUnreadableVariable(t *testing.T) {
	p := testport.New()
	p.EnvC.GetErr = unreadable

	op := NewLaunchEnv(nil, launchEnvPAC, nil).(*launchEnvOp)
	if err := op.prepare(context.Background(), Env{Sys: p}); err == nil {
		t.Fatal("prepare accepted a Port that could not read the variable; the capture it recorded would drive an unsetenv on revert")
	}
	if op.prepared {
		t.Error("prepared = true after a refused capture; the next prepare would skip the read and apply on a capture that was never taken")
	}
	for _, n := range op.names() {
		if _, ok := op.prev[n]; ok {
			t.Errorf("%s was captured from a read that failed", n)
		}
	}
	if len(p.EnvC.SetCalls) != 0 || len(p.EnvC.UnsetCalls) != 0 {
		t.Errorf("a refused capture wrote to the session environment: %v %v", p.EnvC.SetCalls, p.EnvC.UnsetCalls)
	}
}

// The other half of the same rule: a variable the Port COULD read is captured,
// so the refusal above is about the failed read and not about foreign values
// going unrecorded.
func TestLaunchEnvCaptureRecordsAValueItCouldRead(t *testing.T) {
	p := testport.New()
	p.EnvC.GetRet = map[string]string{"HTTPS_PROXY": "http://corp.example:3128"}

	op := NewLaunchEnv(nil, launchEnvPAC, nil).(*launchEnvOp)
	if err := op.prepare(context.Background(), Env{Sys: p}); err != nil {
		t.Fatalf("prepare = %v", err)
	}
	if !op.prevSet["HTTPS_PROXY"] {
		t.Fatal("a foreign HTTPS_PROXY was not captured for restoration")
	}
	if got := op.prev["HTTPS_PROXY"]; got != "http://corp.example:3128" {
		t.Errorf("captured HTTPS_PROXY = %q", got)
	}
	if op.prevSet["HTTP_PROXY"] {
		t.Error("HTTP_PROXY was recorded as set; the Port reported it absent")
	}
}

// ReadLaunchEnv is the diagnostic, and it keeps the tolerance the capture path
// gave up: `dpb doctor` asks "is it set", and an answer of "could not tell"
// where it could say "no" is one nobody can act on. This is the live path —
// doctor.go:552 and coverage.go:226 reach the Port through exactly this call.
func TestReadLaunchEnvTreatsAnUnreadableVariableAsUnset(t *testing.T) {
	p := testport.New()
	p.EnvC.GetErr = unreadable

	v, err := ReadLaunchEnv(context.Background(), Env{Sys: p}, "HTTPS_PROXY")
	if err != nil {
		t.Fatalf("ReadLaunchEnv = %v, want an unreadable variable reported as not set", err)
	}
	if v != "" {
		t.Errorf("value = %q, want the empty string", v)
	}
}

// A failure that said why is still a failure, even for the diagnostic: "could
// not run launchctl" must not be printed as "the variable is not set".
func TestReadLaunchEnvReportsAFailureThatSaidWhy(t *testing.T) {
	p := testport.New()
	p.EnvC.GetErr = fmt.Errorf("netstate: launchctl getenv HTTPS_PROXY: Could not connect to the bootstrap server")

	if _, err := ReadLaunchEnv(context.Background(), Env{Sys: p}, "HTTPS_PROXY"); err == nil {
		t.Fatal("a Port that could not run launchctl was reported as an unset variable")
	}
}
