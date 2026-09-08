package scdarwin

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/sysport"
)

// silentLaunchctl scripts the ambiguous answer: exit non-zero, no output at
// all. Some launchd builds spell "the variable is not set" that way, and a read
// that genuinely broke looks byte-for-byte identical.
func silentLaunchctl(name string) Env {
	key := "launchctl getenv " + name
	return Env{Runner: scriptedRunner{
		out:  map[string]string{key: ""},
		code: map[string]int{key: 1},
	}}
}

// The CAPTURE read refuses the ambiguity.
//
// Reading it as "unset" is destructive, not untidy: launchEnvOp.prepare stores
// the answer in prevSet (op_launchenv.go:118) and Revert runs `launchctl
// unsetenv` on every name it recorded as unset (:180) — so on a machine whose
// launchctl answers this way, a user's own HTTPS_PROXY is deleted on the way
// out. The pre-branch code refused the apply outright (46e30d6,
// op_launchenv.go:105) and this restores that refusal.
func TestEnvGetRefusesASilentLaunchctl(t *testing.T) {
	_, ok, err := New(silentLaunchctl("HTTPS_PROXY")).Env().Get(context.Background(), "HTTPS_PROXY")
	if err == nil {
		t.Fatal("Get answered a launchctl that failed silently; the capture it returns drives an unsetenv on revert")
	}
	if ok {
		t.Error("ok = true on a read that established nothing")
	}
	if !errors.Is(err, sysport.ErrEnvUnreadable) {
		t.Errorf("error = %v, want it to wrap sysport.ErrEnvUnreadable so the diagnostic reader — and only it — can tolerate it", err)
	}
}

// The same scripted launchctl, read through the two paths, gives two different
// answers on purpose. That is the whole reason both exist: the diagnostic only
// prints its answer, the capture feeds a write.
func TestTheCaptureAndDiagnosticReadersDisagreeDeliberately(t *testing.T) {
	e := silentLaunchctl("NO_PROXY")
	ctx := context.Background()

	if _, _, err := New(e).Env().Get(ctx, "NO_PROXY"); err == nil {
		t.Error("the capture read tolerated a launchctl that could not answer")
	}
	v, err := ReadLaunchEnv(ctx, e, "NO_PROXY")
	if err != nil {
		t.Fatalf("the diagnostic read reported %v where it could say \"not set\"", err)
	}
	if v != "" {
		t.Errorf("value = %q, want the empty string", v)
	}
}

// A launchctl that said WHY it failed is not the ambiguous case, and must not
// be marked unreadable — sysport.EnvLookup would then swallow a real breakage
// and `dpb doctor` would print "not set" for a variable it never read.
func TestEnvGetDoesNotMarkATalkativeFailureUnreadable(t *testing.T) {
	e := Env{Runner: scriptedRunner{
		out:  map[string]string{"launchctl getenv X": "Could not connect to the bootstrap server"},
		code: map[string]int{"launchctl getenv X": 5},
	}}
	_, _, err := New(e).Env().Get(context.Background(), "X")
	if err == nil {
		t.Fatal("a launchctl that said why it failed produced no error")
	}
	if errors.Is(err, sysport.ErrEnvUnreadable) {
		t.Errorf("error = %v, want a plain failure: the diagnostic reader would read the unreadable marker as \"not set\"", err)
	}
	if !strings.Contains(err.Error(), "bootstrap server") {
		t.Errorf("error = %v, want it to carry what launchctl printed", err)
	}
}

// An unset variable on a launchd build that exits 0 is still just "not set",
// on both paths — the refusal above is about the failure, not about emptiness.
func TestEnvGetOnAnHonestlyUnsetVariable(t *testing.T) {
	e := Env{Runner: scriptedRunner{out: map[string]string{"launchctl getenv HTTP_PROXY": ""}}}
	v, ok, err := New(e).Env().Get(context.Background(), "HTTP_PROXY")
	if err != nil {
		t.Fatalf("Get = %v on an exit-0 empty answer", err)
	}
	if ok || v != "" {
		t.Errorf("Get = %q, ok=%v; want the variable reported as not set", v, ok)
	}
}
