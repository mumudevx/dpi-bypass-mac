package cliapp

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/observ"
)

func TestOnOffReloadReachTheDaemon(t *testing.T) {
	c := newCLI(t)
	var mu sync.Mutex
	var got []string
	mark := func(name string) func(context.Context) error {
		return func(context.Context) error {
			mu.Lock()
			got = append(got, name)
			mu.Unlock()
			return nil
		}
	}
	startControl(t, c.layout, observ.Handler{
		On: mark("on"), Off: mark("off"), Reload: mark("reload"),
	})

	for _, cmd := range []string{"on", "off", "reload"} {
		r := c.exec(t, cmd)
		if r.code != ExitOK {
			t.Fatalf("%s: exit code = %d\n%s", cmd, r.code, r.stderr)
		}
		if strings.TrimSpace(r.stdout) == "" {
			t.Errorf("%s printed nothing; a kill switch the user cannot tell worked is not one", cmd)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(got, ",") != "on,off,reload" {
		t.Fatalf("the daemon saw %v", got)
	}
}

// With no daemon, `dpb off` cannot do anything — and must say what to do
// instead rather than failing with a dial error.
func TestOffWithNoDaemonNamesThePermanentAlternative(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "off")
	if r.code != ExitError {
		t.Fatalf("exit code = %d, want %d", r.code, ExitError)
	}
	if !strings.Contains(r.stderr, "no dpb is running") {
		t.Errorf("stderr = %q", r.stderr)
	}
	if !strings.Contains(r.stderr, c.layout.ConfigFile()) {
		t.Errorf("the permanent alternative was not named: %q", r.stderr)
	}
}

// `dpb panic` reaches a running dpb.
func TestPanicAsksTheDaemonToUnwind(t *testing.T) {
	c := newCLI(t)
	called := make(chan struct{}, 1)
	startControl(t, c.layout, observ.Handler{
		Panic: func(context.Context) error {
			called <- struct{}{}
			return nil
		},
	})
	r := c.exec(t, "panic")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	select {
	case <-called:
	default:
		t.Fatal("the daemon's Panic handler was never called")
	}
}

// This is the case a user actually reaches for `dpb panic` in: the browser
// stopped working, Activity Monitor shows nothing, and the machine is still
// pointed at a process that is gone. With no daemon to ask, panic replays the
// journal itself.
func TestPanicWithNoDaemonReplaysTheJournal(t *testing.T) {
	c := newCLI(t)
	pacPath := seedPendingPAC(t, c.layout, deadPID)

	r := c.exec(t, "panic")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "replaying the journal") {
		t.Errorf("output:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "undone:") {
		t.Errorf("nothing was reported as undone:\n%s", r.stdout)
	}
	if _, err := os.Stat(pacPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the PAC file survived: %v", err)
	}
}

func TestPanicWithNothingToDo(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "panic")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "already empty") {
		t.Errorf("output:\n%s", r.stdout)
	}
}

// A daemon that refuses to unwind must NOT be second-guessed by replaying the
// journal underneath it: two processes reverting the same records is the one
// situation the journal cannot describe.
func TestPanicDoesNotRaceALiveDaemonThatRefused(t *testing.T) {
	c := newCLI(t)
	pacPath := seedPendingPAC(t, c.layout, deadPID)
	startControl(t, c.layout, observ.Handler{
		Panic: func(context.Context) error { return errors.New("the routes are wedged") },
	})

	r := c.exec(t, "panic")
	if r.code != ExitError {
		t.Fatalf("exit code = %d, want %d", r.code, ExitError)
	}
	if !strings.Contains(r.stderr, "doctor --repair") {
		t.Errorf("the safe next step was not named: %q", r.stderr)
	}
	if _, err := os.Stat(pacPath); err != nil {
		t.Fatalf("panic replayed underneath a live daemon: %v", err)
	}
}
