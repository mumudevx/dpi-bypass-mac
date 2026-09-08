package cliapp

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/config"
	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/observ"
)

// With no dpb running, `dpb status` still has to be useful. That is the whole
// "it worked yesterday" case: the user has already stopped and started things,
// and an answer that needs the daemon up cannot be given.
func TestStatusWithNoDaemon(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "status")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	for _, want := range []string{
		"dpb is NOT running",
		"profile:",
		"ladder:",
		"cache:",
		"journal:   empty",
		"tuned:     none",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output does not contain %q:\n%s", want, r.stdout)
		}
	}
}

// The line that matters most on a broken machine: unfinished system changes,
// and the command that undoes them.
func TestStatusReportsJournalResidue(t *testing.T) {
	c := newCLI(t)
	seedPendingPAC(t, c.layout, deadPID)

	r := c.exec(t, "status")
	if !strings.Contains(r.stdout, "unfinished system change") {
		t.Fatalf("residue was not reported:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "dpb doctor --repair") {
		t.Fatalf("the remedy was not named:\n%s", r.stdout)
	}
}

func TestStatusFromTheRunningDaemon(t *testing.T) {
	c := newCLI(t)
	started := time.Now().Add(-90 * time.Second)
	startControl(t, c.layout, observ.Handler{
		Status: func(context.Context) (observ.Status, error) {
			return observ.Status{
				PID: 4242, Started: started, Mode: "watch", Profile: "turkey",
				Listeners: []observ.Listener{{Kind: "http", Addr: "127.0.0.1:8080"}},
				Applied:   []string{"set the auto-proxy URL to http://127.0.0.1:8080/dpb.pac"},
				Ladder:    []string{"", "tlsfrag:pos=snimid"},
				Resolvers: []observ.ResolverHealth{
					{Label: "doh cloudflare", OK: true, Tried: true, Latency: 26 * time.Millisecond},
					{Label: "udp 9.9.9.9:9953"}, // never tried
					{Label: "system", Tried: true, Sinkhole: true},
				},
				Conns: observ.Snapshot{
					Totals: observ.Totals{Conns: 12, OK: 11, Failed: 1, Judged: 9, Escalated: 3},
					Hosts:  6, EscalatedHosts: 5, Window: 30 * time.Minute,
					Drift: &observ.DriftEvent{
						Suspected: "your ISP's DPI likely changed",
						Remedy:    observ.DriftRemedy,
					},
				},
			}, nil
		},
	})

	r := c.exec(t, "status")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	for _, want := range []string{
		"dpb is RUNNING (pid 4242)",
		"listening: http    127.0.0.1:8080",
		"applied:   set the auto-proxy URL",
		"plain -> tlsfrag:pos=snimid",
		"flows:     12 total",
		"DRIFT:",
		observ.DriftRemedy,
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("output does not contain %q:\n%s", want, r.stdout)
		}
	}
	// A rung the chain never reached says nothing about itself. Rendering it as
	// "failed" would send a user chasing a resolver that is fine.
	if !strings.Contains(r.stdout, "untried") {
		t.Errorf("an untried resolver was not labelled as such:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "POISONED") {
		t.Errorf("a poisoned resolver was not called out:\n%s", r.stdout)
	}
}

// A dpb holding the run lock whose socket does not answer is neither "running
// normally" nor "not running", and saying which it is matters.
func TestStatusReportsALiveRunWithNoSocket(t *testing.T) {
	c := newCLI(t)
	lock, err := netstate.AcquireLock(c.layout.LockFile())
	if err != nil {
		t.Fatalf("acquire lock: %v", err)
	}
	defer lock.Release()

	r := c.exec(t, "status")
	if !strings.Contains(r.stdout, "dpb is RUNNING") {
		t.Fatalf("a live lock holder was reported as stopped:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "not answering") {
		t.Fatalf("the unreachable socket was not reported:\n%s", r.stdout)
	}
}

// A tuned profile measured on another network is worse than none: acting on it
// would desync flows on evidence gathered somewhere else. Status must say so
// rather than printing a strategy that is not in use.
func TestStatusFlagsATunedProfileFromAnotherNetwork(t *testing.T) {
	c := newCLI(t)
	tuned := config.Tuned{
		Version: 1, CreatedAt: time.Now().Add(-time.Hour),
		NetworkKey: "wifi-somewhere-else", Confidence: "high",
		Strategy: "tlsfrag:pos=snimid", ToolVersion: "test",
		Ladder:  []string{"", "tlsfrag:pos=snimid"},
		Blocked: []string{"discord.com"},
	}
	if err := tuned.Save(c.layout.TunedFile()); err != nil {
		t.Fatalf("save tuned: %v", err)
	}
	r := c.exec(t, "status")
	if !strings.Contains(r.stdout, "ON A DIFFERENT NETWORK") {
		t.Fatalf("a foreign tuned profile was not flagged:\n%s", r.stdout)
	}
}

func TestStatusJSON(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, "status", "--json")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	var st observ.Status
	if err := json.Unmarshal([]byte(r.stdout), &st); err != nil {
		t.Fatalf("decode: %v\n%s", err, r.stdout)
	}
	if st.Running {
		t.Error("status reported running with nothing bound")
	}
	if st.Journal.Path == "" {
		t.Error("the journal path is missing from the JSON")
	}
}

// --watch redraws until it is interrupted, and an interrupted watch is not a
// failure: the user asked it to run until they stopped it.
func TestStatusWatchStopsOnCancellation(t *testing.T) {
	c := newCLI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan result, 1)
	go func() { done <- c.execCtx(t, ctx, "status", "--watch") }()
	select {
	case r := <-done:
		if r.code != ExitOK {
			t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
		}
		if !strings.Contains(r.stdout, "dpb is NOT running") {
			t.Fatalf("the watch printed nothing:\n%s", r.stdout)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("--watch did not stop when its context was cancelled")
	}
}

// An unreadable configuration must not silence the command. The journal line —
// the one that says whether the machine has residue on it — is exactly what a
// user with a broken config needs to see.
func TestStatusSurvivesABrokenConfig(t *testing.T) {
	c := newCLI(t)
	if err := os.WriteFile(c.layout.ConfigFile(), []byte("nonsense = [\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	r := c.exec(t, "status")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "configuration could not be loaded") {
		t.Errorf("the config failure was not reported:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "journal:") {
		t.Errorf("the journal line was lost:\n%s", r.stdout)
	}
}
