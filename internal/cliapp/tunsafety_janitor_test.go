//go:build !windows

// The two tests here drive a whole `dpb run --tun` through
// startRun/startRunTweak, which spawn fakeDPBBinary — a /bin/sh script
// standing in for the dpb executable the janitor child is spawned from — so
// they carry the same tag as run_test.go, where both are defined. See
// tunsafety_test.go's TestWillMutateCountsTheTunnel for the unit half of the
// same defence, which needs no process at all.

package cliapp

import (
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/front/tunfe"
	"github.com/mumudevx/dpb/internal/netstate"
)

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
