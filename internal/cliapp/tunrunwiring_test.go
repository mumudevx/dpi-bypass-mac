//go:build !windows

// The two tests here drive the shipped `run --tun` command through
// startRunTweak, which spawns fakeDPBBinary — a /bin/sh script standing in
// for the dpb executable the janitor child is spawned from — so they carry
// the same tag as run_test.go, where startRunTweak is defined. Everything
// else in tunrun_test.go drives startTun and its Ops directly, through a
// recorded Sequencer rather than a running process, and needs no such tag.

package cliapp

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/front/tunfe"
	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/netwatch"
)

// TestRunStartsAndTearsDownTheTunnel drives the SHIPPED command from the
// command line down, which is the only thing that proves `dpb run --tun` — not
// startTun, not tunfe — brings a tunnel up and takes it away again.
func TestRunStartsAndTearsDownTheTunnel(t *testing.T) {
	t.Parallel()
	layout := tempLayout(t)
	layout.Elevated = true

	seq := &recordingSeq{started: make(chan struct{})}
	dev, _ := tunfe.NewPipe(tunfe.DefaultMTU)
	// The kernel picks the unit for "utun", which is what --tun-name defaults
	// to, so every Op naming utun7 proves the name was read back off the
	// device rather than copied from the flag.
	dev.SetName("utun7")
	link := &spyLink{Link: dev, seq: seq}

	// watchFacts is the collector the network watcher re-runs on every routing
	// change. See the SelfIface assertion below.
	var (
		watchFacts func(context.Context) (*netstate.Facts, error)
		seenSelf   struct {
			sync.Mutex
			iface string
		}
	)

	h := startRunTweak(t, newFakeMac(), layout, func(g *globals) {
		facts := &netstate.Facts{
			Uplink:   tunFixtureUplink,
			Gateway:  netip.MustParseAddr("192.0.2.1"),
			Services: []string{"Wi-Fi"},
		}
		g.facts = facts
		g.factsFn = func(_ context.Context, e netstate.Env) *netstate.Facts {
			seenSelf.Lock()
			seenSelf.iface = e.SelfIface
			seenSelf.Unlock()
			return facts
		}
		g.openLink = func(string, int, func(string, ...any)) (tunfe.Link, error) { return link, nil }
		g.tunSeq = func(tunfe.Sequencer) tunfe.Sequencer { return seq }
		g.netwatchOpts = func(o *netwatch.Options) {
			o.Source = inertSource{}
			o.Portal = inertProber{}
			watchFacts = o.Facts
		}
	}, "--tun", "--proxy-style", "none")

	seq.awaitStart(t)
	if kinds := seq.kinds(); len(kinds) == 0 || kinds[0] != netstate.OpIfconfig {
		t.Fatalf("`dpb run --tun` applied %v; want the interface first", kinds)
	}
	if d := seq.describe(); !strings.Contains(d[0], "utun7") {
		t.Fatalf("the Ops name the requested device rather than the one the kernel gave us: %s", d[0])
	}
	// The banner names the device, because that is the name every recovery
	// command a user might have to type by hand needs.
	if out := h.out.String(); !strings.Contains(out, "tun") || !strings.Contains(out, link.name()) {
		t.Fatalf("the banner does not name the tunnel:\n%s", out)
	}

	// The watcher has to know which utun is OURS. Our capture routes are the
	// 0.0.0.0/1 + 128.0.0.0/1 pair a WireGuard-style VPN installs, so without
	// this the first routing change after bring-up classifies dpb as a
	// full-tunnel VPN and dpb refuses to run alongside itself with exit 5.
	if watchFacts == nil {
		t.Fatal("the network watcher was never given a facts collector")
	}
	if _, err := watchFacts(context.Background()); err != nil {
		t.Fatalf("re-collect facts: %v", err)
	}
	seenSelf.Lock()
	self := seenSelf.iface
	seenSelf.Unlock()
	if self != link.name() {
		t.Fatalf("the watcher re-collects facts with SelfIface=%q, want %q", self, link.name())
	}

	h.shutdown(t)
	if seq.undone == 0 {
		t.Fatal("`dpb run --tun` exited without reverting the tunnel's system state")
	}
	if link.closedAt.IsZero() {
		t.Fatal("`dpb run --tun` exited without closing the utun")
	}
	if !link.closedAt.After(seq.undoneAt) {
		t.Fatal("the utun closed before the routes naming it were deleted")
	}
}

// TestTunDeviceFailureBringsTheRunDown.
//
// A read error on the utun is not recoverable: the capture routes still point
// at the device, so a process that logged it and carried on would be a
// blackhole printing "Ready". The previous implementation's bare `return` in
// the read loop is exactly that failure, and this is the wiring that makes the
// surfaced error reach the process.
func TestTunDeviceFailureBringsTheRunDown(t *testing.T) {
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
	}, "--tun", "--proxy-style", "none")

	seq.awaitStart(t)
	h.stopped = true // this run is expected to end by itself, with an error
	dev.FailRead(errors.New("the device went away"))

	select {
	case err := <-h.done:
		if err == nil {
			t.Fatal("a dead utun left `dpb run --tun` reporting success")
		}
		if !strings.Contains(err.Error(), "tunnel datapath") {
			t.Fatalf("the failure does not name the tunnel: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("`dpb run --tun` kept running over a device that reads nothing")
	}
	if seq.undone == 0 {
		t.Error("the capture routes were left behind after the device failed")
	}
}
