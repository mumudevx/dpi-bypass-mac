//go:build !windows

// The two `dpb run --tun` tests whose subject is a BSD kernel.
//
// TestTunDefaultsToOffInTheParsedFlags asserts that --tun-name defaults to
// "utun". That default is not a preference: on darwin "utun" with no unit
// number means "the kernel picks a free one", which is why the interface name
// every route and ifconfig Op uses has to be read back off the DEVICE rather
// than off the flag. Windows has no such convention — there is no kernel unit
// allocator for a Wintun adapter, the name IS the adapter's name in Network
// Connections, and tunname_windows.go therefore defaults to "dpb" and rejects
// "utun" as meaningless to a user looking for it there.
// tunrun_windows_test.go asserts both defaults against that value.
//
// TestTunRouteOpsApplyAndRevertThroughNetstate takes the route Ops the command
// built and runs them through a real netstate.Manager against internal/testnet's
// fakes. Its fake system IS macOS route(8): the ScriptRunner's fallback exists
// to reproduce route(8)'s liar shape — "route add" prints its result and exits
// 0 whether or not the route landed, which is the whole reason netstate
// verifies against the RIB instead of the exit status — and it mirrors the
// effect into a fake RIB. scwindows issues no commands for routes at all; it
// calls CreateIpForwardEntry2 and reads GetIpForwardTable2 back
// (internal/sysconf/scwindows/windows.go, Contract 2), so a scripted command
// runner substitutes for nothing there and the Manager reaches the real IP
// Helper. The 2026-09-14 windows-latest run measured exactly that: the test
// failed with `netstate: no interface named "lo0" on this machine`, from
// scwindows/route.go, because the Env it builds names no Port and the fallback
// is the real one.
//
// It is not tagged away as unfixable. Route mutation through a Port IS tested
// on Windows, by internal/sysconf/scwindows' route tests and by
// internal/netstate's op_route_port_test.go against internal/testport; what
// cannot cross the boundary is this test's route(8)-shaped fake, and rewriting
// it to inject a Port would be editing an existing test body.
//
// Both function bodies are unchanged from tunrun_test.go, where they lived
// until the Windows suite started running.

package cliapp

import (
	"bytes"
	"context"
	"testing"

	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/testnet"
)

// TestTunDefaultsToOffInTheParsedFlags pins the default itself rather than the
// help text, so a change of wording cannot hide a change of behaviour.
func TestTunDefaultsToOffInTheParsedFlags(t *testing.T) {
	t.Parallel()
	g := &globals{env: Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}}
	cmd := newRunCmd(g)
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v, _ := cmd.Flags().GetBool("tun"); v {
		t.Fatal("--tun defaults to on; proxy mode must stay the default")
	}
	if v, _ := cmd.Flags().GetString("tun-name"); v != "utun" {
		t.Fatalf("--tun-name defaults to %q, want utun so the kernel picks the unit", v)
	}
}

// TestTunRouteOpsApplyAndRevertThroughNetstate takes the Ops the command built
// and runs them through a real netstate.Manager against internal/testnet's
// fakes, so "journalled through netstate" is a property of the objects rather
// than of a comment.
func TestTunRouteOpsApplyAndRevertThroughNetstate(t *testing.T) {
	t.Parallel()
	fx := newTunFixture(t, tunFixtureOptions{})
	built := fx.seq.applied()
	fx.stop()

	rib := testnet.NewRIB()
	runner := testnet.NewScriptRunner()
	runner.Fallback(func(argv []string) netstate.Result {
		// route(8) on macOS prints "add net ...: gateway ... " and exits 0
		// whether or not the route landed, which is the whole reason netstate
		// verifies against the RIB instead of the exit status. This fake keeps
		// that property and mirrors the effect into the RIB.
		res := netstate.Result{Argv: argv}
		if len(argv) < 4 || argv[0] != "route" {
			return res
		}
		r, ok := parseRouteArgv(argv)
		if !ok {
			return res
		}
		switch r.verb {
		case "add":
			rib.Add(netstate.RouteEntry{Dst: r.dst, Gateway: r.gw, Iface: r.iface, Scoped: r.scoped})
		case "delete":
			rib.Remove(r.dst, "")
		}
		return res
	})

	journal := openTempJournal(t)
	mgr := netstate.NewManager(journal, netstate.Env{Runner: runner, RIB: rib, Logf: t.Logf})

	ctx := context.Background()
	var applied int
	for _, op := range built {
		if op.Kind() != netstate.OpRoute {
			continue
		}
		if err := mgr.Do(ctx, op); err != nil {
			t.Fatalf("apply %s through netstate: %v", op.Describe(), err)
		}
		applied++
	}
	if applied < 4 {
		t.Fatalf("only %d route Op(s) were built; want the scoped default, both halves and a nameserver", applied)
	}
	routes, _ := rib.Routes()
	if len(routes) != applied {
		t.Fatalf("the RIB holds %d route(s) after %d applies", len(routes), applied)
	}

	if errs := mgr.UndoAll(ctx); len(errs) > 0 {
		t.Fatalf("UndoAll: %v", errs)
	}
	routes, _ = rib.Routes()
	if len(routes) != 0 {
		t.Fatalf("teardown left %d route(s) behind: %v", len(routes), routes)
	}
}
