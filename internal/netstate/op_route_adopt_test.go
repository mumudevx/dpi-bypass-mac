package netstate

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/mumudevx/dpb/internal/testport"
)

// These tests pin the DISCRIMINATOR, not the happy path.
//
// Two different collisions reach routeOp, and the whole of Plan 4 Task 4 is the
// claim that matchRoute already tells them apart:
//
//   - The uplink default tunfe installs before the capture routes. On Windows
//     there is no RTF_IFSCOPE, so the row it asks for IS the machine's own
//     default row — the one scwindows read Facts.Uplink and Facts.Gateway out
//     of. That must be ADOPTED: never installed, never deleted.
//   - A capture route colliding with somebody else's row at the same
//     destination. That must stay an ERROR, with mutated() false, so rollback
//     deletes nothing.
//
// Adopting the second would delete a user's routing on exit, which is the
// failure these tests exist to make impossible to reintroduce.

// errDuplicateRoute is the shape both platforms report for "somebody already
// owns that destination": macOS route(8)'s exit-0 "File exists" liar, and
// Windows' ERROR_OBJECT_ALREADY_EXISTS out of CreateIpForwardEntry2.
var errDuplicateRoute = errors.New("CreateIpForwardEntry2: the object already exists")

// windowsDefaultRow is the machine's own default route as scwindows' RIB
// reports it: Scoped is true because the row HAS A NEXT HOP (rib.go), not
// because Windows has a scope flag — it has none.
func windowsDefaultRow(gw netip.Addr, iface string) RouteEntry {
	return RouteEntry{
		Dst:     netip.MustParsePrefix("0.0.0.0/0"),
		Gateway: gw,
		Iface:   iface,
		Scoped:  true,
	}
}

// The uplink default must be adopted when the machine already has that exact
// row, because on Windows it always does: scwindows/facts.go sets
// `f.Uplink, f.Gateway = def.Iface, def.Gateway` from the winning default
// route, and cliapp hands those straight to tunfe.Capture. So the RouteSpec
// asked for and the row found are the same row.
//
// Adopted means three things, and all three are asserted: Add is never called
// (so CreateIpForwardEntry2 never gets the chance to answer
// ERROR_OBJECT_ALREADY_EXISTS), the journal record says Adopted, and teardown
// issues no Delete against the machine's own default.
func TestTheUplinkDefaultIsAdoptedWhenItIsAlreadyTheMachinesRow(t *testing.T) {
	ctx := context.Background()
	gw := netip.MustParseAddr("192.168.1.1")

	p := testport.New()
	p.RouteC.Table = []RouteEntry{windowsDefaultRow(gw, "Ethernet")}

	j, _ := openTestJournal(t)
	m := NewManager(j, Env{Sys: p, RIB: p.RouteC.RIB()})

	op := NewRoute(nil, netip.MustParsePrefix("0.0.0.0/0"), gw, "Ethernet")
	if err := m.Do(ctx, op); err != nil {
		t.Fatalf("Do() = %v, want nil: the row asked for is already in the table", err)
	}

	if n := len(p.RouteC.Adds); n != 0 {
		t.Errorf("Adds = %d, want 0: the uplink default was installed rather than adopted, "+
			"which on Windows is the call that answers ERROR_OBJECT_ALREADY_EXISTS", n)
	}
	recs := m.Applied()
	if len(recs) != 1 {
		t.Fatalf("Applied() = %d records, want 1", len(recs))
	}
	if !recs[0].Adopted {
		t.Errorf("record %s is not Adopted; UndoAll would delete the machine's own default route",
			recs[0].ID)
	}

	if errs := m.UndoAll(ctx); len(errs) != 0 {
		t.Fatalf("UndoAll = %v, want no errors", errs)
	}
	if n := len(p.RouteC.Deletes); n != 0 {
		t.Errorf("Deletes = %d, want 0: teardown removed a route dpb never created", n)
	}
}

// The other collision. A capture route whose destination is already owned by
// somebody else must NOT be adopted and must NOT be reverted: Add fails,
// mutated() stays false, and Manager.rollback issues no Delete.
//
// The RIB here holds a coexisting tunnel's 0.0.0.0/1 on its own interface,
// which is what makes the adoption pre-check refuse: matchRoute compares the
// interface, so a row at our destination on somebody else's device is not our
// row and never satisfies our request.
func TestACaptureRouteCollisionStaysAnErrorAndRevertsNothing(t *testing.T) {
	ctx := context.Background()

	p := testport.New()
	p.RouteC.Table = []RouteEntry{{
		Dst:   netip.MustParsePrefix("0.0.0.0/1"),
		Iface: "utunVPN",
	}}
	p.RouteC.AddErr = errDuplicateRoute

	j, _ := openTestJournal(t)
	m := NewManager(j, Env{Sys: p, RIB: p.RouteC.RIB()})

	op := NewRoute(nil, netip.MustParsePrefix("0.0.0.0/1"), netip.Addr{}, "utun9")
	err := m.Do(ctx, op)
	if err == nil {
		t.Fatal("Do() = nil: a destination owned by another tunnel was reported as installed")
	}
	if !errors.Is(err, errDuplicateRoute) {
		t.Errorf("Do() = %v, want it to wrap the duplicate error", err)
	}

	if op.(*routeOp).mutated() {
		t.Error("mutated() = true after a refused Add; rollback would delete another owner's route")
	}
	if n := len(p.RouteC.Deletes); n != 0 {
		t.Errorf("Deletes = %d, want 0: rollback deleted a route dpb never created", n)
	}
	if n := len(m.Applied()); n != 0 {
		t.Errorf("Applied() = %d records, want 0: a failed Add is not an applied change", n)
	}
}

// darwin is unchanged, and this is the assertion that says so at the level the
// change could have broken: an UNSCOPED default does not satisfy a SCOPED
// request, so the adoption pre-check refuses and the Op really does install the
// -ifscope row.
//
// macOS needs that row because RTF_IFSCOPE is part of a route's identity and a
// socket pinned with IP_BOUND_IF resolves against the scoped table. Windows has
// no such flag, which is the entire difference between this test and the first
// one: same request, same Op, opposite outcome, decided only by what the
// kernel table already holds.
func TestAnUnscopedDefaultDoesNotSatisfyAScopedRequest(t *testing.T) {
	ctx := context.Background()
	gw := netip.MustParseAddr("192.168.1.1")

	p := testport.New()
	p.RouteC.Table = []RouteEntry{{
		Dst:     netip.MustParsePrefix("0.0.0.0/0"),
		Gateway: gw,
		Iface:   "en0",
		Scoped:  false, // the machine's own default, no RTF_IFSCOPE
	}}
	env := Env{Sys: p, RIB: p.RouteC.RIB()}

	op := NewRoute(nil, netip.MustParsePrefix("0.0.0.0/0"), gw, "en0")
	if canAdopt(op) && op.Verify(ctx, env) == nil {
		t.Fatal("the unscoped default was adopted as the scoped one; macOS would then run " +
			"with no -ifscope row and every upstream socket back inside the tunnel")
	}

	if err := op.Apply(ctx, env); err != nil {
		t.Fatalf("Apply() = %v", err)
	}
	if n := len(p.RouteC.Adds); n != 1 {
		t.Fatalf("Adds = %d, want 1: darwin must still install the scoped default", n)
	}
	want := RouteSpec{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gw: gw, Iface: "en0"}
	if got := p.RouteC.Adds[0]; got != want {
		t.Errorf("RouteSpec = %+v, want %+v", got, want)
	}
}

// canAdopt is a decision, not an accident of the default. routeOp is the only
// Op in this package that permits adoption; the four settings Ops refuse it
// because their Verify can only pass by finding a previous run's residue.
func TestRouteIsTheOnlyOpThatPermitsAdoption(t *testing.T) {
	route := NewRoute(nil, netip.MustParsePrefix("0.0.0.0/1"), netip.Addr{}, "utun9")
	if !canAdopt(route) {
		t.Error("canAdopt(route) = false; the uplink default could never be adopted on Windows")
	}
	if _, ok := route.(adoptChecker); !ok {
		t.Error("routeOp does not implement adoptChecker: the decision is back to being " +
			"an invisible default that nobody grepping for canAdopt will find")
	}

	dns := NewDNSServers(nil, []string{"127.0.0.1"}, []string{"Wi-Fi"})
	if canAdopt(dns) {
		t.Error("canAdopt(dns) = true; our own resolver list would be adopted as the user's")
	}
}
