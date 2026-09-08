//go:build darwin

package netstate

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// TestReverifyRestoresWhatTheNetworkFlushed is the network-change contract:
// macOS drops interface routes on a link change, and a run that never looked
// again would go on reporting a capture route it no longer has.
func TestReverifyRestoresWhatTheNetworkFlushed(t *testing.T) {
	f := newFakeSystem()
	f.ifaces["utun4"] = &fakeIface{index: 22, mtu: 1500}
	f.install(t)
	m, _ := newTestManager(t, f)
	ctx := context.Background()

	dst := netip.MustParsePrefix("0.0.0.0/1")
	if err := m.Do(ctx, NewRoute(f, dst, netip.Addr{}, "utun4")); err != nil {
		t.Fatalf("Do(route): %v", err)
	}
	if err := m.Do(ctx, NewPAC(f, pacURL, []string{"Wi-Fi"})); err != nil {
		t.Fatalf("Do(pac): %v", err)
	}

	// Nothing has moved yet: everything checks out and nothing is re-applied.
	rep, err := m.Reverify(ctx)
	if err != nil {
		t.Fatalf("Reverify on an intact system: %v", err)
	}
	if len(rep.Checked) != 2 || len(rep.Missing) != 0 || !rep.OK() {
		t.Fatalf("intact system reported %+v", rep)
	}

	// Now the link change: the route is gone from the kernel table and the
	// service's PAC was switched off underneath us.
	f.mu.Lock()
	kept := f.routes[:0]
	for _, r := range f.routes {
		if r.Dst != dst {
			kept = append(kept, r)
		}
	}
	f.routes = kept
	f.svc["Wi-Fi"].pacOn = false
	f.mu.Unlock()

	rep, err = m.Reverify(ctx)
	if err != nil {
		t.Fatalf("Reverify: %v", err)
	}
	if len(rep.Missing) != 2 {
		t.Fatalf("Missing = %d (%+v), want both settings", len(rep.Missing), rep.Missing)
	}
	if len(rep.Restored) != 2 || !rep.OK() {
		t.Fatalf("Restored = %+v, Failed = %+v", rep.Restored, rep.Failed)
	}
	if ok, err := f.Exists(dst, "utun4"); err != nil || !ok {
		t.Fatalf("the capture route was not put back (ok=%v err=%v)", ok, err)
	}
	if !f.svc["Wi-Fi"].pacOn {
		t.Fatal("the PAC was not put back")
	}

	// And teardown still works: the re-applied state is reverted exactly once.
	if errs := m.UndoAll(ctx); len(errs) != 0 {
		t.Fatalf("UndoAll after Reverify: %v", errs)
	}
	if f.svc["Wi-Fi"].pacOn {
		t.Fatal("the PAC survived teardown after a Reverify")
	}
	if ok, _ := f.Exists(dst, "utun4"); ok {
		t.Fatal("the capture route survived teardown after a Reverify")
	}
}

// TestReverifyNeverTouchesAnAdoptedRecord is the VPN case. An adopted default
// is somebody else's; re-applying it would install their configuration on
// their behalf, and the wave 1 review already found one defect in this family
// (a rollback deleting a coexisting VPN's half-default).
func TestReverifyNeverTouchesAnAdoptedRecord(t *testing.T) {
	f := newFakeSystem()
	f.ifaces["utun4"] = &fakeIface{index: 22, mtu: 1500}
	f.install(t)
	// A VPN's half-default is already in the table and we did not put it there.
	dst := netip.MustParsePrefix("0.0.0.0/1")
	f.mu.Lock()
	f.routes = append(f.routes, RouteEntry{Dst: dst, Iface: "utun4", Index: 22})
	f.mu.Unlock()

	m, _ := newTestManager(t, f)
	ctx := context.Background()
	if err := m.Do(ctx, NewRoute(f, dst, netip.Addr{}, "utun4")); err != nil {
		t.Fatalf("Do: %v", err)
	}
	applied := m.Applied()
	if len(applied) != 1 || !applied[0].Adopted {
		t.Fatalf("the record was not adopted: %+v", applied)
	}

	// Take it away, then Reverify. An adopted record is not ours to check or
	// to put back: re-adding it would install somebody else's route for them.
	f.mu.Lock()
	kept := f.routes[:0]
	for _, r := range f.routes {
		if r.Dst != dst {
			kept = append(kept, r)
		}
	}
	f.routes = kept
	before := len(f.calls)
	f.mu.Unlock()

	rep, err := m.Reverify(ctx)
	if err != nil {
		t.Fatalf("Reverify: %v", err)
	}
	if len(rep.Missing) != 0 || len(rep.Restored) != 0 {
		t.Fatalf("an adopted record was acted on: %+v", rep)
	}
	if len(rep.Checked) != 1 {
		t.Fatalf("Checked = %+v", rep.Checked)
	}
	f.mu.Lock()
	after := len(f.calls)
	f.mu.Unlock()
	if after != before {
		t.Fatalf("Reverify ran %d command(s) for an adopted record", after-before)
	}
}

// TestReverifyReportsWhatItCouldNotRestore: a networksetup that refuses must
// be reported, not swallowed. The alternative is a process that believes it
// re-applied something it did not.
func TestReverifyReportsWhatItCouldNotRestore(t *testing.T) {
	f := newFakeSystem()
	f.install(t)
	m, _ := newTestManager(t, f)
	ctx := context.Background()

	if err := m.Do(ctx, NewPAC(f, pacURL, []string{"Wi-Fi"})); err != nil {
		t.Fatalf("Do: %v", err)
	}
	f.mu.Lock()
	f.svc["Wi-Fi"].pacOn = false
	f.mu.Unlock()
	f.failNext("networksetup -setautoproxyurl", 5)

	rep, err := m.Reverify(ctx)
	if err == nil {
		t.Fatal("Reverify reported success after a refused re-apply")
	}
	if rep.OK() || len(rep.Failed) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if !strings.Contains(rep.Failed[0].Note, "re-apply") {
		t.Fatalf("the failure does not say what it was doing: %q", rep.Failed[0].Note)
	}
	// The journal entry is untouched, so teardown still knows what to put back.
	if len(m.Applied()) != 1 {
		t.Fatalf("Applied() = %+v; a failed re-apply must not drop the record", m.Applied())
	}
}

// TestReverifyIsANoOpUnderDryRun: --dry-run applies nothing, so there is
// nothing to re-apply and nothing to run a command about.
func TestReverifyIsANoOpUnderDryRun(t *testing.T) {
	f := newFakeSystem()
	f.install(t)
	j, _ := openTestJournal(t)
	e := f.env0()
	e.DryRun = true
	m := NewManager(j, e)
	ctx := context.Background()

	if err := m.Do(ctx, NewPAC(f, pacURL, []string{"Wi-Fi"})); err != nil {
		t.Fatalf("Do: %v", err)
	}
	f.mu.Lock()
	before := len(f.calls)
	f.mu.Unlock()

	rep, err := m.Reverify(ctx)
	if err != nil {
		t.Fatalf("Reverify: %v", err)
	}
	if len(rep.Checked)+len(rep.Missing)+len(rep.Restored)+len(rep.Failed) != 0 {
		t.Fatalf("dry-run Reverify reported %+v", rep)
	}
	f.mu.Lock()
	after := len(f.calls)
	f.mu.Unlock()
	if after != before {
		t.Fatalf("dry-run Reverify ran %d command(s)", after-before)
	}
}

// TestReverifyOnANewManagerIsEmpty pins the trivial case: nothing applied,
// nothing to check, no error.
func TestReverifyOnANewManagerIsEmpty(t *testing.T) {
	f := newFakeSystem()
	m, _ := newTestManager(t, f)
	rep, err := m.Reverify(context.Background())
	if err != nil || !rep.OK() || len(rep.Checked) != 0 {
		t.Fatalf("Reverify on an empty manager = %+v, %v", rep, err)
	}
}
