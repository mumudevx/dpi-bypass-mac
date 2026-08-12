//go:build darwin

package sysnet

import (
	"context"
	"testing"
	"time"
)

func TestRouteManagerJournalTeardown(t *testing.T) {
	fr := &fakeRunner{}
	rm := NewRouteManager("utun9", fr, nil)
	ctx := context.Background()

	if err := rm.CaptureAll(ctx); err != nil {
		t.Fatal(err)
	}
	if !fr.hasCall("route", "-q", "add", "-net", "0.0.0.0/1", "-interface", "utun9") {
		t.Fatal("did not add 0.0.0.0/1 route")
	}
	if !fr.hasCall("route", "-q", "add", "-net", "128.0.0.0/1", "-interface", "utun9") {
		t.Fatal("did not add 128.0.0.0/1 route")
	}

	before := len(fr.calls)
	rm.Teardown(ctx)
	if !fr.hasCall("route", "-q", "delete", "-net", "128.0.0.0/1", "-interface", "utun9") {
		t.Fatal("did not delete 128.0.0.0/1 route on teardown")
	}
	if !fr.hasCall("route", "-q", "delete", "-net", "0.0.0.0/1", "-interface", "utun9") {
		t.Fatal("did not delete 0.0.0.0/1 route on teardown")
	}
	if len(fr.calls) <= before {
		t.Fatal("teardown issued no commands")
	}

	// Teardown is idempotent: a second call adds nothing.
	n := len(fr.calls)
	rm.Teardown(ctx)
	if len(fr.calls) != n {
		t.Fatal("second teardown was not a no-op")
	}
}

func TestDefaultInterfaceParse(t *testing.T) {
	cr := &scriptedRunner{out: map[string]string{
		"route -n get default": "   gateway: 10.0.0.1\n  interface: en0\n  flags: <UP>\n",
	}}
	if got := DefaultInterface(context.Background(), cr); got != "en0" {
		t.Fatalf("interface = %q, want en0", got)
	}
}

func TestDefaultGatewayParse(t *testing.T) {
	cr := &scriptedRunner{out: map[string]string{
		"route -n get default": "   route to: default\n    gateway: 10.0.0.1\n  interface: en0\n",
	}}
	if got := DefaultGateway(context.Background(), cr); got != "10.0.0.1" {
		t.Fatalf("gateway = %q, want 10.0.0.1", got)
	}
}

func TestDefaultGatewayEmptyWhenAbsent(t *testing.T) {
	cr := &scriptedRunner{out: map[string]string{"route -n get default": "  interface: en0\n"}}
	if got := DefaultGateway(context.Background(), cr); got != "" {
		t.Fatalf("gateway = %q, want empty", got)
	}
}

// Without an interface-scoped default route, an IP_BOUND_IF upstream socket
// fails with ENETUNREACH once the split-default routes are installed: the
// scoped lookup matches 0.0.0.0/1 -> utun, rejects it for the wrong scope, and
// has nothing en0-scoped to fall back to. Measured on this machine: bound dial
// goes from ENETUNREACH to connected with only this route added.
func TestScopeUplinkAddsScopedDefaultRoute(t *testing.T) {
	fr := &fakeRunner{}
	rm := NewRouteManager("utun9", fr, nil)
	ctx := context.Background()

	if err := rm.ScopeUplink(ctx, "10.0.0.1", "en0"); err != nil {
		t.Fatalf("ScopeUplink: %v", err)
	}
	if !fr.hasCall("route", "-q", "add", "-net", "default", "10.0.0.1", "-ifscope", "en0") {
		t.Fatalf("did not add a scoped default route; calls: %v", fr.calls)
	}

	rm.Teardown(ctx)
	if !fr.hasCall("route", "-q", "delete", "-net", "default", "10.0.0.1", "-ifscope", "en0") {
		t.Fatal("scoped default route was not journalled for teardown")
	}
}

func TestScopeUplinkKeepsAnExistingRouteAndDoesNotDeleteIt(t *testing.T) {
	// A VPN or an earlier run may already own this route. Adopting it is fine;
	// deleting it on our way out is not.
	fr := &failingRunner{out: "route: writing to routing socket: File exists\n"}
	rm := NewRouteManager("utun9", fr, nil)
	ctx := context.Background()

	if err := rm.ScopeUplink(ctx, "10.0.0.1", "en0"); err != nil {
		t.Fatalf("ScopeUplink should tolerate an existing route, got %v", err)
	}
	before := len(fr.calls)
	rm.Teardown(ctx)
	if len(fr.calls) != before {
		t.Fatalf("teardown deleted a route we did not create: %v", fr.calls[before:])
	}
}

func TestScopeUplinkReportsRealFailures(t *testing.T) {
	fr := &failingRunner{out: "route: not in table\n"}
	rm := NewRouteManager("utun9", fr, nil)
	if err := rm.ScopeUplink(context.Background(), "10.0.0.1", "en0"); err == nil {
		t.Fatal("expected an error when route(8) fails for a real reason")
	}
}

func TestBoundDialerConstruction(t *testing.T) {
	if _, err := BoundDialer("lo0", time.Second); err != nil {
		t.Fatalf("BoundDialer(lo0): %v", err)
	}
	if _, err := BoundDialer("nonexistent-iface-xyz", time.Second); err == nil {
		t.Fatal("expected error for nonexistent interface")
	}
}
