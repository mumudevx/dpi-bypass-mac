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

func TestBoundDialerConstruction(t *testing.T) {
	if _, err := BoundDialer("lo0", time.Second); err != nil {
		t.Fatalf("BoundDialer(lo0): %v", err)
	}
	if _, err := BoundDialer("nonexistent-iface-xyz", time.Second); err == nil {
		t.Fatal("expected error for nonexistent interface")
	}
}
