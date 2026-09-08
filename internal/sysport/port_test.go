package sysport

import "testing"

func TestCapsHasAndMissing(t *testing.T) {
	got := CapProxyAuto | CapRouteWrite
	if !got.Has(CapProxyAuto) {
		t.Errorf("Has(CapProxyAuto) = false, want true")
	}
	if got.Has(CapDNSOverride) {
		t.Errorf("Has(CapDNSOverride) = true, want false")
	}
	// Has(0) is true: an Op needing nothing is satisfied by any Port. This
	// mirrors strategy.Cap, whose comment states the same rule.
	if !got.Has(0) {
		t.Errorf("Has(0) = false, want true")
	}
	want := CapDNSOverride | CapSessionEnv
	if m := got.Missing(want); m != want {
		t.Errorf("Missing(%b) = %b, want %b", want, m, want)
	}
	if m := got.Missing(CapProxyAuto); m != 0 {
		t.Errorf("Missing(CapProxyAuto) = %b, want 0", m)
	}
}
