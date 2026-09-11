//go:build windows

package flow

import "testing"

// TestBindToInterfaceUnknownName checks the one piece of bindToInterface that
// does not need a real socket or a real adapter: an interface name Windows
// cannot resolve must fail before either setsockopt call, the same contract
// dialer_darwin.go's implementation has. This machine cannot run Windows, so
// this file exists to be exercised by whatever CI or developer machine does;
// `GOOS=windows go vet` only confirms it type-checks.
//
// dialer_test.go's TestNetDialerBindsToAnInterface already drives this same
// path indirectly through NetDialer.DialTCP on every OS; this test calls
// bindToInterface directly so a failure here names the function, not the
// dialer plumbing around it.
func TestBindToInterfaceUnknownName(t *testing.T) {
	t.Parallel()
	for _, v6 := range []bool{false, true} {
		if err := bindToInterface(0, "nosuchif-dpb-test", v6); err == nil {
			t.Fatalf("bindToInterface(v6=%v) with an unresolvable name: want an error, got nil", v6)
		}
	}
}
