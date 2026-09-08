//go:build darwin

package netstate

import (
	"testing"

	"github.com/mumudevx/dpb/internal/sysconf/scdarwin"
)

// TestCheckProxyPair is the half of scdarwin's TestParseProxyStateEnabled that
// tests code which stayed here. Parsing `scutil --proxy` moved to scdarwin;
// deciding whether the parsed state satisfies what an Op asked for did not,
// because that is the Op's contract rather than macOS's output format.
//
// parseProxyState is bound to the exported parser so the assertions below are
// the ones that were always here, run against a real capture rather than a
// hand-built map — a ProxyState assembled by the test would assert that
// checkProxyPair agrees with the test's idea of scutil, which is the thing
// nobody needs to know.
var parseProxyState = scdarwin.ParseProxyState

// scutilProxyPACOn is synthesised, not captured: enabling a system PAC would
// mutate the developer's machine, which this test suite is not allowed to do.
// The key names and the "0"/"1" boolean encoding are taken verbatim from the
// captured testdata/scutil_proxy.txt.
const scutilProxyPACOn = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 8080
  HTTPSProxy : 127.0.0.1
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://127.0.0.1:8080/dpb.pac
  SOCKSEnable : 1
  SOCKSPort : 1080
  SOCKSProxy : 127.0.0.1
}`

func TestCheckProxyPair(t *testing.T) {
	st := parseProxyState(scutilProxyPACOn)
	if err := checkProxyPair(st, "HTTP", "127.0.0.1", 8080); err != nil {
		t.Fatalf("checkProxyPair: %v", err)
	}
	if err := checkProxyPair(st, "HTTP", "127.0.0.1", 9999); err == nil {
		t.Fatal("checkProxyPair accepted the wrong port")
	}
	if err := checkProxyPair(st, "HTTP", "10.0.0.1", 8080); err == nil {
		t.Fatal("checkProxyPair accepted the wrong host")
	}
	if err := checkProxyPair(parseProxyState(fixture(t, "scutil_proxy.txt")), "HTTP", "127.0.0.1", 8080); err == nil {
		t.Fatal("checkProxyPair accepted a disabled proxy")
	}
}
