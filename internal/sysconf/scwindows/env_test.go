//go:build windows

package scwindows

import (
	"context"
	"testing"

	"golang.org/x/sys/windows"
)

// Like every other test in this package, these can only RUN on a Windows host
// and CI does not yet have one (see iphlp_test.go). GOOS=windows go vet
// compiles them and go test -c proves they link; neither proves an assertion
// has ever passed.
//
// Get, Set and Unset go straight to HKCU\Environment through
// golang.org/x/sys/windows/registry, with no injectable seam the way Set's
// netsh calls have one in dns_test.go — the same shape proxy.go's registry
// reads and writes are in. What is tested here is what remains testable
// without one: the empty-name guard each function checks BEFORE ever opening
// a key (so it runs regardless of whether a registry exists to open), and
// the WM_SETTINGCHANGE broadcast's constants and lParam, none of which need a
// live SendMessageTimeoutW call to get wrong.

// TestEnvGetRefusesAnEmptyName: the guard runs before OpenKey, so this needs
// no registry access to check.
func TestEnvGetRefusesAnEmptyName(t *testing.T) {
	c := envCtl{p: &port{}}
	_, ok, err := c.Get(context.Background(), "")
	if err == nil {
		t.Fatal(`Get("") returned no error`)
	}
	if ok {
		t.Error(`Get("") reported ok=true`)
	}
}

// TestEnvSetRefusesAnEmptyName: the guard runs before CreateKey.
func TestEnvSetRefusesAnEmptyName(t *testing.T) {
	c := envCtl{p: &port{}}
	if err := c.Set(context.Background(), "", "value"); err == nil {
		t.Fatal(`Set("", "value") returned no error`)
	}
}

// TestEnvUnsetRefusesAnEmptyName: the guard runs before OpenKey.
func TestEnvUnsetRefusesAnEmptyName(t *testing.T) {
	c := envCtl{p: &port{}}
	if err := c.Unset(context.Background(), ""); err == nil {
		t.Fatal(`Unset("") returned no error`)
	}
}

// TestWMSettingChangeBroadcastConstants pins the four winuser.h values
// broadcastEnvironmentChange relies on. A wrong one here would not fail to
// compile — HWND_BROADCAST off by a bit sends to the wrong handle, a wrong
// WM_SETTINGCHANGE value broadcasts a message nothing is listening for, and a
// missing SMTO_ABORTIFHUNG makes this wait out the full timeout against a
// window Windows has already given up on — and none of that fails loudly
// without a Windows host to observe the broadcast's effect on.
func TestWMSettingChangeBroadcastConstants(t *testing.T) {
	if hwndBroadcast != 0xffff {
		t.Errorf("hwndBroadcast = %#x, want 0xffff (HWND_BROADCAST)", hwndBroadcast)
	}
	if wmSettingChange != 0x001A {
		t.Errorf("wmSettingChange = %#x, want 0x001A (WM_SETTINGCHANGE / WM_WININICHANGE)", wmSettingChange)
	}
	if smtoAbortIfHung != 0x0002 {
		t.Errorf("smtoAbortIfHung = %#x, want 0x0002 (SMTO_ABORTIFHUNG)", smtoAbortIfHung)
	}
	// "Short" is the whole point (a hung window must not stall teardown), so
	// this pins an upper bound rather than an exact figure: any value in a
	// reasonable "short" range is fine, but a value that crept back up toward
	// MSDN's own sample (5000ms) would defeat the reason this exists.
	if settingsBroadcastTimeoutMS <= 0 || settingsBroadcastTimeoutMS > 2000 {
		t.Errorf("settingsBroadcastTimeoutMS = %d, want a short (<= 2000ms) per-window budget", settingsBroadcastTimeoutMS)
	}
}

// TestEnvironmentChangeLParamIsEnvironment pins the exact string MSDN
// documents for this broadcast; see environmentChangeLParam's doc comment.
func TestEnvironmentChangeLParamIsEnvironment(t *testing.T) {
	p, err := environmentChangeLParam()
	if err != nil {
		t.Fatalf("environmentChangeLParam: %v", err)
	}
	if got := windows.UTF16PtrToString(p); got != "Environment" {
		t.Errorf("environmentChangeLParam = %q, want %q", got, "Environment")
	}
}
