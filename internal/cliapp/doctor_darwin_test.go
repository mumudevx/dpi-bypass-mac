//go:build darwin

package cliapp

import (
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/paths"
)

// These pin the darwin half of Task 5's platform split: checkPaths,
// checkSystemProxy and checkProxyEnv now call out to doctor_darwin.go /
// doctor_windows.go for their Remedy text, and this is what proves the
// darwin side still says exactly what it said before the split.

func TestNotWritableRemedyNamesSudoChownWhenNotElevated(t *testing.T) {
	got := notWritableRemedy(paths.Layout{Elevated: false, User: "alice", StateDir: "/tmp/dpb-state"})
	if !strings.Contains(got, "sudo chown") || !strings.Contains(got, "alice") || !strings.Contains(got, "/tmp/dpb-state") {
		t.Errorf("remedy = %q, want it to name sudo chown, the user and the directory", got)
	}
}

func TestNotWritableRemedyElevatedPointsAtPermissions(t *testing.T) {
	got := notWritableRemedy(paths.Layout{Elevated: true, StateDir: "/tmp/dpb-state"})
	if !strings.Contains(got, "check the permissions on /tmp/dpb-state") {
		t.Errorf("remedy = %q", got)
	}
	if strings.Contains(got, "sudo") {
		t.Errorf("remedy = %q, an already-elevated dpb should not be told to sudo", got)
	}
}

func TestProxyInspectRemedyNamesScutil(t *testing.T) {
	if got := proxyInspectRemedy(); !strings.Contains(got, "scutil --proxy") {
		t.Errorf("remedy = %q", got)
	}
}

func TestProxyEnvRemedyNamesLaunchctl(t *testing.T) {
	if got := proxyEnvRemedy(); !strings.Contains(got, "launchctl getenv") {
		t.Errorf("remedy = %q", got)
	}
}

func TestProxySystemNameIsMacOS(t *testing.T) {
	if got := proxySystemName(); got != "macOS" {
		t.Errorf("proxySystemName() = %q, want macOS", got)
	}
}

func TestPlatformChecksIsEmptyOnDarwin(t *testing.T) {
	if got := platformChecks(paths.Layout{}); got != nil {
		t.Errorf("platformChecks() = %+v, want nil so darwin's check list is unchanged", got)
	}
}
