//go:build windows

// This file tests service_windows.go's decision logic the same way
// tunname_windows_test.go tests validateTunName: the pure computations a
// mistake in would misinform an install or a status read, kept apart from the
// registry and SCM calls that surround them and cannot run without a real
// service control manager.
//
// Nothing here can be executed in this environment — there is no Windows
// machine to run it on — but `GOOS=windows go test -c ./internal/cliapp/`
// links it and `GOOS=windows go vet ./...` type-checks it, which is what a
// change to this logic gets checked against until a Windows CI runner exists.
// The expected strings in TestWinServiceImagePathMatchesWhatCreateServiceStores
// were produced by running syscall.EscapeArg's published algorithm
// (GOROOT/src/syscall/exec_windows.go) standalone on darwin — it is pure byte
// manipulation with no OS call in it — rather than guessed by hand, since a
// wrong "want" here would be a defect wearing a passing test's clothes.

package cliapp

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// TestWinServiceImagePathMatchesWhatCreateServiceStores is winServiceImagePath's
// own comment made executable: verifyWinService's registry check is only as
// good as this reproducing mgr.CreateService's escaping exactly, not
// approximately.
func TestWinServiceImagePathMatchesWhatCreateServiceStores(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		exe  string
		args []string
		want string
	}{
		{
			name: "exe with a space is quoted whole",
			exe:  `C:\Program Files\dpb\dpb.exe`,
			want: `"C:\Program Files\dpb\dpb.exe"`,
		},
		{
			name: "plain exe and arg need no escaping",
			exe:  `C:\dpb\dpb.exe`,
			args: []string{"run"},
			want: `C:\dpb\dpb.exe run`,
		},
		{
			name: "an arg with a space is quoted on its own",
			exe:  `C:\dpb\dpb.exe`,
			args: []string{"run", "--profile", "turkey line"},
			want: `C:\dpb\dpb.exe run --profile "turkey line"`,
		},
		{
			name: "exe needing quotes and a plain arg both appear",
			exe:  `C:\Program Files\dpb\dpb.exe`,
			args: []string{"run"},
			want: `"C:\Program Files\dpb\dpb.exe" run`,
		},
		{
			name: "an embedded quote is backslash-escaped",
			exe:  `C:\dpb\dpb.exe`,
			args: []string{`a"b`},
			want: `C:\dpb\dpb.exe a\"b`,
		},
		{
			name: "a trailing backslash is doubled before the closing quote",
			exe:  `C:\dpb\dpb.exe`,
			args: []string{`C:\some dir\`},
			want: `C:\dpb\dpb.exe "C:\some dir\\"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := winServiceImagePath(tc.exe, tc.args); got != tc.want {
				t.Errorf("winServiceImagePath(%q, %q) = %q, want %q", tc.exe, tc.args, got, tc.want)
			}
		})
	}
}

// TestServiceRecoveryActionsShape checks the SCM sees the same restart-forever
// shape service.go's comment on serviceThrottle describes for launchd's
// KeepAlive, at the SAME delay — not a Windows-specific number invented here.
func TestServiceRecoveryActionsShape(t *testing.T) {
	t.Parallel()
	got := serviceRecoveryActions()
	want := time.Duration(serviceThrottle) * time.Second

	// Three, not one: MSDN's SERVICE_FAILURE_ACTIONS performs element [N-1] on
	// the Nth failure and repeats the last element once N exceeds the array, so
	// this needs at least two entries to actually mean "unbounded", and the
	// comment on serviceRecoveryActions asks for three so it reads that way
	// rather than as "restart once".
	if len(got) < 2 {
		t.Fatalf("serviceRecoveryActions() has %d entries, want at least 2 so a repeated "+
			"failure keeps restarting rather than stopping after the array runs out", len(got))
	}
	for i, a := range got {
		if a.Type != mgr.ServiceRestart {
			t.Errorf("action %d has Type %d, want mgr.ServiceRestart (%d)", i, a.Type, mgr.ServiceRestart)
		}
		if a.Delay != want {
			t.Errorf("action %d has Delay %s, want %s (serviceThrottle, the same reasoning "+
				"as launchd's ThrottleInterval)", i, a.Delay, want)
		}
	}
}

// TestStatusMechanismRefusesTheUnsupportedLogonTaskMechanism exercises the one
// branch of statusMechanism that needs neither the registry nor the SCM: a
// scope bound to winLogonTask, the mechanism that does not exist yet. Nothing
// can have been installed under it, so "not found, nothing to be unsure about"
// has to be unconditional rather than the product of a lookup.
func TestStatusMechanismRefusesTheUnsupportedLogonTaskMechanism(t *testing.T) {
	t.Parallel()
	g := &globals{}
	s := serviceScope{system: false, mech: winLogonTask}

	found, running, cannotTell := statusMechanism(context.Background(), g, s)
	if found {
		t.Error("found = true for a mechanism whose install refuses by name")
	}
	if running {
		t.Error("running = true for a mechanism whose install refuses by name")
	}
	if cannotTell != nil {
		t.Errorf("cannotTell = %v, want nil: there is no third answer when nothing can be "+
			"installed in the first place", cannotTell)
	}
}

// TestUnsupportedLogonTaskNamesTheVerbAndPointsAtSystem checks the refusal
// every winLogonTask verb returns names the verb that was actually typed and
// points at the mechanism that works, per the by-name-refusal discipline
// service_windows.go's header states for internal/netwatch/route_other.go and
// internal/emit/stub_other.go.
func TestUnsupportedLogonTaskNamesTheVerbAndPointsAtSystem(t *testing.T) {
	t.Parallel()
	for _, verb := range []string{"install", "uninstall", "start", "stop"} {
		err := unsupportedLogonTask(verb)
		if err == nil {
			t.Fatalf("unsupportedLogonTask(%q) = nil", verb)
		}
		msg := err.Error()
		if !strings.Contains(msg, verb) {
			t.Errorf("unsupportedLogonTask(%q) = %q, does not name the verb that was refused", verb, msg)
		}
		if !strings.Contains(msg, "--system") {
			t.Errorf("unsupportedLogonTask(%q) = %q, does not point at the mechanism that works", verb, msg)
		}
	}
}

// TestWinStateNameMapsEveryKnownState locks winStateName's table down: `sc
// query` and the event log print these numbers, so a state this tool has no
// name for must fall back to printing the number rather than "unknown".
func TestWinStateNameMapsEveryKnownState(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		st   svc.State
		want string
	}{
		{svc.Stopped, "stopped"},
		{svc.StartPending, "starting"},
		{svc.StopPending, "stopping"},
		{svc.Running, "running"},
		{svc.ContinuePending, "resuming"},
		{svc.PausePending, "pausing"},
		{svc.Paused, "paused"},
		{svc.State(99), "state 99"}, // not a state x/sys defines
	} {
		if got := winStateName(tc.st); got != tc.want {
			t.Errorf("winStateName(%d) = %q, want %q", tc.st, got, tc.want)
		}
	}
}

// TestWinStatusTextPrefersTheDpbExitCodeOverWin32 walks every branch of
// winStatusText's switch: a running service reports plainly regardless of
// stale exit codes left from a previous stop, a dpb-reported exit wins over a
// Win32 one, ERROR_SERVICE_SPECIFIC_ERROR left in Win32ExitCode with no
// specific code alongside it is the sentinel meaning "look elsewhere" rather
// than a real error to print, and ordinary Win32 failures print their number.
func TestWinStatusTextPrefersTheDpbExitCodeOverWin32(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		st   svc.Status
		want string
	}{
		{
			name: "a running service ignores stale exit codes",
			st: svc.Status{State: svc.Running, Win32ExitCode: 1067,
				ServiceSpecificExitCode: 5},
			want: "running",
		},
		{
			name: "a dpb exit code is reported by name",
			st:   svc.Status{State: svc.Stopped, ServiceSpecificExitCode: 5},
			want: "stopped (dpb exit 5)",
		},
		{
			name: "an ordinary win32 failure is reported by number",
			st:   svc.Status{State: svc.Stopped, Win32ExitCode: 1067},
			want: "stopped (win32 error 1067)",
		},
		{
			name: "the service-specific sentinel with no specific code is not printed as a win32 error",
			st: svc.Status{State: svc.Stopped,
				Win32ExitCode: uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR)},
			want: "stopped",
		},
		{
			name: "a clean stop reports nothing extra",
			st:   svc.Status{State: svc.Stopped},
			want: "stopped",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := winStatusText(tc.st); got != tc.want {
				t.Errorf("winStatusText(%+v) = %q, want %q", tc.st, got, tc.want)
			}
		})
	}
}

// TestWinStartTypeNameMapsKnownValues locks winStartTypeName's table down: the
// registry's Start value is what statusMechanism prints as "startup", and an
// unrecognised value should say its number rather than something misleading.
func TestWinStartTypeNameMapsKnownValues(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		v    uint64
		want string
	}{
		{uint64(windows.SERVICE_AUTO_START), "automatic (starts at boot)"},
		{uint64(windows.SERVICE_DEMAND_START), "manual"},
		{uint64(windows.SERVICE_DISABLED), "disabled"},
		{999, "start type 999"},
	} {
		if got := winStartTypeName(tc.v); got != tc.want {
			t.Errorf("winStartTypeName(%d) = %q, want %q", tc.v, got, tc.want)
		}
	}
}
