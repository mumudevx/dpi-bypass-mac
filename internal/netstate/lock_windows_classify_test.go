//go:build windows

package netstate

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// Only ERROR_INVALID_PARAMETER is evidence of death. Every other Win32 failure
// is "could not tell", and this is the list that matters in practice:
// ERROR_ACCESS_DENIED is what OpenProcess answers for a dpb running as SYSTEM
// or under another desktop user, which is a supported configuration, not a
// corner case.
func TestOnlyAnImpossiblePidReadsAsDead(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"no such process", windows.ERROR_INVALID_PARAMETER, true},
		{"refused: another account or SYSTEM", windows.ERROR_ACCESS_DENIED, false},
		{"handle torn down under us", windows.ERROR_INVALID_HANDLE, false},
		{"out of memory", windows.ERROR_NOT_ENOUGH_MEMORY, false},
		{"not a Win32 error at all", errors.New("something else"), false},
		{"no error", nil, false},
	} {
		if got := noSuchProcess(tc.err); got != tc.want {
			t.Errorf("%s: noSuchProcess(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

// A process we cannot open is still a process. pid 4 is the System process:
// it always exists, and an unelevated dpb is refused when it asks to open it.
// The old code read that refusal as "no start time, no name, therefore dead",
// which is the input that makes Replay tear a live run's networking down.
//
// The assertion holds either way round, which is what makes it a safe one to
// run anywhere: elevated, the open succeeds and the process is present;
// unelevated, the open is refused and the process is unknown. Both are alive.
func TestAProcessWeCannotOpenIsNotReportedDead(t *testing.T) {
	const systemPID = 4
	if _, ok := processIdentity(systemPID); !ok {
		t.Error("processIdentity(System) reported dead; a refused query must read as alive")
	}
}

// A pid that cannot exist is the one case that must read as dead, or a stale
// lock record would never be cleared.
func TestAnImpossiblePidIsReportedDead(t *testing.T) {
	for _, pid := range []int{0, -1, -2} {
		if _, ok := processIdentity(pid); ok {
			t.Errorf("processIdentity(%d) reported a live process", pid)
		}
	}
}

// The liveness question is asked of the handle's signalled state, which is
// defined in both directions, rather than of GetProcessTimes' lpExitTime, which
// MSDN documents as undefined while the process has not exited. Our own process
// is the one case whose answer is known without ambiguity.
func TestProcessExitedSaysRunningForOurselves(t *testing.T) {
	h, err := openProcess(os.Getpid())
	if err != nil {
		t.Fatalf("openProcess(self): %v", err)
	}
	defer windows.CloseHandle(h)

	exited, known := processExited(h)
	if !known {
		t.Fatal("processExited could not answer for this very process")
	}
	if exited {
		t.Fatal("processExited says this running process has exited")
	}
}

// unknownComm is not a name, and sameExecutable must not test it as one: an
// unidentifiable live process is treated as a peer, because calling it a
// stranger is what lets Replay revert its owner's settings.
func TestSameExecutableTreatsAnUnknownNameAsOurs(t *testing.T) {
	if !sameExecutable(unknownComm) {
		t.Error("an unidentified process was called a stranger")
	}
	if !sameExecutable(`C:\Program Files\dpb\` + selfComm()) {
		t.Error("our own image path was called a stranger")
	}
	if sameExecutable(`C:\Windows\System32\notepad.exe`) {
		t.Error("an unrelated program was accepted as us")
	}
}
