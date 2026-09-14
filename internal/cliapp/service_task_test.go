package cliapp

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
)

// These tests run on every platform, which is the whole reason
// service_task.go exists: the Scheduled Task mechanism itself cannot be
// executed here, so its DECISIONS are kept somewhere a test can reach them.
// service_task_windows_test.go covers the parts that need the windows build
// tag and can only be type-checked.
//
// None of these are named TestService*: that prefix names the darwin service
// suite, whose count is asserted elsewhere, and these belong to the logon
// task's decision logic rather than to that suite.

// TestWinProcCountsExcludesTheCaller is Critical 1 made executable. The
// snapshot walk is driven by dpb.exe asking about dpb.exe, so an observer
// that matches on the name alone always finds the caller — see winProcCounts'
// comment for the three defects that produced.
func TestWinProcCountsExcludesTheCaller(t *testing.T) {
	t.Parallel()
	const self = 4242
	for _, tc := range []struct {
		name    string
		procN   string
		pid     int
		exeBase string
		want    bool
	}{
		{
			name:    "the caller's own process never counts",
			procN:   "dpb.exe",
			pid:     self,
			exeBase: "dpb.exe",
			want:    false,
		},
		{
			name:    "another dpb.exe — the task's own action — does count",
			procN:   "dpb.exe",
			pid:     self + 1,
			exeBase: "dpb.exe",
			want:    true,
		},
		{
			name:    "Windows' case-insensitive file names are matched case-insensitively",
			procN:   "DPB.EXE",
			pid:     self + 1,
			exeBase: "dpb.exe",
			want:    true,
		},
		{
			name:    "an unrelated process does not count",
			procN:   "explorer.exe",
			pid:     self + 1,
			exeBase: "dpb.exe",
			want:    false,
		},
		{
			name:    "PID 0 (the idle process) never counts even under a matching name",
			procN:   "dpb.exe",
			pid:     0,
			exeBase: "dpb.exe",
			want:    false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := winProcCounts(tc.procN, tc.pid, tc.exeBase, self); got != tc.want {
				t.Errorf("winProcCounts(%q, %d, %q, %d) = %v, want %v",
					tc.procN, tc.pid, tc.exeBase, self, got, tc.want)
			}
		})
	}
}

// TestWinProcCountsCannotReportTheStopVerbAsAFailure is the same rule stated
// as the consequence that mattered: a stop polls for the process to be GONE,
// so a walk over a snapshot whose only dpb.exe is the caller must answer
// "not running" or the user-scope stop can never succeed.
func TestWinProcCountsCannotReportTheStopVerbAsAFailure(t *testing.T) {
	t.Parallel()
	self := os.Getpid()
	// The snapshot a `dpb service stop` sees one moment after the task's own
	// process has exited: dpb.exe is still in it, because the caller is
	// dpb.exe.
	snapshot := []struct {
		name string
		pid  int
	}{
		{"System", 4},
		{"explorer.exe", self - 7},
		{"dpb.exe", self},
	}
	for _, e := range snapshot {
		if winProcCounts(e.name, e.pid, "dpb.exe", self) {
			t.Fatalf("winProcCounts counted %s (pid %d) as a live task while the caller is pid %d",
				e.name, e.pid, self)
		}
	}
}

// TestClassifyTaskFileSeparatesCouldNotLookFromVerificationFailed is Critical
// 2's decision. An ACL-denied read is the NORMAL case on the unelevated path
// the README advertises, and treating it as a failed verification made
// rollbackLogonTask delete a task that had been created correctly.
func TestClassifyTaskFileSeparatesCouldNotLookFromVerificationFailed(t *testing.T) {
	t.Parallel()
	denied := fmt.Errorf(`read C:\Windows\System32\Tasks\dpb: %w`, fs.ErrPermission)
	for _, tc := range []struct {
		name     string
		found    bool
		err      error
		want     taskFileState
		abstains bool
	}{
		{
			name:  "read and parsed: the strong checks can run",
			found: true,
			want:  taskFileRead,
		},
		{
			name: "no such file: an answer, not a failure",
			want: taskFileAbsent,
		},
		{
			name:     "Access is denied: I could not look",
			err:      denied,
			want:     taskFileDenied,
			abstains: true,
		},
		{
			name:     "any other read failure: also I could not look",
			err:      errors.New("locate the Windows directory: the system cannot find the path"),
			want:     taskFileUnreachable,
			abstains: true,
		},
		{
			name:  "the bytes arrived and did not parse: evidence about the task itself",
			found: true,
			err:   errors.New("parse: expected element type <Task>"),
			want:  taskFileBroken,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := classifyTaskFile(tc.found, tc.err)
			if got != tc.want {
				t.Errorf("classifyTaskFile(%v, %v) = %v, want %v", tc.found, tc.err, got, tc.want)
			}
			if got.couldNotLook() != tc.abstains {
				t.Errorf("classifyTaskFile(%v, %v).couldNotLook() = %v, want %v",
					tc.found, tc.err, got.couldNotLook(), tc.abstains)
			}
		})
	}
}

// TestClassifyTaskFileReadsAWrappedPermissionError checks the ACL case is
// recognised through the wrapping readLogonTaskFile actually applies —
// `fmt.Errorf("read %s: %w", path, err)` — rather than only through a bare
// sentinel, since the bare form is not what any caller ever sees.
func TestClassifyTaskFileReadsAWrappedPermissionError(t *testing.T) {
	t.Parallel()
	inner := &fs.PathError{Op: "open", Path: `C:\Windows\System32\Tasks\dpb`, Err: fs.ErrPermission}
	wrapped := fmt.Errorf(`read C:\Windows\System32\Tasks\dpb: %w`, inner)
	if got := classifyTaskFile(false, wrapped); got != taskFileDenied {
		t.Errorf("classifyTaskFile(false, %v) = %v, want taskFileDenied", wrapped, got)
	}
}

// TestLogonTaskObserverNoteSaysWhichObserverAnswered covers the other half of
// the fix: falling back to schtasks silently would let a user believe the
// install was confirmed against the definition Task Scheduler persisted when
// it was confirmed only against the tool that wrote it.
func TestLogonTaskObserverNoteSaysWhichObserverAnswered(t *testing.T) {
	t.Parallel()
	const path = `C:\Windows\System32\Tasks\dpb`
	err := errors.New("the process cannot access the file")

	for _, tc := range []struct {
		state taskFileState
		want  []string
	}{
		{state: taskFileDenied, want: []string{path, "Administrator", "schtasks"}},
		{state: taskFileUnreachable, want: []string{path, err.Error(), "schtasks"}},
		{state: taskFileAbsent, want: []string{path, "does not exist", "schtasks"}},
	} {
		note := logonTaskObserverNote(tc.state, path, err)
		if note == "" {
			t.Errorf("logonTaskObserverNote(%v, ...) = \"\", want a sentence naming the observer that answered", tc.state)
			continue
		}
		for _, want := range tc.want {
			if !strings.Contains(note, want) {
				t.Errorf("logonTaskObserverNote(%v, ...) = %q, want it to mention %q", tc.state, note, want)
			}
		}
	}

	// A state where the file observer DID answer has no note: printing one
	// would claim a fallback that did not happen.
	for _, state := range []taskFileState{taskFileRead, taskFileBroken} {
		if note := logonTaskObserverNote(state, path, err); note != "" {
			t.Errorf("logonTaskObserverNote(%v, ...) = %q, want \"\" — the file observer answered", state, note)
		}
	}
}
