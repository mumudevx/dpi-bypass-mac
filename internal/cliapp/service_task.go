package cliapp

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// This file is the platform-free half of service_task_windows.go: the
// decisions its Windows-only observers hand to it, kept where a test can
// actually RUN them.
//
// Everything here is a pure function over values that a process snapshot, a
// file read or an ACL produced. That split is not cosmetic. The Scheduled Task
// mechanism cannot be executed anywhere in this repository — there is no
// Windows machine — so a mistake in the part that DECIDES would otherwise be
// caught only by a type-check (`GOOS=windows go vet`), which is exactly how
// both of the defects this file was created for got in: a liveness observer
// that counted the process asking the question, and a file read denied by an
// ACL reported as a failed verification. Both were one `if` away from correct
// and neither was reachable by any test.
//
// The same reasoning service_windows.go gives for winServiceImagePath, and
// service_task_windows.go's own header for parseTaskXML, applied one level
// further out: if a decision can be separated from the syscall that fed it,
// it is separated, so the decision is testable on any host.

// winProcCounts reports whether one entry in a Windows process snapshot counts
// as "the job is running".
//
// # Why the caller's own PID is excluded
//
// The snapshot is walked by `dpb service status|stop|install`, and the process
// running those verbs is itself called dpb.exe. Without this exclusion every
// walk finds a match on its first question — ITSELF — with three consequences,
// each of which was a real defect:
//
//   - `dpb service stop` ends the task, polls for the process to disappear,
//     keeps seeing the caller for the whole 30 s budget and then fails with
//     "dpb is still running dpb after 30s". The user-scope stop could never
//     succeed.
//   - `dpb service status` printed "state running" on a machine whose logon
//     task was dead.
//   - installLogonTask's `if !running` guard was unreachable, so a task that
//     registered but never started reported "installed".
//
// The exclusion follows this package's own precedent: coverage.go's parseLsof
// drops `cur.PID == selfPID || cur.PID == os.Getpid()` for the same reason —
// counting dpb as its own client would report dpb as its own user.
//
// # What this deliberately still does NOT distinguish
//
// Matching is by base name, so a SECOND dpb.exe that is not the task's — the
// same user's foreground `dpb run`, another user's session on a shared
// machine, or an unrelated binary that happens to be named dpb.exe — still
// counts. That imprecision is accepted rather than overlooked, and it is now
// bounded: with the caller excluded, a false positive can only ever make
// `service stop` report "it is still running" or `service status` over-report,
// never make a correct stop fail by construction.
//
// The two ways to narrow it further were both weighed and declined.
// QueryFullProcessImageName would compare the full image path, but reading it
// means trusting that API's access check not to fail quietly for a process
// this caller has every right to see, and a failure there has no honest
// answer: "counts" reintroduces the false positive and "does not count" hides
// the real task. ProcessIdToSessionId has the identical problem (MSDN
// documents ERROR_ACCESS_DENIED for it), and Task Scheduler exposes no PID for
// its action to key off instead. One more Windows API whose quiet failure
// would have to be guessed at is a worse trade than a limitation that is
// written down.
func winProcCounts(name string, pid int, exeBase string, selfPID int) bool {
	if pid == 0 || pid == selfPID {
		return false
	}
	return strings.EqualFold(name, exeBase)
}

// taskFileState is what the file observer — %WINDIR%\System32\Tasks\<name>,
// the copy Task Scheduler persists and the only observer that is independent
// of the schtasks command dpb registered the task with — managed to
// contribute.
//
// Five states rather than a bool, because "the definition says something
// wrong" and "I was not allowed to look" are not the same evidence and must
// not lead to the same action. The distinction is this project's oldest rule
// (service.go's serviceStatus comment lists the defects it has already cost:
// a ProcessStart reading a failed query as "dead", an envCtl.Get reading a
// failed read as "unset", a Configured turning DHCP DNS into permanent
// static, a proxy revert leaving ProxyEnable=1) and it applies with more
// force here than anywhere, because the action on "verification failed" is to
// DELETE the task.
type taskFileState int

const (
	// taskFileRead: the bytes arrived and parsed. The strong checks — Command,
	// Arguments, LogonTrigger — can run, and this is the only state in which
	// they mean anything.
	taskFileRead taskFileState = iota

	// taskFileAbsent: the observer looked and there is no such file. An
	// answer, not a failure.
	taskFileAbsent

	// taskFileDenied: an ACL refused the read.
	//
	// This is the NORMAL state on the path the README advertises as the
	// supported way to run proxy mode. %WINDIR%\System32\Tasks does not grant
	// standard users read access — which is precisely why `schtasks /query`
	// exists for them — so an unelevated `dpb service install` gets "Access is
	// denied" from a task it created perfectly. Reported as a failed
	// verification, it made rollbackLogonTask delete a good install and left
	// the supported install path with no way to succeed at all.
	taskFileDenied

	// taskFileUnreachable: the read failed for some other reason (a sharing
	// violation, an I/O error, GetWindowsDirectory itself failing). Also "I
	// could not look" — it is no more evidence about the task's contents than
	// the ACL case is.
	taskFileUnreachable

	// taskFileBroken: the bytes arrived and were not a task definition. The
	// one failure state that IS evidence about the task itself, because it is
	// the only one where dpb actually saw what Task Scheduler wrote down.
	taskFileBroken
)

// couldNotLook reports whether this state means the file observer abstained,
// as opposed to answering. Callers must fall back to the schtasks observer
// when it is true, and must never treat it as grounds for undoing anything.
func (s taskFileState) couldNotLook() bool {
	return s == taskFileDenied || s == taskFileUnreachable
}

// classifyTaskFile turns readLogonTaskFile's (found, err) pair into the state
// above.
//
// readLogonTaskFile's contract is what makes this decidable: a missing file is
// (false, nil), a parse failure is (true, err) — the bytes were read — and
// every failure to obtain the bytes at all is (false, err).
func classifyTaskFile(found bool, err error) taskFileState {
	switch {
	case err == nil && found:
		return taskFileRead
	case err == nil:
		return taskFileAbsent
	case found:
		return taskFileBroken
	case errors.Is(err, fs.ErrPermission):
		// ERROR_ACCESS_DENIED reaches Go as fs.ErrPermission
		// (syscall.Errno.Is maps it), so this is the ACL case named in
		// taskFileDenied and not a guess from the error text — which would be
		// localised anyway, the hazard service_task_windows.go's header spends
		// its longest paragraph on.
		return taskFileDenied
	default:
		return taskFileUnreachable
	}
}

// logonTaskObserverNote is the sentence dpb prints when the file observer did
// not contribute and schtasks answered instead.
//
// It exists because "say so" is half of the fix: falling back silently would
// leave a user believing an install was confirmed against the definition Task
// Scheduler persisted when it was only confirmed against the tool that wrote
// it. path and err are passed in rather than resolved here so this stays a
// pure function on every platform.
func logonTaskObserverNote(state taskFileState, path string, err error) string {
	switch state {
	case taskFileDenied:
		return fmt.Sprintf("%s is not readable without Administrator — that is what its ACL is for — "+
			"so schtasks is the only observer that answered; the task itself is fine", path)
	case taskFileUnreachable:
		return fmt.Sprintf("%s could not be read (%v), so schtasks is the only observer that answered", path, err)
	case taskFileAbsent:
		return fmt.Sprintf("%s does not exist, but schtasks knows the task; schtasks is the only observer that answered", path)
	default:
		return ""
	}
}
