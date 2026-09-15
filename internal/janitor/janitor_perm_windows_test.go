//go:build windows

package janitor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/netstate"
)

// holdExclusively opens path with NO sharing at all, which is how Windows
// denies access: DeleteFile on a file another handle holds without
// FILE_SHARE_DELETE fails with ERROR_SHARING_VIOLATION. That is the mechanism
// janitor_perm_unix_test.go gets from chmod(dir, 0o500), and it is a mechanism
// Windows really has — unlike os.Chmod, which writes no ACL and denies
// nothing.
func holdExclusively(t *testing.T, path string) {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("path %q: %v", path, err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		0, // share nothing: no other handle may read, write or delete
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("hold %s open exclusively: %v", path, err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(h) })
}

// TestReplayReportsAFailedRevertOnWindows is
// janitor_perm_unix_test.go's TestReplayReportsAFailedRevert with the denial
// Windows can actually make. The property is Replay's, not POSIX's: a record
// whose revert cannot be carried out is REPORTED rather than swallowed,
// because a partially reverted machine is a fact the user has to be able to
// read.
//
// Before this file the Windows run of that test passed its chmod and then
// reverted cleanly, so Replay's failure-reporting path had never executed on
// Windows at all.
func TestReplayReportsAFailedRevertOnWindows(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "journal.ndjson")
	pacPath := filepath.Join(dir, "sub", "dpb.pac")

	env := netstate.Env{Logf: t.Logf}
	journalAs(t, journalPath, netstate.NewPACFile(pacPath, pacContent), env, os.Getpid())

	// The PAC is now on disk. Hold it open with no sharing, so the os.Remove
	// inside pacFileOp.Revert cannot delete it.
	holdExclusively(t, pacPath)

	rep, err := Replay(context.Background(), Options{
		JournalPath: journalPath,
		Env:         env,
		Logf:        t.Logf,
		OwnerAlive:  func(int, time.Time) bool { return false },
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if rep.Clean() || len(rep.Failed) != 1 {
		t.Fatalf("report = %+v, want one failure reported", rep)
	}
}

// TestReplayReportsAnUnopenableJournalOnWindows is the second half of the same
// split. A journal path that names a DIRECTORY cannot be opened as a file on
// any platform, and unlike a 0o500 parent directory it is a denial Windows
// honours, so the "an unopenable journal is an error, not an empty report"
// contract is asserted here rather than assumed.
func TestReplayReportsAnUnopenableJournalOnWindows(t *testing.T) {
	dir := t.TempDir()
	notAFile := filepath.Join(dir, "journal.ndjson")
	if err := os.Mkdir(notAFile, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_, err := Replay(context.Background(), Options{
		JournalPath: notAFile,
		Env:         netstate.Env{},
	})
	if err == nil {
		t.Fatal("an unopenable journal produced no error")
	}
}
