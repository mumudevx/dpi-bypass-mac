//go:build !windows

// The two Replay tests whose whole premise is a directory that chmod can make
// undeletable-from.
//
// What they assert that Windows cannot express: chmod(2). Both tests create the
// failure they check for by setting a directory to mode 0o500 — the first so
// that os.Remove of the PAC file inside it fails and the failure is REPORTED
// rather than swallowed, the second so that opening a journal inside it fails
// at all. On Windows os.Chmod writes no ACL: it toggles
// FILE_ATTRIBUTE_READONLY and nothing else, and that attribute is ignored for
// creating and deleting entries in a directory (it is not even honoured for
// directories themselves). The mode argument to os.Mkdir is discarded outright.
// So on Windows the setup step succeeds, denies nothing, and the assertion
// fails because the thing it was waiting to observe never happened —
// TestReplayReportsAFailedRevert reverted cleanly (measured 2026-09-14:
// "1 pending, 1 reverted, 0 skipped, 0 failed") and
// TestReplayReportsAnUnopenableJournal opened its journal.
//
// The properties themselves are not POSIX — "a revert that cannot be carried
// out is reported" and "a journal that cannot be opened is an error" are
// Replay's contract on every platform — so janitor_perm_windows_test.go asserts
// both again, denying access the way Windows actually denies it: a share-mode
// lock for the first, and a path that cannot name a file for the second.
//
// Both function bodies are unchanged from janitor_test.go, where they lived
// until the Windows suite started running. They keep using journalAs and
// pacContent from that file, which carries no build tag.

package janitor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/netstate"
)

// A record whose revert cannot be carried out is REPORTED, not swallowed. A
// partially reverted machine is a fact the user has to be able to read.
func TestReplayReportsAFailedRevert(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "journal.ndjson")
	pacPath := filepath.Join(dir, "sub", "dpb.pac")

	env := netstate.Env{Logf: t.Logf}
	journalAs(t, journalPath, netstate.NewPACFile(pacPath, pacContent), env, os.Getpid())

	// Make the directory unremovable-from, so os.Remove of the PAC fails.
	if err := os.Chmod(filepath.Dir(pacPath), 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(pacPath), 0o755) })

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

func TestReplayReportsAnUnopenableJournal(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "locked")
	if err := os.Mkdir(sub, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })

	_, err := Replay(context.Background(), Options{
		JournalPath: filepath.Join(sub, "journal.ndjson"),
		Env:         netstate.Env{},
	})
	if err == nil {
		t.Fatal("an unopenable journal produced no error")
	}
}
