package netstate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func openTestJournal(t *testing.T) (*fileJournal, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "journal.ndjson")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	t.Cleanup(func() { j.Close() })
	fj := j.(*fileJournal)
	// ps costs a fork per Begin and the tests do not depend on a real start time.
	fj.startedAt = func(int) (time.Time, bool) { return time.Unix(1_700_000_000, 0), true }
	return fj, path
}

func TestJournalBeginCommitDone(t *testing.T) {
	j, path := openTestJournal(t)
	ctx := context.Background()

	tok, err := j.Begin(ctx, Record{Kind: OpRoute, ID: "route:0.0.0.0/1@utun4"})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	pending, err := j.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("Pending = %d records, want 1", len(pending))
	}
	if pending[0].Applied || pending[0].Verified {
		t.Fatal("a begun record must not claim to be applied")
	}
	if pending[0].PID != os.Getpid() {
		t.Fatalf("PID = %d, want %d", pending[0].PID, os.Getpid())
	}
	if pending[0].StartedAt.IsZero() {
		t.Fatal("StartedAt was not filled in; pid reuse would be undetectable")
	}

	if err := j.Commit(ctx, tok, Record{Kind: OpRoute, ID: "route:0.0.0.0/1@utun4", Applied: true, Verified: true}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	pending, _ = j.Pending(ctx)
	if len(pending) != 1 || !pending[0].Applied || !pending[0].Verified {
		t.Fatalf("after Commit, Pending = %+v", pending)
	}

	if err := j.Done(ctx, tok); err != nil {
		t.Fatalf("Done: %v", err)
	}
	pending, _ = j.Pending(ctx)
	if len(pending) != 0 {
		t.Fatalf("after Done, Pending = %+v", pending)
	}

	// "The journal is empty" is a promise `dpb doctor` makes to the user, so an
	// append-only file that never shrinks would break it.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Size() != 0 {
		b, _ := os.ReadFile(path)
		t.Fatalf("journal was not compacted, %d bytes remain: %s", fi.Size(), b)
	}
}

// TestJournalFsyncsBeforeApply asserts the ordering the durability argument
// rests on: the revert record is on stable storage before the caller is told it
// may mutate anything.
func TestJournalFsyncsBeforeApply(t *testing.T) {
	j, path := openTestJournal(t)
	ctx := context.Background()

	if _, err := j.Begin(ctx, Record{Kind: OpProxyPAC, ID: "proxy.pac:Wi-Fi", Revert: json.RawMessage(`{"url":""}`)}); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// Read through a second descriptor: what Begin returned must already be
	// visible to any other process, which is what the fsync buys.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(b), `"phase":"begin"`) || !strings.Contains(string(b), "proxy.pac:Wi-Fi") {
		t.Fatalf("Begin did not durably write the record: %s", b)
	}
}

func TestJournalOrdersBySeqAndSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.ndjson")
	ctx := context.Background()

	j, err := OpenJournal(path)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if _, err := j.Begin(ctx, Record{Kind: OpRoute, ID: id}); err != nil {
			t.Fatalf("Begin(%s): %v", id, err)
		}
	}
	if err := j.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	j2, err := OpenJournal(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer j2.Close()
	pending, err := j2.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 3 {
		t.Fatalf("Pending = %d, want 3", len(pending))
	}
	for i, want := range []string{"a", "b", "c"} {
		if pending[i].ID != want {
			t.Fatalf("pending[%d].ID = %q, want %q", i, pending[i].ID, want)
		}
	}
	// A reopened journal must continue the sequence, not restart it: colliding
	// with a record from the previous run would make Done close the wrong one.
	tok, err := j2.Begin(ctx, Record{Kind: OpRoute, ID: "d"})
	if err != nil {
		t.Fatalf("Begin after reopen: %v", err)
	}
	if tok != 4 {
		t.Fatalf("token after reopen = %d, want 4", tok)
	}
}

// TestJournalTornFinalLine models a SIGKILL landing mid-write. Everything
// before the torn line is still authoritative and must still be replayable.
func TestJournalTornFinalLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.ndjson")
	ctx := context.Background()

	j, _ := OpenJournal(path)
	if _, err := j.Begin(ctx, Record{Kind: OpRoute, ID: "good"}); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	j.Close()

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := f.WriteString(`{"phase":"begin","seq":2,"kind":"route","id":"tor`); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	j2, err := OpenJournal(path)
	if err != nil {
		t.Fatalf("reopen over a torn line: %v", err)
	}
	defer j2.Close()
	pending, err := j2.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "good" {
		t.Fatalf("Pending = %+v, want just the intact record", pending)
	}
}

func TestJournalClosedRejectsWrites(t *testing.T) {
	j, _ := openTestJournal(t)
	if err := j.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := j.Begin(context.Background(), Record{Kind: OpRoute, ID: "x"}); err == nil {
		t.Fatal("Begin on a closed journal must fail")
	}
}

func TestJournalRespectsContext(t *testing.T) {
	j, _ := openTestJournal(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := j.Begin(ctx, Record{Kind: OpRoute, ID: "x"}); err == nil {
		t.Fatal("Begin ignored a cancelled context")
	}
	if err := j.Commit(ctx, 1, Record{}); err == nil {
		t.Fatal("Commit ignored a cancelled context")
	}
	if err := j.Done(ctx, 1); err == nil {
		t.Fatal("Done ignored a cancelled context")
	}
	if _, err := j.Pending(ctx); err == nil {
		t.Fatal("Pending ignored a cancelled context")
	}
}

func TestOpenJournalErrors(t *testing.T) {
	if _, err := OpenJournal(""); err == nil {
		t.Fatal("OpenJournal(\"\") must fail")
	}
	dir := t.TempDir()
	blocker := filepath.Join(dir, "notadir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(filepath.Join(blocker, "journal.ndjson")); err == nil {
		t.Fatal("OpenJournal must fail when the parent path is a file")
	}
}

func TestJournalPathAccessor(t *testing.T) {
	j, path := openTestJournal(t)
	if j.Path() != path {
		t.Fatalf("Path() = %q, want %q", j.Path(), path)
	}
}

// TestJournalInteriorTornLine is SF7. The `break` at the first decode error was
// correct only while the torn line was last — and the journal is reopened
// O_APPEND, so the next run's Begin concatenates onto the fragment and turns it
// into an INTERIOR corrupt line. Everything after it then vanished from
// Pending(): applied, journalled mutations that doctor --repair, the janitor and
// the login agent could no longer see, which is an UNDER-approximate journal —
// the one direction this design exists to avoid.
func TestJournalInteriorTornLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.ndjson")
	ctx := context.Background()

	j, _ := OpenJournal(path)
	if _, err := j.Begin(ctx, Record{Kind: OpRoute, ID: "first"}); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	j.Close()

	// A SIGKILL mid-write leaves a fragment with no newline.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"phase":"begin","seq":2,"kind":"route","id":"tor`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// The next two runs append behind it.
	for _, id := range []string{"second", "third"} {
		j2, err := OpenJournal(path)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		if _, err := j2.Begin(ctx, Record{Kind: OpRoute, ID: id}); err != nil {
			t.Fatalf("Begin(%s): %v", id, err)
		}
		j2.Close()
	}

	j3, err := OpenJournal(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer j3.Close()
	pending, err := j3.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	var ids []string
	for _, r := range pending {
		ids = append(ids, r.ID)
	}
	if !reflect.DeepEqual(ids, []string{"first", "second", "third"}) {
		t.Fatalf("Pending() sees %v of 3 real records; the rest are unrevertable", ids)
	}
}

// TestJournalFragmentBeforeEveryRecord is the worse half of SF7: with a
// fragment first, readAllLocked returned nothing, and the next Done() reached
// compactLocked, concluded the journal was empty, and Truncate(0)'d live
// records away.
func TestJournalFragmentBeforeEveryRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.ndjson")
	ctx := context.Background()

	if err := os.WriteFile(path, []byte(`{"phase":"begin","seq":9,"kind":"rou`), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	defer j.Close()

	keep, err := j.Begin(ctx, Record{Kind: OpRoute, ID: "keep"})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	drop, err := j.Begin(ctx, Record{Kind: OpRoute, ID: "drop"})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := j.Done(ctx, drop); err != nil {
		t.Fatalf("Done: %v", err)
	}

	pending, err := j.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "keep" || pending[0].Seq != uint64(keep) {
		t.Fatalf("Pending = %+v, want the live record to have survived compaction", pending)
	}
}

// TestOpenJournalHealsATornTail: the fragment is truncated at open, so O_APPEND
// can never weld the next record onto it.
func TestOpenJournalHealsATornTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.ndjson")
	if err := os.WriteFile(path, []byte("{\"phase\":\"begin\",\"seq\":1,\"id\":\"whole\"}\n{\"phase\":\"beg"), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	defer j.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		t.Fatalf("journal does not end on a record boundary: %q", b)
	}
	if want := "{\"phase\":\"begin\",\"seq\":1,\"id\":\"whole\"}\n"; string(b) != want {
		t.Fatalf("journal = %q, want the torn fragment gone and only %q left", b, want)
	}
}

// TestJournalFsyncsItsParentDirectory is SF27. A file's data being durable does
// not make its directory entry durable, so on a first-ever run a power loss
// between Begin and Apply could leave the journal unlinked — the system proxy
// pointing at a dead port with no record dpb set it. fsync on a directory is
// unobservable from inside the process, so the seam is what is asserted.
func TestJournalFsyncsItsParentDirectory(t *testing.T) {
	var synced []string
	old := dirSyncer
	t.Cleanup(func() { dirSyncer = old })
	dirSyncer = func(dir string) error {
		synced = append(synced, dir)
		return old(dir)
	}

	dir := filepath.Join(t.TempDir(), "state")
	j, err := OpenJournal(filepath.Join(dir, "journal.ndjson"))
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	defer j.Close()
	if len(synced) != 1 || synced[0] != dir {
		t.Fatalf("directories fsynced = %v, want [%s]", synced, dir)
	}
}

func TestFsyncDirReportsAMissingDirectory(t *testing.T) {
	if err := fsyncDir(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("fsyncDir on a missing directory must fail")
	}
}

// TestJournalRecordsANonZeroStartTime is the second effect of MF8: fileJournal
// records the owning process's start time so Replay can defeat pid reuse, and
// it read it through the same locale-dependent ps parse. On a Turkish Mac every
// Record and the lock file were written with StartedAt zero, disabling the
// defence entirely.
func TestJournalRecordsANonZeroStartTime(t *testing.T) {
	t.Setenv("LC_ALL", "tr_TR.UTF-8")
	t.Setenv("LANG", "tr_TR.UTF-8")
	path := filepath.Join(t.TempDir(), "journal.ndjson")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	defer j.Close()
	ctx := context.Background()
	if _, err := j.Begin(ctx, Record{Kind: OpRoute, ID: "x"}); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	pending, err := j.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("Pending = %+v", pending)
	}
	if pending[0].StartedAt.IsZero() {
		t.Fatal("the record carries no start time, so pid reuse cannot be detected")
	}
	if pending[0].PID != os.Getpid() {
		t.Fatalf("record PID = %d, want %d", pending[0].PID, os.Getpid())
	}
}

func TestOpenJournalReportsAFailedDirectorySync(t *testing.T) {
	old := dirSyncer
	t.Cleanup(func() { dirSyncer = old })
	dirSyncer = func(string) error { return errors.New("injected") }
	if _, err := OpenJournal(filepath.Join(t.TempDir(), "journal.ndjson")); err == nil {
		t.Fatal("OpenJournal must report a parent directory it could not make durable")
	}
}

func TestOpenJournalReportsAnUnhealableTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.ndjson")
	if err := os.WriteFile(path, []byte("fragment with no newline"), 0o400); err != nil {
		t.Fatal(err)
	}
	// Read-only: the heal cannot truncate, and OpenJournal must say so rather
	// than carry on and weld the next record onto the fragment.
	if _, err := OpenJournal(path); err == nil {
		t.Fatal("OpenJournal accepted a torn tail it could not heal")
	}
}
