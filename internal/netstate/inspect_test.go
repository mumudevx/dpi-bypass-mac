package netstate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// ReadPending exists because OpenJournal is a WRITE. These tests pin both
// halves of that claim: the same view of what is outstanding, and no mutation
// of the file to obtain it.

func TestReadPendingMatchesPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.ndjson")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	ctx := context.Background()

	tok, err := j.Begin(ctx, Record{Kind: OpProxyPAC, ID: "pac/Wi-Fi"})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := j.Commit(ctx, tok, Record{Kind: OpProxyPAC, ID: "pac/Wi-Fi", Applied: true}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := j.Begin(ctx, Record{Kind: OpDNSServers, ID: "dns/Wi-Fi"}); err != nil {
		t.Fatalf("begin 2: %v", err)
	}

	want, err := j.Pending(ctx)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, err := ReadPending(path)
	if err != nil {
		t.Fatalf("ReadPending: %v", err)
	}
	if len(got) != len(want) || len(got) != 2 {
		t.Fatalf("ReadPending returned %d records, Pending returned %d, want 2", len(got), len(want))
	}
	for i := range got {
		if got[i].Seq != want[i].Seq || got[i].Kind != want[i].Kind || got[i].ID != want[i].ID {
			t.Fatalf("record %d: ReadPending %+v, Pending %+v", i, got[i], want[i])
		}
	}
}

// A torn final line is the shape a SIGKILL mid-append leaves, and it is also
// the shape a LIVE writer's in-progress append has. ReadPending must skip it
// and must leave the bytes alone; OpenJournal, by contrast, heals it.
func TestReadPendingDoesNotHealATornLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.ndjson")
	good := `{"phase":"begin","seq":1,"kind":"proxy.pac","id":"pac/Wi-Fi","pid":1,` +
		`"started_at":"2026-09-02T07:50:52Z","applied":false,"verified":false,` +
		`"adopted":false,"revert":{},"note":""}` + "\n"
	torn := `{"phase":"begin","seq":2,"kind":"dns.se`
	if err := os.WriteFile(path, []byte(good+torn), 0o600); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}

	got, err := ReadPending(path)
	if err != nil {
		t.Fatalf("ReadPending: %v", err)
	}
	if len(got) != 1 || got[0].Seq != 1 {
		t.Fatalf("got %+v, want exactly the one complete record", got)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("ReadPending modified the journal:\nbefore %q\nafter  %q", before, after)
	}
}

func TestReadPendingOnAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nothing-here.ndjson")
	got, err := ReadPending(path)
	if err != nil {
		t.Fatalf("ReadPending on a missing file: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d records from a missing file, want 0", len(got))
	}
	// It must not have created it: `dpb status` is a question, not a mutation.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("ReadPending created %s", path)
	}
}

func TestReadPendingRejectsAnEmptyPath(t *testing.T) {
	if _, err := ReadPending(""); err == nil {
		t.Fatal("ReadPending(\"\") returned no error")
	}
}
