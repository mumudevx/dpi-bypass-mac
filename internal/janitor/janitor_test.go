package janitor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/netstate"
)

// pacContent is what the fixture mutation writes. Its exact bytes do not
// matter; what matters is that the file is a real piece of system state that a
// real netstate Op applies and reverts.
var pacContent = []byte("function FindProxyForURL(u, h) { return \"DIRECT\"; }\n")

// journalAs writes a committed journal record for op, attributed to pid.
//
// It is what netstate.Manager.Do does, minus the pid: Manager stamps the
// CURRENT process, and the whole point of a janitor test is a record owned by
// somebody else. Nothing else is faked — the Op is a real one and Apply really
// writes the file.
func journalAs(t *testing.T, journalPath string, op netstate.Op, env netstate.Env, pid int) {
	t.Helper()
	ctx := context.Background()

	j, err := netstate.OpenJournal(journalPath)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	defer j.Close()

	rec := op.Record()
	rec.Kind, rec.ID = op.Kind(), op.ID()
	rec.PID = pid
	if st, ok := netstate.ProcessStart(pid); ok {
		rec.StartedAt = st
	}
	tok, err := j.Begin(ctx, rec)
	if err != nil {
		t.Fatalf("journal begin: %v", err)
	}
	if err := op.Apply(ctx, env); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := op.Verify(ctx, env); err != nil {
		t.Fatalf("verify: %v", err)
	}
	rec.Applied, rec.Verified = true, true
	if err := j.Commit(ctx, tok, rec); err != nil {
		t.Fatalf("journal commit: %v", err)
	}
}

// This is the M12 acceptance clause, with a throwaway process standing in for
// the dpb that would otherwise be holding real system state: SIGKILL the
// parent, and within a couple of seconds the mutation is undone and the journal
// file is empty.
func TestJanitorUndoesTheParentsMutationAfterSIGKILL(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "journal.ndjson")
	pacPath := filepath.Join(dir, "dpb.pac")

	parent := spawnSleeper(t)
	env := netstate.Env{Logf: t.Logf, PriorResidue: true}
	journalAs(t, journalPath, netstate.NewPACFile(pacPath, pacContent), env, parent.Process.Pid)

	if _, err := os.Stat(pacPath); err != nil {
		t.Fatalf("the fixture mutation was not applied: %v", err)
	}

	type result struct {
		rep netstate.ReplayReport
		err error
	}
	done := make(chan result, 1)
	go func() {
		rep, err := Run(context.Background(), Options{
			ParentPID:   parent.Process.Pid,
			JournalPath: journalPath,
			Env:         env,
			Logf:        t.Logf,
		})
		done <- result{rep, err}
	}()

	// While the parent lives, nothing is touched. A janitor that replayed on
	// start-up would delete a running dpb's PAC out from under it.
	time.Sleep(200 * time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("the janitor replayed while its parent was alive: %+v %v", r.rep, r.err)
	default:
	}
	if _, err := os.Stat(pacPath); err != nil {
		t.Fatalf("the PAC file was removed before the parent died: %v", err)
	}

	if err := syscall.Kill(parent.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill: %v", err)
	}

	var r result
	select {
	case r = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the janitor did not replay within 3s of the kill")
	}
	if r.err != nil {
		t.Fatalf("janitor.Run: %v", r.err)
	}
	if len(r.rep.Reverted) != 1 || !r.rep.Clean() {
		t.Fatalf("replay report = %+v", r.rep)
	}

	if _, err := os.Stat(pacPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the PAC file survived the replay: %v", err)
	}
	fi, err := os.Stat(journalPath)
	if err != nil {
		t.Fatalf("stat journal: %v", err)
	}
	if fi.Size() != 0 {
		b, _ := os.ReadFile(journalPath)
		t.Fatalf("the journal is %d bytes after replay, want 0:\n%s", fi.Size(), b)
	}
}

// Records owned by a dpb that is STILL RUNNING are left alone. Two concurrent
// runs must not be able to clobber each other, and this is the guard that makes
// `dpb doctor --repair` safe to type while a dpb is up.
func TestReplayLeavesALiveOwnersRecordsAlone(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "journal.ndjson")
	pacPath := filepath.Join(dir, "dpb.pac")

	env := netstate.Env{Logf: t.Logf}
	journalAs(t, journalPath, netstate.NewPACFile(pacPath, pacContent), env, os.Getpid())

	rep, err := Replay(context.Background(), Options{
		JournalPath: journalPath,
		Env:         env,
		Logf:        t.Logf,
		// The owner is this test process, and it is alive.
		OwnerAlive: func(pid int, _ time.Time) bool { return pid == os.Getpid() },
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(rep.Reverted) != 0 || len(rep.Skipped) != 1 {
		t.Fatalf("report = %+v, want the record skipped", rep)
	}
	if _, err := os.Stat(pacPath); err != nil {
		t.Fatalf("a live owner's PAC file was removed: %v", err)
	}
	// And the record is still pending, so whoever owns it can still finish.
	pending, err := netstate.ReadPending(journalPath)
	if err != nil {
		t.Fatalf("ReadPending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("%d record(s) still pending, want 1", len(pending))
	}
}

// Replay is idempotent: a second pass over an empty journal is a no-op, which
// is what makes the login agent safe to run at every login.
func TestReplayOnAnEmptyJournalIsANoOp(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "journal.ndjson")
	rep, err := Replay(context.Background(), Options{
		JournalPath: journalPath,
		Env:         netstate.Env{Logf: t.Logf},
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(rep.Pending) != 0 || !rep.Clean() {
		t.Fatalf("report = %+v", rep)
	}
}

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

func TestRunValidatesItsArguments(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		o    Options
		want string
	}{
		{"no parent", Options{JournalPath: "j"}, "parent-pid"},
		{"negative parent", Options{ParentPID: -3, JournalPath: "j"}, "parent-pid"},
		{"self", Options{ParentPID: os.Getpid(), JournalPath: "j"}, "this process"},
		{"no journal", Options{ParentPID: 1}, "journal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Run(ctx, tc.o)
			if err == nil {
				t.Fatal("no error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// The Wait seam is honoured, so the replay half is testable without a process.
func TestRunUsesTheWaitSeam(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "journal.ndjson")
	pacPath := filepath.Join(dir, "dpb.pac")

	env := netstate.Env{Logf: t.Logf}
	journalAs(t, journalPath, netstate.NewPACFile(pacPath, pacContent), env, 999999)

	waited := 0
	rep, err := Run(context.Background(), Options{
		ParentPID:   999999,
		JournalPath: journalPath,
		Env:         env,
		Logf:        t.Logf,
		Wait: func(context.Context, int) error {
			waited++
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if waited != 1 {
		t.Fatalf("the Wait seam was called %d times", waited)
	}
	if len(rep.Reverted) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if _, err := os.Stat(pacPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the PAC file survived: %v", err)
	}
}

// A cancelled wait is the parent stopping the janitor on a clean exit. It ran
// UndoAll itself, so nothing must be replayed.
func TestRunDoesNotReplayWhenTheWaitIsCancelled(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "journal.ndjson")
	pacPath := filepath.Join(dir, "dpb.pac")

	env := netstate.Env{Logf: t.Logf}
	journalAs(t, journalPath, netstate.NewPACFile(pacPath, pacContent), env, 999999)

	_, err := Run(context.Background(), Options{
		ParentPID:   999999,
		JournalPath: journalPath,
		Env:         env,
		Wait:        func(context.Context, int) error { return context.Canceled },
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(pacPath); err != nil {
		t.Fatalf("a cancelled janitor reverted anyway: %v", err)
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

// Replay's own error return — as opposed to a report full of Failed records —
// fires when the journal cannot be READ even though it opened cleanly. An
// already-cancelled context is the deterministic way to hit that: Replay's own
// comment warns that the journal must be opened on a FRESH context because a
// cancelled one "would journal nothing and revert nothing" — this pins that a
// cancelled context comes back as a real error rather than an empty report
// that looks like a clean, fully-replayed machine.
func TestReplayReportsWhenTheContextIsAlreadyCancelled(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "journal.ndjson")
	// A journal that OPENS fine (unlike TestReplayReportsAnUnopenableJournal),
	// so the failure under test is netstate.Replay's own read of it, not the
	// open netstate.OpenJournal already guards.
	if err := os.WriteFile(journalPath, nil, 0o600); err != nil {
		t.Fatalf("seed empty journal: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Replay(ctx, Options{
		JournalPath: journalPath,
		Env:         netstate.Env{Logf: t.Logf},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Replay with a cancelled context = %v, want context.Canceled", err)
	}
}

// Replay tolerates a nil context: the janitor's own Run passes one through, and
// `dpb doctor --repair` builds one, but a caller may not.
func TestReplayWithANilContext(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "journal.ndjson")
	pacPath := filepath.Join(dir, "dpb.pac")
	env := netstate.Env{Logf: t.Logf}
	journalAs(t, journalPath, netstate.NewPACFile(pacPath, pacContent), env, 999999)

	//nolint:staticcheck // a nil context is exactly what is under test here
	rep, err := Replay(nil, Options{
		JournalPath: journalPath,
		Env:         env,
		OwnerAlive:  func(int, time.Time) bool { return false },
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(rep.Reverted) != 1 {
		t.Fatalf("report = %+v", rep)
	}
}

// Run with a nil context must behave like Run with Background, because that is
// how a caller wiring the janitor from a signal-driven command will reach it.
func TestRunWithANilContext(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "journal.ndjson")
	pacPath := filepath.Join(dir, "dpb.pac")
	env := netstate.Env{Logf: t.Logf}
	journalAs(t, journalPath, netstate.NewPACFile(pacPath, pacContent), env, 999999)

	//nolint:staticcheck // a nil context is exactly what is under test here
	rep, err := Run(nil, Options{
		ParentPID:   999999,
		JournalPath: journalPath,
		Env:         env,
		Wait:        func(context.Context, int) error { return nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rep.Reverted) != 1 {
		t.Fatalf("report = %+v", rep)
	}
}

// A record whose op kind cannot be rebuilt is reported rather than silently
// dropped: an unrevertable mutation the user is never told about is the worst
// outcome this package has.
func TestReplayReportsAnUnknownOpKind(t *testing.T) {
	dir := t.TempDir()
	journalPath := filepath.Join(dir, "journal.ndjson")

	j, err := netstate.OpenJournal(journalPath)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	tok, err := j.Begin(context.Background(), netstate.Record{
		Kind: netstate.OpKind("from.the.future"), ID: "x", PID: 999999,
	})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := j.Commit(context.Background(), tok, netstate.Record{
		Kind: netstate.OpKind("from.the.future"), ID: "x", PID: 999999, Applied: true,
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	rep, err := Replay(context.Background(), Options{
		JournalPath: journalPath,
		Env:         netstate.Env{Logf: t.Logf},
		OwnerAlive:  func(int, time.Time) bool { return false },
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if rep.Clean() || len(rep.Failed) != 1 {
		t.Fatalf("report = %+v, want the unknown kind reported as a failure", rep)
	}
}
