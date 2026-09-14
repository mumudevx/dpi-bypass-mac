//go:build !windows

// This file contains tests that depend on Unix process signals and behaviours
// (SIGKILL, kqueue, process spawning with exec) which have no Windows equivalent.
// The janitor itself is a Unix-only subsystem for handling a parent's SIGKILL.

package janitor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/netstate"
)

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
