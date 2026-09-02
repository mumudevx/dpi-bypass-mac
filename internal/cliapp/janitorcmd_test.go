package cliapp

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/janitor"
)

// The hidden command is what janitor.Spawn actually runs. If its name or its
// flags drift from what Spawn passes, the janitor becomes a child that exits
// with a usage error the moment it starts — silently, on the one exit path
// nobody tests by hand.
func TestJanitorCommandNameMatchesWhatSpawnRuns(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, janitor.JanitorCommand, "--parent-pid", "0")
	// It must be REACHED (a usage error about the pid), not rejected as an
	// unknown command.
	if strings.Contains(r.stderr, "unknown command") {
		t.Fatalf("`dpb %s` is not registered: %s", janitor.JanitorCommand, r.stderr)
	}
	if r.code != ExitUsage {
		t.Fatalf("exit code = %d, want %d\n%s", r.code, ExitUsage, r.stderr)
	}
}

func TestJanitorRejectsWatchingItself(t *testing.T) {
	c := newCLI(t)
	r := c.exec(t, janitor.JanitorCommand,
		"--parent-pid", strconv.Itoa(os.Getpid()),
		"--journal", c.layout.JournalFile())
	if r.code != ExitUsage {
		t.Fatalf("exit code = %d, want %d\n%s", r.code, ExitUsage, r.stderr)
	}
	if !strings.Contains(r.stderr, "this process") {
		t.Errorf("stderr = %q", r.stderr)
	}
}

// The end-to-end shape: a parent that is already gone means "replay now", and
// the mutation it left behind is undone.
func TestJanitorReplaysForAParentThatIsAlreadyGone(t *testing.T) {
	c := newCLI(t)
	pacPath := seedPendingPAC(t, c.layout, deadPID)

	r := c.exec(t, janitor.JanitorCommand,
		"--parent-pid", strconv.Itoa(deadPID),
		"--journal", c.layout.JournalFile())
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	// Everything the child says goes to stderr: its stdout is not connected to
	// anything a person reads.
	if !strings.Contains(r.stderr, "undone:") {
		t.Fatalf("the child reported nothing on stderr:\n%s", r.stderr)
	}
	if _, err := os.Stat(pacPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the PAC file survived: %v", err)
	}
}

// With no --journal the child falls back to the layout's, which is what makes a
// hand-typed invocation during debugging do the right thing.
func TestJanitorDefaultsToTheLayoutJournal(t *testing.T) {
	c := newCLI(t)
	seedPendingPAC(t, c.layout, deadPID)

	r := c.exec(t, janitor.JanitorCommand, "--parent-pid", strconv.Itoa(deadPID))
	if r.code != ExitOK {
		t.Fatalf("exit code = %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	fi, err := os.Stat(c.layout.JournalFile())
	if err != nil {
		t.Fatalf("stat journal: %v", err)
	}
	if fi.Size() != 0 {
		t.Fatalf("the journal is %d bytes after the janitor ran", fi.Size())
	}
}
