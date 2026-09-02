package netstate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAcquireLockIsExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "run.lock")

	l, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if l.Path() != path {
		t.Fatalf("Path() = %q", l.Path())
	}

	if _, err := AcquireLock(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("second AcquireLock err = %v, want ErrLocked", err)
	}

	info, err := ReadLock(path)
	if err != nil {
		t.Fatalf("ReadLock: %v", err)
	}
	if info.PID != os.Getpid() {
		t.Fatalf("lock PID = %d, want %d", info.PID, os.Getpid())
	}
	if info.StartedAt.IsZero() {
		t.Fatal("lock did not record a start time; pid reuse would be undetectable")
	}
	if info.Comm == "" {
		t.Fatal("lock did not record the executable name")
	}

	if err := l.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("second Release: %v", err)
	}

	l2, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("AcquireLock after Release: %v", err)
	}
	l2.Release()
}

func TestAcquireLockBadPath(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(filepath.Join(blocker, "run.lock")); err == nil {
		t.Fatal("AcquireLock must fail when the parent path is a file")
	}
}

func TestReadLockErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadLock(filepath.Join(dir, "missing.lock")); err == nil {
		t.Fatal("ReadLock on a missing file must fail")
	}
	bad := filepath.Join(dir, "bad.lock")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLock(bad); err == nil {
		t.Fatal("ReadLock on a corrupt file must fail")
	}
}

func TestProcessStartAndOwnerAlive(t *testing.T) {
	pid := os.Getpid()
	start, ok := ProcessStart(pid)
	if !ok {
		t.Skip("ps is unavailable in this environment")
	}
	if start.IsZero() || start.After(time.Now()) {
		t.Fatalf("ProcessStart = %v, which is not a plausible start time", start)
	}

	if !OwnerAlive(pid, start) {
		t.Fatal("OwnerAlive said this very process is dead")
	}
	// The whole point of recording a start time: a recycled pid must not be
	// mistaken for the process that wrote the journal record.
	if OwnerAlive(pid, start.Add(-time.Hour)) {
		t.Fatal("OwnerAlive ignored a mismatched start time; pid reuse would clobber a live run")
	}
	if OwnerAlive(pid, time.Time{}) != true {
		t.Fatal("a zero recorded start time must fall back to the pid-and-name check")
	}
	if OwnerAlive(0, start) || OwnerAlive(-1, start) {
		t.Fatal("OwnerAlive accepted a non-positive pid")
	}
	if _, ok := ProcessStart(1 << 30); ok {
		t.Fatal("ProcessStart reported a start time for an impossible pid")
	}
	// pid 1 (launchd) exists but is not us, so the comm check must reject it.
	if OwnerAlive(1, time.Time{}) {
		t.Fatal("OwnerAlive accepted a process that is not a dpb")
	}
}

func TestPSInfoParsing(t *testing.T) {
	old := psRunner
	t.Cleanup(func() { psRunner = old })

	cases := []struct {
		name string
		out  string
		code int
		ok   bool
		comm string
	}{
		{"real shape", "Wed Sep  2 04:48:20 2026     /bin/zsh", 0, true, "/bin/zsh"},
		{"comm with spaces", "Wed Sep  2 04:48:20 2026 /Applications/My App/dpb", 0, true, "/Applications/My App/dpb"},
		{"no such process", "", 1, false, ""},
		{"empty output", "", 0, false, ""},
		{"too few fields", "Wed Sep 2", 0, false, ""},
		{"unparseable date", "Notaday Sep  2 04:48:20 2026 /bin/zsh", 0, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			psRunner = runnerFunc(func(_ context.Context, name string, args ...string) Result {
				return Result{Argv: append([]string{name}, args...), Combined: c.out, Code: c.code}
			})
			comm, start, ok := psInfo(4242)
			if ok != c.ok {
				t.Fatalf("psInfo ok = %v, want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			if comm != c.comm {
				t.Fatalf("comm = %q, want %q", comm, c.comm)
			}
			if start.Year() != 2026 || start.Month() != time.September || start.Day() != 2 {
				t.Fatalf("start = %v", start)
			}
		})
	}
}

func TestOwnerAliveRejectsForeignExecutable(t *testing.T) {
	old := psRunner
	t.Cleanup(func() { psRunner = old })
	psRunner = runnerFunc(func(_ context.Context, name string, args ...string) Result {
		return Result{
			Argv:     append([]string{name}, args...),
			Combined: "Wed Sep  2 04:48:20 2026 /usr/sbin/cupsd",
		}
	})
	if OwnerAlive(4242, time.Time{}) {
		t.Fatal("OwnerAlive accepted a pid owned by an unrelated program")
	}
}

func TestSelfComm(t *testing.T) {
	if got := selfComm(); got == "" || strings.ContainsRune(got, filepath.Separator) {
		t.Fatalf("selfComm() = %q, want a bare base name", got)
	}
}
