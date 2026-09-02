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
	oldPS, oldStart := psRunner, procStarter
	t.Cleanup(func() { psRunner, procStarter = oldPS, oldStart })
	stamp := time.Date(2026, time.September, 2, 4, 48, 20, 0, time.Local)
	procStarter = func(int) (time.Time, bool) { return stamp, true }

	var gotArgs []string
	cases := []struct {
		name string
		out  string
		code int
		ok   bool
		comm string
	}{
		{"real shape", "/bin/zsh", 0, true, "/bin/zsh"},
		{"comm with spaces", "/Applications/My App/dpb", 0, true, "/Applications/My App/dpb"},
		{"trailing whitespace", "  /bin/zsh  \n", 0, true, "/bin/zsh"},
		{"no such process", "", 1, false, ""},
		{"empty output", "", 0, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			psRunner = runnerFunc(func(_ context.Context, name string, args ...string) Result {
				gotArgs = append([]string{name}, args...)
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
			if !start.Equal(stamp) {
				t.Fatalf("start = %v, want the kernel's answer %v", start, stamp)
			}
		})
	}

	// MF8: nothing psInfo asks for may be locale-formatted. lstart is, and its
	// FIELD ORDER changes too, so no amount of parsing makes it safe.
	for _, a := range gotArgs {
		if strings.Contains(a, "lstart") {
			t.Fatalf("psInfo asked ps for a locale-formatted column: %v", gotArgs)
		}
	}
}

// TestOwnerAliveOnATurkishMac is MF8. `ps -o lstart=` is formatted through
// LC_TIME, exec.Command inherits os.Environ(), and Terminal.app exports LANG
// from the region — so on a Türkçe Mac, which is the entire target audience,
// this very process printed "Çar  2 Eyl 07:50:52 2026" where the C locale
// prints "Wed Sep  2 07:50:52 2026". Parsed with a fixed English layout that
// fails, OwnerAlive reports a LIVE dpb as dead, and Replay then reverts a
// running instance's journal while it is serving traffic.
func TestOwnerAliveOnATurkishMac(t *testing.T) {
	pid := os.Getpid()
	start, ok := ProcessStart(pid)
	if !ok {
		t.Skip("cannot read this process's start time in this environment")
	}
	for _, loc := range []string{"tr_TR.UTF-8", "tr_TR.ISO8859-9"} {
		t.Run(loc, func(t *testing.T) {
			t.Setenv("LC_ALL", loc)
			t.Setenv("LANG", loc)
			t.Setenv("LC_TIME", loc)
			if got, ok := ProcessStart(pid); !ok || !got.Equal(start) {
				t.Fatalf("ProcessStart under %s = %v/%v, want %v", loc, got, ok, start)
			}
			if !OwnerAlive(pid, start) {
				t.Fatalf("OwnerAlive said this very running process is dead under %s", loc)
			}
		})
	}
}

// TestAcquireLockIsReadableThroughout is SF26. `dpb status` and `dpb doctor`
// read the lock file deliberately without taking the flock, so the window in
// which the file is zero bytes is a window in which they report
// "unexpected end of JSON input" instead of an owner.
func TestAcquireLockIsReadableThroughout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.lock")
	// Seed a longer previous record, so a write that does not shorten the file
	// afterwards would leave a trailing fragment.
	if err := os.WriteFile(path, []byte(`{"pid":999999,"comm":"a-much-longer-previous-record-than-ours"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	bad := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := ReadLock(path); err != nil {
				select {
				case bad <- err:
				default:
				}
				return
			}
		}
	}()

	for i := 0; i < 400; i++ {
		l, err := AcquireLock(path)
		if err != nil {
			close(stop)
			<-done
			t.Fatalf("AcquireLock: %v", err)
		}
		if err := l.Release(); err != nil {
			close(stop)
			<-done
			t.Fatalf("Release: %v", err)
		}
	}
	close(stop)
	<-done
	select {
	case err := <-bad:
		t.Fatalf("a concurrent unlocked reader saw a torn lock file: %v", err)
	default:
	}

	info, err := ReadLock(path)
	if err != nil {
		t.Fatalf("ReadLock: %v", err)
	}
	if info.PID != os.Getpid() {
		t.Fatalf("lock PID = %d, want %d", info.PID, os.Getpid())
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

// TestPriorResidue: the signal that lets an Op discard a loopback proxy or
// resolver it cannot match exactly. It has to be conservative — answering "yes"
// wrongly destroys a working local resolver the user configured themselves.
func TestPriorResidue(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	t.Run("clean journal and no lock", func(t *testing.T) {
		j, _ := openTestJournal(t)
		if PriorResidue(ctx, j, filepath.Join(dir, "absent.lock")) {
			t.Fatal("a clean journal and no lock file is not residue")
		}
	})

	t.Run("pending journal record", func(t *testing.T) {
		j, _ := openTestJournal(t)
		if _, err := j.Begin(ctx, Record{Kind: OpProxyPAC, ID: "x"}); err != nil {
			t.Fatal(err)
		}
		if !PriorResidue(ctx, j, "") {
			t.Fatal("a pending journal record is exactly what residue means")
		}
	})

	t.Run("lock held by a dead owner", func(t *testing.T) {
		j, _ := openTestJournal(t)
		path := filepath.Join(t.TempDir(), "run.lock")
		if err := os.WriteFile(path, []byte(`{"pid":1073741824,"comm":"dpb"}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if !PriorResidue(ctx, j, path) {
			t.Fatal("a lock naming a pid that is not running is residue")
		}
	})

	t.Run("lock held by us", func(t *testing.T) {
		j, _ := openTestJournal(t)
		path := filepath.Join(t.TempDir(), "run.lock")
		l, err := AcquireLock(path)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Release()
		if PriorResidue(ctx, j, path) {
			t.Fatal("our own lock is not a previous run's residue")
		}
	})

	t.Run("unreadable lock", func(t *testing.T) {
		j, _ := openTestJournal(t)
		path := filepath.Join(t.TempDir(), "bad.lock")
		if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if PriorResidue(ctx, j, path) {
			t.Fatal("a lock file we cannot parse must not be read as residue")
		}
	})
}

func TestProcessStartRejectsNonPositivePIDs(t *testing.T) {
	if _, ok := ProcessStart(0); ok {
		t.Fatal("ProcessStart accepted pid 0")
	}
	if _, ok := ProcessStart(-1); ok {
		t.Fatal("ProcessStart accepted a negative pid")
	}
	if _, _, ok := psInfo(0); ok {
		t.Fatal("psInfo accepted pid 0")
	}
	// The kernel read is the authority, and it has no answer for a pid that is
	// not there.
	if _, ok := kernelProcessStart(1 << 30); ok {
		t.Fatal("kernelProcessStart invented a start time for an impossible pid")
	}
}
