package cliapp

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/netstate"
	"github.com/mumudevx/dpi-bypass-mac/internal/observ"
	"github.com/mumudevx/dpi-bypass-mac/internal/paths"
)

// The M12 commands are the ones that read and repair the machine, so every test
// here drives them against a fake macOS and a temporary layout. Nothing in this
// file touches the real proxy pane, the real journal or the real launchd.

// shortLayout is tempLayout with a short root.
//
// t.TempDir() derives its path from the test's name, and the control socket
// lives under StateDir: a long test name plus darwin's private temp prefix can
// push the socket path past sun_path's 104 bytes, at which point
// Layout.ControlSocket() falls back to a per-uid name in $TMPDIR that every
// other test would share. Keeping the root short keeps each test's socket its
// own.
func shortLayout(t *testing.T) paths.Layout {
	t.Helper()
	dir, err := os.MkdirTemp("", "dpb")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	l := paths.Layout{
		ConfigDir: filepath.Join(dir, "c"),
		StateDir:  filepath.Join(dir, "s"),
		CacheDir:  filepath.Join(dir, "k"),
		LogDir:    filepath.Join(dir, "l"),
		UID:       os.Getuid(),
		GID:       os.Getgid(),
		Home:      dir,
	}
	if err := l.EnsureDirs(); err != nil {
		t.Fatalf("ensure dirs: %v", err)
	}
	if p := l.ControlSocket(); !strings.HasPrefix(p, dir) {
		t.Fatalf("the control socket fell back to the shared path %q; shorten the test root", p)
	}
	return l
}

// cli runs one command against an injected layout and a fake macOS.
type cli struct {
	layout paths.Layout
	mac    *fakeMac
}

func newCLI(t *testing.T) *cli {
	t.Helper()
	return &cli{layout: shortLayout(t), mac: newFakeMac()}
}

// exec runs `dpb <args...>` and returns the exit code and both streams.
func (c *cli) exec(t *testing.T, args ...string) result {
	t.Helper()
	return c.execCtx(t, context.Background(), args...)
}

func (c *cli) execCtx(t *testing.T, ctx context.Context, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	layout := c.layout
	g := &globals{
		env:    Env{Args: args, Stdout: &out, Stderr: &errOut},
		layout: &layout,
		runner: c.mac,
		rib:    c.mac,
		facts:  &netstate.Facts{Uplink: "en0", Services: []string{"Wi-Fi"}},
		getenv: func(string) string { return "" },
	}
	root := newRoot(g)
	root.SetArgs(args)
	root.SetOut(&out)
	root.SetErr(&errOut)

	code := ExitOK
	if err := root.ExecuteContext(ctx); err != nil {
		errOut.WriteString("dpb: " + err.Error() + "\n")
		code = exitCodeFor(err)
	}
	t.Logf("dpb %s -> %d\n%s%s", strings.Join(args, " "), code, out.String(), errOut.String())
	return result{code: code, stdout: out.String(), stderr: errOut.String()}
}

// controlFixture is a control server standing in for a running dpb.
type controlFixture struct {
	srv    *observ.ControlServer
	cancel context.CancelFunc
	done   chan error
}

func startControl(t *testing.T, l paths.Layout, h observ.Handler) *controlFixture {
	t.Helper()
	srv, err := observ.NewControlServer(observ.ControlOptions{
		Path: l.ControlSocket(), Handler: h, Logf: t.Logf,
	})
	if err != nil {
		t.Fatalf("control server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &controlFixture{srv: srv, cancel: cancel, done: make(chan error, 1)}
	go func() { f.done <- srv.Serve(ctx) }()
	t.Cleanup(func() { f.stop(t) })
	return f
}

func (f *controlFixture) stop(t *testing.T) {
	t.Helper()
	f.cancel()
	select {
	case err := <-f.done:
		if err != nil {
			t.Errorf("control Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the control server did not stop")
	}
}

// deadPID is a process id no machine will have: darwin's default pid_max is
// 99999. A journal record attributed to it is unambiguously a record whose
// owner is gone, which is what `dpb doctor --repair` and the janitor act on.
const deadPID = 999999

// seedPendingPAC applies a real PAC-file mutation and journals it as if a dpb
// that is now gone had done it.
//
// It writes the record by hand rather than through netstate.Manager because
// Manager stamps the CURRENT process, and this test process is alive: Replay
// would skip its own records and the repair under test would do nothing. Only
// the pid is synthetic — the Op, the Apply and the journal are the real ones.
func seedPendingPAC(t *testing.T, l paths.Layout, pid int) string {
	t.Helper()
	pacPath := filepath.Join(l.StateDir, "dpb.pac")
	op := netstate.NewPACFile(pacPath, []byte("function FindProxyForURL(u,h){return \"DIRECT\";}\n"))

	j, err := netstate.OpenJournal(l.JournalFile())
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	defer j.Close()

	ctx := context.Background()
	rec := op.Record()
	rec.Kind, rec.ID, rec.PID = op.Kind(), op.ID(), pid
	tok, err := j.Begin(ctx, rec)
	if err != nil {
		t.Fatalf("journal begin: %v", err)
	}
	env := netstate.Env{}
	if err := op.Apply(ctx, env); err != nil {
		t.Fatalf("apply: %v", err)
	}
	rec.Applied, rec.Verified = true, true
	if err := j.Commit(ctx, tok, rec); err != nil {
		t.Fatalf("journal commit: %v", err)
	}
	return pacPath
}
