//go:build !windows

// This file exercises resolve()'s Unix-only behaviour — SUDO_USER, the uid==0
// daemon path, /Library — which paths_unix.go now owns exclusively. It cannot
// compile for windows (systemRoot etc. no longer exist there); windows'
// equivalent lives in paths_windows_test.go. No assertion here changed.
package paths

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func userEnv(m map[string]string) env {
	return env{
		getenv: envFrom(m),
		uid:    501,
		gid:    20,
		current: func() (*user.User, error) {
			return &user.User{Uid: "501", Gid: "20", Username: "muhsin", HomeDir: "/Users/muhsin"}, nil
		},
		lookup: func(string) (*user.User, error) { return nil, errors.New("lookup should not be called") },
	}
}

func TestResolveUnprivilegedUser(t *testing.T) {
	got, err := resolve(userEnv(nil))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	want := Layout{
		ConfigDir: "/Users/muhsin/.config/dpb",
		StateDir:  "/Users/muhsin/.local/state/dpb",
		CacheDir:  "/Users/muhsin/.cache/dpb",
		LogDir:    "/Users/muhsin/Library/Logs/dpb",
		UID:       501, GID: 20,
		User: "muhsin", Home: "/Users/muhsin",
	}
	if got != want {
		t.Errorf("layout =\n  %+v\nwant\n  %+v", got, want)
	}
	if got.System || got.Elevated {
		t.Error("an unprivileged run must be neither System nor Elevated")
	}
}

// sudo is the whole reason this package exists: `sudo dpb run --tun` must not
// leave a root-owned journal and cache that the next unprivileged `dpb status`
// cannot read.
func TestResolveUnderSudoUsesTheInvokingUser(t *testing.T) {
	e := env{
		getenv: envFrom(map[string]string{"SUDO_USER": "muhsin"}),
		uid:    0,
		gid:    0,
		lookup: func(name string) (*user.User, error) {
			if name != "muhsin" {
				t.Fatalf("looked up %q, want muhsin", name)
			}
			return &user.User{Uid: "501", Gid: "20", Username: "muhsin", HomeDir: "/Users/muhsin"}, nil
		},
		current: func() (*user.User, error) {
			t.Fatal("user.Current must not be consulted when SUDO_USER is set")
			return nil, nil
		},
	}

	got, err := resolve(e)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.System {
		t.Error("a sudo run is not the system layout")
	}
	if !got.Elevated {
		t.Error("Elevated must be true under sudo")
	}
	if got.UID != 501 || got.GID != 20 {
		t.Errorf("owner = %d:%d, want 501:20 — root-owned state is the bug", got.UID, got.GID)
	}
	if got.StateDir != "/Users/muhsin/.local/state/dpb" {
		t.Errorf("StateDir = %q, want the invoking user's", got.StateDir)
	}
	if got.JournalFile() != "/Users/muhsin/.local/state/dpb/journal.ndjson" {
		t.Errorf("JournalFile = %q", got.JournalFile())
	}
}

func TestResolveRootDaemonUsesLibrary(t *testing.T) {
	e := env{
		getenv:  envFrom(nil),
		uid:     0,
		gid:     0,
		lookup:  func(string) (*user.User, error) { return nil, errors.New("no") },
		current: func() (*user.User, error) { return nil, errors.New("no") },
	}
	got, err := resolve(e)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !got.System || !got.Elevated {
		t.Fatalf("root with no SUDO_USER must be the system layout, got %+v", got)
	}
	if got.ConfigDir != systemRoot || got.StateDir != systemRoot {
		t.Errorf("system dirs = %q/%q, want %q", got.ConfigDir, got.StateDir, systemRoot)
	}
	if got.LogDir != systemLogRoot {
		t.Errorf("LogDir = %q, want %q", got.LogDir, systemLogRoot)
	}
	if strings.Contains(got.StateDir, "/var/root") {
		t.Error("state must never live in root's home")
	}
	if got.UID != 0 {
		t.Errorf("UID = %d, want 0", got.UID)
	}
}

// `sudo -u root` / a launchd job that exports SUDO_USER=root is a daemon, not
// a user session.
func TestResolveSudoUserRootIsTreatedAsDaemon(t *testing.T) {
	e := env{
		getenv:  envFrom(map[string]string{"SUDO_USER": "root"}),
		uid:     0,
		lookup:  func(string) (*user.User, error) { t.Fatal("must not look up root"); return nil, nil },
		current: func() (*user.User, error) { return nil, errors.New("no") },
	}
	got, err := resolve(e)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !got.System {
		t.Errorf("SUDO_USER=root should give the system layout, got %+v", got)
	}
}

func TestResolveHonoursAbsoluteXDGOnly(t *testing.T) {
	e := userEnv(map[string]string{
		"XDG_CONFIG_HOME": "/opt/cfg",
		"XDG_STATE_HOME":  "relative/state", // must be ignored per the XDG spec
		"XDG_CACHE_HOME":  "  /opt/cache  ",
	})
	got, err := resolve(e)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.ConfigDir != "/opt/cfg/dpb" {
		t.Errorf("ConfigDir = %q", got.ConfigDir)
	}
	if got.StateDir != "/Users/muhsin/.local/state/dpb" {
		t.Errorf("a relative XDG_STATE_HOME must be ignored, got %q", got.StateDir)
	}
	if got.CacheDir != "/opt/cache/dpb" {
		t.Errorf("CacheDir = %q", got.CacheDir)
	}
}

func TestResolveSudoUserLookupFailureIsReported(t *testing.T) {
	e := env{
		getenv:  envFrom(map[string]string{"SUDO_USER": "ghost"}),
		uid:     0,
		lookup:  func(string) (*user.User, error) { return nil, errors.New("unknown user") },
		current: func() (*user.User, error) { return nil, errors.New("no") },
	}
	if _, err := resolve(e); err == nil {
		t.Fatal("a SUDO_USER that cannot be resolved must be an error, not a silent fall back to root")
	}
}

func TestResolveSudoUserWithoutHomeIsReported(t *testing.T) {
	e := env{
		getenv:  envFrom(map[string]string{"SUDO_USER": "nobody"}),
		uid:     0,
		lookup:  func(string) (*user.User, error) { return &user.User{Username: "nobody"}, nil },
		current: func() (*user.User, error) { return nil, errors.New("no") },
	}
	if _, err := resolve(e); err == nil {
		t.Fatal("a SUDO_USER with no home must be an error")
	}
}

func TestResolveFallsBackToHOMEWhenUserLookupFails(t *testing.T) {
	e := env{
		getenv:  envFrom(map[string]string{"HOME": "/Users/fallback", "USER": "fb"}),
		uid:     501,
		gid:     20,
		current: func() (*user.User, error) { return nil, errors.New("no passwd entry") },
		lookup:  func(string) (*user.User, error) { return nil, errors.New("no") },
	}
	got, err := resolve(e)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Home != "/Users/fallback" || got.User != "fb" {
		t.Errorf("layout = %+v, want the HOME fallback", got)
	}
	// The uid comes from the process, since there is no passwd entry to read.
	if got.UID != 501 || got.GID != 20 {
		t.Errorf("owner = %d:%d, want the process ids", got.UID, got.GID)
	}
}

func TestResolveFailsWhenNothingIdentifiesTheUser(t *testing.T) {
	e := env{
		getenv:  envFrom(nil),
		uid:     501,
		current: func() (*user.User, error) { return nil, errors.New("no passwd entry") },
		lookup:  func(string) (*user.User, error) { return nil, errors.New("no") },
	}
	if _, err := resolve(e); err == nil {
		t.Fatal("with neither passwd nor HOME, resolve must fail rather than write to the working directory")
	}
}

func TestResolveCurrentUserWithoutHome(t *testing.T) {
	e := env{
		getenv:  envFrom(nil),
		uid:     501,
		current: func() (*user.User, error) { return &user.User{Uid: "501", Username: "x"}, nil },
		lookup:  func(string) (*user.User, error) { return nil, errors.New("no") },
	}
	if _, err := resolve(e); err == nil {
		t.Fatal("a user with no home directory must be an error")
	}
}

func TestResolveUsesTheRealEnvironment(t *testing.T) {
	got, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.StateDir == "" || !filepath.IsAbs(got.StateDir) {
		t.Fatalf("StateDir = %q, want an absolute path", got.StateDir)
	}
}

func TestFileAccessors(t *testing.T) {
	l := Layout{ConfigDir: "/c", StateDir: "/s", CacheDir: "/k", LogDir: "/l"}
	cases := map[string]string{
		l.ConfigFile():   "/c/config.toml",
		l.TunedFile():    "/s/tuned.toml",
		l.JournalFile():  "/s/journal.ndjson",
		l.LockFile():     "/s/run.lock",
		l.PACFile():      "/s/dpb.pac",
		l.VerdictFile():  "/s/verdicts.json",
		l.EventLogFile(): "/l/events.ndjson",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestControlSocketFitsSunPath(t *testing.T) {
	short := Layout{StateDir: "/s", UID: 501}
	if got := short.ControlSocket(); got != "/s/control.sock" {
		t.Errorf("ControlSocket = %q", got)
	}

	deep := Layout{StateDir: "/Users/" + strings.Repeat("d", 120), UID: 501}
	got := deep.ControlSocket()
	if len(got) >= maxUnixPath {
		t.Errorf("ControlSocket = %q (%d bytes), which does not fit sockaddr_un.sun_path", got, len(got))
	}
	if !strings.Contains(got, "dpb-501.sock") {
		t.Errorf("the fallback must be deterministic per uid so the client finds it, got %q", got)
	}
}

func TestDirsDeduplicates(t *testing.T) {
	l := Layout{ConfigDir: systemRoot, StateDir: systemRoot, CacheDir: systemCache, LogDir: systemLogRoot}
	got := l.Dirs()
	if len(got) != 3 {
		t.Fatalf("Dirs = %v, want the shared config/state directory listed once", got)
	}
	empty := Layout{}
	if len(empty.Dirs()) != 0 {
		t.Errorf("empty layout Dirs = %v", empty.Dirs())
	}
}

func TestEnsureDirsCreatesEverything(t *testing.T) {
	base := t.TempDir()
	l := Layout{
		ConfigDir: filepath.Join(base, "config"),
		StateDir:  filepath.Join(base, "state"),
		CacheDir:  filepath.Join(base, "cache"),
		LogDir:    filepath.Join(base, "logs"),
		UID:       os.Getuid(), GID: os.Getgid(),
	}
	if err := l.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	for _, d := range l.Dirs() {
		st, err := os.Stat(d)
		if err != nil {
			t.Fatalf("stat %s: %v", d, err)
		}
		if !st.IsDir() {
			t.Errorf("%s is not a directory", d)
		}
	}
	// Idempotent: a second run must not fail on existing directories.
	if err := l.EnsureDirs(); err != nil {
		t.Fatalf("second EnsureDirs: %v", err)
	}
}

func TestEnsureDirsReportsCreationFailure(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := Layout{StateDir: filepath.Join(file, "state")}
	if err := l.EnsureDirs(); err == nil {
		t.Fatal("EnsureDirs must report a directory it could not create")
	}
}

func TestChownIsANoOpUnlessElevatedForAUser(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, l := range []Layout{
		{},                             // unprivileged
		{Elevated: true, System: true}, // daemon
		{Elevated: true, UID: 0},       // root acting for root
	} {
		if err := l.Chown(f); err != nil {
			t.Errorf("Chown must be a no-op for %+v, got %v", l, err)
		}
	}
}

func TestChownReportsFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; the chown would succeed")
	}
	// Elevated is asserted rather than real, so the chown is actually attempted
	// and fails on EPERM — which is exactly the error a caller must be told
	// about rather than have swallowed.
	l := Layout{Elevated: true, UID: 1, GID: 1}
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := l.Chown(f); err == nil {
		t.Fatal("a failed chown must be reported: a root-owned state directory breaks the next unprivileged run")
	}
}
