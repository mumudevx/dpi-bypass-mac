// Package paths resolves every on-disk location dpb uses.
//
// The hard problem it exists to solve is sudo. `dpb run --tun` needs root, but
// the config, the verdict cache and the journal belong to the human who typed
// the command. If root writes them, the next unprivileged `dpb status` cannot
// read its own cache, and `dpb doctor --repair` run as the user cannot replay a
// journal root owns. So when SUDO_USER is set we resolve the *invoking* user's
// home and record their uid/gid, and EnsureDirs hands ownership back.
//
// Only a genuine daemon — root with no SUDO_USER, i.e. launchd — uses the
// system locations under /Library.
package paths

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)

// Layout is a resolved set of locations plus the identity that should own them.
type Layout struct {
	// ConfigDir holds user-editable input: config.toml, bypass files.
	ConfigDir string
	// StateDir holds durable state we own: journal, verdict store, tuned.toml,
	// the PAC file, the control socket, the run lock.
	StateDir string
	// CacheDir holds discardable state: DNS caches.
	CacheDir string
	// LogDir holds the NDJSON event log and its rotations.
	LogDir string

	// UID/GID own everything created under the directories above. Under sudo
	// these are the invoking user's, not root's.
	UID int
	GID int

	// User is the login name UID belongs to, best effort ("" if unknown).
	User string
	// Home is the home directory the layout was derived from ("" for the
	// system layout).
	Home string

	// System is true when the layout is the machine-wide one under /Library,
	// which happens only for root with no SUDO_USER (a launchd daemon).
	System bool
	// Elevated is true when the process is running as root, whether or not
	// the layout is the system one.
	Elevated bool
}

// env is the ambient state Resolve reads. It is a struct so the resolution
// rules can be unit-tested without a real sudo, a real root, or a real home.
type env struct {
	getenv  func(string) string
	uid     int
	gid     int
	lookup  func(username string) (*user.User, error)
	current func() (*user.User, error)
}

// Resolve derives the layout from the real process environment.
func Resolve() (Layout, error) {
	return resolve(env{
		getenv:  os.Getenv,
		uid:     os.Getuid(),
		gid:     os.Getgid(),
		lookup:  user.Lookup,
		current: user.Current,
	})
}

// appDir is the leaf directory name every platform's layout nests state under.
const appDir = "dpb"

// ConfigFile is the user's TOML configuration.
func (l Layout) ConfigFile() string { return filepath.Join(l.ConfigDir, "config.toml") }

// TunedFile is the profile `dpb tune` writes and `dpb run --profile tuned` reads.
func (l Layout) TunedFile() string { return filepath.Join(l.StateDir, "tuned.toml") }

// JournalFile is the append-only record of every system mutation. It lives in
// StateDir because losing it means losing the ability to undo.
func (l Layout) JournalFile() string { return filepath.Join(l.StateDir, "journal.ndjson") }

// LockFile holds the advisory flock plus the owning pid and start time.
func (l Layout) LockFile() string { return filepath.Join(l.StateDir, "run.lock") }

// PACFile is the proxy auto-config served at /dpb.pac and pointed at by the
// system auto-proxy URL.
func (l Layout) PACFile() string { return filepath.Join(l.StateDir, "dpb.pac") }

// VerdictFile is the durable per-host verdict store, namespaced internally by
// NetworkID.
func (l Layout) VerdictFile() string { return filepath.Join(l.StateDir, "verdicts.json") }

// EventLogFile is the NDJSON event log.
func (l Layout) EventLogFile() string { return filepath.Join(l.LogDir, "events.ndjson") }

// maxUnixPath is darwin's sockaddr_un.sun_path capacity. Exceeding it does not
// fail at bind with a clear error everywhere it is touched, so the path is
// chosen to fit rather than discovered to be too long at runtime.
const maxUnixPath = 104

// ControlSocket is the unix socket `dpb status`/`why`/`on`/`off` talk to.
//
// A deep home directory can push StateDir past sun_path, so an over-long path
// falls back to a per-uid name under the system temp directory. The fallback is
// deterministic, so the client computes the same answer as the server.
func (l Layout) ControlSocket() string {
	p := filepath.Join(l.StateDir, "control.sock")
	if len(p) < maxUnixPath {
		return p
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("dpb-%d.sock", l.UID))
}

// Dirs is every directory EnsureDirs creates, in a stable order.
func (l Layout) Dirs() []string {
	seen := make(map[string]bool, 4)
	var out []string
	for _, d := range []string{l.ConfigDir, l.StateDir, l.CacheDir, l.LogDir} {
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// EnsureDirs creates the layout's directories and, when running as root on
// behalf of a user, hands them to that user.
//
// Chown failures are not fatal on their own — the directory exists and this
// process can use it — but they are returned so the caller can warn, because a
// root-owned state directory is how the next unprivileged run breaks.
func (l Layout) EnsureDirs() error {
	for _, d := range l.Dirs() {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("paths: create %s: %w", d, err)
		}
		// UID == -1 means there is no owner to hand back: the sudo split this
		// method exists for is a Unix-only problem (see paths_windows.go), and
		// os.Chown is not even supported on Windows.
		if l.UID == -1 {
			continue
		}
		if err := l.Chown(d); err != nil {
			return err
		}
	}
	return nil
}

// Chown gives path to the layout's owner when this process is root acting for a
// user. It is a no-op otherwise, including for the system layout.
func (l Layout) Chown(path string) error {
	if !l.Elevated || l.System || l.UID == 0 {
		return nil
	}
	if err := os.Chown(path, l.UID, l.GID); err != nil {
		return fmt.Errorf("paths: chown %s to %d:%d: %w", path, l.UID, l.GID, err)
	}
	return nil
}
