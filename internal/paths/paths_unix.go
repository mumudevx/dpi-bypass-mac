//go:build !windows

package paths

import (
	"errors"
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// systemRoot is where a launchd daemon keeps state. Apple's own guidance
	// for a daemon with no home directory.
	systemRoot    = "/Library/Application Support/dpb"
	systemLogRoot = "/Library/Logs/dpb"
	systemCache   = "/Library/Caches/dpb"
)

func resolve(e env) (Layout, error) {
	l := Layout{UID: e.uid, GID: e.gid, Elevated: e.uid == 0}

	owner, err := ownerOf(e)
	if err != nil {
		return Layout{}, err
	}

	if owner == nil {
		// Root with no SUDO_USER: a daemon. Machine-wide locations, owned by
		// root, and deliberately NOT /var/root — nothing should ever have to
		// read dpb state out of root's home.
		l.System = true
		l.User = "root"
		l.ConfigDir = systemRoot
		l.StateDir = systemRoot
		l.CacheDir = systemCache
		l.LogDir = systemLogRoot
		return l, nil
	}

	l.User = owner.Username
	l.Home = owner.HomeDir
	if owner.Uid != "" {
		if uid, err := strconv.Atoi(owner.Uid); err == nil {
			l.UID = uid
		}
	}
	if owner.Gid != "" {
		if gid, err := strconv.Atoi(owner.Gid); err == nil {
			l.GID = gid
		}
	}

	// XDG is honoured because a user who has set it means it. It is read from
	// the environment of the process that actually invoked us, which under
	// sudo is the user's environment only if sudo preserved it; when it did
	// not, the ~/.config default is the right answer anyway.
	l.ConfigDir = xdgDir(e, "XDG_CONFIG_HOME", owner.HomeDir, ".config")
	l.StateDir = xdgDir(e, "XDG_STATE_HOME", owner.HomeDir, filepath.Join(".local", "state"))
	l.CacheDir = xdgDir(e, "XDG_CACHE_HOME", owner.HomeDir, ".cache")
	l.LogDir = filepath.Join(owner.HomeDir, "Library", "Logs", appDir)
	return l, nil
}

// ownerOf returns the user the layout belongs to, or nil for the system layout.
func ownerOf(e env) (*user.User, error) {
	if name := strings.TrimSpace(e.getenv("SUDO_USER")); name != "" && name != "root" {
		u, err := e.lookup(name)
		if err != nil {
			return nil, fmt.Errorf("paths: SUDO_USER=%q could not be looked up: %w", name, err)
		}
		if u.HomeDir == "" {
			return nil, fmt.Errorf("paths: SUDO_USER=%q has no home directory", name)
		}
		return u, nil
	}

	if e.uid == 0 {
		return nil, nil // a real daemon
	}

	u, err := e.current()
	if err != nil {
		// user.Current fails in a static binary with no cgo and no passwd
		// entry. HOME is the honest fallback; failing here would make the
		// tool unusable rather than merely differently-located.
		home := strings.TrimSpace(e.getenv("HOME"))
		if home == "" {
			return nil, fmt.Errorf("paths: cannot determine the current user and HOME is unset: %w", err)
		}
		return &user.User{Username: strings.TrimSpace(e.getenv("USER")), HomeDir: home}, nil
	}
	if u.HomeDir == "" {
		return nil, errors.New("paths: the current user has no home directory")
	}
	return u, nil
}

func xdgDir(e env, key, home string, fallback string) string {
	// Only an absolute XDG value is honoured; the spec says a relative one
	// must be ignored, and a relative state directory would put the journal
	// somewhere that depends on the working directory.
	if v := strings.TrimSpace(e.getenv(key)); filepath.IsAbs(v) {
		return filepath.Join(v, appDir)
	}
	return filepath.Join(home, fallback, appDir)
}
