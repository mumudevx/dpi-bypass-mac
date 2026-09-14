//go:build windows

package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// The problem this package exists to solve — sudo splitting ownership between
// root and the invoking user — has no Windows equivalent. UAC elevation keeps
// the SAME user account, so %LOCALAPPDATA% resolves to one place whether or not
// the process is elevated, and there is no ownership to hand back.
//
// So UID and GID are -1 here and EnsureDirs performs no chown. The one real
// split is service context: a service runs as LocalSystem with no user profile,
// which is the Windows analogue of a launchd daemon and gets the machine-wide
// locations under %ProgramData%.
const (
	systemRootEnv = "ProgramData"
	userRoamEnv   = "APPDATA"
	userLocalEnv  = "LOCALAPPDATA"
)

func resolve(e env) (Layout, error) {
	l := Layout{UID: -1, GID: -1}

	if elevated, err := isElevated(); err == nil {
		l.Elevated = elevated
	}
	// A service has no user profile to write into. svc.IsWindowsService is the
	// authority; an error means "not a service", which is the safe reading for
	// an interactive run.
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		l.System = true
	}

	if l.System {
		sys, err := systemLayout(e)
		if err != nil {
			return Layout{}, err
		}
		sys.Elevated = l.Elevated
		return sys, nil
	}

	roam := strings.TrimSpace(e.getenv(userRoamEnv))
	local := strings.TrimSpace(e.getenv(userLocalEnv))
	if roam == "" || local == "" {
		return Layout{}, fmt.Errorf("paths: %%APPDATA%% and %%LOCALAPPDATA%% must both be set")
	}
	// Config is roaming because a profile follows the user between machines and
	// a bypass strategy is worth carrying. State, cache and logs are local:
	// a journal describing THIS machine's routes must not roam to another.
	l.ConfigDir = filepath.Join(roam, appDir)
	l.StateDir = filepath.Join(local, appDir)
	l.CacheDir = filepath.Join(local, appDir, "cache")
	l.LogDir = filepath.Join(local, appDir, "logs")
	return l, nil
}

// systemLayout is the machine-wide layout, the one a dpb running as a Windows
// service resolves for itself. It is factored out of resolve() so SystemLayout
// below can hand the SAME answer to a process that is not a service.
func systemLayout(e env) (Layout, error) {
	root := strings.TrimSpace(e.getenv(systemRootEnv))
	if root == "" {
		return Layout{}, fmt.Errorf("paths: %%%s%% is unset; cannot place machine-wide state", systemRootEnv)
	}
	base := filepath.Join(root, appDir)
	return Layout{
		UID: -1, GID: -1,
		System:    true,
		User:      "SYSTEM",
		ConfigDir: base,
		StateDir:  base,
		CacheDir:  filepath.Join(base, "cache"),
		LogDir:    filepath.Join(base, "logs"),
	}, nil
}

// SystemLayout returns the machine-wide layout without being a service.
//
// `dpb service install --system` runs as an elevated interactive user, so
// Resolve() gives it that user's %LOCALAPPDATA% locations — but the service it
// is installing runs as LocalSystem and will resolve the %ProgramData% ones.
// The installer has to name the log files the service will actually write, or
// `dpb service logs --system` reads the wrong half; that is exactly the trap
// service_darwin.go's serviceScopeFor documents for a LaunchDaemon. This exists
// so the installer and the service agree by construction, rather than by two
// copies of the same filepath.Join staying in step for the life of the tree.
//
// It is Windows-only because the problem is: on darwin the daemon's locations
// are literal paths under /Library that service_darwin.go already spells out.
func SystemLayout() (Layout, error) {
	return systemLayout(env{getenv: os.Getenv})
}

// isElevated reports whether this process holds a UAC-elevated token.
//
// Verified against golang.org/x/sys@v0.43.0/windows/security_windows.go:
// Token.IsElevated() exists there (it wraps GetTokenInformation with
// TokenElevation internally), so that is used directly rather than
// reimplementing the GetTokenInformation call ourselves. OpenCurrentProcessToken
// is marked deprecated in that file in favor of the no-close GetCurrentProcessToken,
// but it is used here anyway because it gives a real error return and a token to
// Close, which matches how resolve() above treats isElevated's error as "assume
// not elevated" rather than ignoring failure outright.
func isElevated() (bool, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false, err
	}
	defer token.Close()
	return token.IsElevated(), nil
}
