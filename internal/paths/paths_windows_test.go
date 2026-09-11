//go:build windows

package paths

import "testing"

func TestWindowsUserLayout(t *testing.T) {
	got, err := resolve(env{
		getenv: func(k string) string {
			switch k {
			case "APPDATA":
				return `C:\Users\muhsin\AppData\Roaming`
			case "LOCALAPPDATA":
				return `C:\Users\muhsin\AppData\Local`
			}
			return ""
		},
		uid: -1, gid: -1,
	})
	if err != nil {
		t.Fatalf("resolve() error = %v", err)
	}
	if want := `C:\Users\muhsin\AppData\Roaming\dpb`; got.ConfigDir != want {
		t.Errorf("ConfigDir = %q, want %q", got.ConfigDir, want)
	}
	if want := `C:\Users\muhsin\AppData\Local\dpb`; got.StateDir != want {
		t.Errorf("StateDir = %q, want %q", got.StateDir, want)
	}
	// UID/GID are meaningless on Windows: elevation keeps the same account, so
	// there is no ownership handback for EnsureDirs to perform.
	if got.UID != -1 || got.GID != -1 {
		t.Errorf("UID/GID = %d/%d, want -1/-1", got.UID, got.GID)
	}
}
