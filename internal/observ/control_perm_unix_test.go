//go:build !windows

// The control socket's permission test, which asserts a POSIX mode.
//
// What it asserts that Windows cannot express: os.Stat().Mode().Perm() ==
// 0o600 on the socket file. NewControlServer narrows the socket with
// paths.RestrictToOwner, whose Windows implementation replaces the file's DACL
// because Windows has no mode bits to set, and Go derives Mode().Perm() from
// the file ATTRIBUTES alone — so it answers 0666 there whatever the DACL says.
// RestrictToOwner states that as one of its two limits: "a caller must not use
// the mode as evidence".
//
// The code underneath is correct on Windows and was not always: os.Chmod(0o600)
// is what this call site used to be, and on Windows that wrote no ACL and
// returned nil, leaving the socket that is dpb's entire authentication story at
// mode 0666. The 2026-09-14 windows-latest run is what measured it; see
// docs/MEASUREMENTS-windows.md. Only the assertion cannot cross the boundary.
//
// control_windows_test.go asks the same question of the socket's security
// descriptor, and internal/paths'
// TestRestrictToOwnerReplacesTheDACLWithOneProtectedEntry asserts the mechanism
// itself.
//
// The function body is unchanged from control_test.go, where it lived until the
// Windows suite started running.

package observ

import (
	"os"
	"testing"
)

// Filesystem permissions are the whole authentication story for this socket.
func TestSocketIsOwnerOnly(t *testing.T) {
	s, _ := serve(t, Handler{})
	fi, err := os.Stat(s.Path())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode = %o, want 0600", perm)
	}
}
