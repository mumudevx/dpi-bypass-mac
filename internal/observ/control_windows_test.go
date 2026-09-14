//go:build windows

package observ

import (
	"testing"

	"golang.org/x/sys/windows"
)

// TestSocketDACLIsOwnerOnly is control_perm_unix_test.go's
// TestSocketIsOwnerOnly asked of the place the answer lives on Windows.
//
// Filesystem permissions are the whole authentication story for this socket,
// and on Windows those permissions are a security descriptor, not a mode. The
// two things worth asserting are that the socket carries a DACL OF ITS OWN —
// a nil DACL grants Everyone full control — and that the DACL is PROTECTED, so
// the SYSTEM and Administrators entries %LOCALAPPDATA% hands down are not
// merged into it. An unprotected one-entry DACL is the failure shape
// os.Chmod(0o600) had here before paths.RestrictToOwner replaced it: it
// returns nil and narrows nothing.
//
// One caveat control.go already states and this test cannot settle: what the
// permissions gate on Windows is who may OPEN the socket file, and whether AFD
// also consults them on connect is not something a single-account CI runner
// can demonstrate. This asserts the descriptor dpb wrote, not an equivalence
// with the Unix side.
func TestSocketDACLIsOwnerOnly(t *testing.T) {
	s, _ := serve(t, Handler{})

	sd, err := windows.GetNamedSecurityInfo(s.Path(), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read the control socket's security descriptor: %v", err)
	}

	dacl, defaulted, err := sd.DACL()
	if err != nil {
		t.Fatalf("read the DACL: %v", err)
	}
	if dacl == nil || defaulted {
		t.Fatalf("the control socket carries no DACL of its own (dacl=%v defaulted=%v); "+
			"a nil DACL grants EVERYONE full control of dpb's only authentication boundary",
			dacl, defaulted)
	}
	if dacl.AceCount != 1 {
		t.Errorf("the socket's DACL holds %d entries, want exactly 1: every entry "+
			"beyond ours is another account that can reach the control socket", dacl.AceCount)
	}

	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("read the descriptor control bits: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("the socket's DACL is not protected (control = %#x); it still inherits "+
			"the state directory's SYSTEM and Administrators entries", control)
	}
}
