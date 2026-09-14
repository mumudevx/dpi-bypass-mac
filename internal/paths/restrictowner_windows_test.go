//go:build windows

package paths

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// TestRestrictToOwnerReplacesTheDACLWithOneProtectedEntry is the assertion
// RestrictToOwner never had, on either platform's side of it.
//
// It exists because the thing it checks is invisible to the API the two
// callers' own tests used. internal/config's TestTunedWriteIsPrivateAndAtomic
// and internal/observ's TestSocketIsOwnerOnly both asked
// os.Stat().Mode().Perm() for 0600; on Windows Go derives that number from the
// file ATTRIBUTES alone, so it answers 0666 no matter what the DACL says, and
// those two tests can only ever be run where mode bits are real (see their
// `!windows` files). This test asks the security descriptor instead, which is
// the only place the answer lives on Windows.
//
// What it proves, and what it does not. It proves the descriptor carries a
// DACL that is PROTECTED — so nothing is inherited from the parent directory,
// which is the half that does the work: %LOCALAPPDATA% inherits entries for
// SYSTEM and for the local Administrators group, and an unprotected one-entry
// DACL would leave the file exactly as readable as before while still
// returning nil. It proves the DACL holds exactly ONE entry, so no other
// trustee survived. And it proves that entry still grants THIS process, by
// reopening the file afterwards — a one-ACE DACL naming the wrong SID would be
// a file its own owner could not read, which is the failure
// restrictToOwner's GetTokenUser choice exists to avoid.
//
// It does not decode the ACE's trustee SID; doing so needs unsafe pointer
// arithmetic over ACCESS_ALLOWED_ACE.SidStart for no gain over the reopen
// above.
func TestRestrictToOwnerReplacesTheDACLWithOneProtectedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tuned.toml")
	if err := os.WriteFile(path, []byte("version = 1\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := RestrictToOwner(path); err != nil {
		t.Fatalf("RestrictToOwner: %v", err)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read back the security descriptor: %v", err)
	}

	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("read the descriptor control bits: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("the DACL is not protected (control = %#x); the parent directory's "+
			"SYSTEM and Administrators entries are still inherited", control)
	}

	dacl, defaulted, err := sd.DACL()
	if err != nil {
		t.Fatalf("read the DACL: %v", err)
	}
	if dacl == nil || defaulted {
		t.Fatalf("the file carries no DACL of its own (dacl=%v defaulted=%v); "+
			"a nil DACL grants EVERYONE full control", dacl, defaulted)
	}
	if dacl.AceCount != 1 {
		t.Errorf("the DACL holds %d entries, want exactly 1: every entry beyond "+
			"ours is another account that can read the file", dacl.AceCount)
	}

	// The one entry has to be OURS. GetTokenUser rather than the signed-in
	// user is deliberate in restrictToOwner — an elevated dpb runs as the
	// admin account — and getting that wrong produces a file this process
	// itself cannot reopen.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the restricted file is unreadable by the account that owns it: %v", err)
	}
	if len(b) == 0 {
		t.Error("the restricted file read back empty")
	}
}

// TestRestrictToOwnerOnAMissingFileIsAnError: restrictToOwner is called on a
// file that was just created, and a failure to narrow it is reported rather
// than ignored by both callers. A silent success on a path that does not exist
// would make that reporting meaningless.
func TestRestrictToOwnerOnAMissingFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope", "tuned.toml")
	if err := RestrictToOwner(path); err == nil {
		t.Fatal("RestrictToOwner reported success for a path that does not exist")
	}
}
