//go:build windows

// The Windows half of the tuned-profile privacy assertion.
//
// tuned_perm_unix_test.go explains why its own assertion cannot cross the
// platform boundary: it reads os.Stat().Mode().Perm(), and on Windows Go
// derives that number from the file ATTRIBUTES alone, so it answers 0666
// however tight the DACL is. It then points at two tests as the Windows
// replacement — internal/paths' TestRestrictToOwnerReplacesTheDACLWithOne-
// ProtectedEntry for privacy and tuned_windows_test.go for atomicity.
//
// Between those two there was still a gap, and it is the gap that matters:
// paths' test proves RestrictToOwner works when it is called, and
// TestTunedWriteIsAtomic proves Save's rename replaces the destination — but
// nothing on Windows proved Save CALLS RestrictToOwner at all. The unix side
// has that assertion (a 0600 file is proof the call happened), so on Windows
// alone `Save` could have gone back to os.Chmod — which writes no ACL there,
// which is exactly the defect the 2026-09-14 windows-latest run caught — and
// every test in this package would still have passed.

package config_test

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/config"
)

// TestTunedSaveRestrictsTheInstalledFileToItsOwner asserts on the file Save
// actually installed, not on a temp file and not on RestrictToOwner in
// isolation.
//
// That distinction is the second thing this test buys. tuned.go narrows the
// TEMP file and then renames it over the destination, on the stated reasoning
// that "the rename carries the ACL with the file, and it is a protected DACL,
// so the target directory's inherited entries are not re-applied on the way".
// That is a claim about MoveFileEx, and it had no assertion behind it: if a
// move re-applied inheritance, the installed profile would carry the state
// directory's SYSTEM and Administrators entries and the narrowing would have
// been undone by the very step that published it.
//
// The assertions are the same three internal/paths makes, for the same stated
// reasons — protected, so nothing is inherited; exactly one entry, so no other
// trustee survived; and readable by this process, so the one entry is ours
// rather than a SID that locks the owner out.
func TestTunedSaveRestrictsTheInstalledFileToItsOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tuned.toml")
	if err := good().Save(path); err != nil {
		t.Fatalf("Save: %v", err)
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
		t.Errorf("the installed profile's DACL is not protected (control = %#x); "+
			"either Save did not call paths.RestrictToOwner or the rename "+
			"re-applied the directory's inherited entries", control)
	}

	dacl, defaulted, err := sd.DACL()
	if err != nil {
		t.Fatalf("read the DACL: %v", err)
	}
	if dacl == nil || defaulted {
		t.Fatalf("the installed profile carries no DACL of its own (dacl=%v "+
			"defaulted=%v); a nil DACL grants EVERYONE full control", dacl, defaulted)
	}
	if dacl.AceCount != 1 {
		t.Errorf("the installed profile's DACL holds %d entries, want exactly 1: "+
			"the profile names the sites this user reaches for, and every entry "+
			"beyond ours is another account that can read them", dacl.AceCount)
	}

	// Loading it back proves the surviving entry grants THIS process: a
	// one-ACE DACL naming the wrong SID would be a profile dpb wrote and can
	// never read, which is a worse outcome than the leak it was fixing.
	if _, err := config.LoadTuned(path); err != nil {
		t.Errorf("the restricted profile is unreadable by the account that wrote it: %v", err)
	}
}
