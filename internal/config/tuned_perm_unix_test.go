//go:build !windows

// The tuned-profile write test, which asserts a POSIX mode.
//
// What it asserts that Windows cannot express: os.Stat().Mode().Perm() ==
// 0o600. Tuned.Save narrows the file with paths.RestrictToOwner, whose Windows
// implementation replaces the file's DACL — there are no mode bits to set on
// Windows — and Go derives Mode().Perm() from the file ATTRIBUTES and nothing
// else, so it answers 0666 on Windows however tight the DACL is. That is
// stated as a limit on RestrictToOwner itself: "a caller must not use the mode
// as evidence".
//
// So this is not a test that fails on Windows and was tagged away. The
// underlying code IS correct there — os.Chmod(0o600) used to be what Save
// called, which wrote no ACL at all and left the file at 0666 for every
// account on the machine, and the 2026-09-14 windows-latest run is what caught
// it (docs/MEASUREMENTS-windows.md). What cannot cross the platform boundary
// is the ASSERTION, because the API it reads through cannot see the answer.
//
// The two halves are asserted elsewhere on Windows:
//
//   - privacy, against the security descriptor rather than the mode:
//     internal/paths, TestRestrictToOwnerReplacesTheDACLWithOneProtectedEntry.
//   - atomicity, which is portable and is if anything more fragile on Windows
//     where a rename over an existing file is a different operation:
//     tuned_windows_test.go.
//
// The function body is unchanged from tuned_test.go, where it lived until the
// Windows suite started running.

package config_test

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTunedWriteIsPrivateAndAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tuned.toml")
	if err := good().Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600: the profile names the sites this user reaches for", perm)
	}
	// A second write must replace it and leave no temp file behind.
	if err := good().Save(path); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(ents) != 1 {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only tuned.toml", names)
	}
}
