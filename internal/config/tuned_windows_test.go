//go:build windows

package config_test

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTunedWriteIsAtomic is the half of tuned_perm_unix_test.go's
// TestTunedWriteIsPrivateAndAtomic that Windows can express, asserted here
// because Windows is where it is most likely to break.
//
// Save writes a temp file beside the target and renames over it. On Unix that
// rename is a single atomic syscall that silently replaces the destination; on
// Windows os.Rename goes through MoveFileEx with MOVEFILE_REPLACE_EXISTING,
// which fails outright if any other handle holds the destination without
// FILE_SHARE_DELETE. A second Save that left its temp file behind — or wrote
// the profile under a second name — would be invisible to every other test in
// this package, because they all read the file back by the name they asked
// for.
//
// The privacy half cannot be asserted through Mode().Perm() here; see
// tuned_perm_unix_test.go for why, and internal/paths'
// TestRestrictToOwnerReplacesTheDACLWithOneProtectedEntry for where it is
// asserted instead.
func TestTunedWriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tuned.toml")
	if err := good().Save(path); err != nil {
		t.Fatalf("Save: %v", err)
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
	if len(ents) == 1 && ents[0].Name() != "tuned.toml" {
		t.Errorf("the surviving file is %q, want tuned.toml", ents[0].Name())
	}
}
