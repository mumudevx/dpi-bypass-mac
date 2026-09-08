package netstate

import "testing"

// TestFsyncDirAcceptsARealDirectory pins the half of fsyncDir's contract that
// has to hold identically on both platforms: a directory that exists is not an
// error.
//
// dirSyncer is on the startup path of BOTH the run lock (writeLockRecord, via
// AcquireLock) and the journal (OpenJournal), so a leaf that answered with an
// error would not degrade durability — it would stop dpb from starting. On Unix
// this runs the real fsync against a real directory; on Windows, where there is
// no directory-fsync primitive to run, it pins the no-op contract so a later
// change cannot quietly turn a missing guarantee into a failed startup.
func TestFsyncDirAcceptsARealDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := fsyncDir(dir); err != nil {
		t.Fatalf("fsyncDir(%q) = %v, want nil", dir, err)
	}
	// And through the seam the two callers actually reach it by.
	if err := dirSyncer(dir); err != nil {
		t.Fatalf("dirSyncer(%q) = %v, want nil", dir, err)
	}
}
