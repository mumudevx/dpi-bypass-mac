//go:build windows

package netstate

import (
	"fmt"
	"os"
)

// fsyncDir cannot do on Windows what its Unix twin does, and says so rather
// than implying the two are equivalent.
//
// Windows exposes no directory-fsync primitive at all: FlushFileBuffers on a
// directory handle is not supported, so there is no call to make here. That
// means the guarantee the Unix leaf buys — the directory ENTRY is on the
// platter, not merely the file's contents — is not bought here. What stands in
// for it belongs to the filesystem rather than to dpb: NTFS records directory
// metadata through its own log, so a rename or create that has already returned
// is ordered by that log. That is weaker and it is not ours to rely on, but it
// is what the platform offers.
//
// The one real flush Windows does offer is on a VOLUME handle. It is not used:
// it needs administrator rights, and it would flush every pending write on the
// disk, for every process, to make one directory entry durable.
//
// Returning an error instead would be far worse than a weaker guarantee.
// dirSyncer sits on the startup path of BOTH the run lock (writeLockRecord, via
// AcquireLock) and the journal (OpenJournal), so a leaf that failed here would
// mean dpb could not start on Windows at all.
//
// A directory that is not there is still reported. The callers pass a directory
// they created moments earlier, so that answer is a real failure rather than a
// missing fsync, and it keeps one error contract across both platforms —
// TestFsyncDirReportsAMissingDirectory asserts it on whichever it runs on.
func fsyncDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("netstate: open directory %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("netstate: open directory %s: not a directory", dir)
	}
	return nil
}
