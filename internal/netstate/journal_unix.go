//go:build !windows

package netstate

import (
	"fmt"
	"os"
)

// fsyncDir makes a directory entry durable. Creating a file and fsyncing its
// contents does not persist the name that points at it.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("netstate: open directory %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("netstate: fsync directory %s: %w", dir, err)
	}
	return nil
}

// truncateJournalFile shortens the journal to size.
//
// The journal's OWN handle does it here. open(2)'s O_APPEND changes only WHERE
// a write lands; it takes nothing away from what the descriptor may do, so
// ftruncate(2) on it is permitted and this leaf is the one-line identity its
// callers used to inline. path is therefore unused — the Windows leaf needs it,
// and journal_windows.go says why.
func truncateJournalFile(f *os.File, _ string, size int64) error {
	return f.Truncate(size)
}
