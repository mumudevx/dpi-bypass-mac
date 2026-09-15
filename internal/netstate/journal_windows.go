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

// truncateJournalFile shortens the journal to size through a SECOND, very
// short-lived handle, because the journal's own handle cannot do it here.
//
// # The evidence
//
// Go maps os.O_APPEND onto Windows access rights by taking GENERIC_WRITE AWAY
// and putting FILE_APPEND_DATA in its place — $GOROOT/src/syscall/
// syscall_windows.go's Open(), whose own comment reads "Remove GENERIC_WRITE
// unless O_TRUNC is set, in which case we need it to truncate the file".
// (*os.File).Truncate ends at SetEndOfFile, and SetEndOfFile needs
// FILE_WRITE_DATA: exactly the right that substitution drops. So a truncate on
// the append handle fails with ERROR_ACCESS_DENIED on the process's OWN file.
//
// That is measured, not inferred. The windows-latest CI run of 2026-09-14 —
// the first time any of this project's Windows code ran — failed 11 tests on
// it across internal/netstate, internal/janitor and internal/cliapp, every one
// reporting `truncate <journal>: Access is denied.`; see
// docs/MEASUREMENTS-windows.md. Five rounds of code review had read the same
// two Truncate calls and seen nothing wrong.
//
// # Why O_APPEND is not simply dropped instead
//
// It is the guarantee three of journal.go's comments rest on (OpenJournal,
// truncateToLastLine, foldJournal): more than one process holds this file open
// at once — `dpb run`, `dpb doctor --repair`, the janitor child — and O_APPEND
// is what makes each of their appends land at the CURRENT end of file instead
// of at a stale offset one of them cached. Without it a second writer's Begin
// record can be written over the first's, which is the under-approximate
// journal — applied mutations with no record to revert them — that the whole
// design exists to avoid.
//
// A separate handle for the truncate alone keeps that guarantee intact, on both
// platforms, because this handle NEVER writes a byte of file data. It cannot
// weld a fragment to a real record; it can only move the end of the file, which
// is the operation the caller asked for.
//
// Opening it while the journal's handle is open is allowed because Go opens
// files with FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE (Open() in the
// same file), and it is closed before this function returns, so it can never
// outlive the operation or be inherited by a child.
//
// It takes the path explicitly rather than reading f.Name(): the path is what
// OpenJournal was given, f.Name() is only whatever string happened to be handed
// to os.OpenFile, and a journal-healing path is the wrong place to depend on
// those staying the same thing.
func truncateJournalFile(_ *os.File, path string, size int64) error {
	// O_WRONLY and not O_APPEND: plain GENERIC_WRITE, which is what carries
	// FILE_WRITE_DATA. No O_CREATE either — the file must already exist, and
	// creating one here would hide a caller bug behind an empty journal.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		return err
	}
	// Flushed through THIS handle: the caller's Sync is on the append handle,
	// and a new end-of-file set through a different handle is not part of what
	// that one is obliged to push to the platter.
	return f.Sync()
}
