//go:build windows

package paths

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// Windows' rename is not POSIX's rename, and this is where the difference is
// paid for, once, for every write-temp-then-rename in this tree.
//
// MoveFileEx(MOVEFILE_REPLACE_EXISTING) — what os.Rename compiles to here — has
// to OPEN the destination to delete it. If anything else holds that file open
// at that instant, or if a previous replacement of the same destination is
// still in its delete-pending window, the call fails with ERROR_ACCESS_DENIED
// or ERROR_SHARING_VIOLATION. POSIX rename(2) has no such window: it never
// opens the destination at all.
//
// Measured, not inferred: on windows-latest, 2026-09-14,
// TestStoreIsConcurrencySafe drove 400 Flush() calls from 8 goroutines and 7 of
// them failed with `rename ... verdicts.json: Access is denied.` — the store
// silently losing the verdicts it had just been told to make durable. See
// docs/MEASUREMENTS-windows.md.
//
// It is not only a test artefact. The same failure is a well-known Windows
// field problem for write-temp-then-rename: Defender's real-time scanner, the
// Search indexer and backup agents all open a file they have just seen created,
// which is precisely the destination of the next flush. A single-attempt rename
// on Windows therefore drops data on an ordinary desktop, not just under
// contention from dpb itself.
//
// Which is why this does not live in internal/policy any more. It landed there
// because the verdict store is where the failure was first measured, but the
// reasoning above never mentioned the verdict store: it is about Defender and a
// destination file, and this tree replaces a destination file in five other
// places. The one that matters most is the PAC install
// (internal/netstate/op_pacfile.go), which runs on the MUTATION path — a
// sharing violation there is a revert that did not happen and a user left with
// a system proxy pointing at a PAC that is not the one dpb thinks it wrote.
// The others are the tuned profile (internal/config/tuned.go), the netstate
// lock (internal/netstate/lock.go), the event log's rotation
// (internal/observ/events.go) and the verdict store this started as.
//
// This package is the home because it already owns the other Windows-specific
// fact about dpb's own files — RestrictToOwner's ACL — and because it imports
// no other package in this tree, so netstate, policy, config and observ can all
// reach it without an import cycle.
const (
	// replaceAttempts and the delays below bound the wait at roughly 400ms.
	// The window being waited out is a delete-pending state or a scanner's
	// read, both measured in milliseconds; a budget an order of magnitude
	// larger than that is generous without turning a stuck file into a hang.
	// No caller is on the connection path: the verdict store's Flush() is
	// called off it (see fileStore.shouldFlush), and the PAC install, the lock
	// acquisition, the profile write and a log rotation are all setup or
	// teardown steps that a user is already waiting on a system call for.
	replaceAttempts = 12
	replaceDelay    = time.Millisecond
	replaceMaxDelay = 50 * time.Millisecond
)

// ReplaceFile moves oldpath onto newpath, retrying the two transient Windows
// sharing failures and nothing else.
//
// Only ERROR_ACCESS_DENIED and ERROR_SHARING_VIOLATION are retried. A wrong
// path, a read-only volume or a cross-device move is permanent, and retrying it
// would turn an immediate error into a 400ms one. The LAST error is returned
// rather than a fabricated one, so a caller that does fail sees what Windows
// actually said. In particular ERROR_FILE_NOT_FOUND comes straight back on the
// first attempt, so a caller that treats a missing source as success — the
// event log's rotation does, for a generation that does not exist yet — keeps
// answering immediately rather than waiting out a budget for a file that is
// never going to appear.
func ReplaceFile(oldpath, newpath string) error {
	delay := replaceDelay
	var err error
	for i := range replaceAttempts {
		if err = os.Rename(oldpath, newpath); err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) &&
			!errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return err
		}
		if i == replaceAttempts-1 {
			break
		}
		time.Sleep(delay)
		if delay < replaceMaxDelay {
			delay *= 2
		}
	}
	return err
}
