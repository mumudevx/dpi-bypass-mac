//go:build windows

package policy

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// Windows' rename is not POSIX's rename, and this is where the difference is
// paid for.
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
const (
	// replaceAttempts and the delays below bound the wait at roughly 400ms.
	// The window being waited out is a delete-pending state or a scanner's
	// read, both measured in milliseconds; a budget an order of magnitude
	// larger than that is generous without turning a stuck file into a hang.
	// Flush() is called off the connection path (see fileStore.shouldFlush),
	// so this waits on nobody's traffic.
	replaceAttempts = 12
	replaceDelay    = time.Millisecond
	replaceMaxDelay = 50 * time.Millisecond
)

// replaceFile moves oldpath onto newpath, retrying the two transient Windows
// sharing failures and nothing else.
//
// Only ERROR_ACCESS_DENIED and ERROR_SHARING_VIOLATION are retried. A wrong
// path, a read-only volume or a cross-device move is permanent, and retrying it
// would turn an immediate error into a 400ms one. The LAST error is returned
// rather than a fabricated one, so a caller that does fail sees what Windows
// actually said.
func replaceFile(oldpath, newpath string) error {
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
