package netstate

import (
	"errors"
	"fmt"
	"os"
)

// ReadPending reports the journal's outstanding records WITHOUT opening it for
// writing.
//
// OpenJournal is not a read-only operation: it creates the file if it is
// missing, fsyncs the containing directory, and heals a torn final line by
// truncating the file. All three are right for a process that is about to
// journal something, and all three are wrong for `dpb status` and `dpb doctor`,
// which only want to look. Truncating in particular is a genuine hazard: the
// "torn final line" a reader sees may be a line a LIVE dpb is halfway through
// appending, and healing it would delete a record the owner still believes it
// wrote.
//
// A missing file is not an error. It is the ordinary state of a machine where
// dpb has never applied a system mutation, and it means the same thing an empty
// file does: nothing is pending.
func ReadPending(path string) ([]Record, error) {
	if path == "" {
		return nil, errors.New("netstate: journal path is empty")
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("netstate: read journal %s: %w", path, err)
	}
	return foldJournal(b)
}
