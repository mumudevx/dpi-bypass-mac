package observ

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Record is one line of the NDJSON event log.
//
// Fields is flattened into the top-level object, so `jq 'select(.host=="x")'`
// works without knowing an envelope shape. Reserved keys (ts, kind) win over a
// caller field of the same name rather than being silently shadowed.
type Record struct {
	Time   time.Time
	Kind   string
	Fields map[string]any
}

// EventLogOptions configures an EventLog.
type EventLogOptions struct {
	// Path is the active log file. Its directory must already exist.
	Path string
	// MaxBytes rotates the file once it would exceed this size. 0 selects
	// DefaultMaxBytes; a negative value disables rotation.
	MaxBytes int64
	// Keep is how many rotated generations to retain (events.ndjson.1 ..
	// events.ndjson.N). 0 selects DefaultKeep.
	Keep int
	// Now is a clock seam for tests. nil means time.Now.
	Now func() time.Time
	// Chown, when non-nil, is called on every file the log creates. It is how
	// a run under sudo leaves logs the user can still read.
	Chown func(path string) error
}

const (
	// DefaultMaxBytes keeps a full log under a few megabytes total. The event
	// log is a debugging aid on a laptop, not a metrics pipeline.
	DefaultMaxBytes = 8 << 20
	DefaultKeep     = 3
)

// EventLog appends NDJSON records to a file, rotating by size. It is safe for
// concurrent use.
type EventLog struct {
	mu   sync.Mutex
	f    *os.File
	size int64
	opts EventLogOptions
}

// OpenEventLog opens (creating if needed) the event log at opts.Path.
func OpenEventLog(opts EventLogOptions) (*EventLog, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("observ: event log path is empty")
	}
	if opts.MaxBytes == 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	if opts.Keep <= 0 {
		opts.Keep = DefaultKeep
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	e := &EventLog{opts: opts}
	if err := e.open(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *EventLog) open() error {
	f, err := os.OpenFile(e.opts.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("observ: open event log %s: %w", e.opts.Path, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("observ: stat event log %s: %w", e.opts.Path, err)
	}
	e.f = f
	e.size = st.Size()
	if e.opts.Chown != nil {
		if err := e.opts.Chown(e.opts.Path); err != nil {
			return err
		}
	}
	return nil
}

// Write appends one record. The returned error is the caller's to report; the
// event log never logs about itself, to keep the logger and the event log from
// feeding each other.
func (e *EventLog) Write(r Record) error {
	if r.Time.IsZero() {
		r.Time = e.opts.Now()
	}
	line, err := marshalRecord(r)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.f == nil {
		return fmt.Errorf("observ: event log %s is closed", e.opts.Path)
	}
	if err := e.rotateIfNeededLocked(int64(len(line))); err != nil {
		return err
	}
	n, err := e.f.Write(line)
	e.size += int64(n)
	if err != nil {
		return fmt.Errorf("observ: write event log %s: %w", e.opts.Path, err)
	}
	return nil
}

func marshalRecord(r Record) ([]byte, error) {
	obj := make(map[string]any, len(r.Fields)+2)
	for k, v := range r.Fields {
		obj[k] = v
	}
	obj["ts"] = r.Time.UTC().Format(time.RFC3339Nano)
	obj["kind"] = r.Kind
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("observ: marshal %q event: %w", r.Kind, err)
	}
	return append(b, '\n'), nil
}

func (e *EventLog) rotateIfNeededLocked(incoming int64) error {
	if e.opts.MaxBytes < 0 || e.size+incoming <= e.opts.MaxBytes {
		return nil
	}
	// A single record larger than the whole budget must still be written
	// somewhere; rotating first at least keeps it in a file of its own.
	if err := e.f.Close(); err != nil {
		return fmt.Errorf("observ: close event log before rotation: %w", err)
	}
	e.f = nil
	if err := e.shift(); err != nil {
		return err
	}
	return e.open()
}

// shift renames events.ndjson.(N-1) -> .N downwards and the active file -> .1,
// dropping the oldest generation.
func (e *EventLog) shift() error {
	base := e.opts.Path
	oldest := fmt.Sprintf("%s.%d", base, e.opts.Keep)
	if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("observ: remove %s: %w", oldest, err)
	}
	for i := e.opts.Keep - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", base, i)
		to := fmt.Sprintf("%s.%d", base, i+1)
		if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("observ: rotate %s -> %s: %w", from, to, err)
		}
	}
	to := base + ".1"
	if err := os.Rename(base, to); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("observ: rotate %s -> %s: %w", base, to, err)
	}
	if e.opts.Chown != nil {
		if err := e.opts.Chown(to); err != nil {
			return err
		}
	}
	return nil
}

// Size is the current size of the active file in bytes.
func (e *EventLog) Size() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.size
}

// Files lists the active log and its surviving rotations, newest first. It is
// what `dpb doctor` prints when it tells a user which files to attach.
func (e *EventLog) Files() []string {
	base := e.opts.Path
	out := []string{}
	if _, err := os.Stat(base); err == nil {
		out = append(out, base)
	}
	var rotated []string
	for i := 1; i <= e.opts.Keep; i++ {
		p := fmt.Sprintf("%s.%d", base, i)
		if _, err := os.Stat(p); err == nil {
			rotated = append(rotated, p)
		}
	}
	sort.Strings(rotated)
	return append(out, rotated...)
}

// Close flushes and closes the active file. It is idempotent.
func (e *EventLog) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.f == nil {
		return nil
	}
	err := e.f.Close()
	e.f = nil
	if err != nil {
		return fmt.Errorf("observ: close event log %s: %w", e.opts.Path, err)
	}
	return nil
}

// EventLogPathFor is the conventional filename inside a log directory.
func EventLogPathFor(dir string) string { return filepath.Join(dir, "events.ndjson") }
