package netstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// OpKind names the class of system state an Op mutates. It is the discriminator
// Replay uses to rebuild an Op from a journal record after the process that
// wrote it is gone.
type OpKind string

const (
	OpProxyPAC   OpKind = "proxy.pac"
	OpProxyHTTP  OpKind = "proxy.http"
	OpProxySOCKS OpKind = "proxy.socks"
	OpPACFile    OpKind = "proxy.pacfile"
	OpLaunchEnv  OpKind = "proxy.launchenv"
	OpDNSServers OpKind = "dns.servers"
	OpRoute      OpKind = "route"
	OpIfconfig   OpKind = "ifconfig"
)

// Record is one journalled mutation. It has to be self-sufficient: a different
// process, at a later login, with no memory of this run, must be able to undo
// the mutation from this record alone.
type Record struct {
	Seq       uint64    `json:"seq"`
	Kind      OpKind    `json:"kind"`
	ID        string    `json:"id"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Applied   bool      `json:"applied"`
	Verified  bool      `json:"verified"`
	// Adopted marks state that already existed and that we did NOT create — a
	// VPN's -ifscope default, an admin-set PAC, a previous run's route. Revert is
	// a no-op for adopted records, which is what stops Ctrl-C from deleting a
	// VPN's routes.
	Adopted bool            `json:"adopted"`
	Revert  json.RawMessage `json:"revert"`
	Note    string          `json:"note"`
}

// Token identifies an open journal entry. It is the record's sequence number.
type Token uint64

// Journal is the durability layer. Its contract is deliberately pessimistic:
// the revert record hits stable storage before the mutation is attempted, so a
// SIGKILL in between leaves an over-approximate journal rather than an
// under-approximate one.
type Journal interface {
	// Begin writes the revert record and fsyncs BEFORE the mutation is attempted,
	// so a SIGKILL between the two leaves an over-approximate journal — the safe
	// direction, since every Revert is idempotent and VerifyReverted tolerates
	// already-absent state.
	Begin(ctx context.Context, r Record) (Token, error)
	Commit(ctx context.Context, t Token, r Record) error
	Done(ctx context.Context, t Token) error
	Pending(ctx context.Context) ([]Record, error)
	Path() string
	Close() error
}

// phase discriminates the three kinds of line in the NDJSON stream. Embedding
// Record keeps the on-disk shape flat and greppable.
type entry struct {
	Phase string `json:"phase"`
	Record
}

const (
	phaseBegin  = "begin"
	phaseCommit = "commit"
	phaseDone   = "done"
)

var errJournalClosed = errors.New("netstate: journal is closed")

// dirSyncer is the seam that makes "we fsynced the parent directory" testable;
// fsync on a directory is invisible from inside the process by construction.
var dirSyncer = fsyncDir

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

type fileJournal struct {
	mu   sync.Mutex
	path string
	f    *os.File
	seq  uint64

	// self identifies the process that owns the records this journal writes, so
	// Replay in a later process can tell "a live dpb owns this" from "a corpse
	// owns this". Resolved once, lazily, because it costs a fork.
	selfOnce  sync.Once
	selfStart time.Time

	now       func() time.Time
	pid       func() int
	startedAt func(pid int) (time.Time, bool)
}

// OpenJournal opens (creating as needed) the append-only journal at path.
func OpenJournal(path string) (Journal, error) {
	if path == "" {
		return nil, errors.New("netstate: journal path is empty")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("netstate: create journal directory %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("netstate: open journal %s: %w", path, err)
	}
	// The file's own fsync does not make its directory entry durable. On a
	// first-ever run a power loss between Begin and Apply could otherwise leave
	// the journal unlinked — an under-approximate journal, which is the one
	// direction this design exists to avoid, with the system proxy left pointing
	// at a dead port and no record that dpb set it.
	if err := dirSyncer(filepath.Dir(path)); err != nil {
		f.Close()
		return nil, err
	}
	// Heal a torn final line before anything appends to it. The journal is opened
	// O_APPEND, so a fragment left by a SIGKILL mid-write would be concatenated
	// with the next run's Begin and become an INTERIOR corrupt line — and an
	// interior corrupt line used to hide every record after it.
	if err := truncateToLastLine(f); err != nil {
		f.Close()
		return nil, err
	}
	j := &fileJournal{
		path:      path,
		f:         f,
		now:       time.Now,
		pid:       os.Getpid,
		startedAt: ProcessStart,
	}
	// Continue the sequence rather than restarting it, so records from a previous
	// run and this one never collide in a file that still holds both.
	recs, err := j.readAll()
	if err != nil {
		f.Close()
		return nil, err
	}
	for _, r := range recs {
		if r.Seq > j.seq {
			j.seq = r.Seq
		}
	}
	return j, nil
}

func (j *fileJournal) Path() string { return j.path }

func (j *fileJournal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return nil
	}
	err := j.f.Close()
	j.f = nil
	if err != nil {
		return fmt.Errorf("netstate: close journal: %w", err)
	}
	return nil
}

func (j *fileJournal) self() time.Time {
	j.selfOnce.Do(func() {
		if t, ok := j.startedAt(j.pid()); ok {
			j.selfStart = t
		}
	})
	return j.selfStart
}

func (j *fileJournal) Begin(ctx context.Context, r Record) (Token, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.seq++
	r.Seq = j.seq
	if r.PID == 0 {
		r.PID = j.pid()
	}
	if r.StartedAt.IsZero() {
		r.StartedAt = j.self()
	}
	if err := j.write(entry{Phase: phaseBegin, Record: r}); err != nil {
		j.seq--
		return 0, err
	}
	return Token(r.Seq), nil
}

func (j *fileJournal) Commit(ctx context.Context, t Token, r Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	r.Seq = uint64(t)
	if r.PID == 0 {
		r.PID = j.pid()
	}
	if r.StartedAt.IsZero() {
		r.StartedAt = j.self()
	}
	return j.write(entry{Phase: phaseCommit, Record: r})
}

func (j *fileJournal) Done(ctx context.Context, t Token) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.write(entry{Phase: phaseDone, Record: Record{Seq: uint64(t)}}); err != nil {
		return err
	}
	return j.compactLocked()
}

// write appends one line and fsyncs it. The fsync is the entire point of the
// journal: an entry that is only in the page cache does not survive the power
// loss it exists to survive.
func (j *fileJournal) write(e entry) error {
	if j.f == nil {
		return errJournalClosed
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("netstate: marshal journal record: %w", err)
	}
	b = append(b, '\n')
	if _, err := j.f.Write(b); err != nil {
		return fmt.Errorf("netstate: append to journal %s: %w", j.path, err)
	}
	if err := j.f.Sync(); err != nil {
		return fmt.Errorf("netstate: fsync journal %s: %w", j.path, err)
	}
	return nil
}

// compactLocked truncates the file once nothing is outstanding. "The journal is
// empty" is an observable promise made to `dpb doctor` and to the janitor, and
// an append-only file that never shrinks cannot keep it.
func (j *fileJournal) compactLocked() error {
	recs, err := j.readAllLocked()
	if err != nil {
		return err
	}
	if len(recs) != 0 {
		return nil
	}
	if err := j.f.Truncate(0); err != nil {
		return fmt.Errorf("netstate: truncate journal %s: %w", j.path, err)
	}
	if _, err := j.f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("netstate: rewind journal %s: %w", j.path, err)
	}
	return j.f.Sync()
}

func (j *fileJournal) Pending(ctx context.Context) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.readAllLocked()
}

func (j *fileJournal) readAll() ([]Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.readAllLocked()
}

// readAllLocked folds the NDJSON stream into the set of records that are still
// outstanding. It reads from disk rather than memory because the reader is
// usually a different process (`dpb doctor --repair`, the janitor child).
func (j *fileJournal) readAllLocked() ([]Record, error) {
	b, err := os.ReadFile(j.path)
	if err != nil {
		return nil, fmt.Errorf("netstate: read journal %s: %w", j.path, err)
	}
	return foldJournal(b)
}

// truncateToLastLine drops a trailing partial line, so the file always ends on
// a record boundary and O_APPEND can never weld a fragment to a real record.
func truncateToLastLine(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("netstate: stat journal: %w", err)
	}
	n := fi.Size()
	if n == 0 {
		return nil
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, n-1); err != nil {
		return fmt.Errorf("netstate: read journal tail: %w", err)
	}
	if last[0] == '\n' {
		return nil
	}
	b, err := io.ReadAll(io.NewSectionReader(f, 0, n))
	if err != nil {
		return fmt.Errorf("netstate: read journal: %w", err)
	}
	keep := int64(bytes.LastIndexByte(b, '\n') + 1)
	if err := f.Truncate(keep); err != nil {
		return fmt.Errorf("netstate: heal torn journal line: %w", err)
	}
	return f.Sync()
}

// foldJournal reduces the NDJSON stream to the records still outstanding.
//
// It folds line by line and SKIPS a line it cannot decode rather than stopping
// at it. Stopping is correct only while the torn line is last, and the journal
// is opened O_APPEND: a fragment that is not last hides every record after it,
// which is an under-approximate journal — applied mutations nothing can revert,
// invisible to doctor --repair, the janitor and the login agent. Worse, a
// fragment before every real record made readAllLocked return nothing, and the
// next Done() then concluded the journal was empty and truncated live records
// away.
func foldJournal(b []byte) ([]Record, error) {
	open := map[uint64]Record{}
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var e entry
		if err := json.Unmarshal(line, &e); err != nil {
			// A torn line is the expected shape of a SIGKILL mid-write. It costs us
			// that one record; every other line is still authoritative.
			continue
		}
		switch e.Phase {
		case phaseBegin, phaseCommit:
			open[e.Seq] = e.Record
		case phaseDone:
			delete(open, e.Seq)
		}
	}
	out := make([]Record, 0, len(open))
	for _, r := range open {
		out = append(out, r)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Seq < out[b].Seq })
	return out, nil
}
