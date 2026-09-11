package netstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LockInfo is the content of the run lock file. It records both the pid and the
// owning process's start time, because a pid on its own is a lie the moment the
// kernel recycles it, and reverting a healthy concurrent run's system state is
// far worse than doing nothing.
type LockInfo struct {
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Comm      string    `json:"comm"`
}

// Lock is a whole-file exclusive lock held for the life of a run: flock on
// Unix, LockFileEx on Windows. The lock itself lives on a companion file next
// to the record file; see flockPath for why.
type Lock struct {
	f    *os.File
	path string
	once sync.Once
}

// ErrLocked is returned when another live dpb already holds the run lock.
var ErrLocked = errors.New("netstate: another dpb run holds the lock")

// flockPath is the companion file that carries the advisory flock for the run
// lock whose record lives at path.
//
// The two are separate for one reason: the record is installed by RENAME, and
// rename swaps the inode out from under the name. An flock taken on the record
// file would be left holding an unlinked inode the instant the next run renamed
// a fresh record into place, so a second dpb would open the new inode, flock it
// successfully, and both processes would believe they owned the machine's proxy
// settings. The companion's inode is created once and never moves, so it is a
// stable thing to exclude on, and the record file is free to be replaced whole.
//
// Windows makes the same split mandatory from the other direction: a locked
// region pins the file, so a lock taken on the record itself would make the
// rename in writeLockRecord fail outright rather than merely mislead.
func flockPath(path string) string { return path + ".flock" }

// AcquireLock takes an exclusive non-blocking flock and then installs the
// caller's identity at path. The identity is installed after the lock is held,
// so a reader either sees the previous owner's record or ours, never a mix.
func AcquireLock(path string) (*Lock, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("netstate: create lock directory %s: %w", dir, err)
		}
	}
	// Name the file that actually failed. Reporting `path` here sent the user
	// (and doctor's remedy line) to run.lock when the unopenable file was
	// run.lock.flock beside it.
	f, err := os.OpenFile(flockPath(path), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("netstate: open lock %s: %w", flockPath(path), err)
	}
	if err := lockFile(f); err != nil {
		f.Close()
		// Both leaves report contention as ErrLocked — EWOULDBLOCK from
		// flock(LOCK_NB), ERROR_LOCK_VIOLATION from LockFileEx with
		// LOCKFILE_FAIL_IMMEDIATELY — so the message the user sees names the
		// run lock they know about rather than the companion beside it. Any
		// other failure is already named by the leaf, which knows which file
		// it touched.
		if errors.Is(err, ErrLocked) {
			return nil, fmt.Errorf("%w (%s)", ErrLocked, path)
		}
		return nil, err
	}

	pid := os.Getpid()
	info := LockInfo{PID: pid, Comm: selfComm()}
	if t, ok := ProcessStart(pid); ok {
		info.StartedAt = t
	}
	if err := writeLockRecord(path, info); err != nil {
		_ = unlockFile(f)
		f.Close()
		return nil, err
	}
	return &Lock{f: f, path: path}, nil
}

// writeLockRecord installs info at path as one indivisible step: it is written
// to a temporary file in the same directory, fsynced, and renamed over path.
//
// Nothing simpler is enough. `dpb status`, `dpb doctor` and PriorResidue read
// this file deliberately WITHOUT taking the flock — they have to, since the
// point is to describe the process that holds it — and a reader that lands
// mid-update is how a running instance's own settings get reverted underneath
// it. Updating in place cannot be made safe by ordering the write and the
// truncate, nor by padding the record out to the previous owner's length:
// os.ReadFile sizes its buffer from a stat and then reads in a LOOP, so a
// record that grows between two of those reads comes back as the old file with
// the tail of the new one welded on — measured on this machine as
// `{"pid":999999,...}\nmm":"netstate.test"}`, which parses as "invalid
// character 'm' after top-level value". Rename removes the window rather than
// narrowing it: a reader's open() pins an inode whose bytes never change again.
// TestAcquireLockIsReadableThroughout is the regression.
func writeLockRecord(path string, info LockInfo) error {
	b, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("netstate: marshal lock info: %w", err)
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("netstate: create temporary lock in %s: %w", dir, err)
	}
	name := tmp.Name()
	// A no-op once the rename below has succeeded, and the thing that keeps a
	// failed acquisition from littering the state directory when it has not.
	defer os.Remove(name)

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("netstate: write lock %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("netstate: fsync lock %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("netstate: close lock %s: %w", name, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("netstate: install lock %s: %w", path, err)
	}
	// Same reason the journal fsyncs its parent: fsyncing the file persists the
	// bytes, not the name that points at them, and PriorResidue reads this file
	// after exactly the crash that would lose the name.
	if err := dirSyncer(dir); err != nil {
		return err
	}
	return nil
}

// Release drops the lock. The record file is left behind on purpose: its
// contents are the breadcrumb `dpb doctor` reads to describe who last held it.
func (l *Lock) Release() error {
	var err error
	l.once.Do(func() {
		if e := unlockFile(l.f); e != nil {
			err = e
		}
		if e := l.f.Close(); e != nil && err == nil {
			err = fmt.Errorf("netstate: close lock %s: %w", l.path, e)
		}
	})
	return err
}

// Path returns the lock file's path.
func (l *Lock) Path() string { return l.path }

// ReadLock reads the identity of whoever last wrote the lock file. It does not
// take the lock, so it is safe to call from `dpb status`.
func ReadLock(path string) (LockInfo, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return LockInfo{}, fmt.Errorf("netstate: read lock %s: %w", path, err)
	}
	var info LockInfo
	if err := json.Unmarshal(bytes.TrimSpace(b), &info); err != nil {
		return LockInfo{}, fmt.Errorf("netstate: parse lock %s: %w", path, err)
	}
	return info, nil
}

// ownerVerdict is what a platform's process query concluded about a pid, with
// the answer that gets forgotten spelled out as a value: it concluded nothing.
//
// Asking the kernel about a process has three outcomes, not two. It is there,
// it is not there, and the kernel declined to say — the last being ordinary
// rather than exotic, since a dpb running as SYSTEM or under another desktop
// user is refused by a query that a same-user dpb is granted.
//
// The type exists because the two errors of resolving that third case are not
// symmetric, and the asymmetry is the whole safety argument of this file:
//
//   - Guess "dead" about a LIVE run and OwnerAlive is false, PriorResidue is
//     true, and Replay reverts that run's proxy, DNS and routes while its user
//     is browsing through them.
//   - Guess "alive" about a dead one and a lock record outlives its owner until
//     `dpb doctor` reports it and the user clears it.
//
// So alive() resolves anything short of positive evidence of death in favour of
// life. Only lock_windows.go builds these verdicts today; the type is here, in
// the portable file beside OwnerAlive, because the rule belongs to OwnerAlive's
// contract rather than to one platform's syscalls.
type ownerVerdict int

const (
	// ownerUnknown is a query that failed for a reason which says nothing about
	// whether the process exists: refused for want of rights, or answered with
	// something unaccounted for.
	ownerUnknown ownerVerdict = iota
	// ownerGone is positive evidence of death — the pid names no process, or
	// the process is known to have exited.
	ownerGone
	// ownerPresent is positive evidence of life.
	ownerPresent
)

// alive resolves a verdict the way OwnerAlive needs it. Note what it is NOT:
// `v == ownerPresent`. Writing it that way would fold ownerUnknown into death
// and cost a live user their network configuration.
func (v ownerVerdict) alive() bool { return v != ownerGone }

// OwnerAlive reports whether the process that wrote a journal record is still
// running. It is the default for Replay's ownerAlive argument.
//
// Three things must hold: the pid exists, its start time matches the recorded
// one (defeating pid reuse), and its executable has the same base name as ours
// (so an unrelated program that inherited the pid is not mistaken for a peer).
// A recorded zero start time falls back to the pid-and-name check, which is the
// best a record written before the start time was readable can support.
//
// Both inputs are per-platform and nothing else here is: processIdentity is
// `ps -o comm=` on Unix and QueryFullProcessImageName on Windows, ProcessStart
// is a sysctl, procfs or GetProcessTimes. sameExecutable is per-platform too,
// because Windows path comparison is case-insensitive and Unix is not.
func OwnerAlive(pid int, started time.Time) bool {
	if pid <= 0 {
		return false
	}
	comm, ok := processIdentity(pid)
	if !ok {
		return false
	}
	if !sameExecutable(comm) {
		return false
	}
	start, _ := ProcessStart(pid)
	if started.IsZero() || start.IsZero() {
		return true
	}
	// The coarsest source here reports whole seconds, so anything inside a
	// second is the same instant.
	d := start.Sub(started)
	if d < 0 {
		d = -d
	}
	return d < 2*time.Second
}

var selfCommOnce sync.Once
var selfCommName string

func selfComm() string {
	selfCommOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			selfCommName = filepath.Base(os.Args[0])
			return
		}
		selfCommName = filepath.Base(exe)
	})
	return selfCommName
}

// PriorResidue reports whether a previous dpb run left system state behind: the
// journal still holds pending records, or the run lock names an owner that is
// no longer alive. It is what Env.PriorResidue should be set from, and it is the
// only thing that lets an Op discard a captured loopback proxy or resolver it
// cannot match exactly.
//
// It is deliberately conservative. Answering "no" costs a user, at worst, a
// restored setting that points at a port nobody is listening on — recoverable,
// and PAC and DNS both fail open. Answering "yes" wrongly destroys a working
// local resolver or proxy the user configured themselves, which is not.
func PriorResidue(ctx context.Context, j Journal, lockPath string) bool {
	if j != nil {
		if pending, err := j.Pending(ctx); err == nil && len(pending) > 0 {
			return true
		}
	}
	if lockPath == "" {
		return false
	}
	info, err := ReadLock(lockPath)
	if err != nil || info.PID <= 0 || info.PID == os.Getpid() {
		return false
	}
	return !OwnerAlive(info.PID, info.StartedAt)
}
