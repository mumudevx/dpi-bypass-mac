package netstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
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

// Lock is an advisory flock on the run lock file, held for the life of a run.
type Lock struct {
	f    *os.File
	path string
	once sync.Once
}

// ErrLocked is returned when another live dpb already holds the run lock.
var ErrLocked = errors.New("netstate: another dpb run holds the lock")

// AcquireLock takes an exclusive non-blocking flock on path and writes the
// caller's identity into it. The identity is written after the lock is held, so
// a reader either sees the previous owner's record or ours, never a mix.
func AcquireLock(path string) (*Lock, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("netstate: create lock directory %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("netstate: open lock %s: %w", path, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (%s)", ErrLocked, path)
		}
		return nil, fmt.Errorf("netstate: lock %s: %w", path, err)
	}

	pid := os.Getpid()
	info := LockInfo{PID: pid, Comm: selfComm()}
	if t, ok := ProcessStart(pid); ok {
		info.StartedAt = t
	}
	b, err := json.Marshal(info)
	if err != nil {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
		return nil, fmt.Errorf("netstate: marshal lock info: %w", err)
	}
	if err := f.Truncate(0); err != nil {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
		return nil, fmt.Errorf("netstate: truncate lock %s: %w", path, err)
	}
	if _, err := f.WriteAt(append(b, '\n'), 0); err != nil {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
		return nil, fmt.Errorf("netstate: write lock %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
		return nil, fmt.Errorf("netstate: fsync lock %s: %w", path, err)
	}
	return &Lock{f: f, path: path}, nil
}

// Release drops the lock. The file is left behind on purpose: its contents are
// the breadcrumb `dpb doctor` reads to describe who last held it.
func (l *Lock) Release() error {
	var err error
	l.once.Do(func() {
		if e := unix.Flock(int(l.f.Fd()), unix.LOCK_UN); e != nil {
			err = fmt.Errorf("netstate: unlock %s: %w", l.path, e)
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

// psRunner is the seam that lets the ps-backed helpers be tested without
// depending on which processes happen to exist on the machine.
var psRunner Runner = NewExecRunner(nil)

// psTimeout bounds the ps call; a hung ps must not stall teardown.
const psTimeout = 3 * time.Second

// psLstartLayout matches `ps -o lstart=`, e.g. "Tue Sep  2 09:41:07 2026".
const psLstartLayout = "Mon Jan _2 15:04:05 2006"

// ProcessStart reports when pid started, using `ps -o lstart=`. ok is false if
// the process does not exist or the timestamp cannot be parsed.
func ProcessStart(pid int) (time.Time, bool) {
	_, start, ok := psInfo(pid)
	return start, ok
}

func psInfo(pid int) (comm string, start time.Time, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), psTimeout)
	defer cancel()
	res := psRunner.Run(ctx, "ps", "-o", "lstart=,comm=", "-p", strconv.Itoa(pid))
	if res.Failed() {
		return "", time.Time{}, false
	}
	line := strings.TrimSpace(firstLine(res.Combined))
	if line == "" {
		return "", time.Time{}, false
	}
	// lstart is exactly five whitespace-separated fields; everything after it is
	// comm, which may itself contain spaces.
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return "", time.Time{}, false
	}
	stamp := strings.Join(fields[:5], " ")
	t, err := time.ParseInLocation(psLstartLayout, stamp, time.Local)
	if err != nil {
		return "", time.Time{}, false
	}
	return strings.Join(fields[5:], " "), t, true
}

// OwnerAlive reports whether the process that wrote a journal record is still
// running. It is the default for Replay's ownerAlive argument.
//
// Three things must hold: the pid exists, its start time matches the recorded
// one (defeating pid reuse), and its executable has the same base name as ours
// (so an unrelated program that inherited the pid is not mistaken for a peer).
// A recorded zero start time falls back to the pid-and-name check, which is the
// best a record written before ps was reachable can support.
func OwnerAlive(pid int, started time.Time) bool {
	if pid <= 0 {
		return false
	}
	comm, start, ok := psInfo(pid)
	if !ok {
		return false
	}
	if filepath.Base(comm) != selfComm() {
		return false
	}
	if started.IsZero() || start.IsZero() {
		return true
	}
	// ps reports whole seconds, so anything inside a second is the same instant.
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
