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
	// Write first, then shorten to what we wrote. Truncating first would leave
	// the file zero bytes for as long as the write takes, and `dpb status` and
	// `dpb doctor` read this file deliberately without taking the flock — they
	// would get "unexpected end of JSON input" instead of an owner. This order
	// is what makes the comment above true: a reader sees the previous owner's
	// record or ours, never neither.
	b = append(b, '\n')
	if _, err := f.WriteAt(b, 0); err != nil {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
		return nil, fmt.Errorf("netstate: write lock %s: %w", path, err)
	}
	if err := f.Truncate(int64(len(b))); err != nil {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
		return nil, fmt.Errorf("netstate: truncate lock %s: %w", path, err)
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
// depending on which processes happen to exist on the machine. It pins LC_ALL=C
// so nothing ps prints can change shape with the user's region — see psInfo.
var psRunner Runner = newExecRunnerEnv(nil, []string{"LC_ALL=C"})

// psTimeout bounds the ps call; a hung ps must not stall teardown.
const psTimeout = 3 * time.Second

// procStarter is the seam for the kernel start-time read, so tests can drive a
// pid the machine does not have.
var procStarter = kernelProcessStart

// ProcessStart reports when pid started, read from the kernel through
// sysctl KERN_PROC_PID. ok is false if the process does not exist.
//
// This deliberately does NOT parse `ps -o lstart=`. ps formats that column
// through LC_TIME, and the layout is not merely translated — it is reordered:
// on a Türkçe Mac, which is the entire target audience, the same process prints
// "Çar  2 Eyl 07:50:52 2026" (day before month) where the C locale prints
// "Wed Sep  2 07:50:52 2026". Parsing that with a fixed English layout fails,
// psInfo reports the process dead, and Replay then reverts a RUNNING dpb's
// journal — deleting its routes and restoring the user's DNS while it is
// serving traffic, which is exactly what this file's opening comment calls "far
// worse than doing nothing". The kernel's own timeval has no locale.
func ProcessStart(pid int) (time.Time, bool) {
	if pid <= 0 {
		return time.Time{}, false
	}
	return procStarter(pid)
}

func kernelProcessStart(pid int) (time.Time, bool) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil {
		return time.Time{}, false
	}
	tv := kp.Proc.P_starttime
	if tv.Sec == 0 && tv.Usec == 0 {
		return time.Time{}, false
	}
	return time.Unix(tv.Sec, int64(tv.Usec)*1000), true
}

// psInfo reports pid's executable name and start time.
//
// It asks ps for `comm=` and nothing else. Every other column ps can print is
// either locale-formatted (lstart) or variable-width, and splitting a line on a
// field count that holds in en_US but not in tr_TR is how a live process came
// to look dead. comm is a path, so it is the same bytes in every locale.
func psInfo(pid int) (comm string, start time.Time, ok bool) {
	if pid <= 0 {
		return "", time.Time{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), psTimeout)
	defer cancel()
	res := psRunner.Run(ctx, "ps", "-o", "comm=", "-p", strconv.Itoa(pid))
	if res.Failed() {
		return "", time.Time{}, false
	}
	// Not firstLine(): that substitutes "(no output)" for an empty string, which
	// would turn "this pid does not exist" into a plausible-looking name.
	out := strings.TrimSpace(res.Combined)
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		out = out[:i]
	}
	comm = strings.TrimSpace(out)
	if comm == "" {
		return "", time.Time{}, false
	}
	start, _ = ProcessStart(pid)
	return comm, start, true
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
