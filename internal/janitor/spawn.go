package janitor

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

// JanitorCommand is the hidden subcommand the child runs. It is a const rather
// than a string typed in two places because cliapp registers the command and
// this file spawns it, and a typo would only show up as a janitor that never
// worked — silently, on the one exit path nobody tests by hand.
const JanitorCommand = "_janitor"

// SpawnOptions configure the child process.
type SpawnOptions struct {
	// Exe is the dpb binary to run. Empty means os.Executable().
	//
	// It MUST be a dpb binary: netstate.OwnerAlive compares the base name of a
	// journal record's owning process against the base name of the CURRENT
	// executable, so a janitor running under any other name would decide that
	// its own live parent is a stranger.
	Exe string
	// ParentPID is the process to watch. Zero means os.Getpid().
	ParentPID int
	// JournalPath is the journal the child replays. Required.
	JournalPath string
	// Stderr, when non-nil, receives the child's diagnostics. Nil discards
	// them: the child normally outlives the terminal its parent was started
	// from, and writing to a closed pty would kill it with SIGPIPE at the
	// moment it is needed.
	Stderr *os.File
	// Env is the child's environment. Nil means the parent's, which is what
	// carries SUDO_USER through so the child resolves the same paths.
	Env []string
}

// Child is a running janitor.
type Child struct {
	cmd  *exec.Cmd
	once sync.Once
	err  error
}

// Spawn starts the janitor child.
//
// Detaching the child from its parent is platform-bound — see detachAttrs in
// spawn_unix.go and spawn_windows.go — but everything else about starting it
// is not, which is why this file carries no build tag.
func Spawn(o SpawnOptions) (*Child, error) {
	if o.JournalPath == "" {
		return nil, errors.New("janitor: spawn needs the journal path")
	}
	exe := o.Exe
	if exe == "" {
		p, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("janitor: find this executable: %w", err)
		}
		exe = p
	}
	pid := o.ParentPID
	if pid == 0 {
		pid = os.Getpid()
	}

	cmd := exec.Command(exe, JanitorCommand,
		"--parent-pid", strconv.Itoa(pid),
		"--journal", o.JournalPath)
	cmd.Env = o.Env
	cmd.Stdin = nil
	cmd.Stdout = nil
	if o.Stderr != nil {
		cmd.Stderr = o.Stderr
	}
	cmd.SysProcAttr = detachAttrs()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("janitor: start %s %s: %w", exe, JanitorCommand, err)
	}
	return &Child{cmd: cmd}, nil
}

// PID is the child's process id, or 0 if it never started.
func (c *Child) PID() int {
	if c == nil || c.cmd == nil || c.cmd.Process == nil {
		return 0
	}
	return c.cmd.Process.Pid
}

// Stop ends the janitor and reaps it. It is called on the clean exit paths,
// where the parent has already run UndoAll itself and there is nothing left to
// replay.
//
// Leaving the child running instead would be safe — it would wake, find an
// empty journal and exit — but it would also leave a stray process behind for
// every run, and a user who sees two dpb processes in Activity Monitor has no
// way to know which one is the real one.
//
// HOW the child is asked to go is a platform leaf, requestStop: SIGTERM on
// Unix, TerminateProcess on Windows. It has to be, because a shared
// Process.Signal(SIGTERM) is not merely less graceful on Windows, it is an
// immediate error there — os/exec_windows.go answers every signal but Kill
// with syscall.EWINDOWS — so this, the NORMAL exit path, would report
// "not supported by windows" on every clean Ctrl-C and stall the whole
// stopBudget first because nothing had actually been asked to exit.
func (c *Child) Stop() error {
	if c == nil || c.cmd == nil || c.cmd.Process == nil {
		return nil
	}
	c.once.Do(func() {
		if err := requestStop(c.cmd.Process); err != nil &&
			!errors.Is(err, os.ErrProcessDone) {
			c.err = fmt.Errorf("janitor: stop child %d: %w", c.cmd.Process.Pid, err)
		}
		// Reap it, but never block the parent's teardown budget on it: a
		// janitor that ignores the stop request is a bug worth reporting, not
		// a reason to hold the user's network settings hostage.
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = c.cmd.Wait()
		}()
		select {
		case <-done:
		case <-time.After(stopBudget):
			if c.err == nil {
				c.err = fmt.Errorf("janitor: child %d did not exit within %s",
					c.cmd.Process.Pid, stopBudget)
			}
			_ = c.cmd.Process.Kill()
		}
	})
	return c.err
}

// stopBudget bounds how long Stop waits for the child to go away.
const stopBudget = 2 * time.Second
