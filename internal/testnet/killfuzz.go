package testnet

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os/exec"
	"syscall"
	"time"
)

// KillFuzz runs a subprocess many times, SIGKILLs it at pseudo-random offsets,
// and checks the world afterwards.
//
// SIGKILL is the only interesting signal for this tool. Every graceful path —
// SIGINT, SIGTERM, a panic barrier, a deferred UndoAll — can be tested with an
// ordinary unit test, and all of them run the teardown code. SIGKILL runs none
// of it, which is precisely the case where a journal that was not fsynced before
// the mutation leaves a user's proxy settings pointing at a process that no
// longer exists. So the assertion after each kill is not "the program handled
// it" but "the state the program left behind is recoverable".
type KillFuzz struct {
	// Cmd builds the subprocess for iteration i. Required.
	Cmd func(ctx context.Context, i int) *exec.Cmd
	// After runs once the process is dead. killed reports whether the kill
	// landed before the process exited on its own. Replay the journal here and
	// assert the fake system is back to baseline. Required.
	After func(i int, killed bool) error
	// Iterations to run. 0 means 1.
	Iterations int
	// MinDelay and MaxDelay bound the kill offset. The point of a range is that
	// the kill lands at a different point in the mutation sequence each time;
	// with MaxDelay <= MinDelay every iteration kills at MinDelay.
	MinDelay, MaxDelay time.Duration
	// Seed makes the offsets reproducible. A failure that cannot be replayed is
	// a failure nobody will fix.
	Seed int64
	Logf func(string, ...any)
}

// Report summarises a fuzz run.
type Report struct {
	Iterations int
	Killed     int // the SIGKILL landed on a running process
	Exited     int // the process finished before the kill was due
}

// ErrKillFuzzConfig means the fuzzer was not given enough to run.
var ErrKillFuzzConfig = errors.New("testnet: killfuzz needs Cmd and After")

// Run executes the fuzz loop. It stops at the first After error and returns it
// alongside the partial report, because iterating past a state leak only
// produces more confusing leaks.
func (k *KillFuzz) Run(ctx context.Context) (Report, error) {
	var rep Report
	if k.Cmd == nil || k.After == nil {
		return rep, ErrKillFuzzConfig
	}
	iters := max(k.Iterations, 1)
	seed := uint64(k.Seed)
	if seed == 0 {
		seed = 0x9E3779B97F4A7C15
	}
	rnd := rand.New(rand.NewPCG(seed, seed^0x5DEECE66D))

	for i := range iters {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		delay := k.MinDelay
		if k.MaxDelay > k.MinDelay {
			delay += time.Duration(rnd.Int64N(int64(k.MaxDelay - k.MinDelay)))
		}
		killed, err := k.once(ctx, i, delay)
		rep.Iterations++
		if killed {
			rep.Killed++
		} else {
			rep.Exited++
		}
		if err != nil {
			return rep, err
		}
		if k.Logf != nil {
			k.Logf("testnet: killfuzz iteration %d: delay %v, killed %v", i, delay, killed)
		}
		if err := k.After(i, killed); err != nil {
			return rep, fmt.Errorf("testnet: killfuzz iteration %d (delay %v, killed %v): %w",
				i, delay, killed, err)
		}
	}
	return rep, nil
}

// once starts one subprocess, kills it after delay, and waits for it.
func (k *KillFuzz) once(ctx context.Context, i int, delay time.Duration) (killed bool, err error) {
	cmd := k.Cmd(ctx, i)
	if cmd == nil {
		return false, fmt.Errorf("testnet: killfuzz iteration %d: Cmd returned nil", i)
	}
	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("testnet: killfuzz iteration %d: start: %w", i, err)
	}
	pid := cmd.Process.Pid

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-done:
		return false, nil
	case <-ctx.Done():
		_ = syscall.Kill(pid, syscall.SIGKILL)
		<-done
		return true, ctx.Err()
	case <-timer.C:
	}

	// Kill and then WAIT. Returning before the process is reaped would let the
	// next iteration's assertions race a dying process that still holds the
	// journal's flock.
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return false, fmt.Errorf("testnet: killfuzz iteration %d: kill %d: %w", i, pid, err)
	}
	waitErr := <-done

	var exit *exec.ExitError
	if errors.As(waitErr, &exit) {
		if st, ok := exit.Sys().(syscall.WaitStatus); ok && st.Signaled() && st.Signal() == syscall.SIGKILL {
			return true, nil
		}
	}
	// The process finished on its own between the timer firing and the kill.
	return false, nil
}
