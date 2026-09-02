package testnet

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// killfuzzHelperEnv marks the re-executed test binary as the child process. The
// standard os/exec test pattern: the child is this same binary running one
// no-op test, which keeps the fuzzer's own test fast and free of build steps.
const killfuzzHelperEnv = "TESTNET_KILLFUZZ_HELPER"

// TestKillFuzzHelperProcess is the subprocess. It writes a marker file, then
// blocks until killed or until its budget expires, so a test can tell a kill
// from a natural exit by looking at what the marker says.
func TestKillFuzzHelperProcess(t *testing.T) {
	mode := os.Getenv(killfuzzHelperEnv)
	if mode == "" {
		t.Skip("not the killfuzz child")
	}
	marker := os.Getenv(killfuzzHelperEnv + "_MARKER")
	if marker != "" {
		if err := os.WriteFile(marker, []byte("started"), 0o600); err != nil {
			t.Fatalf("write marker: %v", err)
		}
	}
	if mode == "exit" {
		return
	}
	time.Sleep(30 * time.Second)
	if marker != "" {
		// Only reached if the kill never landed, which the assertions catch.
		_ = os.WriteFile(marker, []byte("survived"), 0o600)
	}
}

func helperCmd(mode, marker string) func(context.Context, int) *exec.Cmd {
	return func(ctx context.Context, i int) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestKillFuzzHelperProcess")
		cmd.Env = append(os.Environ(),
			killfuzzHelperEnv+"="+mode,
			killfuzzHelperEnv+"_MARKER="+marker,
		)
		return cmd
	}
}

// TestKillFuzzKillsAndReaps is the guarantee the journal durability suite rests
// on: the process really is SIGKILLed, really is reaped before After runs, and
// the fuzzer says so.
func TestKillFuzzKillsAndReaps(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	var seen []bool
	k := &KillFuzz{
		Cmd:        helperCmd("block", marker),
		Iterations: 3,
		MinDelay:   30 * time.Millisecond,
		MaxDelay:   60 * time.Millisecond,
		Seed:       11,
		Logf:       func(string, ...any) {},
		After: func(i int, killed bool) error {
			seen = append(seen, killed)
			b, err := os.ReadFile(marker)
			if err != nil {
				return err
			}
			if string(b) != "started" {
				return errors.New("child ran to completion instead of being killed: " + string(b))
			}
			return nil
		},
	}
	rep, err := k.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Iterations != 3 || rep.Killed != 3 || rep.Exited != 0 {
		t.Fatalf("report = %+v, want 3 kills", rep)
	}
	for i, killed := range seen {
		if !killed {
			t.Errorf("iteration %d reported no kill", i)
		}
	}
}

// TestKillFuzzNotesANaturalExit keeps the report honest when the child finishes
// first. Counting that as a kill would overstate how much of the crash window
// the suite has actually explored.
func TestKillFuzzNotesANaturalExit(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	k := &KillFuzz{
		Cmd:        helperCmd("exit", marker),
		Iterations: 2,
		MinDelay:   10 * time.Second, // far longer than the child lives
		After:      func(int, bool) error { return nil },
	}
	rep, err := k.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Killed != 0 || rep.Exited != 2 {
		t.Fatalf("report = %+v, want two natural exits", rep)
	}
}

// TestKillFuzzStopsOnCheckFailure: iterating past a state leak only produces
// more confusing leaks, and the error must name the iteration and its delay so a
// failure can be reproduced from the seed.
func TestKillFuzzStopsOnCheckFailure(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	boom := errors.New("journal not empty after replay")
	calls := 0
	k := &KillFuzz{
		Cmd:        helperCmd("block", marker),
		Iterations: 5,
		MinDelay:   20 * time.Millisecond,
		Seed:       3,
		After: func(i int, killed bool) error {
			calls++
			if i == 1 {
				return boom
			}
			return nil
		},
	}
	rep, err := k.Run(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the check failure", err)
	}
	if calls != 2 {
		t.Fatalf("After ran %d times, want it to stop at the failure", calls)
	}
	if rep.Iterations != 2 {
		t.Fatalf("report = %+v", rep)
	}
	if !strings.Contains(err.Error(), "iteration 1") || !strings.Contains(err.Error(), "delay") {
		t.Errorf("error does not identify the iteration and delay: %v", err)
	}
}

func TestKillFuzzConfigIsRequired(t *testing.T) {
	if _, err := (&KillFuzz{}).Run(context.Background()); !errors.Is(err, ErrKillFuzzConfig) {
		t.Fatalf("err = %v, want ErrKillFuzzConfig", err)
	}
	k := &KillFuzz{Cmd: func(context.Context, int) *exec.Cmd { return nil }}
	if _, err := k.Run(context.Background()); !errors.Is(err, ErrKillFuzzConfig) {
		t.Fatalf("err = %v, want ErrKillFuzzConfig without After", err)
	}
}

func TestKillFuzzNilCmdIsAnError(t *testing.T) {
	k := &KillFuzz{
		Cmd:   func(context.Context, int) *exec.Cmd { return nil },
		After: func(int, bool) error { return nil },
	}
	if _, err := k.Run(context.Background()); err == nil {
		t.Fatal("a nil Cmd was accepted")
	}
}

func TestKillFuzzHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	k := &KillFuzz{
		Cmd:   helperCmd("exit", ""),
		After: func(int, bool) error { return nil },
	}
	if _, err := k.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
