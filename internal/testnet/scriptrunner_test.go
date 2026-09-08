package testnet

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/netstate"
)

// TestRouteFixtureIsTheCapturedLiar is the load-bearing test of this package.
//
// macOS route(8) has no failure exit path: Apple's route.c declares newroute()
// as void and main() does `newroute(argc, argv); exit(0)`. Re-verified on this
// machine on 2026-09-02, `route -n get -inet6 2001:db8::1` printed
// "route: writing to routing socket: not in table" and exited 0. Every route
// mutation in this tool is therefore verified against the kernel RIB and never
// against an exit code, and this test pins the captured evidence so the rule
// cannot be quietly relaxed.
func TestRouteFixtureIsTheCapturedLiar(t *testing.T) {
	out := MustFixture("route_exit0_fail.txt")
	if !strings.Contains(out, "writing to routing socket") {
		t.Fatalf("fixture lost its captured text: %q", out)
	}
	if !strings.Contains(out, "not in table") {
		t.Fatalf("fixture lost the failure reason: %q", out)
	}

	s := NewScriptRunner().OnFixture("route -n get", "route_exit0_fail.txt")
	r := s.Run(context.Background(), "route", "-n", "get", "-inet6", "2001:db8::1")

	if r.Code != 0 {
		t.Fatalf("exit code = %d; the captured failure exits 0", r.Code)
	}
	if !r.Failed() {
		t.Fatalf("Result.Failed() = false for %q at exit 0; this is the defect the "+
			"known-liar table exists to catch", r.Combined)
	}
	if r.Reason() == "" {
		t.Errorf("Reason() is empty for a known liar")
	}
}

// TestFixturesAreAllPresent guards against a fixture being deleted, which would
// silently turn a captured-reality test into a hand-written one.
func TestFixturesAreAllPresent(t *testing.T) {
	want := map[string]string{
		"route_exit0_fail.txt":      "writing to routing socket",
		"scutil_dns.txt":            "nameserver[0] : 192.168.0.1",
		"scutil_proxy.txt":          "HTTPSEnable : 0",
		"networksetup_services.txt": "(Hardware Port: Wi-Fi, Device: en0)",
	}
	got := Fixtures()
	if len(got) != len(want) {
		t.Fatalf("Fixtures() = %v, want %d entries", got, len(want))
	}
	for name, needle := range want {
		body, err := Fixture(name)
		if err != nil {
			t.Errorf("Fixture(%q): %v", name, err)
			continue
		}
		if !strings.Contains(body, needle) {
			t.Errorf("%s does not contain %q", name, needle)
		}
	}
	if _, err := Fixture("nope.txt"); !errors.Is(err, ErrNoFixture) {
		t.Errorf("Fixture(nope) = %v, want ErrNoFixture", err)
	}
}

func TestMustFixturePanicsOnUnknown(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustFixture did not panic on an unknown name")
		}
	}()
	_ = MustFixture("nope.txt")
}

// TestUnscriptedCommandFails pins the safe default: a fake that succeeds for
// commands nobody scripted lets a test pass while the code runs something
// unreviewed against a user's network settings.
func TestUnscriptedCommandFails(t *testing.T) {
	s := NewScriptRunner()
	r := s.Run(context.Background(), "networksetup", "-setwebproxy", "Wi-Fi", "1.2.3.4", "8080")
	if !r.Failed() {
		t.Fatal("an unscripted command succeeded")
	}
	if !errors.Is(r.Err, ErrUnscripted) {
		t.Fatalf("err = %v, want ErrUnscripted", r.Err)
	}
	if !strings.Contains(r.Combined, "-setwebproxy") {
		t.Errorf("combined output does not name the command: %q", r.Combined)
	}
}

// TestLongestPatternWins lets a specific rule sit over a general one, which is
// how a test scripts "every scutil call fails except this one".
func TestLongestPatternWins(t *testing.T) {
	s := NewScriptRunner().
		OnOutput("scutil", "general", 0).
		OnOutput("scutil --proxy", "specific", 0)

	if got := s.Run(context.Background(), "scutil", "--proxy").Combined; got != "specific" {
		t.Errorf("scutil --proxy = %q, want the longer pattern to win", got)
	}
	if got := s.Run(context.Background(), "scutil", "--dns").Combined; got != "general" {
		t.Errorf("scutil --dns = %q, want the general rule", got)
	}
}

// TestWildcardToken covers the service name a test cannot know in advance.
func TestWildcardToken(t *testing.T) {
	s := NewScriptRunner().OnOutput("networksetup -setdnsservers * 127.0.0.1", "", 0)
	if r := s.Run(context.Background(), "networksetup", "-setdnsservers", "Wi-Fi", "127.0.0.1"); r.Failed() {
		t.Fatalf("wildcard did not match: %+v", r)
	}
	if r := s.Run(context.Background(), "networksetup", "-setdnsservers", "Wi-Fi", "8.8.8.8"); !r.Failed() {
		t.Fatal("wildcard matched a different final argument")
	}
}

// TestCallsAreRecorded is what lets a test assert on ordering, which is the only
// way to check that teardown ran in reverse.
func TestCallsAreRecorded(t *testing.T) {
	s := NewScriptRunner().OnOutput("networksetup", "", 0)
	ctx := context.Background()
	s.Run(ctx, "networksetup", "-setwebproxystate", "Wi-Fi", "on")
	s.Run(ctx, "networksetup", "-setwebproxystate", "Wi-Fi", "off")

	calls := s.Calls()
	if len(calls) != 2 {
		t.Fatalf("Calls() = %v", calls)
	}
	if calls[0][3] != "on" || calls[1][3] != "off" {
		t.Fatalf("call order lost: %v", calls)
	}
	if n := s.Count("networksetup -setwebproxystate"); n != 2 {
		t.Errorf("Count = %d, want 2", n)
	}
	if !s.Ran("networksetup -setwebproxystate Wi-Fi off") {
		t.Error("Ran() missed the off call")
	}
	if s.Ran("route") {
		t.Error("Ran() invented a route call")
	}

	// Mutating the returned slice must not corrupt the record.
	calls[0][0] = "tampered"
	if s.Calls()[0][0] != "networksetup" {
		t.Error("Calls() returned an aliased slice")
	}

	s.Reset()
	if len(s.Calls()) != 0 {
		t.Error("Reset did not clear the calls")
	}
}

// TestUnusedRulesAreReported catches a script that has drifted away from the
// code it fakes — the way a fixture-driven suite rots into one that tests
// nothing.
func TestUnusedRulesAreReported(t *testing.T) {
	s := NewScriptRunner().
		OnOutput("route -n get default", "gateway: 192.168.0.1", 0).
		OnOutput("ifconfig utun9", "", 0)

	s.Run(context.Background(), "route", "-n", "get", "default")
	unused := s.Unused()
	if len(unused) != 1 || unused[0] != "ifconfig utun9" {
		t.Fatalf("Unused() = %v, want [ifconfig utun9]", unused)
	}
	s.Reset()
	if len(s.Unused()) != 2 {
		t.Fatalf("Reset must clear hit counts, got %v", s.Unused())
	}
}

// TestOnFuncSeesArgv lets a script answer differently per invocation, which is
// how the adopt-detection tests model "the route was absent, then present".
func TestOnFuncSeesArgv(t *testing.T) {
	var seen []string
	s := NewScriptRunner().OnFunc("route", func(argv []string) netstate.Result {
		seen = argv
		return netstate.Result{Combined: strings.Join(argv, "|")}
	})
	r := s.Run(context.Background(), "route", "add", "-host", "1.2.3.4", "192.168.0.1")
	if r.Combined != "route|add|-host|1.2.3.4|192.168.0.1" {
		t.Fatalf("combined = %q", r.Combined)
	}
	if len(seen) != 5 {
		t.Fatalf("handler saw %v", seen)
	}
	if len(r.Argv) != 5 {
		t.Errorf("Result.Argv = %v, want it filled in", r.Argv)
	}
}

// TestFallbackAndLatency covers the two knobs a slow-command test needs.
func TestFallbackAndLatency(t *testing.T) {
	s := NewScriptRunner().Fallback(func(argv []string) netstate.Result {
		return netstate.Result{Argv: argv, Combined: "ok"}
	})
	s.Latency = 5 * time.Millisecond

	r := s.Run(context.Background(), "anything")
	if r.Failed() {
		t.Fatalf("fallback did not take effect: %+v", r)
	}
	if r.Duration != 5*time.Millisecond {
		t.Errorf("Duration = %v, want the configured latency", r.Duration)
	}
}

// TestCancelledContextIsReported keeps the fake honest about a cancelled
// teardown: the command must not appear to have succeeded.
func TestCancelledContextIsReported(t *testing.T) {
	s := NewScriptRunner().OnOutput("route", "", 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := s.Run(ctx, "route", "delete", "default")
	if !r.Failed() || !errors.Is(r.Err, context.Canceled) {
		t.Fatalf("cancelled run = %+v, want a context error", r)
	}
	// It must still be recorded: a test asserting "teardown attempted the
	// delete" needs to see it.
	if !s.Ran("route delete default") {
		t.Error("a cancelled call was not recorded")
	}
}

// TestScriptRunnerSatisfiesTheInterface is a compile-time claim made explicit,
// because the whole package is worthless if it stops being a netstate.Runner.
func TestScriptRunnerSatisfiesTheInterface(t *testing.T) {
	var r netstate.Runner = NewScriptRunner()
	if r.Run(context.Background(), "true").Code != 127 {
		t.Fatal("unexpected default result")
	}
}
