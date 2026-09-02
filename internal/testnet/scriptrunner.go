// Package testnet is the fake macOS this tool is developed against.
//
// Everything netstate touches — route(8), networksetup, scutil, ifconfig, the
// kernel RIB — is either root-only, destructive, or both, so the previous
// implementation left all of it at 0% coverage and shipped a route verifier that
// trusted an exit code that can never be non-zero. The fakes here are driven by
// output captured from a real machine (internal/testnet/fixtures), so a test
// asserts against what macOS actually printed rather than against what the
// author assumed it would print.
package testnet

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/mumudevx/dpi-bypass-mac/internal/netstate"
)

//go:embed fixtures/*.txt
var fixtureFS embed.FS

// ErrNoFixture is returned for a name that is not in the captured set.
var ErrNoFixture = errors.New("testnet: no such fixture")

// Fixture returns a captured command output by file name, e.g.
// "route_exit0_fail.txt". The bytes are the machine's, verbatim.
func Fixture(name string) (string, error) {
	b, err := fixtureFS.ReadFile(path.Join("fixtures", name))
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrNoFixture, name)
	}
	return string(b), nil
}

// MustFixture is Fixture for a name the caller knows exists.
func MustFixture(name string) string {
	s, err := Fixture(name)
	if err != nil {
		panic(err)
	}
	return s
}

// Fixtures lists every captured output available.
func Fixtures() []string {
	ents, err := fixtureFS.ReadDir("fixtures")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// ErrUnscripted is what an unregistered command returns.
//
// It is a failure rather than an empty success on purpose. A fake that silently
// succeeds for anything it was not told about lets a test pass while the code
// under test runs a command nobody reviewed — which, for a package whose job is
// mutating a user's network settings, is the worst available default.
var ErrUnscripted = errors.New("testnet: command not scripted")

type rule struct {
	pattern []string
	fn      func(argv []string) netstate.Result
	hits    int
}

// ScriptRunner is a netstate.Runner driven by a script.
//
// Patterns are matched against the full argv (command name first) as a prefix,
// with "*" matching any single token. The longest matching pattern wins, so a
// specific rule can be layered over a general one.
type ScriptRunner struct {
	mu       sync.Mutex
	rules    []*rule
	fallback func(argv []string) netstate.Result
	calls    [][]string
	// Latency is added to every Result's Duration, so a caller that reasons
	// about command cost has something non-zero to reason about.
	Latency time.Duration
}

var _ netstate.Runner = (*ScriptRunner)(nil)

// NewScriptRunner returns a runner that fails every command until scripted.
func NewScriptRunner() *ScriptRunner {
	return &ScriptRunner{
		fallback: func(argv []string) netstate.Result {
			return netstate.Result{
				Argv:     argv,
				Code:     127,
				Combined: "testnet: " + strings.Join(argv, " ") + ": not scripted",
				Err:      ErrUnscripted,
			}
		},
	}
}

// OnFunc registers a handler for commands matching pattern.
func (s *ScriptRunner) OnFunc(pattern string, fn func(argv []string) netstate.Result) *ScriptRunner {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, &rule{pattern: strings.Fields(pattern), fn: fn})
	return s
}

// On registers a fixed Result for commands matching pattern. Argv is filled in
// from the actual call, so an assertion can still see what was run.
func (s *ScriptRunner) On(pattern string, r netstate.Result) *ScriptRunner {
	return s.OnFunc(pattern, func(argv []string) netstate.Result {
		out := r
		out.Argv = argv
		return out
	})
}

// OnOutput registers combined output and an exit code.
func (s *ScriptRunner) OnOutput(pattern, combined string, code int) *ScriptRunner {
	return s.On(pattern, netstate.Result{Combined: combined, Code: code})
}

// OnFixture registers a captured output with exit code 0.
//
// Zero is not a convenience default, it is the point: route(8) has no failure
// exit path — Apple's route.c declares newroute() as void and main() does
// `newroute(argc, argv); exit(0)` — so the captured failure in
// fixtures/route_exit0_fail.txt is a failure that exits 0, and any code that
// compares Code against zero instead of calling Result.Failed() is wrong.
func (s *ScriptRunner) OnFixture(pattern, fixture string) *ScriptRunner {
	return s.OnOutput(pattern, MustFixture(fixture), 0)
}

// Fallback replaces the unscripted-command behaviour.
func (s *ScriptRunner) Fallback(fn func(argv []string) netstate.Result) *ScriptRunner {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fallback = fn
	return s
}

// Run implements netstate.Runner.
func (s *ScriptRunner) Run(ctx context.Context, name string, args ...string) netstate.Result {
	argv := append([]string{name}, args...)

	s.mu.Lock()
	s.calls = append(s.calls, argv)
	best := -1
	bestLen := -1
	for i, r := range s.rules {
		if matches(r.pattern, argv) && len(r.pattern) > bestLen {
			best, bestLen = i, len(r.pattern)
		}
	}
	var fn func([]string) netstate.Result
	if best >= 0 {
		s.rules[best].hits++
		fn = s.rules[best].fn
	} else {
		fn = s.fallback
	}
	latency := s.Latency
	s.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return netstate.Result{Argv: argv, Code: -1, Err: err, Duration: latency}
	}
	out := fn(argv)
	if out.Argv == nil {
		out.Argv = argv
	}
	out.Duration += latency
	return out
}

// matches reports whether pattern is a prefix of argv, with "*" wild.
func matches(pattern, argv []string) bool {
	if len(pattern) > len(argv) {
		return false
	}
	for i, p := range pattern {
		if p != "*" && p != argv[i] {
			return false
		}
	}
	return true
}

// Calls returns every argv the runner was asked to run, in order.
func (s *ScriptRunner) Calls() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]string, len(s.calls))
	for i, c := range s.calls {
		out[i] = append([]string(nil), c...)
	}
	return out
}

// Count returns how many calls matched pattern.
func (s *ScriptRunner) Count(pattern string) int {
	pat := strings.Fields(pattern)
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		if matches(pat, c) {
			n++
		}
	}
	return n
}

// Ran reports whether any call matched pattern.
func (s *ScriptRunner) Ran(pattern string) bool { return s.Count(pattern) > 0 }

// Unused returns the patterns that were registered and never matched. A test
// that asserts on it catches a script drifting away from the code it fakes,
// which is how a fixture-driven suite rots into a suite that tests nothing.
func (s *ScriptRunner) Unused() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.rules {
		if r.hits == 0 {
			out = append(out, strings.Join(r.pattern, " "))
		}
	}
	return out
}

// Reset clears the recorded calls, keeping the script.
func (s *ScriptRunner) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = nil
	for _, r := range s.rules {
		r.hits = 0
	}
}
