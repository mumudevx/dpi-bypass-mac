package scdarwin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeSystem is the networksetup half of netstate's fakeSystem, copied rather
// than moved.
//
// Moved is not an option: netstate's copy answers route, ifconfig, launchctl
// and scutil as well, implements RIBReader over the same state, and roughly
// sixty netstate tests drive their Ops through it — after this refactor they
// still will, because an Op reaches macOS through a Port built from that same
// Runner. Go cannot share an unexported test helper across a package boundary,
// so the services tests that follow ListServices here bring the part they need
// with them. Task 2 set the precedent when it duplicated sysport's fixture()
// helper and its testdata for the same reason.
//
// The bodies are verbatim, so a divergence between the two fakes is a
// divergence in what macOS is being modelled as doing, not an accident of
// transcription.
type fakeSystem struct {
	mu sync.Mutex

	order []string
	svc   map[string]*fakeService

	calls []string

	// failCmd injects a failure the next time a command whose joined argv has
	// the given prefix runs. The value is how many more times to fail.
	failCmd map[string]int
}

type fakeService struct {
	device   string
	disabled bool
}

func newFakeSystem() *fakeSystem {
	return &fakeSystem{
		order: []string{"Wi-Fi", "Thunderbolt Bridge"},
		svc: map[string]*fakeService{
			"Wi-Fi":              {device: "en0"},
			"Thunderbolt Bridge": {device: "bridge0"},
		},
		failCmd: map[string]int{},
	}
}

func (f *fakeSystem) env0() Env {
	return Env{Runner: f, Logf: func(string, ...any) {}}
}

// ── failure injection ────────────────────────────────────────────────────────

func (f *fakeSystem) failNext(prefix string, times int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failCmd[prefix] = times
}

func (f *fakeSystem) shouldFail(joined string) bool {
	for prefix, n := range f.failCmd {
		if n > 0 && strings.HasPrefix(joined, prefix) {
			f.failCmd[prefix] = n - 1
			return true
		}
	}
	return false
}

// ── Runner ───────────────────────────────────────────────────────────────────

func (f *fakeSystem) Run(_ context.Context, name string, args ...string) Result {
	f.mu.Lock()
	defer f.mu.Unlock()

	argv := append([]string{name}, args...)
	joined := strings.Join(argv, " ")
	f.calls = append(f.calls, joined)

	res := Result{Argv: argv}
	if f.shouldFail(joined) {
		res.Combined = "injected failure"
		res.Code = 1
		return res
	}

	switch name {
	case "networksetup":
		res.Combined, res.Code = f.networksetup(args)
	default:
		res.Combined, res.Code = name+": command not found", 127
	}
	return res
}

func (f *fakeSystem) networksetup(args []string) (string, int) {
	if len(args) == 0 {
		return "** Error: The parameters were not valid.", 4
	}
	if args[0] == "-listnetworkserviceorder" {
		var b strings.Builder
		b.WriteString("An asterisk (*) denotes that a network service is disabled.\n")
		for i, name := range f.order {
			s := f.svc[name]
			star := ""
			if s.disabled {
				star = "*"
			}
			fmt.Fprintf(&b, "(%d) %s%s\n(Hardware Port: %s, Device: %s)\n\n", i+1, star, name, name, s.device)
		}
		return strings.TrimRight(b.String(), "\n"), 0
	}
	return "** Error: The parameters were not valid.", 4
}

// fixture duplicates netstate's helper of the same name over this package's own
// copy of the captured tool output, for the reason above.
func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return strings.TrimRight(string(b), "\n")
}
