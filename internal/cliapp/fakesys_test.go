package cliapp

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/mumudevx/dpb/internal/netstate"
)

// fakeMac is an in-memory macOS: it answers networksetup, scutil and launchctl
// from ONE piece of state, and implements netstate.RIBReader over an empty
// routing table.
//
// One source of truth is what makes the assertions here mean anything. netstate
// verifies every mutation through a different subsystem than it wrote with —
// networksetup writes, `scutil --proxy` reads — so a fake that recorded the
// commands issued rather than modelling their effect would let a run that
// changed nothing report success.
type fakeMac struct {
	mu sync.Mutex

	order []string
	svc   map[string]*fakeSvc
	env   map[string]string

	calls []string
	// fail makes the next N calls whose joined argv has this prefix fail.
	fail map[string]int
	// watch, if set, is called once per command with its joined argv, AFTER the
	// command has taken effect and outside the mutex, so the callback is free to
	// observe the running proxy — that is how a test pins the ORDER of teardown
	// against something other than the fake's own call log.
	watch func(argv string)
}

type fakeSvc struct {
	device string

	pacURL string
	pacOn  bool

	webHost string
	webPort int
	webOn   bool

	secHost string
	secPort int
	secOn   bool

	sockHost string
	sockPort int
	sockOn   bool
}

func newFakeMac() *fakeMac {
	return &fakeMac{
		order: []string{"Wi-Fi"},
		svc:   map[string]*fakeSvc{"Wi-Fi": {device: "en0"}},
		env:   map[string]string{},
		fail:  map[string]int{},
	}
}

func (f *fakeMac) failNext(prefix string, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[prefix] = n
}

// watchCalls installs (or, with nil, removes) the per-command observer.
func (f *fakeMac) watchCalls(fn func(argv string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.watch = fn
}

func (f *fakeMac) Run(ctx context.Context, name string, args ...string) netstate.Result {
	res := f.run(ctx, name, args...)
	f.mu.Lock()
	w := f.watch
	f.mu.Unlock()
	if w != nil {
		w(strings.Join(res.Argv, " "))
	}
	return res
}

func (f *fakeMac) run(_ context.Context, name string, args ...string) netstate.Result {
	f.mu.Lock()
	defer f.mu.Unlock()

	argv := append([]string{name}, args...)
	joined := strings.Join(argv, " ")
	f.calls = append(f.calls, joined)

	res := netstate.Result{Argv: argv}
	for prefix, n := range f.fail {
		if n > 0 && strings.HasPrefix(joined, prefix) {
			f.fail[prefix] = n - 1
			res.Combined, res.Code = "** Error: injected", 1
			return res
		}
	}

	switch name {
	case "networksetup":
		res.Combined, res.Code = f.networksetup(args)
	case "scutil":
		res.Combined, res.Code = f.scutil(args)
	case "launchctl":
		res.Combined, res.Code = f.launchctl(args)
	case "ps":
		// No such process: nothing this fake runs is alive.
		res.Combined, res.Code = "", 1
	default:
		res.Combined, res.Code = name+": command not found", 127
	}
	return res
}

func (f *fakeMac) networksetup(args []string) (string, int) {
	if len(args) == 0 {
		return "** Error: The parameters were not valid.", 4
	}
	if args[0] == "-listnetworkserviceorder" {
		var b strings.Builder
		b.WriteString("An asterisk (*) denotes that a network service is disabled.\n")
		for i, name := range f.order {
			fmt.Fprintf(&b, "(%d) %s\n(Hardware Port: %s, Device: %s)\n\n",
				i+1, name, name, f.svc[name].device)
		}
		return strings.TrimRight(b.String(), "\n"), 0
	}
	if len(args) < 2 {
		return "** Error: The parameters were not valid.", 4
	}
	s, ok := f.svc[args[1]]
	if !ok {
		return args[1] + " is not a recognized network service.", 4
	}
	switch args[0] {
	case "-getautoproxyurl":
		url := s.pacURL
		if url == "" {
			url = "(null)"
		}
		return fmt.Sprintf("URL: %s\nEnabled: %s", url, yesNo(s.pacOn)), 0
	case "-setautoproxyurl":
		s.pacURL, s.pacOn = args[2], true
		return "", 0
	case "-setautoproxystate":
		s.pacOn = args[2] == "on"
		return "", 0
	case "-getwebproxy":
		return proxyGet(s.webOn, s.webHost, s.webPort), 0
	case "-getsecurewebproxy":
		return proxyGet(s.secOn, s.secHost, s.secPort), 0
	case "-getsocksfirewallproxy":
		return proxyGet(s.sockOn, s.sockHost, s.sockPort), 0
	case "-setwebproxy":
		s.webHost, s.webPort, s.webOn = args[2], atoi(args[3]), true
		return "", 0
	case "-setsecurewebproxy":
		s.secHost, s.secPort, s.secOn = args[2], atoi(args[3]), true
		return "", 0
	case "-setsocksfirewallproxy":
		s.sockHost, s.sockPort, s.sockOn = args[2], atoi(args[3]), true
		return "", 0
	case "-setwebproxystate":
		s.webOn = args[2] == "on"
		return "", 0
	case "-setsecurewebproxystate":
		s.secOn = args[2] == "on"
		return "", 0
	case "-setsocksfirewallproxystate":
		s.sockOn = args[2] == "on"
		return "", 0
	}
	return "** Error: The parameters were not valid.", 4
}

func (f *fakeMac) scutil(args []string) (string, int) {
	switch {
	case len(args) == 1 && args[0] == "--proxy":
		return f.proxySnapshotLocked(), 0
	case len(args) == 1 && args[0] == "--dns":
		return "DNS configuration\n\nresolver #1\n  nameserver[0] : 192.168.0.1\n  if_index : 14 (en0)\n", 0
	case len(args) == 2 && args[0] == "--nc" && args[1] == "list":
		return "Available network connection services in the current set (*=enabled):", 0
	}
	return "scutil: unknown option", 1
}

// proxySnapshotLocked renders `scutil --proxy` for the primary service. It is
// also the byte-for-byte snapshot the teardown test compares against.
func (f *fakeMac) proxySnapshotLocked() string {
	s := f.svc[f.order[0]]
	var b strings.Builder
	b.WriteString("<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n  }\n  FTPPassive : 1\n")
	fmt.Fprintf(&b, "  HTTPEnable : %s\n", zeroOne(s.webOn))
	if s.webOn {
		fmt.Fprintf(&b, "  HTTPPort : %d\n  HTTPProxy : %s\n", s.webPort, s.webHost)
	}
	fmt.Fprintf(&b, "  HTTPSEnable : %s\n", zeroOne(s.secOn))
	if s.secOn {
		fmt.Fprintf(&b, "  HTTPSPort : %d\n  HTTPSProxy : %s\n", s.secPort, s.secHost)
	}
	fmt.Fprintf(&b, "  ProxyAutoConfigEnable : %s\n", zeroOne(s.pacOn))
	if s.pacOn {
		fmt.Fprintf(&b, "  ProxyAutoConfigURLString : %s\n", s.pacURL)
	}
	fmt.Fprintf(&b, "  SOCKSEnable : %s\n", zeroOne(s.sockOn))
	b.WriteString("}")
	return b.String()
}

func (f *fakeMac) proxySnapshot() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.proxySnapshotLocked()
}

func (f *fakeMac) environment() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for k, v := range f.env {
		out[k] = v
	}
	return out
}

func (f *fakeMac) launchctl(args []string) (string, int) {
	if len(args) < 2 {
		return "Usage: launchctl", 1
	}
	switch args[0] {
	case "getenv":
		return f.env[args[1]], 0
	case "setenv":
		if len(args) < 3 {
			return "Usage: launchctl setenv", 1
		}
		f.env[args[1]] = args[2]
		return "", 0
	case "unsetenv":
		delete(f.env, args[1])
		return "", 0
	}
	return "Unrecognized subcommand", 1
}

// callsMatching returns the joined argvs whose prefix matches, in order.
func (f *fakeMac) callsMatching(prefixes ...string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		for _, p := range prefixes {
			if strings.HasPrefix(c, p) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// ── RIBReader: an empty table, which is all proxy mode needs ────────────────

func (f *fakeMac) Routes() ([]netstate.RouteEntry, error) { return nil, nil }

func (f *fakeMac) Default() (netstate.RouteEntry, bool, error) {
	return netstate.RouteEntry{}, false, nil
}

func (f *fakeMac) ScopedDefault(string) (netstate.RouteEntry, bool, error) {
	return netstate.RouteEntry{}, false, nil
}

func (f *fakeMac) Exists(netip.Prefix, string) (bool, error) { return false, nil }

func proxyGet(on bool, host string, port int) string {
	return fmt.Sprintf("Enabled: %s\nServer: %s\nPort: %d\nAuthenticated Proxy Enabled: 0",
		yesNo(on), host, port)
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func zeroOne(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
