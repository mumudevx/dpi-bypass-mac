package sysport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return strings.TrimRight(string(b), "\n")
}

// TestRouteExitZeroIsFailure is the load-bearing test of this package. The
// fixture is the verbatim output of `route -n get -inet6 2001:db8::1` captured
// on this machine, which exits 0 while having done nothing. Apple's route.c
// declares newroute() void and main() does `newroute(argc, argv); exit(0)`, so
// there is no failure exit path to check and Code must never be trusted.
func TestRouteExitZeroIsFailure(t *testing.T) {
	out := fixture(t, "route_exit0_fail.txt")
	if !strings.Contains(out, "writing to routing socket") {
		t.Fatalf("fixture does not contain the captured failure text: %q", out)
	}

	res := Result{
		Argv:     []string{"route", "-n", "get", "-inet6", "2001:db8::1"},
		Combined: out,
		Code:     0,
	}
	if res.Code != 0 {
		t.Fatalf("fixture must exercise the exit-0 path, got code %d", res.Code)
	}
	if !res.Failed() {
		t.Fatalf("Failed() = false for %q; route(8) exiting 0 after a routing-socket error must be a failure", out)
	}
	reason := res.Reason()
	if !strings.Contains(reason, "exited 0") || !strings.Contains(reason, "writing to routing socket") {
		t.Fatalf("Reason() = %q, want it to name both the zero exit and the matched text", reason)
	}
	if res.Error() == nil {
		t.Fatal("Error() = nil for a failed result")
	}
}

func TestLiarTable(t *testing.T) {
	tests := []struct {
		name     string
		argv     []string
		combined string
		code     int
		want     bool
	}{
		{"route add over an existing route", []string{"route", "add"},
			"route: writing to routing socket: File exists", 0, true},
		{"route delete of an absent route", []string{"route", "delete"},
			"add net 0.0.0.0: gateway 10.0.0.1: not in table", 0, true},
		{"route unreachable", []string{"route", "add"},
			"route: writing to routing socket: Network is unreachable", 0, true},
		{"route no such process", []string{"route", "delete"},
			"route: writing to routing socket: No such process", 0, true},
		{"route clean add", []string{"route", "add"}, "add net 0.0.0.0: gateway 10.0.0.1", 0, false},

		{"networksetup unknown service", []string{"networksetup", "-getdnsservers", "Nope"},
			"No Such Service is not a recognized network service.\n** Error: The parameters were not valid.", 4, true},
		{"networksetup error on stdout with exit 0", []string{"networksetup", "-setdnsservers", "Wi-Fi"},
			"** Error: The parameters were not valid.", 0, true},
		{"networksetup clean", []string{"networksetup", "-getdnsservers", "Wi-Fi"},
			"There aren't any DNS Servers set on Wi-Fi.", 0, false},

		{"ifconfig missing interface", []string{"ifconfig", "utun99"},
			"ifconfig: interface utun99 does not exist", 0, true},
		{"ifconfig ioctl", []string{"ifconfig", "utun4", "inet", "10.0.0.1", "10.0.0.2", "up"},
			"ifconfig: ioctl (SIOCAIFADDR): Invalid argument", 0, true},
		{"ifconfig clean", []string{"ifconfig", "utun4"}, "utun4: flags=8051<UP,POINTOPOINT,RUNNING>", 0, false},

		{"launchctl bootstrap failed", []string{"launchctl", "bootstrap", "gui/501"},
			"Bootstrap failed: 5: Input/output error", 0, true},
		{"launchctl permission", []string{"launchctl", "setenv", "HTTPS_PROXY", "x"},
			"launchctl: Operation not permitted", 0, true},
		{"launchctl clean", []string{"launchctl", "getenv", "HTTPS_PROXY"}, "", 0, false},

		{"unknown command with a scary message is trusted", []string{"scutil", "--proxy"},
			"not in table", 0, false},
		{"non-zero always fails", []string{"scutil", "--proxy"}, "", 1, true},
		{"empty argv never panics", nil, "not in table", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Result{Argv: tt.argv, Combined: tt.combined, Code: tt.code}
			if got := res.Failed(); got != tt.want {
				t.Fatalf("Failed() = %v, want %v (combined %q, code %d)", got, tt.want, tt.combined, tt.code)
			}
			if tt.want && res.Reason() == "" {
				t.Fatal("a failed result must explain itself")
			}
			if !tt.want && res.Reason() != "" {
				t.Fatalf("a clean result must have no reason, got %q", res.Reason())
			}
		})
	}
}

// TestLiarTableAgainstCapturedOutputs runs the real captured tool output
// through the same table, so a fixture that stops reproducing the failure shape
// fails the build.
func TestLiarTableAgainstCapturedOutputs(t *testing.T) {
	cases := []struct {
		file string
		argv []string
		code int
	}{
		{"route_exit0_fail.txt", []string{"route", "-n", "get", "-inet6", "2001:db8::1"}, 0},
		{"networksetup_error.txt", []string{"networksetup", "-getdnsservers", "No Such Service"}, 4},
		{"ifconfig_missing.txt", []string{"ifconfig", "utun99"}, 1},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			res := Result{Argv: c.argv, Combined: fixture(t, c.file), Code: c.code}
			if !res.Failed() {
				t.Fatalf("captured failure output was not detected: %q", res.Combined)
			}
			// The networksetup and ifconfig fixtures happen to exit non-zero on this
			// machine; assert the table catches them even if a future macOS stops
			// bothering to set an exit status.
			zero := Result{Argv: c.argv, Combined: res.Combined, Code: 0}
			if !zero.Failed() {
				t.Fatalf("output %q is only detected via its exit status, not the table", res.Combined)
			}
		})
	}
}

func TestCleanCapturedOutputsAreNotFlagged(t *testing.T) {
	cases := []struct {
		file string
		argv []string
	}{
		{"networksetup_services.txt", []string{"networksetup", "-listnetworkserviceorder"}},
		{"networksetup_dns_none.txt", []string{"networksetup", "-getdnsservers", "Wi-Fi"}},
		{"networksetup_autoproxy_off.txt", []string{"networksetup", "-getautoproxyurl", "Wi-Fi"}},
		{"networksetup_webproxy_off.txt", []string{"networksetup", "-getwebproxy", "Wi-Fi"}},
		{"scutil_proxy.txt", []string{"scutil", "--proxy"}},
		{"scutil_dns.txt", []string{"scutil", "--dns"}},
		{"scutil_nc_empty.txt", []string{"scutil", "--nc", "list"}},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			res := Result{Argv: c.argv, Combined: fixture(t, c.file), Code: 0}
			if res.Failed() {
				t.Fatalf("clean output flagged as a failure: %s", res.Reason())
			}
		})
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine(""); got != "(no output)" {
		t.Fatalf("firstLine(%q) = %q", "", got)
	}
	if got := firstLine("a\nb"); got != "a" {
		t.Fatalf("firstLine = %q, want %q", got, "a")
	}
	if got := firstLine("  solo  "); got != "solo" {
		t.Fatalf("firstLine = %q, want %q", got, "solo")
	}
}
