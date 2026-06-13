package sysnet

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls     [][]string
	responses map[string]string // keyed by networksetup subcommand
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if name == "networksetup" && len(args) > 0 {
		if r, ok := f.responses[args[0]]; ok {
			return r, nil
		}
	}
	return "", nil
}

func (f *fakeRunner) hasCall(want ...string) bool {
	for _, c := range f.calls {
		if len(c) != len(want) {
			continue
		}
		match := true
		for i := range c {
			if c[i] != want[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestEnableAndRestore(t *testing.T) {
	fr := &fakeRunner{responses: map[string]string{
		"-getwebproxy":           "Enabled: Yes\nServer: 10.0.0.1\nPort: 3128\n",
		"-getsecurewebproxy":     "Enabled: No\nServer:\nPort: 0\n",
		"-getsocksfirewallproxy": "Enabled: No\nServer:\nPort: 0\n",
	}}
	state := filepath.Join(t.TempDir(), "backup.json")
	m := NewProxyManager(ProxyConfig{
		Runner:    fr,
		Host:      "127.0.0.1",
		HTTPPort:  8080,
		StatePath: state,
		Services:  []string{"Wi-Fi"},
	})

	if err := m.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !fr.hasCall("networksetup", "-setwebproxy", "Wi-Fi", "127.0.0.1", "8080") {
		t.Fatal("did not set web proxy")
	}
	if !fr.hasCall("networksetup", "-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "8080") {
		t.Fatal("did not set secure web proxy")
	}
	if !fr.hasCall("networksetup", "-setwebproxystate", "Wi-Fi", "on") {
		t.Fatal("did not enable web proxy state")
	}

	// Restore must put back the previously-enabled web proxy (10.0.0.1:3128)
	// and disable the secure proxy that was previously off.
	m.Restore(context.Background())
	if !fr.hasCall("networksetup", "-setwebproxy", "Wi-Fi", "10.0.0.1", "3128") {
		t.Fatal("did not restore prior web proxy server")
	}
	if !fr.hasCall("networksetup", "-setsecurewebproxystate", "Wi-Fi", "off") {
		t.Fatal("did not turn off secure proxy that was originally off")
	}
}

func TestParseProxyState(t *testing.T) {
	st := parseProxyState("Enabled: Yes\nServer: 1.2.3.4\nPort: 9999\nAuthenticated Proxy Enabled: 0\n")
	if !st.Enabled || st.Server != "1.2.3.4" || st.Port != "9999" {
		t.Fatalf("parsed = %+v", st)
	}
}

func TestDefaultRouteService(t *testing.T) {
	fr := &fakeRunner{responses: map[string]string{}}
	// route output and service order are not networksetup subcommands, so wire
	// them via a custom runner.
	cr := &scriptedRunner{out: map[string]string{
		"route -n get default":                  "   gateway: 192.168.1.1\n  interface: en0\n",
		"networksetup -listnetworkserviceorder": "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n(2) Thunderbolt\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n",
	}}
	m := NewProxyManager(ProxyConfig{Runner: cr, HTTPPort: 8080})
	if svc := m.defaultRouteService(context.Background()); svc != "Wi-Fi" {
		t.Fatalf("service = %q, want Wi-Fi", svc)
	}
	_ = fr
}

type scriptedRunner struct{ out map[string]string }

func (s *scriptedRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	return s.out[key], nil
}
