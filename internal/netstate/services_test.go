package netstate

import (
	"context"
	"reflect"
	"testing"
)

func TestParseServiceOrderCaptured(t *testing.T) {
	svcs := parseServiceOrder(fixture(t, "networksetup_services.txt"))
	if len(svcs) == 0 {
		t.Fatal("no services parsed from the captured output")
	}
	byName := map[string]Service{}
	for _, s := range svcs {
		byName[s.Name] = s
	}
	wifi, ok := byName["Wi-Fi"]
	if !ok {
		t.Fatalf("Wi-Fi missing from %+v", svcs)
	}
	if wifi.Device != "en0" {
		t.Fatalf("Wi-Fi device = %q, want en0", wifi.Device)
	}
	if wifi.Hardware != "Wi-Fi" {
		t.Fatalf("Wi-Fi hardware port = %q", wifi.Hardware)
	}
	if wifi.Order == 0 {
		t.Fatal("service order was not parsed")
	}
	if wifi.Disabled {
		t.Fatal("Wi-Fi is enabled on this machine")
	}
}

func TestParseServiceOrderDisabled(t *testing.T) {
	out := "An asterisk (*) denotes that a network service is disabled.\n" +
		"(1) *Old Ethernet\n(Hardware Port: Ethernet, Device: en5)\n\n" +
		"(2) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n"
	svcs := parseServiceOrder(out)
	if len(svcs) != 2 {
		t.Fatalf("parsed %d services: %+v", len(svcs), svcs)
	}
	if !svcs[0].Disabled || svcs[0].Name != "Old Ethernet" {
		t.Fatalf("disabled service parsed as %+v", svcs[0])
	}
	// A disabled service must never be configured: networksetup accepts the
	// command and changes nothing, which is exactly the silent no-op this
	// package exists to prevent.
	if got := serviceNames(svcs); !reflect.DeepEqual(got, []string{"Wi-Fi"}) {
		t.Fatalf("serviceNames = %v, want only the enabled service", got)
	}
	if s, ok := ServiceForDevice(svcs, "en0"); !ok || s.Name != "Wi-Fi" {
		t.Fatalf("ServiceForDevice(en0) = %+v ok=%v", s, ok)
	}
	if _, ok := ServiceForDevice(svcs, "utun7"); ok {
		t.Fatal("ServiceForDevice found a service for a device that has none")
	}
}

func TestParseServiceOrderTrailingServiceWithoutHardwareLine(t *testing.T) {
	out := "(1) Wi-Fi\n"
	svcs := parseServiceOrder(out)
	if len(svcs) != 1 || svcs[0].Name != "Wi-Fi" || svcs[0].Device != "" {
		t.Fatalf("parsed %+v", svcs)
	}
}

func TestListServices(t *testing.T) {
	f := newFakeSystem()
	svcs, err := ListServices(context.Background(), f.env0())
	if err != nil {
		t.Fatalf("ListServices: %v", err)
	}
	if got := serviceNames(svcs); !reflect.DeepEqual(got, []string{"Wi-Fi", "Thunderbolt Bridge"}) {
		t.Fatalf("serviceNames = %v", got)
	}

	f.failNext("networksetup -listnetworkserviceorder", 1)
	if _, err := ListServices(context.Background(), f.env0()); err == nil {
		t.Fatal("ListServices swallowed a command failure")
	}
}

func TestListServicesRejectsUnparseableOutput(t *testing.T) {
	e := Env{Runner: runnerFunc(func(_ context.Context, name string, args ...string) Result {
		return Result{Argv: append([]string{name}, args...), Combined: "An asterisk (*) denotes that a network service is disabled."}
	})}
	if _, err := ListServices(context.Background(), e); err == nil {
		t.Fatal("an empty service list must be an error, not an empty slice")
	}
}

type runnerFunc func(ctx context.Context, name string, args ...string) Result

func (f runnerFunc) Run(ctx context.Context, name string, args ...string) Result {
	return f(ctx, name, args...)
}
