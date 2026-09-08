//go:build !darwin && !windows

package netstate

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"

	"github.com/mumudevx/dpb/internal/sysport"
)

// dpb has no system-mutation implementation for this platform. Every method
// errors by name rather than returning a zero value, for the reason
// emit/stub_other.go gives: a capability that is silently absent is how a
// mutation gets skipped without anyone noticing.
//
// The build tag excludes windows deliberately. Plan 3 adds port_windows.go, and
// writing the tag this way now means that file drops in without editing this
// one.
func newDefaultPort(Env) Port { return unsupportedPort{} }

// newDefaultRIB has no kernel reader to hand out here, so it hands out one that
// says so on every call. Returning nil would turn a missing implementation into
// a nil dereference somewhere else.
func newDefaultRIB() RIBReader { return unsupportedRIB{} }

func unsupported(what string) error {
	return fmt.Errorf("netstate: %s is implemented for darwin and windows only; this binary is %s/%s",
		what, runtime.GOOS, runtime.GOARCH)
}

type unsupportedPort struct{}

func (unsupportedPort) Proxy() sysport.ProxyController { return unsupportedProxy{} }
func (unsupportedPort) DNS() sysport.DNSController     { return unsupportedDNS{} }
func (unsupportedPort) Route() sysport.RouteController { return unsupportedRoute{} }
func (unsupportedPort) Iface() sysport.IfaceController { return unsupportedIface{} }
func (unsupportedPort) Env() sysport.EnvController     { return unsupportedEnv{} }
func (unsupportedPort) Facts() sysport.FactsCollector  { return unsupportedFacts{} }

// Caps is zero: this platform grants nothing, so an Op that asks is refused by
// name before it runs rather than after it has half-applied.
func (unsupportedPort) Caps() sysport.Caps { return 0 }

type unsupportedProxy struct{}

func (unsupportedProxy) Services(context.Context) ([]string, error) {
	return nil, unsupported("listing network services")
}

func (unsupportedProxy) Configured(context.Context, string) (sysport.ProxySettings, error) {
	return sysport.ProxySettings{}, unsupported("reading a service's proxy settings")
}

func (unsupportedProxy) SetAuto(context.Context, string, string) error {
	return unsupported("setting an auto-proxy (PAC) URL")
}

func (unsupportedProxy) SetManual(context.Context, string, sysport.ProxyKind, string, int) error {
	return unsupported("setting a manual proxy")
}

func (unsupportedProxy) Restore(context.Context, string, sysport.ProxySettings) error {
	return unsupported("restoring a service's proxy settings")
}

func (unsupportedProxy) Live(context.Context) (sysport.ProxyState, error) {
	return sysport.ProxyState{}, unsupported("reading the live proxy configuration")
}

type unsupportedDNS struct{}

func (unsupportedDNS) Configured(context.Context, string) ([]string, error) {
	return nil, unsupported("reading a service's resolvers")
}

func (unsupportedDNS) Set(context.Context, string, []string) error {
	return unsupported("setting a service's resolvers")
}

func (unsupportedDNS) Clear(context.Context, string) error {
	return unsupported("clearing a service's resolvers")
}

func (unsupportedDNS) Live(context.Context) ([]string, error) {
	return nil, unsupported("reading the live resolvers")
}

type unsupportedRoute struct{}

func (unsupportedRoute) Add(context.Context, sysport.RouteSpec) error {
	return unsupported("adding a route")
}

func (unsupportedRoute) Delete(context.Context, sysport.RouteSpec) error {
	return unsupported("deleting a route")
}

func (unsupportedRoute) RIB() sysport.RIBReader { return unsupportedRIB{} }

type unsupportedRIB struct{}

func (unsupportedRIB) Routes() ([]sysport.RouteEntry, error) {
	return nil, unsupported("reading the kernel routing table")
}

func (unsupportedRIB) Default() (sysport.RouteEntry, bool, error) {
	return sysport.RouteEntry{}, false, unsupported("reading the default route")
}

func (unsupportedRIB) ScopedDefault(string) (sysport.RouteEntry, bool, error) {
	return sysport.RouteEntry{}, false, unsupported("reading a scoped default route")
}

func (unsupportedRIB) Exists(netip.Prefix, string) (bool, error) {
	return false, unsupported("looking a route up in the kernel routing table")
}

type unsupportedIface struct{}

func (unsupportedIface) Configure(context.Context, string, sysport.IfaceConfig) error {
	return unsupported("configuring a tunnel interface")
}

func (unsupportedIface) Unconfigure(context.Context, string, sysport.IfaceConfig) error {
	return unsupported("removing a tunnel interface's address")
}

func (unsupportedIface) Addrs(context.Context, string) ([]netip.Addr, error) {
	return nil, unsupported("reading an interface's addresses")
}

type unsupportedEnv struct{}

func (unsupportedEnv) Get(context.Context, string) (string, bool, error) {
	return "", false, unsupported("reading a login-session environment variable")
}

func (unsupportedEnv) Set(context.Context, string, string) error {
	return unsupported("setting a login-session environment variable")
}

func (unsupportedEnv) Unset(context.Context, string) error {
	return unsupported("unsetting a login-session environment variable")
}

type unsupportedFacts struct{}

func (unsupportedFacts) Collect(context.Context, string) (*sysport.Facts, error) {
	return nil, unsupported("collecting the machine's network facts")
}
