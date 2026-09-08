// Package testport is a recording fake of sysport.Port.
//
// It is a SIBLING of sysport, not a subpackage of it, and that is deliberate:
// the Makefile's COVER_GATED_RE is a prefix match on
// "internal/(...|sysport|...)/", so a fake living at internal/sysport/fake
// would be swept into the coverage gate and its unused methods — most tests
// only drive one or two controllers — would sit at 0.0% and fail the build.
// A sibling package never matches that prefix. It also follows the idiom
// already in this tree: internal/testnet fakes the RIB and the command
// runner, internal/testcensor fakes a censoring middlebox, and this package
// fakes the Port the same way.
//
// This is a DIFFERENT kind of fake from internal/netstate/fakesystem_test.go
// and internal/sysconf/scdarwin/fakesystem_test.go, which fake the
// command-line tools scdarwin shells out to. Those prove scdarwin builds the
// right argv; this proves an Op makes the right decision — what to add, what
// NOT to roll back, what to capture before overwriting — without any argv at
// all. Both are wanted, and neither replaces the other.
package testport

import (
	"context"
	"net/netip"

	"github.com/mumudevx/dpb/internal/sysport"
)

// Port is a sysport.Port that mutates nothing and remembers everything asked
// of it, so a test can assert what an Op requested of the OS rather than what
// a tool happened to print.
type Port struct {
	ProxyC *Proxy
	DNSC   *DNS
	RouteC *Route
	IfaceC *Iface
	EnvC   *Env
	FactsC *FactsC
	CapsV  sysport.Caps
}

// New returns a Port with every capability granted. Everything is granted by
// default — rather than nothing — so that a test asserting a capability
// SHORTFALL must say so explicitly (by clearing CapsV or masking a bit out);
// a missing grant is never something a test acquires by accident of setup
// order.
func New() *Port {
	return &Port{
		ProxyC: &Proxy{}, DNSC: &DNS{}, RouteC: &Route{}, IfaceC: &Iface{},
		EnvC: &Env{}, FactsC: &FactsC{},
		CapsV: sysport.CapProxyAuto | sysport.CapProxyManual | sysport.CapDNSOverride |
			sysport.CapRouteWrite | sysport.CapIfaceConfig | sysport.CapSessionEnv |
			sysport.CapPerService,
	}
}

func (p *Port) Proxy() sysport.ProxyController { return p.ProxyC }
func (p *Port) DNS() sysport.DNSController     { return p.DNSC }
func (p *Port) Route() sysport.RouteController { return p.RouteC }
func (p *Port) Iface() sysport.IfaceController { return p.IfaceC }
func (p *Port) Env() sysport.EnvController     { return p.EnvC }
func (p *Port) Facts() sysport.FactsCollector  { return p.FactsC }
func (p *Port) Caps() sysport.Caps             { return p.CapsV }

var _ sysport.Port = (*Port)(nil)

// ---------------------------------------------------------------------------
// Route

// Route records every route request. Adds and Deletes are the specs asked
// for, in order; AddErr and DeleteErr are returned instead of performing the
// call.
//
// A failed call is NOT recorded. That is what lets
// TestRouteOpDoesNotRollBackAFailedAdd assert "nothing was asked of the OS"
// after an error: routeOp.mutated() must stay false so Manager.rollback never
// issues a Delete for a route this process never actually created — the
// "File exists" liar means the destination was already owned by somebody
// else, and deleting it anyway would remove their route, not ours.
type Route struct {
	Adds      []sysport.RouteSpec
	Deletes   []sysport.RouteSpec
	AddErr    error
	DeleteErr error
	Table     []sysport.RouteEntry // what RIB() reports
}

func (r *Route) Add(_ context.Context, s sysport.RouteSpec) error {
	if r.AddErr != nil {
		return r.AddErr
	}
	r.Adds = append(r.Adds, s)
	return nil
}

func (r *Route) Delete(_ context.Context, s sysport.RouteSpec) error {
	if r.DeleteErr != nil {
		return r.DeleteErr
	}
	r.Deletes = append(r.Deletes, s)
	return nil
}

func (r *Route) RIB() sysport.RIBReader { return staticRIB{r} }

// staticRIB reports Route.Table. It is deliberately dumb: the fake's whole
// point is that a test sets Table directly rather than driving it indirectly
// through Add/Delete, which is what "MUST NOT share a code path with Add and
// Delete" (sysport.RouteController.RIB) requires even of a fake.
type staticRIB struct{ r *Route }

func (s staticRIB) Routes() ([]sysport.RouteEntry, error) {
	return s.r.Table, nil
}

func (s staticRIB) Default() (sysport.RouteEntry, bool, error) {
	return pickDefault(s.r.Table, "")
}

func (s staticRIB) ScopedDefault(iface string) (sysport.RouteEntry, bool, error) {
	return pickDefault(s.r.Table, iface)
}

func (s staticRIB) Exists(dst netip.Prefix, iface string) (bool, error) {
	want := dst.Masked()
	for _, e := range s.r.Table {
		if e.Dst == want && (iface == "" || e.Iface == iface) {
			return true, nil
		}
	}
	return false, nil
}

// pickDefault mirrors internal/testnet's RIB fake: the unscoped default when
// iface is empty, the interface-scoped one otherwise, IPv4 winning over IPv6.
func pickDefault(rs []sysport.RouteEntry, iface string) (sysport.RouteEntry, bool, error) {
	var v6 sysport.RouteEntry
	var haveV6 bool
	for _, e := range rs {
		if e.Dst.Bits() != 0 {
			continue
		}
		if iface == "" {
			if e.Scoped {
				continue
			}
		} else if !e.Scoped || e.Iface != iface {
			continue
		}
		if e.Dst.Addr().Is4() {
			return e, true, nil
		}
		if !haveV6 {
			v6, haveV6 = e, true
		}
	}
	return v6, haveV6, nil
}

// ---------------------------------------------------------------------------
// Proxy

// ProxyConfiguredCall records one Configured read: the service asked about
// and the kinds actually requested. The kinds matter — sysport.ProxyController
// documents that requesting only what a caller intends to restore is load
// bearing, not an optimisation, so a test can check an Op never asks for more
// than it means to capture.
type ProxyConfiguredCall struct {
	Svc   string
	Kinds []sysport.ProxyKind
}

// ProxySetAutoCall records one SetAuto request.
type ProxySetAutoCall struct {
	Svc string
	URL string
}

// ProxySetManualCall records one SetManual request.
type ProxySetManualCall struct {
	Svc  string
	Kind sysport.ProxyKind
	Host string
	Port int
}

// ProxyRestoreCall records one Restore request.
type ProxyRestoreCall struct {
	Svc  string
	Prev sysport.ProxySettings
}

// Proxy fakes sysport.ProxyController: a slice per mutating method recording
// what was asked, an Err per method returned instead of performing the call
// (and never recorded), and a settable return value per read.
type Proxy struct {
	ServicesRet []string
	ServicesErr error

	ConfiguredCalls []ProxyConfiguredCall
	ConfiguredRet   sysport.ProxySettings
	ConfiguredErr   error

	SetAutoCalls []ProxySetAutoCall
	SetAutoErr   error

	SetManualCalls []ProxySetManualCall
	SetManualErr   error

	RestoreCalls []ProxyRestoreCall
	RestoreErr   error

	LiveRet sysport.ProxyState
	LiveErr error
}

func (p *Proxy) Services(context.Context) ([]string, error) {
	if p.ServicesErr != nil {
		return nil, p.ServicesErr
	}
	return p.ServicesRet, nil
}

func (p *Proxy) Configured(_ context.Context, svc string, kinds ...sysport.ProxyKind) (sysport.ProxySettings, error) {
	if p.ConfiguredErr != nil {
		return sysport.ProxySettings{}, p.ConfiguredErr
	}
	p.ConfiguredCalls = append(p.ConfiguredCalls, ProxyConfiguredCall{Svc: svc, Kinds: kinds})
	return p.ConfiguredRet, nil
}

func (p *Proxy) SetAuto(_ context.Context, svc, url string) error {
	if p.SetAutoErr != nil {
		return p.SetAutoErr
	}
	p.SetAutoCalls = append(p.SetAutoCalls, ProxySetAutoCall{Svc: svc, URL: url})
	return nil
}

func (p *Proxy) SetManual(_ context.Context, svc string, kind sysport.ProxyKind, host string, port int) error {
	if p.SetManualErr != nil {
		return p.SetManualErr
	}
	p.SetManualCalls = append(p.SetManualCalls, ProxySetManualCall{Svc: svc, Kind: kind, Host: host, Port: port})
	return nil
}

func (p *Proxy) Restore(_ context.Context, svc string, prev sysport.ProxySettings) error {
	if p.RestoreErr != nil {
		return p.RestoreErr
	}
	p.RestoreCalls = append(p.RestoreCalls, ProxyRestoreCall{Svc: svc, Prev: prev})
	return nil
}

func (p *Proxy) Live(context.Context) (sysport.ProxyState, error) {
	if p.LiveErr != nil {
		return sysport.ProxyState{}, p.LiveErr
	}
	return p.LiveRet, nil
}

// ---------------------------------------------------------------------------
// DNS

// DNSSetCall records one Set request.
type DNSSetCall struct {
	Svc     string
	Servers []string
}

// DNS fakes sysport.DNSController the same shape as Proxy: a slice per
// mutating method, an Err per method, a settable return value per read.
type DNS struct {
	ConfiguredCalls []string // service names asked about
	ConfiguredRet   []string
	ConfiguredErr   error

	SetCalls []DNSSetCall
	SetErr   error

	ClearCalls []string // service names cleared
	ClearErr   error

	LiveRet []string
	LiveErr error
}

func (d *DNS) Configured(_ context.Context, svc string) ([]string, error) {
	if d.ConfiguredErr != nil {
		return nil, d.ConfiguredErr
	}
	d.ConfiguredCalls = append(d.ConfiguredCalls, svc)
	return d.ConfiguredRet, nil
}

func (d *DNS) Set(_ context.Context, svc string, servers []string) error {
	if d.SetErr != nil {
		return d.SetErr
	}
	d.SetCalls = append(d.SetCalls, DNSSetCall{Svc: svc, Servers: append([]string(nil), servers...)})
	return nil
}

func (d *DNS) Clear(_ context.Context, svc string) error {
	if d.ClearErr != nil {
		return d.ClearErr
	}
	d.ClearCalls = append(d.ClearCalls, svc)
	return nil
}

func (d *DNS) Live(context.Context) ([]string, error) {
	if d.LiveErr != nil {
		return nil, d.LiveErr
	}
	return d.LiveRet, nil
}

// ---------------------------------------------------------------------------
// Iface

// IfaceCall records one Configure or Unconfigure request.
type IfaceCall struct {
	Iface string
	Cfg   sysport.IfaceConfig
}

// Iface fakes sysport.IfaceController.
type Iface struct {
	ConfigureCalls []IfaceCall
	ConfigureErr   error

	UnconfigureCalls []IfaceCall
	UnconfigureErr   error

	AddrsRet []netip.Addr
	AddrsErr error
}

func (i *Iface) Configure(_ context.Context, iface string, cfg sysport.IfaceConfig) error {
	if i.ConfigureErr != nil {
		return i.ConfigureErr
	}
	i.ConfigureCalls = append(i.ConfigureCalls, IfaceCall{Iface: iface, Cfg: cfg})
	return nil
}

func (i *Iface) Unconfigure(_ context.Context, iface string, cfg sysport.IfaceConfig) error {
	if i.UnconfigureErr != nil {
		return i.UnconfigureErr
	}
	i.UnconfigureCalls = append(i.UnconfigureCalls, IfaceCall{Iface: iface, Cfg: cfg})
	return nil
}

func (i *Iface) Addrs(context.Context, string) ([]netip.Addr, error) {
	if i.AddrsErr != nil {
		return nil, i.AddrsErr
	}
	return i.AddrsRet, nil
}

// ---------------------------------------------------------------------------
// Env

// EnvSetCall records one Set request.
type EnvSetCall struct {
	Name  string
	Value string
}

// Env fakes sysport.EnvController. GetRet models the launchd session
// environment as a map; a name absent from it is a miss (ok=false), the same
// answer launchctl getenv gives for a variable it has never seen.
type Env struct {
	GetRet map[string]string
	GetErr error

	SetCalls []EnvSetCall
	SetErr   error

	UnsetCalls []string
	UnsetErr   error
}

func (e *Env) Get(_ context.Context, name string) (string, bool, error) {
	if e.GetErr != nil {
		return "", false, e.GetErr
	}
	v, ok := e.GetRet[name]
	return v, ok, nil
}

func (e *Env) Set(_ context.Context, name, value string) error {
	if e.SetErr != nil {
		return e.SetErr
	}
	e.SetCalls = append(e.SetCalls, EnvSetCall{Name: name, Value: value})
	return nil
}

func (e *Env) Unset(_ context.Context, name string) error {
	if e.UnsetErr != nil {
		return e.UnsetErr
	}
	e.UnsetCalls = append(e.UnsetCalls, name)
	return nil
}

// ---------------------------------------------------------------------------
// Facts

// FactsC fakes sysport.FactsCollector. The name avoids colliding with
// sysport.Facts, which CollectRet holds a pointer to.
type FactsC struct {
	CollectCalls []string // selfIface values Collect was called with
	CollectRet   *sysport.Facts
	CollectErr   error
}

func (f *FactsC) Collect(_ context.Context, selfIface string) (*sysport.Facts, error) {
	if f.CollectErr != nil {
		return nil, f.CollectErr
	}
	f.CollectCalls = append(f.CollectCalls, selfIface)
	return f.CollectRet, nil
}
