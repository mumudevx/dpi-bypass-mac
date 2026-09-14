//go:build windows

package cliapp

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"sync"

	"github.com/mumudevx/dpb/internal/netstate"
	"github.com/mumudevx/dpb/internal/sysport"
)

// harnessPort is what makes this package's command tests mean anything on
// Windows.
//
// # The hole it fills
//
// Every test here drives a command against fakeMac: an in-memory machine that
// answers networksetup, scutil and launchctl from one piece of state. On
// darwin that is enough, because globals.sysOf() builds scdarwin over the
// injected Runner and scdarwin reaches the system by running those three
// tools — the fake substitutes for the whole platform.
//
// On Windows there is no Runner to substitute for. scwindows reaches the
// system through advapi32, winhttp.dll and iphlpapi directly, and takes a
// Runner only for `netsh` (whose exit status alone it consults). So a Windows
// run of these tests injected a Runner nothing read: `dpb doctor` and
// `dpb coverage` went to the CI runner's REAL registry hive, reported "no
// system proxy is set" whatever the test had just set up, and every assertion
// about residue failed. Worse, that is a test suite reading and — on the paths
// that write — mutating the machine it happens to run on.
//
// Measured on the 2026-09-14 windows-latest run, before this file existed:
// eight doctor tests and two coverage tests failed that way, and the command
// layer above scwindows had therefore never been executed against any known
// system state on Windows at all. scwindows has its own tests; doctor.go and
// coverage.go did not have any that ran here.
//
// # What it is, and what it is not
//
// It is a sysport.Port over fakeMac's state, so the platform-neutral readers
// the commands use — netstate.ReadProxyState, ReadLaunchEnv, LiveNameservers,
// all of which go through Env.sys() — see the machine the test set up. The
// code under test is the WINDOWS build of the command layer, platform leaves
// included: proxySystemName() answers "Windows", proxyEnvRemedy() names
// `reg query HKCU\Environment`, coverage's mechanism names carry the
// "environment " prefix rather than "launchd ", and platformChecks() adds the
// wintun and hive checks.
//
// It is NOT a model of a Windows machine's registry. The machine it models is
// the same one the darwin harness models — services named "Wi-Fi", an uplink
// named en0 — because that is the vocabulary the test bodies speak, and
// because the question these tests ask is about the command layer's decisions
// and not about how a platform stores a proxy. The latter question belongs to
// internal/sysconf/scwindows, which answers it against the real registry
// format in its own tests. Keeping the two separate is what stops this file
// from becoming a second, worse scwindows.
//
// Writes are issued THROUGH fakeMac.Run with the same argv scdarwin would
// send, rather than poking its fields, so fakeMac.calls stays a truthful
// record on both platforms and callsMatching/proxySnapshot keep working.
// Reads go to the state directly.
func harnessPort(f *fakeMac) netstate.Port {
	return &harnessSysPort{
		f:    f,
		live: []string{fakeMacLiveResolver},
	}
}

// fakeMacLiveResolver is the single resolver fakeMac's `scutil --dns` answer
// names. TestHarnessPortDNSMatchesTheFakeScutil pins the two together, because
// the tun bring-up sequence installs a /32 host route per system resolver and
// a drift here would silently drop that route on one platform only.
const fakeMacLiveResolver = "192.168.0.1"

type harnessSysPort struct {
	f *fakeMac

	mu   sync.Mutex
	live []string
	svc  map[string][]string
}

func (p *harnessSysPort) Proxy() sysport.ProxyController { return harnessProxy{p} }
func (p *harnessSysPort) DNS() sysport.DNSController     { return harnessDNS{p} }
func (p *harnessSysPort) Route() sysport.RouteController { return harnessRoute{p} }
func (p *harnessSysPort) Iface() sysport.IfaceController { return harnessIface{p} }
func (p *harnessSysPort) Env() sysport.EnvController     { return harnessEnv{p} }
func (p *harnessSysPort) Facts() sysport.FactsCollector  { return harnessFacts{p} }

// Caps grants everything, for internal/testport's reason: a test asserting a
// capability SHORTFALL must say so explicitly rather than acquiring it by
// accident of setup order.
func (p *harnessSysPort) Caps() sysport.Caps {
	return sysport.CapProxyAuto | sysport.CapProxyManual | sysport.CapDNSOverride |
		sysport.CapRouteWrite | sysport.CapIfaceConfig | sysport.CapSessionEnv |
		sysport.CapPerService
}

var _ sysport.Port = (*harnessSysPort)(nil)

// ── proxy ───────────────────────────────────────────────────────────────────

type harnessProxy struct{ p *harnessSysPort }

func (h harnessProxy) Services(context.Context) ([]string, error) {
	f := h.p.f
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.order...), nil
}

// snapshot copies one service's stored proxy settings out from under the lock.
func (h harnessProxy) snapshot(svc string) (fakeSvc, error) {
	f := h.p.f
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.svc[svc]
	if !ok {
		return fakeSvc{}, fmt.Errorf("netstate: %s is not a recognized network service", svc)
	}
	return *s, nil
}

// Configured is the CAPTURE read, and it records which kinds it describes for
// the reason sysport.ProxySettings spells out: a Restore that cannot tell
// "never asked about" from "the user has none" switches off proxies this tool
// never touched.
func (h harnessProxy) Configured(_ context.Context, svc string,
	kinds ...sysport.ProxyKind) (sysport.ProxySettings, error) {

	s, err := h.snapshot(svc)
	if err != nil {
		return sysport.ProxySettings{}, err
	}
	if len(kinds) == 0 {
		kinds = []sysport.ProxyKind{sysport.ProxyAuto, sysport.ProxyWeb, sysport.ProxySOCKS}
	}
	out := sysport.ProxySettings{Kinds: append([]sysport.ProxyKind(nil), kinds...)}
	for _, k := range kinds {
		switch k {
		case sysport.ProxyAuto:
			out.AutoURL, out.AutoOn = s.pacURL, s.pacOn
		case sysport.ProxyWeb:
			out.WebHost, out.WebPort, out.WebOn = s.webHost, s.webPort, s.webOn
			out.SecureHost, out.SecurePort, out.SecureOn = s.secHost, s.secPort, s.secOn
		case sysport.ProxySOCKS:
			out.SOCKSHost, out.SOCKSPort, out.SOCKSOn = s.sockHost, s.sockPort, s.sockOn
		}
	}
	return out, nil
}

func (h harnessProxy) SetAuto(ctx context.Context, svc, url string) error {
	return h.run(ctx,
		[]string{"-setautoproxyurl", svc, url},
		[]string{"-setautoproxystate", svc, "on"},
	)
}

func (h harnessProxy) SetManual(ctx context.Context, svc string, kind sysport.ProxyKind,
	host string, port int) error {

	p := strconv.Itoa(port)
	switch kind {
	case sysport.ProxyWeb:
		// Web and secure are one kind, exactly as scdarwin treats them: they
		// are never useful apart and Restore puts both back together.
		return h.run(ctx,
			[]string{"-setwebproxy", svc, host, p},
			[]string{"-setsecurewebproxy", svc, host, p},
			[]string{"-setwebproxystate", svc, "on"},
			[]string{"-setsecurewebproxystate", svc, "on"},
		)
	case sysport.ProxySOCKS:
		return h.run(ctx,
			[]string{"-setsocksfirewallproxy", svc, host, p},
			[]string{"-setsocksfirewallproxystate", svc, "on"},
		)
	}
	// Refused by name with a reason, never skipped quietly, as scdarwin does:
	// a PAC URL is not a host:port and SetAuto is the verb that installs one.
	return fmt.Errorf("netstate: SetManual cannot install an auto-proxy (PAC) setting on %s; use SetAuto", svc)
}

func (h harnessProxy) Restore(ctx context.Context, svc string, prev sysport.ProxySettings) error {
	// A capture that names no kinds is refused here too. The guard belongs to
	// every implementation of Restore — sysport.ProxySettings.CheckRestorable
	// says so — and a fake that skipped it would let a test pass against a
	// zero-value capture that would wipe the user's proxy configuration on a
	// real machine.
	if err := prev.CheckRestorable(); err != nil {
		return err
	}
	var cmds [][]string
	for _, k := range prev.Kinds {
		switch k {
		case sysport.ProxyAuto:
			cmds = append(cmds,
				[]string{"-setautoproxyurl", svc, prev.AutoURL},
				[]string{"-setautoproxystate", svc, onOff(prev.AutoOn)})
		case sysport.ProxyWeb:
			cmds = append(cmds,
				[]string{"-setwebproxy", svc, prev.WebHost, strconv.Itoa(prev.WebPort)},
				[]string{"-setwebproxystate", svc, onOff(prev.WebOn)},
				[]string{"-setsecurewebproxy", svc, prev.SecureHost, strconv.Itoa(prev.SecurePort)},
				[]string{"-setsecurewebproxystate", svc, onOff(prev.SecureOn)})
		case sysport.ProxySOCKS:
			cmds = append(cmds,
				[]string{"-setsocksfirewallproxy", svc, prev.SOCKSHost, strconv.Itoa(prev.SOCKSPort)},
				[]string{"-setsocksfirewallproxystate", svc, onOff(prev.SOCKSOn)})
		}
	}
	return h.run(ctx, cmds...)
}

// Live is the VERIFIER: it reads the primary service's resolved configuration
// and reports it under the scutil key names, which sysport.ProxyState
// documents as a shared vocabulary both platform implementations publish.
// The key set is the one scwindows' proxyStateFromIE produces, so a command
// reading it here reads exactly the names it would on a real Windows machine.
func (h harnessProxy) Live(context.Context) (sysport.ProxyState, error) {
	f := h.p.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.order) == 0 {
		return sysport.ProxyState{Keys: map[string]string{}}, nil
	}
	s := f.svc[f.order[0]]
	st := sysport.ProxyState{
		Keys:       map[string]string{},
		Exceptions: []string{"*.local"},
	}
	st.Keys["ProxyAutoDiscoveryEnable"] = zeroOne(false)
	st.Keys["ProxyAutoConfigEnable"] = zeroOne(s.pacOn)
	if s.pacOn {
		st.Keys["ProxyAutoConfigURLString"] = s.pacURL
	}
	setTriple(st.Keys, "HTTP", s.webOn, s.webHost, s.webPort)
	setTriple(st.Keys, "HTTPS", s.secOn, s.secHost, s.secPort)
	setTriple(st.Keys, "SOCKS", s.sockOn, s.sockHost, s.sockPort)
	return st, nil
}

// setTriple writes one scheme's Enable/Proxy/Port triple. The host and port
// keys are written only when the setting is ON, which is what both platform
// implementations do: a disabled proxy's stored Server is real (macOS keeps
// it, and so does the Windows hive) but it is not what the system resolves to,
// and publishing it would make `dpb doctor` report a proxy nobody is using.
func setTriple(keys map[string]string, prefix string, on bool, host string, port int) {
	keys[prefix+"Enable"] = zeroOne(on)
	if !on {
		return
	}
	keys[prefix+"Proxy"] = host
	keys[prefix+"Port"] = strconv.Itoa(port)
}

// run issues networksetup argv through the fake, so a mutation this Port makes
// is visible in fakeMac.calls exactly as the darwin path's is.
func (h harnessProxy) run(ctx context.Context, cmds ...[]string) error {
	for _, args := range cmds {
		if err := h.p.f.Run(ctx, "networksetup", args...).Error(); err != nil {
			return err
		}
	}
	return nil
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// ── DNS ─────────────────────────────────────────────────────────────────────

type harnessDNS struct{ p *harnessSysPort }

func (h harnessDNS) Configured(_ context.Context, svc string) ([]string, error) {
	h.p.mu.Lock()
	defer h.p.mu.Unlock()
	if v, ok := h.p.svc[svc]; ok {
		return append([]string(nil), v...), nil
	}
	// No override recorded: the service uses what DHCP supplied, which is the
	// same list Live reports.
	return append([]string(nil), h.p.live...), nil
}

func (h harnessDNS) Set(ctx context.Context, svc string, servers []string) error {
	if err := h.p.f.Run(ctx, "networksetup",
		append([]string{"-setdnsservers", svc}, servers...)...).Error(); err != nil {
		return err
	}
	h.p.mu.Lock()
	defer h.p.mu.Unlock()
	if h.p.svc == nil {
		h.p.svc = map[string][]string{}
	}
	h.p.svc[svc] = append([]string(nil), servers...)
	h.p.live = append([]string(nil), servers...)
	return nil
}

func (h harnessDNS) Clear(ctx context.Context, svc string) error {
	if err := h.p.f.Run(ctx, "networksetup", "-setdnsservers", svc, "Empty").Error(); err != nil {
		return err
	}
	h.p.mu.Lock()
	defer h.p.mu.Unlock()
	delete(h.p.svc, svc)
	h.p.live = []string{fakeMacLiveResolver}
	return nil
}

func (h harnessDNS) Live(context.Context) ([]string, error) {
	h.p.mu.Lock()
	defer h.p.mu.Unlock()
	return append([]string(nil), h.p.live...), nil
}

// ── session environment ─────────────────────────────────────────────────────

type harnessEnv struct{ p *harnessSysPort }

// Get is the CAPTURE read. An absent variable is reported as not set with no
// error — that is establishable here, unlike the launchd ambiguity
// sysport.ErrEnvUnreadable exists for — because this store is a map.
func (h harnessEnv) Get(_ context.Context, name string) (string, bool, error) {
	f := h.p.f
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.env[name]
	return v, ok, nil
}

func (h harnessEnv) Set(ctx context.Context, name, value string) error {
	return h.p.f.Run(ctx, "launchctl", "setenv", name, value).Error()
}

func (h harnessEnv) Unset(ctx context.Context, name string) error {
	return h.p.f.Run(ctx, "launchctl", "unsetenv", name).Error()
}

// ── routes, interfaces, facts ───────────────────────────────────────────────

// These three exist because sysport.Port is one interface. No test in this
// package reaches them on Windows: the tun fixture's sequencer records Ops
// instead of applying them, and every other command that would mutate a route
// is in a `!windows` file because its fake system is macOS route(8). Each
// therefore fails BY NAME rather than pretending to succeed, which is the rule
// internal/netstate/port_other.go applies to an unsupported platform for the
// same reason: a stub that compiles, looks right and silently succeeds is the
// defect class this project has already found three of in Windows' own stdlib.

type harnessRoute struct{ p *harnessSysPort }

func (harnessRoute) Add(context.Context, sysport.RouteSpec) error {
	return fmt.Errorf("netstate: the command harness's Port installs no routes; " +
		"a test that needs one must drive a real netstate.Manager")
}

func (harnessRoute) Delete(context.Context, sysport.RouteSpec) error {
	return fmt.Errorf("netstate: the command harness's Port deletes no routes; " +
		"a test that needs one must drive a real netstate.Manager")
}

func (h harnessRoute) RIB() sysport.RIBReader { return h.p.f }

type harnessIface struct{ p *harnessSysPort }

func (harnessIface) Configure(_ context.Context, iface string, _ sysport.IfaceConfig) error {
	return fmt.Errorf("netstate: the command harness's Port cannot configure %s", iface)
}

func (harnessIface) Unconfigure(_ context.Context, iface string, _ sysport.IfaceConfig) error {
	return fmt.Errorf("netstate: the command harness's Port cannot unconfigure %s", iface)
}

func (harnessIface) Addrs(_ context.Context, iface string) ([]netip.Addr, error) {
	return nil, fmt.Errorf("netstate: the command harness's Port cannot read %s's addresses", iface)
}

type harnessFacts struct{ p *harnessSysPort }

// Collect answers with the machine fakeMac models. Every command test injects
// globals.facts directly, so this is reached only by a caller that built an Env
// without them; answering rather than failing keeps that caller working the way
// it does on darwin, where the fake's networksetup and scutil supply the same
// two facts.
func (h harnessFacts) Collect(context.Context, string) (*sysport.Facts, error) {
	f := h.p.f
	f.mu.Lock()
	defer f.mu.Unlock()
	return &sysport.Facts{
		Uplink:   "en0",
		Services: append([]string(nil), f.order...),
	}, nil
}
