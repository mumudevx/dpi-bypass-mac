//go:build windows

// Package scwindows is sysport.Port for Windows.
//
// # Contract 1: verification reads through a different subsystem
//
// Every mutation this package makes is read back through something other than
// the thing that wrote it, so that a write which reported success but changed
// nothing is caught. Where a command-line tool is unavoidable — `netsh`, for
// DNS — ONLY ITS EXIT STATUS IS CONSULTED, never its text. Windows localizes
// tool output and there is no LC_ALL=C to turn that off: a parser written
// against the English strings reads an empty answer on a Turkish or German
// install, and an empty answer is indistinguishable from "no setting" to every
// caller above this package.
//
// # Contract 2: route and iface are weaker than that, and this says so
//
// Route and interface mutations apply AND verify through the same API family,
// IP Helper (iphlpapi.dll). That is weaker than the macOS write-CLI/read-kernel
// split scdarwin gets — there, route(8) and an AF_ROUTE socket share no code at
// all — and it is stated here rather than papered over, exactly as scdarwin
// documents its own `launchctl setenv`/`getenv` exception.
//
// The mitigation is real but partial: CreateIpForwardEntry2 writes ONE ROW,
// while GetBestRoute2 asks the forwarding engine WHICH NEXT HOP IT WOULD
// CHOOSE for a destination — a question whose answer traverses route selection
// across every row in the table and the state of every interface. A row that
// was accepted into the table but loses selection, or sits on an interface that
// is down, answers the first question and fails the second. GetIpForwardTable2
// sits between the two: it re-reads the table rather than the FIB's choice, so
// it catches a write that landed differently from what was asked, but not a
// write that landed correctly and is nonetheless not used.
//
// # Contract 2b: the proxy verifier is weaker for a hive that is not our own
//
// proxyCtl normally satisfies Contract 1 well: the setters write registry
// values through advapi32 and Live reads the RESOLVED configuration back out
// of winhttp.dll, a different DLL answering a different question. That split
// survives for the ordinary case and is still the strongest one this package
// has.
//
// It does NOT survive when dpb is elevated as a DIFFERENT account than the
// logged-on user and therefore writes that user's hive by SID (see
// userhive.go). WinHTTP has no by-SID form —
// WinHttpGetIEProxyConfigForCurrentUser answers for the CALLING token, and
// MSDN says so: "If the caller does not impersonate a logged on user, WinHTTP
// attempts to retrieve the Internet Explorer settings for the current service
// process" — so on that path Live reads the same hive the setters wrote and
// the second observer is gone. Live says which observer answered rather than
// letting the two cases look alike, and this is stated here for the same
// reason Contract 2 above is: an exception that is written down can be argued
// with, and one that is not is just a hole.
//
// A smaller version of the same admission applies on BOTH paths: Live reads
// the ProxyEnable DWORD out of the hive even when WinHTTP supplies everything
// else. See proxyCtl.Live for why the verifier needs it and why that read can
// only ever turn a reported proxy OFF.
//
// Why not route.exe, which would restore the CLI/kernel split: it fails
// Contract 1 twice over. It reports failure by printing a localized sentence
// ("The route addition failed: The object already exists.") whose wording is
// translated per install, and its exit status is not a reliable substitute for
// reading that sentence — the same liar shape macOS route(8) has, where
// newroute() is void and main() exits 0 regardless. Trading a typed Win32 error
// code for a localized string plus an unreliable exit status is a worse deal
// than accepting that the write and the second opinion share a DLL.
//
// # Error strings
//
// Error strings in this package keep the "netstate:" prefix, for the reason
// scdarwin gives: the prefix names the subsystem a user reads about in
// `dpb doctor`, not the Go package the code happens to live in, and moving a
// system call between packages must not change what dpb prints.
package scwindows

import (
	"context"
	"errors"
	"sync"

	"github.com/mumudevx/dpb/internal/sysport"
)

type port struct {
	run  sysport.Runner
	rib  sysport.RIBReader
	logf func(string, ...any)

	// The per-user registry root proxy.go and env.go write, resolved on first
	// use and then pinned. The mutex is what makes the pin safe to read from
	// whichever goroutine an Op happens to run on; see (*port).userHive in
	// userhive.go for why it is pinned rather than re-resolved, and why a
	// FAILED resolution is deliberately not pinned.
	hiveMu sync.Mutex
	hive   userHive
	hiveOK bool
}

// New returns the Windows Port reading and writing through e.
//
// It takes the whole Env rather than just a Runner for the reasons scdarwin.New
// gives: e.RIB is the independent verifier, and substituting the kernel's own
// reader when a caller supplied one would make every test that injects a
// routing table read the real machine instead; e.Logf is where best-effort
// failures go, and a Port with nowhere to log would drop the line without
// dropping the failure.
//
// The return type was *port until Plan 3 Task 6, deliberately: returning
// sysport.Port before every controller existed would have required stubbing
// the missing ones, and a stub that compiles, looks right and always fails is
// the exact defect class Plan 2 found three of in Windows' own stdlib
// (syscall.Sendto, internal/poll's RawWrite, os.Process.Signal). All seven
// controllers have now landed, so the signature is the interface and the
// assertion below is a fact rather than a promise.
func New(e Env) sysport.Port { return &port{run: e.runner(), rib: e.RIB, logf: e.Logf} }

// The assertion Task 6 was waiting to be able to make. It is here rather than
// on New's return type alone so that a controller removed or renamed later
// fails to compile at the declaration, not at some caller.
var _ sysport.Port = (*port)(nil)

// NewRIB returns the IP-Helper-backed routing-table reader, for a caller that
// wants the verifier without a Port around it — the same seam scdarwin.NewRIB
// exists for: `dpb doctor` builds a RIB before it has decided what to mutate.
func NewRIB() sysport.RIBReader { return newKernelRIB() }

func (p *port) Route() sysport.RouteController { return routeCtl{p} }

// Proxy writes the per-user Internet Settings registry values and reads the
// resolved configuration back through WinHTTP; see proxy.go. There is one
// proxy configuration per user on Windows and none per network service, which
// is why Caps below withholds CapPerService permanently.
func (p *port) Proxy() sysport.ProxyController { return proxyCtl{p} }

// Iface addresses and MTUs a tunnel device through IP Helper; see iface.go.
func (p *port) Iface() sysport.IfaceController { return ifaceCtl{p} }

// DNS shells out to netsh(1) to write, and reads GetAdaptersAddresses to
// capture and verify; see dns.go.
func (p *port) DNS() sysport.DNSController { return dnsCtl{p} }

// Env sets user-session variables in HKCU\Environment and broadcasts
// WM_SETTINGCHANGE; see env.go.
func (p *port) Env() sysport.EnvController { return envCtl{p} }

// Facts reads the machine's network identity out of the routing table and
// GetAdaptersAddresses; see facts.go. It carries no capability bit — a
// collector reads and never mutates, so there is nothing for a caller to be
// refused.
func (p *port) Facts() sysport.FactsCollector { return factsCtl{p} }

// Caps names what this package can actually do TODAY, not what Windows can do.
// A bit was added by the task that landed the code behind it — CapRouteWrite
// and CapIfaceConfig behind route.go and iface.go, CapProxyAuto and
// CapProxyManual behind proxy.go, CapDNSOverride and CapSessionEnv behind
// dns.go and env.go — and Task 6 checked the total against what shipped: six
// bits, six implemented controllers, and the seventh capability withheld
// below. Granting a capability ahead of its implementation would make netstate
// plan a mutation it then cannot perform, which is the failure mode
// sysport.Caps exists to prevent: refuse BY NAME AND WITH A REASON, never
// promise and then skip quietly.
//
// CapPerService is withheld permanently, not pending: Windows has one proxy
// configuration per user, not one per network service, so there is no
// per-service state for a caller to iterate. Granting it would invite an Op to
// iterate services that do not exist. proxyCtl.Services returns a single
// pseudo-service to say so out loud rather than returning nothing — and
// facts.go's uplinkServices explains why Facts.Services carries adapter names
// instead, which is a different question with a different answer.
func (p *port) Caps() sysport.Caps {
	return sysport.CapRouteWrite | sysport.CapIfaceConfig |
		sysport.CapProxyAuto | sysport.CapProxyManual |
		sysport.CapDNSOverride | sysport.CapSessionEnv
}

// env is the readers' view of this Port.
func (p *port) env() Env { return Env{Runner: p.run, RIB: p.rib, Logf: p.logf} }

// Env is what a Windows reader needs from the world: a Runner to issue the one
// unavoidable tool call (`netsh`, for DNS), a RIB to read the kernel's answer
// back, and somewhere to log what it could not do. It is NOT netstate.Env —
// scwindows cannot import netstate, which is the import cycle sysport exists to
// prevent — and it mirrors scdarwin.Env field for field so that the two ports
// are substitutable at their call sites.
type Env struct {
	Runner sysport.Runner
	RIB    sysport.RIBReader
	Logf   func(string, ...any)
}

func (e Env) runner() sysport.Runner {
	if e.Runner == nil {
		return noRunner{}
	}
	return e.Runner
}

func (e Env) logf(format string, a ...any) {
	if e.Logf != nil {
		e.Logf(format, a...)
	}
}

// Result and RouteEntry are aliases, not definitions, matching scdarwin: the
// code that drives a tool reads better naming what a Runner hands back, and the
// code that reads the routing table reads better naming a routing table entry,
// without qualifying either every time.
type (
	Result     = sysport.Result
	RouteEntry = sysport.RouteEntry
)

// noRunner makes a zero Env fail loudly instead of nil-panicking deep inside a
// reader, which is the difference between a diagnosable bug report and a stack
// trace from a user's laptop.
type noRunner struct{}

func (noRunner) Run(_ context.Context, name string, args ...string) Result {
	return Result{
		Argv: append([]string{name}, args...),
		Err:  errors.New("netstate: Env.Runner is nil"),
	}
}
