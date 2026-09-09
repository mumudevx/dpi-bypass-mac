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

	"github.com/mumudevx/dpb/internal/sysport"
)

type port struct {
	run  sysport.Runner
	rib  sysport.RIBReader
	logf func(string, ...any)
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
// The return type is *port, not sysport.Port, and that is deliberate and
// temporary. Four of the seven controllers (Proxy, DNS, Iface, Env, Facts) land
// in Plan 3 Tasks 3-5; returning the interface today would require stubbing
// them, and a stub that compiles, looks right and always fails is the exact
// defect class Plan 2 found three of in Windows' own stdlib (syscall.Sendto,
// internal/poll's RawWrite, os.Process.Signal). Task 6 widens this signature to
// sysport.Port and lands `var _ sysport.Port = (*port)(nil)` beside it, at the
// moment that assertion can be true rather than a promise.
func New(e Env) *port { return &port{run: e.runner(), rib: e.RIB, logf: e.Logf} }

// NewRIB returns the IP-Helper-backed routing-table reader, for a caller that
// wants the verifier without a Port around it — the same seam scdarwin.NewRIB
// exists for: `dpb doctor` builds a RIB before it has decided what to mutate.
func NewRIB() sysport.RIBReader { return newKernelRIB() }

func (p *port) Route() sysport.RouteController { return routeCtl{p} }

// Caps names what this package can actually do TODAY, not what Windows can do.
// A bit is added by the task that lands the code behind it — CapRouteWrite here,
// the rest in Tasks 3-5 — and Task 6 checks the total against what shipped.
// Granting a capability ahead of its implementation would make netstate plan a
// mutation it then cannot perform, which is the failure mode
// sysport.Caps exists to prevent: refuse BY NAME AND WITH A REASON, never
// promise and then skip quietly.
//
// CapPerService is withheld permanently, not pending: Windows has one proxy
// configuration per user, not one per network service, so there is no
// per-service state for a caller to iterate.
func (p *port) Caps() sysport.Caps { return sysport.CapRouteWrite }

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
