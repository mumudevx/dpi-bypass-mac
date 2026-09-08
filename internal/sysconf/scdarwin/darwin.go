//go:build darwin

// Package scdarwin is sysport.Port for macOS.
//
// Every mutation goes through a command-line tool and every verification goes
// through a different subsystem: networksetup writes proxies and `scutil
// --proxy` reads them, route(8) writes routes and an AF_ROUTE socket reads
// them, ifconfig addresses an interface and net.Interfaces() reads it back.
// The one documented exception is launchctl setenv/getenv, which has no second
// observer; see sysport.EnvController.
//
// Error strings in this package keep the "netstate:" prefix they were written
// with. Moving a system call must not change what dpb prints, and that prefix
// names the subsystem a user reads about in `dpb doctor`, not the Go package
// the code happens to live in.
package scdarwin

import (
	"context"
	"errors"
	"strings"

	"github.com/mumudevx/dpb/internal/sysport"
)

type port struct {
	run  sysport.Runner
	rib  sysport.RIBReader
	logf func(string, ...any)
}

// New returns the macOS Port reading and writing through e.
//
// It takes the whole Env rather than just a Runner because two of the three
// fields are load-bearing and neither can be reconstructed here. e.RIB is the
// independent verifier: substituting the kernel's own reader when a caller
// supplied one would make every test that injects a routing table read the real
// machine instead, and would silently turn "collect facts without a RIB" — an
// error the caller relies on — into a live syscall. e.Logf is where the
// best-effort failures go: Collect records an unreadable service list rather
// than returning it, and a Port with nowhere to log would drop that line from
// `dpb doctor` without dropping the failure.
//
// Passing the runner in rather than constructing one is what lets a test drive
// this implementation with recorded output (internal/testnet).
func New(e Env) sysport.Port {
	return &port{run: e.runner(), rib: e.RIB, logf: e.Logf}
}

// NewRIB returns the kernel-backed routing-table reader, for a caller that
// wants the verifier without a Port around it. netstate.NewRIB is the one
// caller: `dpb doctor` builds a RIB before it has decided what to mutate.
func NewRIB() sysport.RIBReader { return newKernelRIB() }

var _ sysport.Port = (*port)(nil)

func (p *port) Proxy() sysport.ProxyController { return proxyCtl{p} }
func (p *port) DNS() sysport.DNSController     { return dnsCtl{p} }
func (p *port) Route() sysport.RouteController { return routeCtl{p} }
func (p *port) Iface() sysport.IfaceController { return ifaceCtl{p} }
func (p *port) Env() sysport.EnvController     { return envCtl{p} }
func (p *port) Facts() sysport.FactsCollector  { return factsCtl{p} }

// macOS grants every capability dpb has an Op for. The constant is spelled out
// rather than left implicit so that the Windows implementation's shortfall, when
// it lands, is a diff against something.
func (p *port) Caps() sysport.Caps {
	return sysport.CapProxyAuto | sysport.CapProxyManual | sysport.CapDNSOverride |
		sysport.CapRouteWrite | sysport.CapIfaceConfig | sysport.CapSessionEnv |
		sysport.CapPerService
}

// env is the readers' view of this Port.
func (p *port) env() Env { return Env{Runner: p.run, RIB: p.rib, Logf: p.logf} }

// Env is what a macOS reader needs from the world: a Runner to issue the tool
// call, a RIB to read the kernel's answer back, and somewhere to log what it
// could not do. It is NOT netstate.Env — scdarwin cannot import netstate, which
// is the import cycle sysport exists to prevent — but it carries the same
// fields the readers used before the move, so every body here reads exactly as
// it did.
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

// Result and RouteEntry are aliases, not definitions: scdarwin.Result and
// sysport.Result are the same type. netstate/aliases.go carries the same ones
// for the same reason — the code that drives a tool reads better naming what a
// Runner hands back, and the code that reads the RIB reads better naming a
// routing table entry, without qualifying either every time.
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

// firstLine duplicates the unexported helper of the same name in sysport and
// netstate. Result's move to sysport exported only Failed, Reason and Error, so
// ListServices's error message keeps a small private copy rather than growing
// sysport's surface for one call site — the trade netstate/runner.go already
// documents for its own copy.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(no output)"
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
