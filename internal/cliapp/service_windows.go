//go:build windows

package cliapp

import (
	"context"
	"fmt"
	"runtime"
)

// service has no Windows mechanism yet. Plan 5's Task 2 adds winLogonTask (a
// Scheduled Task run as the interactive user, which is what carries proxy
// mode's environment variables into that session) and Task 3 adds winService
// (a Windows service running as LocalSystem, --system's equivalent). Until
// then, every verb refuses by name here rather than writing launchd-shaped
// state — a plist under Library/LaunchAgents, a "gui/<uid>" domain — that
// means nothing on this platform.
//
// That refusal is exactly the discipline internal/netwatch/route_other.go and
// internal/emit/stub_other.go's comments already state for this codebase: a
// capability that is silently absent is how a mutation gets skipped without
// anyone noticing. serviceScopeFor is where it happens — service.go calls it
// first, from every one of the six verbs, before touching anything else — so
// `dpb service install` (or uninstall, start, stop, status, logs) fails loudly
// here instead of quietly doing nothing, or worse, something that looks like a
// launchd job to code that is not expecting to run anywhere else.
//
// installMechanism, uninstallMechanism, startMechanism, stopMechanism and
// statusMechanism below are consequently unreachable in this build:
// serviceScopeFor always errors first, and every verb returns before calling
// them. They still have to exist, with the same shapes service.go calls, for
// `GOOS=windows go build` to succeed — and each refuses by name too, in case a
// future change ever lets one be reached without the gate above it.
func unsupportedService(what string) error {
	return fmt.Errorf("service: %s is not implemented for windows yet (winLogonTask/winService land in a later task); this binary is %s/%s",
		what, runtime.GOOS, runtime.GOARCH)
}

func (g *globals) serviceScopeFor(system bool) (serviceScope, error) {
	return serviceScope{}, unsupportedService("resolving the service scope")
}

func installMechanism(ctx context.Context, g *globals, s serviceScope, args []string) error {
	return unsupportedService("installing the service")
}

func uninstallMechanism(ctx context.Context, g *globals, s serviceScope) error {
	return unsupportedService("uninstalling the service")
}

func startMechanism(ctx context.Context, g *globals, s serviceScope) error {
	return unsupportedService("starting the service")
}

func stopMechanism(ctx context.Context, g *globals, s serviceScope) error {
	return unsupportedService("stopping the service")
}

func statusMechanism(ctx context.Context, g *globals, s serviceScope) (found, running bool) {
	panic("cliapp: service.statusMechanism is windows-unreachable: serviceScopeFor always refuses first")
}
