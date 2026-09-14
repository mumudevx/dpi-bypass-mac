//go:build !windows

package cliapp

import "github.com/mumudevx/dpb/internal/paths"

// harnessMachineChecks is what the command harness puts in
// globals.machineChecks.
//
// On darwin it is nil, so globals.machineChecksOf falls through to
// platformChecks — which returns nil there by design, because every darwin
// fact `dpb doctor` reports is already covered by the platform-neutral checks.
// doctor_darwin_test.go asserts that emptiness directly, and this seam does
// not change it.
func harnessMachineChecks() func(paths.Layout) []check { return nil }
