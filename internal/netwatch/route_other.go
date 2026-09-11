//go:build !darwin && !windows

package netwatch

// dpb ships for darwin and windows. This file exists so `GOOS=linux go build
// ./...` and a cross-platform editor still work as the smoke test they are
// meant to be, and it deliberately stops short of Windows — see the build tag,
// which is the one internal/netstate/port_other.go already uses for the same
// reason.
//
// The tag matters more than the body. A Windows netwatch that compiled against
// this stub would run with no route source at all and say nothing about it:
// the watcher would notice the network moving only when its sleep ticker came
// round, and "dpb is watching the network" would be true in the wiring and
// false in fact. Leaving Windows to fail the build keeps that an open task
// rather than a silent degradation, until the plan that owns netwatch ships a
// real source over the IP Helper notification API.
//
// nil is not a placeholder here, it is the answer Watcher.startSource already
// documents and handles: no kernel source, so the watcher runs on the sleep
// ticker alone — degraded, but not blind.
func newDefaultSource() Source { return nil }
