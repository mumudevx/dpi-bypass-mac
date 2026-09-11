//go:build !darwin && !windows

package netwatch

// dpb ships for darwin and windows, and both now have a real route source:
// route_darwin.go reads PF_ROUTE, route_windows.go registers a callback with
// the IP Helper NotifyRouteChange2 API. This file exists so `GOOS=linux go
// build ./...` and a cross-platform editor still work as the smoke test they
// are meant to be, and its tag is the one internal/netstate/port_other.go
// already uses for the same reason.
//
// The tag mattered more than the body while Windows was still missing. A
// Windows netwatch that compiled against this stub would have run with no
// route source at all and said nothing about it: the watcher would notice the
// network moving only when its sleep ticker came round, and "dpb is watching
// the network" would have been true in the wiring and false in fact. Leaving
// Windows to fail the build kept that an open task rather than a silent
// degradation. It is no longer open, so windows is excluded from this file by
// having an implementation of its own rather than by a build failure.
//
// nil is not a placeholder here, it is the answer Watcher.startSource already
// documents and handles: no kernel source, so the watcher runs on the sleep
// ticker alone — degraded, but not blind. That answer is now given only on
// platforms dpb does not ship for.
func newDefaultSource() Source { return nil }
