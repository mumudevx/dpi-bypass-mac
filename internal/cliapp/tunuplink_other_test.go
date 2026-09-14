//go:build !windows

package cliapp

// tunFixtureUplink is the interface the fixture's machine escapes through. It
// is a real one because IP_BOUND_IF is real: under --tun every socket dpb
// opens for itself is pinned to the uplink, and the fixture's fake resolver is
// on loopback, so the recursion guard under test needs a name the kernel will
// accept.
//
// It was a `const tunFixtureUplink = "lo0"` in tunrun_test.go until the Windows
// suite started running. The value here is unchanged; only its home moved, so
// that the Windows build can discover the same interface under the name that
// platform gives it.
const tunFixtureUplink = "lo0"
