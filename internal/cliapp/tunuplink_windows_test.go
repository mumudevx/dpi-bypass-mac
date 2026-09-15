//go:build windows

package cliapp

import "net"

// tunFixtureUplink is the interface the fixture's machine escapes through, and
// on Windows it cannot be a literal.
//
// It has to be a REAL interface, for the reason the darwin declaration gives:
// under --tun every socket dpb opens for itself is pinned to the uplink
// (IP_UNICAST_IF here, IP_BOUND_IF there) and the fixture's fake resolver is on
// loopback. Loopback is the only interface every machine has — but Windows
// names adapters with a LOCALIZED FriendlyName, "Loopback Pseudo-Interface 1"
// in English and something else on a Turkish or German install, and
// net.Interface.Name reports exactly that string. A literal here would be a
// fixture that works in one locale and not another, which is the same defect
// class the scwindows package comment refuses to parse localized tool output
// for.
//
// The fallback is darwin's name, deliberately: an interface this machine does
// not have makes the pinned dial fail loudly with a name in the message,
// which is a better failure than silently escaping through whatever the
// default route happens to be.
var tunFixtureUplink = discoverLoopbackUplink()

func discoverLoopbackUplink() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return "lo0"
	}
	for _, in := range ifs {
		if in.Flags&net.FlagLoopback != 0 {
			return in.Name
		}
	}
	return "lo0"
}
