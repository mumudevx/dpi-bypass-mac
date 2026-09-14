//go:build darwin

package cliapp

import "regexp"

// validTunName matches the only device names macOS will ever hand this tool:
// "utun" (the kernel picks a free unit) or "utunN".
var validTunName = regexp.MustCompile(`^utun(0|[1-9][0-9]{0,3})?$`)

// defaultTunName is --tun-name's default: the kernel-assigned utun.
const defaultTunName = "utun"

// tunNameHelp is --tun-name's flag description, shown by `dpb run --help`.
const tunNameHelp = "utun device to open; \"utun\" lets the kernel pick the unit"

// validateTunName refuses a --tun-name that is not a utun.
//
// `--tun-name en0` used to be ACCEPTED, and under --dry-run it printed a plan
// that would ifconfig the machine's real uplink, hang the capture routes off it
// and point the system resolvers at it. Nothing was applied, so nobody was
// endangered — but the printed plan was a lie about what the tool would do, and
// --dry-run's only job is to describe exactly that.
//
// The check is a name check and nothing more: it opens no device and reads no
// interface, so it behaves identically as root, unprivileged and under
// --dry-run. Whether a given utun unit is free is the kernel's answer to give,
// and it gives it at open time.
func validateTunName(name string) error {
	if validTunName.MatchString(name) {
		return nil
	}
	return usagef("run: --tun-name %q: a tunnel device on macOS is \"utun\" or \"utunN\", and "+
		"dpb opens one of its own rather than attaching to an interface that already exists.\n"+
		"  %q is the name of a real interface on this machine or of something that is not a "+
		"utun at all; configuring it and routing the whole address space through it is not "+
		"something dpb will describe, let alone do.\n"+
		"  Drop --tun-name to let the kernel pick a free unit, which is the default and what "+
		"every route and ifconfig step is then told about", name, name)
}
