//go:build windows

package cliapp

import "regexp"

// validTunName matches a name wintun will accept as an adapter's FRIENDLY
// name — what Windows shows for it in Network Connections and in
// `Get-NetAdapter`. There is no kernel-assigned unit to parse for the way
// darwin's utunN has one: wintun.CreateAdapter (golang.zx2c4.com/wintun's
// wintun.go) takes whatever UTF-16 string it is given, up to its own
// AdapterNameMax of 128 code units, and reuses an existing adapter of that
// name rather than erroring — see link_windows.go's OpenDevice. The DLL call
// itself enforces no character restriction, but Windows refuses a network
// connection name containing the reserved filesystem characters
// `\ / : * ? " < > |` or a control character — the same set the Rename
// dialog and `netsh interface set interface name=` both refuse — so this
// refuses them here too, with a message that says why instead of a raw
// wintun error two steps later. The 127-rune ceiling leaves the DLL's own
// trailing NUL its code unit; a rune and a UTF-16 code unit differ only for
// characters outside the Basic Multilingual Plane, which nobody types into
// an adapter name on purpose.
var validTunName = regexp.MustCompile(`^[^\x00-\x1f\\/:*?"<>|]{1,127}$`)

// defaultTunName is --tun-name's default: the same "dpb" link_windows.go's
// OpenDevice falls back to when it is handed no name at all
// (defaultAdapterName). It is restated here as a literal rather than
// imported from tunfe so a CLI flag's default stays cliapp's own decision —
// tunfe's fallback exists for its package's own callers, of which the shipped
// command line is only one, and the two are pinned to the same string by
// link_windows.go's doc comment rather than by a shared symbol.
const defaultTunName = "dpb"

// tunNameHelp is --tun-name's flag description, shown by `dpb run --help`.
const tunNameHelp = "wintun adapter's friendly name, as Network Connections shows it (default \"dpb\")"

// validateTunName refuses a --tun-name Windows would refuse for a network
// adapter, before dpb describes or opens anything under it.
//
// Before this rule existed, --tun-name had no Windows-specific check at all:
// it inherited macOS's utunN-only regex unconditionally, so the wintun
// adapter always opened as "utun" — meaningless in Network Connections, where
// a user has to recognise it to find it — and `dpb run --tun --tun-name dpb`,
// the natural thing to type for the name link_windows.go documents, exited 2
// with a message about macOS. The check here is a name check and nothing
// more: it opens no adapter, so it behaves identically unprivileged and under
// --dry-run.
func validateTunName(name string) error {
	if validTunName.MatchString(name) {
		return nil
	}
	return usagef("run: --tun-name %q: not a name Windows will accept for a network adapter.\n"+
		"  A wintun adapter takes a FRIENDLY name — the one Network Connections shows for it, "+
		"not a kernel-assigned unit like macOS's utunN — so it has to be 1-127 characters with "+
		"none of \\ / : * ? \" < > | or a control character in it.\n"+
		"  Drop --tun-name to use %q, the default every route and interface step below is then "+
		"described against", name, defaultTunName)
}
