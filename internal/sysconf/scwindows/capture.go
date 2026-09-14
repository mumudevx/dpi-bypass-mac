//go:build windows

package scwindows

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file is the read side of `dpb devtool capture-sysconf`
// (internal/cliapp/devtool_windows.go). Everything else in this package reads
// these three APIs only to answer a narrower question — is this route the
// default, is this address configured, is this proxy live — and throws the
// rest of the row away on purpose (see rib.go's routeMetric comment on what
// routeEntryFrom discards and why). A capture exists for the opposite reason:
// internal/testnet's package comment says the macOS fakes are driven by
// output CAPTURED FROM A REAL MACHINE, so a test asserts against what the
// machine actually returned rather than what the author assumed it would.
// GetIpForwardTable2, GetAdaptersAddresses and
// WinHttpGetIEProxyConfigForCurrentUser return structs, not text, so there is
// no CLI output to capture — the struct itself has to be, in a shape that
// survives a JSON round trip.
//
// The three types below therefore keep MORE of each row than any production
// caller in this package reads today (Metric, Protocol, Origin, IfType,
// OperStatus, ...). That is deliberate: narrowing the capture to today's
// consumers would reproduce the exact loss routeEntryFrom already documents,
// and a fixture that lost the same fields it exists to preserve would not be
// a capture of anything.
//
// Every unsafe read here goes through the SAME unexported helpers rib.go and
// iface.go already use and route_test.go / iface_test.go already pin
// (sockaddrAddr, adapterAddresses, unicastAddrsOf, winhttpCurrentUserIEProxyConfig
// and its free method) — nothing in this file redeclares a struct layout or
// walks a linked list a second, independent way. A capture tool that got a
// field wrong would be worse than no capture tool: it would hand a future test
// author a fixture that LOOKS like ground truth and is not.

// One thing this file does NOT keep is the identity of the machine it ran on.
//
// A capture is taken on a real machine and exists to be committed as a
// fixture, which makes every field a potential disclosure — and on a managed
// laptop two of them are the disclosure that matters. WinHttp's
// lpszAutoConfigURL on such a machine is an INTERNAL PAC URL, which names the
// employer and often the internal DNS layout with it; lpszProxy and
// lpszProxyBypass name internal hosts and internal domain suffixes; and the
// unicast addresses and route rows name the operator's own network. None of
// that is what a capture is for. The package comment above says the point is
// the STRUCT — the field set, the enum values, the shapes rib.go and iface.go
// decode — and not one of those depends on the real bytes of an address.
//
// So the three exported Capture* functions below redact before they return:
// every address is replaced by a documentation address of the same family and
// the same CATEGORY with its prefix length kept (redactAddrString), and the
// three proxy strings are dropped, with the fact that they were set recorded
// by name instead. A fixture then still carries everything a test asserts
// against and nothing that says whose machine it came from.
//
// Two deliberate limits, both stated rather than hidden:
//
//   - This is not a flag. An opt-out would be the only mode anyone ever pasted
//     into a terminal, on exactly the machine where it matters most.
//   - Adapter FriendlyName and Description are KEPT. They name hardware and
//     not a network ("Wi-Fi", "Intel(R) Wi-Fi 6 AX201"), and tunfe matches on
//     an adapter name, so a fixture without them describes nothing. A VPN
//     client's adapter description can still name a vendor, which is why
//     capture-sysconf's help text says to read the files before committing
//     them: redaction is a floor here, not a substitute for looking.
//
// The unredacted decoders (capturedRouteFrom, capturedAdapterFrom) stay
// unredacted, because they are what capture_test.go pins the Win32 struct
// reading against; redaction is a property of what LEAVES this package.

// CapturedRoute is one MIB_IPFORWARD_ROW2 row, decoded but not narrowed.
type CapturedRoute struct {
	// Destination is the row's prefix, e.g. "0.0.0.0/0" or "2001:db8::/32".
	// Empty when the row's family or prefix length could not be decoded (see
	// sockaddrAddr) — which routeEntryFrom treats as "skip this row", but a
	// capture keeps the row rather than dropping it, so the fixture still
	// says how many rows GetIpForwardTable2 actually returned.
	Destination string `json:"destination"`
	// NextHop is empty for an on-link route, matching MSDN's "the next hop is
	// unspecified (all zeros)" for a local-link destination — see rib.go's
	// routeEntryFrom for the same reading.
	NextHop        string `json:"next_hop,omitempty"`
	InterfaceIndex uint32 `json:"interface_index"`
	// InterfaceName is filled in on a best-effort basis from net.Interfaces(),
	// the same source rib.go's ifaceNames uses. Empty rather than guessed when
	// the index is not in the map, which MSDN says can legitimately happen —
	// see rib.go's zoneName comment on InterfaceIndex not being persistent.
	InterfaceName string `json:"interface_name,omitempty"`
	// Metric is the row's OWN metric offset, not the interface metric
	// routeMetric ranks by; see rib.go's routeMetric comment for why the two
	// are different numbers and why only the interface one is used today.
	Metric   uint32 `json:"metric"`
	Protocol uint32 `json:"protocol"`
	Origin   uint32 `json:"origin"`
	Loopback bool   `json:"loopback,omitempty"`
}

// capturedRouteFrom decodes one row. It is pure — no syscall — so it is
// tested with hand-built rows the same way rib.go's routeEntryFrom is, in
// capture_test.go.
func capturedRouteFrom(row *windows.MibIpForwardRow2, names map[int]string) CapturedRoute {
	c := CapturedRoute{
		InterfaceIndex: row.InterfaceIndex,
		InterfaceName:  names[int(row.InterfaceIndex)],
		Metric:         row.Metric,
		Protocol:       row.Protocol,
		Origin:         row.Origin,
		Loopback:       row.Loopback != 0,
	}
	if dst, ok := sockaddrAddr(&row.DestinationPrefix.Prefix); ok {
		if pfx := netip.PrefixFrom(dst, int(row.DestinationPrefix.PrefixLength)); pfx.IsValid() {
			c.Destination = pfx.Masked().String()
		}
	}
	if nh, ok := sockaddrAddr(&row.NextHop); ok && !nh.IsUnspecified() {
		c.NextHop = nh.String()
	}
	return c
}

// CaptureRoutes reads the whole IP routing table through GetIpForwardTable2
// and decodes every row, for `dpb devtool capture-sysconf` to serialise.
//
// This duplicates the GetIpForwardTable2/FreeMibTable ceremony rib.go's
// Routes already carries, rather than calling through it, because Routes
// returns []sysport.RouteEntry — the narrowed type this file exists to
// avoid. See the package comment above; kernelRIB.Routes stays untouched.
//
// Every row is redacted on the way out: see the redaction comment above.
func CaptureRoutes() ([]CapturedRoute, error) {
	names, err := (&kernelRIB{}).ifaceNames()
	if err != nil {
		return nil, err
	}

	var table *windows.MibIpForwardTable2
	tableErr := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table)
	defer func() {
		if table != nil {
			windows.FreeMibTable(unsafe.Pointer(table))
		}
	}()
	if tableErr != nil {
		return nil, fmt.Errorf("netstate: read the routing table: %w", tableErr)
	}

	rows := table.Rows()
	out := make([]CapturedRoute, 0, len(rows))
	for i := range rows {
		out = append(out, capturedRouteFrom(&rows[i], names).redacted())
	}
	return out, nil
}

// CapturedAdapter is one IP_ADAPTER_ADDRESSES block, decoded but not
// narrowed. See CapturedRoute for why this keeps fields (Description,
// IfType, OperStatus) that ifaceCtl.Addrs never reads.
type CapturedAdapter struct {
	FriendlyName string `json:"friendly_name"`
	Description  string `json:"description,omitempty"`
	IfIndex      uint32 `json:"if_index"`
	// IfType is IFTYPE from ifdef.h (71 = IF_TYPE_IEEE80211, 6 =
	// IF_TYPE_ETHERNET_CSMACD, 131 = IF_TYPE_TUNNEL, ...), kept as the raw
	// number rather than translated: this is a capture, and inventing a
	// name table here is exactly the kind of authored assumption the package
	// comment on this file exists to avoid.
	IfType uint32 `json:"if_type"`
	// OperStatus is IF_OPER_STATUS (1 = IfOperStatusUp), the field
	// net.Interface.Flags&FlagUp is derived from on Windows — see iface.go's
	// bringUp comment.
	OperStatus       uint32   `json:"oper_status"`
	Mtu              uint32   `json:"mtu"`
	UnicastAddresses []string `json:"unicast_addresses,omitempty"`
}

// capturedAdapterFrom decodes one adapter block. It is pure given aa, and
// reuses unicastAddrsOf (iface.go) rather than walking the linked list again.
func capturedAdapterFrom(aa *windows.IpAdapterAddresses) CapturedAdapter {
	c := CapturedAdapter{
		FriendlyName: windows.UTF16PtrToString(aa.FriendlyName),
		Description:  windows.UTF16PtrToString(aa.Description),
		IfIndex:      aa.IfIndex,
		IfType:       aa.IfType,
		OperStatus:   aa.OperStatus,
		Mtu:          aa.Mtu,
	}
	for _, a := range unicastAddrsOf(aa) {
		c.UnicastAddresses = append(c.UnicastAddresses, a.String())
	}
	return c
}

// CaptureAdapters reads the whole adapter list through GetAdaptersAddresses
// and decodes every block, for `dpb devtool capture-sysconf` to serialise.
//
// It calls adapterAddresses (iface.go) rather than reimplementing the
// buffer-growth loop MSDN documents for GetAdaptersAddresses, for the same
// reason CaptureRoutes reuses sockaddrAddr: that loop is already reviewed and
// pinned by iface_test.go, and a second copy is a second place for the size
// contract to drift.
//
// Every block is redacted on the way out: see the redaction comment above.
// The addresses go, the adapter's own names stay, for the reason stated there.
func CaptureAdapters() ([]CapturedAdapter, error) {
	aas, err := adapterAddresses()
	if err != nil {
		return nil, err
	}
	out := make([]CapturedAdapter, 0, len(aas))
	for _, aa := range aas {
		out = append(out, capturedAdapterFrom(aa).redacted())
	}
	return out, nil
}

// CapturedProxyConfig is what WinHttpGetIEProxyConfigForCurrentUser returned,
// success or failure both recorded as DATA rather than as a Go error.
//
// This is the opposite contract from proxyCtl.Live, on purpose. Live must
// never treat a failed read as "no proxy configured" — proxy.go's own comment
// on liveFromWinHTTP explains why an empty answer there is indistinguishable
// from "nothing is set" to every caller above this package. A capture's job
// is exactly the fact Live is forbidden to manufacture: "on this token, this
// call fails with ERROR_FILE_NOT_FOUND" is itself the thing a future test
// author needs recorded, because it is the case Live's own contract depends
// on distinguishing from a working answer.
type CapturedProxyConfig struct {
	Available bool `json:"available"`
	// Error is the Win32 error's text when Available is false. Never both
	// unset: an unavailable capture that does not say why is exactly the
	// silent failure this whole file exists to rule out.
	Error      string `json:"error,omitempty"`
	AutoDetect bool   `json:"auto_detect,omitempty"`
	// AutoConfigURL, Proxy and ProxyBypass are ALWAYS EMPTY in a capture that
	// left this package — CaptureProxyConfig drops them and names them in
	// Redacted instead. They exist as fields because the WinHttp struct has
	// them and because the redaction has to have something to read; see the
	// redaction comment above for why an internal PAC URL is the one field on
	// a managed laptop that must never reach a commit.
	AutoConfigURL string `json:"auto_config_url,omitempty"`
	Proxy         string `json:"proxy,omitempty"`
	ProxyBypass   string `json:"proxy_bypass,omitempty"`
	// Redacted names the fields that were set and were removed, in the JSON
	// spelling above. "the machine had a PAC URL" is the part a test can use;
	// which PAC URL is the part it must not carry. Empty when nothing was set,
	// which is itself the answer on a clean machine.
	Redacted []string `json:"redacted,omitempty"`
}

// CaptureProxyConfig calls WinHttpGetIEProxyConfigForCurrentUser directly,
// for the CALLING process's token — the same call liveFromWinHTTP makes, and
// the same caveat applies: this answers for whoever runs `dpb devtool
// capture-sysconf`, not for a different user's hive. That is the right
// question for this tool: it is a developer running it interactively on their
// own session, not an elevated service reading someone else's registry.
//
// The result is redacted: the three strings are dropped and named. That is
// not a hedge — a developer running this interactively on a corporate laptop
// is precisely the case where lpszAutoConfigURL is an internal PAC URL, and
// the --out this writes through is a path in a git checkout. See the
// redaction comment above.
func CaptureProxyConfig() CapturedProxyConfig {
	var cfg winhttpCurrentUserIEProxyConfig
	// Deferred before the call for the reason proxy.go's Live gives: cfg
	// starts zeroed and free skips nil pointers, so this is safe whether the
	// call fails outright or fills some of the three strings before failing.
	defer cfg.free(func(string, ...any) {})

	if err := WinHttpGetIEProxyConfigForCurrentUser(unsafe.Pointer(&cfg)); err != nil {
		return CapturedProxyConfig{Error: err.Error()}
	}
	return CapturedProxyConfig{
		Available:     true,
		AutoDetect:    cfg.fAutoDetect != 0,
		AutoConfigURL: windows.UTF16PtrToString(cfg.lpszAutoConfigURL),
		Proxy:         windows.UTF16PtrToString(cfg.lpszProxy),
		ProxyBypass:   windows.UTF16PtrToString(cfg.lpszProxyBypass),
	}.redacted()
}

// redacted drops the three proxy strings and records which of them were set.
func (c CapturedProxyConfig) redacted() CapturedProxyConfig {
	out := CapturedProxyConfig{Available: c.Available, Error: c.Error, AutoDetect: c.AutoDetect}
	for _, f := range []struct {
		name, value string
	}{
		{"auto_config_url", c.AutoConfigURL},
		{"proxy", c.Proxy},
		{"proxy_bypass", c.ProxyBypass},
	} {
		if f.value != "" {
			out.Redacted = append(out.Redacted, f.name)
		}
	}
	return out
}

// redacted replaces the row's two addresses. InterfaceName is kept for the
// reason the redaction comment gives for the adapter's own names.
func (c CapturedRoute) redacted() CapturedRoute {
	c.Destination = redactAddrString(c.Destination)
	c.NextHop = redactAddrString(c.NextHop)
	return c
}

// redacted replaces the block's unicast addresses, keeping the slice's
// identity (nil stays nil, which capture_test.go pins as distinct from empty).
func (c CapturedAdapter) redacted() CapturedAdapter {
	for i, a := range c.UnicastAddresses {
		c.UnicastAddresses[i] = redactAddrString(a)
	}
	return c
}

// redactAddrString maps one address or prefix onto a documentation stand-in of
// the same family, the same category, and — for a prefix — the same length.
//
// Category, because the category is the part a fixture is read for: whether a
// row is the default route, an on-link LAN route, a link-local address or a
// multicast group is what a test about route selection asserts on, and none of
// those questions need the real bytes. Identity within a category is what goes:
// two different global next hops both become 198.51.100.0, and that collapse is
// the point rather than a loss.
//
// Unspecified and loopback pass through unchanged because they ARE constants —
// 0.0.0.0/0 is the same sequence of bytes on every machine on earth, and
// replacing it would destroy the one row every reader of a routing-table
// fixture looks for first.
//
// The stand-ins come from the ranges the RFCs reserve for exactly this use:
// 198.51.100.0 is TEST-NET-2 (RFC 5737), 2001:db8:: is the documentation prefix
// (RFC 3849). Neither can route anywhere, so a fixture that leaks into a live
// config fails closed.
func redactAddrString(s string) string {
	if s == "" {
		// An unreadable row keeps its empty Destination: see
		// TestCapturedRouteFromKeepsAnUnreadableRow.
		return ""
	}
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return netip.PrefixFrom(redactAddr(pfx.Addr()), pfx.Bits()).Masked().String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return redactAddr(a).String()
	}
	// Unreachable through capturedRouteFrom/capturedAdapterFrom, which both
	// build their strings from netip. A value this cannot classify is the one
	// value it must not pass through, so it does not.
	return "redacted"
}

// The stand-ins, one per (family, category). Named rather than inline so the
// set is readable as a whole and so the RFC-reserved values are parsed once.
var (
	redactedV4LinkLocal = netip.AddrFrom4([4]byte{169, 254, 0, 0})
	redactedV4Multicast = netip.AddrFrom4([4]byte{224, 0, 0, 0})
	redactedV4Unicast   = netip.AddrFrom4([4]byte{198, 51, 100, 0}) // TEST-NET-2
	redactedV6LinkLocal = netip.MustParseAddr("fe80::")
	redactedV6Multicast = netip.MustParseAddr("ff00::")
	redactedV6Unicast   = netip.MustParseAddr("2001:db8::") // RFC 3849
)

func redactAddr(a netip.Addr) netip.Addr {
	// Is4, not Is4In6: the stand-in has to have the same NUMBER OF BYTES as
	// what it replaces, or PrefixFrom below would pair a 4-byte address with a
	// prefix length only a 16-byte one can carry and produce an invalid prefix.
	// A v4-mapped address is 16 bytes, so it gets the v6 stand-in.
	v4 := a.Is4()
	switch {
	case !a.IsValid(), a.IsUnspecified(), a.IsLoopback():
		return a
	case a.IsLinkLocalUnicast():
		if v4 {
			return redactedV4LinkLocal
		}
		return redactedV6LinkLocal
	case a.IsMulticast():
		if v4 {
			return redactedV4Multicast
		}
		return redactedV6Multicast
	default:
		// Everything that can name a particular network: global unicast, RFC
		// 1918 and CGNAT, and IPv6 ULAs — whose /48 is randomly generated per
		// site and therefore identifies one.
		if v4 {
			return redactedV4Unicast
		}
		return redactedV6Unicast
	}
}
