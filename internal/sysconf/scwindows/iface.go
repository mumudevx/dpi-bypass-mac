//go:build windows

package scwindows

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/sysport"
)

// ifaceCtl addresses and MTUs a tunnel device.
//
// Configure and Unconfigure write through the unicast-IP-address rows
// (CreateUnicastIpAddressEntry / DeleteUnicastIpAddressEntry) and the
// per-family interface row (GetIpInterfaceEntry / SetIpInterfaceEntry).
// Addrs reads back through GetAdaptersAddresses, a different iphlpapi.dll
// call FAMILY working over a different struct family (IP_ADAPTER_ADDRESSES,
// not MIB_UNICASTIPADDRESS_ROW) — that is what makes it a verifier and not a
// mirror of the write, the same separation route.go keeps between
// CreateIpForwardEntry2 and GetIpForwardTable2. See the package comment
// (windows.go), Contract 2, for how much weaker this still is than
// scdarwin's ifconfig/net.Interfaces split, and why that is stated rather
// than hidden.
type ifaceCtl struct{ p *port }

var _ sysport.IfaceController = ifaceCtl{}

// Configure brings iface to cfg in the sequence MSDN's own examples use:
// InitializeUnicastIpAddressEntry to fill every field CreateUnicastIpAddressEntry
// needs that this call does not set explicitly, then the address and prefix
// length, then the create; then, only if a caller actually asked for an MTU,
// GetIpInterfaceEntry followed by SetIpInterfaceEntry — for BOTH address
// families, see setOtherFamilyMTU; and finally the administrative up
// scdarwin gets by passing `up` to ifconfig, see bringUp. Skipping
// InitializeUnicastIpAddressEntry is not a shortcut — see its wrapper in
// iphlp.go for why a zeroed row fails ERROR_INVALID_PARAMETER on fields this
// call never touches.
func (c ifaceCtl) Configure(_ context.Context, iface string, cfg sysport.IfaceConfig) error {
	ifIndex, err := ifaceIndex(iface)
	if err != nil {
		return err
	}

	var row windows.MibUnicastIpAddressRow
	InitializeUnicastIpAddressEntry(&row)
	if err := setUnicastRow(&row, cfg, ifIndex); err != nil {
		return err
	}
	if err := CreateUnicastIpAddressEntry(&row); err != nil {
		// Unlike routeCtl.Add, ERROR_OBJECT_ALREADY_EXISTS is not given special
		// handling here. A duplicate route can belong to a coexisting VPN — see
		// route.go's comment on why that case must not be read as success — but
		// this address lives on a tunnel adapter dpb itself opened and holds the
		// handle to; nothing else on the machine assigns addresses to it, so a
		// duplicate here can only be dpb's own unfinished previous run, and
		// reporting it as a plain error (rather than inventing a second meaning
		// for the same code) is enough: Apply's caller decides what to do with
		// any error the same way regardless.
		return fmt.Errorf("netstate: add address %s to %s: %w", cfg.Local, iface, err)
	}

	if cfg.MTU > 0 {
		// row.Address already carries the family setUnicastRow wrote from
		// cfg.Local; reusing it means Configure never has to parse cfg.Local a
		// second time to know which MIB_IPINTERFACE_ROW (v4's or v6's) to ask
		// for.
		family := (*windows.RawSockaddrInet)(unsafe.Pointer(&row.Address)).Family
		if err := setInterfaceMTU(ifIndex, family, cfg.MTU); err != nil {
			return err
		}
		c.setOtherFamilyMTU(ifIndex, iface, family, cfg.MTU)
	}
	c.bringUp(ifIndex, iface)
	return nil
}

// setOtherFamilyMTU sets the SAME MTU on the address family cfg.Local is not,
// and never fails the Configure over it.
//
// # Why the other family is set at all
//
// An interface has TWO MIB_IPINTERFACE_ROW rows, one per family, each with its
// own NlMtu — so setting the MTU "for iface" the way scdarwin's single
// `ifconfig ... mtu` call does takes two calls here, not one. What decides the
// question is not tidiness, it is what the verifier reads:
// internal/netstate/op_iface.go's Verify compares against net.Interface.MTU,
// and $GOROOT/src/net/interface_windows.go fills that from
// IP_ADAPTER_ADDRESSES.Mtu — ONE number for the whole adapter, with nothing in
// its MSDN description saying which family's row it came from. A v6 config
// that set only the v6 NlMtu could therefore be verified against a number
// Windows took from the v4 row and fail for a reason no log would explain.
// Setting both makes the two rows agree, so whichever one Mtu is drawn from is
// the number Verify wants.
//
// # Why a failure here is logged, not returned
//
// The other family may simply not be there: an adapter with IPv6 unbound has
// no v6 MIB_IPINTERFACE_ROW and GetIpInterfaceEntry answers ERROR_NOT_FOUND.
// That is a normal machine, not a broken Configure, and refusing to bring the
// tunnel up over it would be a regression invented by this fix. The family the
// caller actually asked for is set above and its failure IS returned.
func (c ifaceCtl) setOtherFamilyMTU(ifIndex uint32, iface string, family uint16, mtu int) {
	other := uint16(windows.AF_INET6)
	if family == windows.AF_INET6 {
		other = windows.AF_INET
	}
	if err := setInterfaceMTU(ifIndex, other, mtu); err != nil {
		c.p.env().logf("netstate: set MTU %d on %s for address family %d: %v "+
			"(the configured family is set; this one may not be bound)", mtu, iface, other, err)
	}
}

// bringUp asks for iface's administrative status to be UP, and never fails the
// Configure over it.
//
// scdarwin passes `up` to ifconfig in the same call that sets the address, and
// internal/netstate/op_iface.go's Verify requires net.FlagUp — which
// $GOROOT/src/net/interface_windows.go derives from
// IP_ADAPTER_ADDRESSES.OperStatus == IfOperStatusUp. Nothing above this file
// brings the adapter up, so without this Configure has no step that
// corresponds to the `up` macOS gets.
//
// BELT AND BRACES, PENDING A REAL MACHINE. A Wintun-class adapter is widely
// expected to report media-connected — and therefore IfOperStatusUp — from the
// moment its session is started by whoever opened it, which would make this a
// no-op on every machine dpb actually runs on. That expectation could not be
// established from documentation, and the cost of the two possible mistakes is
// wildly asymmetric: a redundant call costs one syscall, while a missing one
// costs a tunnel that fails Verify with "interface is not up" and no obvious
// cause. So it is issued, and its failure is LOGGED rather than returned,
// because op_iface.go's Verify is the honest judge of whether the adapter is
// actually up — a judgement this call cannot improve on and must not
// pre-empt. ADMIN status is also not the same thing as OPER status: MSDN
// documents SetIfEntry as setting the former, and only the latter reaches
// net.FlagUp, which is the other half of why this cannot be treated as
// authoritative.
//
// Unconfigure has no matching "down", deliberately, for the reason its own
// doc comment gives: the adapter belongs to whoever holds its handle.
func (c ifaceCtl) bringUp(ifIndex uint32, iface string) {
	// MSDN's read-modify-write for this API: GetIfEntry to fill the row,
	// change dwAdminStatus, SetIfEntry. Only Index has to be set going in.
	row := windows.MibIfRow{Index: ifIndex}
	if err := windows.GetIfEntry(&row); err != nil {
		c.p.env().logf("netstate: read interface %s to bring it up: %v "+
			"(the interface read in Verify decides)", iface, err)
		return
	}
	if row.AdminStatus == ifAdminStatusUp {
		return
	}
	row.AdminStatus = ifAdminStatusUp
	if err := SetIfEntry(&row); err != nil {
		c.p.env().logf("netstate: bring %s up: %v (the interface read in Verify decides)", iface, err)
	}
}

// ifAdminStatusUp is MIB_IF_ADMIN_STATUS_UP from ifmib.h, which
// golang.org/x/sys/windows does not declare. It is the value MSDN names for
// MIB_IFROW.dwAdminStatus in SetIfEntry's own documentation; the siblings are
// MIB_IF_ADMIN_STATUS_DOWN (2) and MIB_IF_ADMIN_STATUS_TESTING (3), neither of
// which this package has any reason to set.
const ifAdminStatusUp = 1

// Unconfigure removes the address Configure added, through
// DeleteUnicastIpAddressEntry. It deliberately does NOT bring the interface
// down or touch its MTU, matching scdarwin: a tunnel adapter belongs to
// whoever holds its handle and vanishes when they close it, so downing
// anything else here would be catastrophic for a caller that still owns it.
//
// It also does not call InitializeUnicastIpAddressEntry: MSDN documents
// DeleteUnicastIpAddressEntry as matching a row by its Address and interface
// alone, and this file's own tests pin that OnLinkPrefixLength (the one other
// field setUnicastRow sets) makes no difference to that match.
//
// An interface that has already vanished — the device closed and the whole
// adapter gone — makes ifaceIndex fail, which is reported as a plain error
// here. That is the same shape as scdarwin's ifconfig saying "does not
// exist": netstate's ifconfigOp.Revert (internal/netstate/op_iface.go) already
// logs whatever this returns and moves on regardless, leaving the kernel read
// in VerifyReverted to decide whether the revert actually succeeded. Nothing
// platform-specific is needed here to get that behaviour.
func (c ifaceCtl) Unconfigure(_ context.Context, iface string, cfg sysport.IfaceConfig) error {
	ifIndex, err := ifaceIndex(iface)
	if err != nil {
		return err
	}
	var row windows.MibUnicastIpAddressRow
	if err := setUnicastRow(&row, cfg, ifIndex); err != nil {
		return err
	}
	if err := DeleteUnicastIpAddressEntry(&row); err != nil {
		return fmt.Errorf("netstate: remove address %s from %s: %w", cfg.Local, iface, err)
	}
	return nil
}

// Addrs reads iface's unicast addresses back through GetAdaptersAddresses.
// See ifaceCtl's own doc comment for why that is a different call family from
// Configure and Unconfigure, and therefore a genuine verifier.
//
// An interface findAdapter cannot find carries no addresses, matching
// scdarwin: a tunnel adapter that has already gone away with the file handle
// that owned it answers with (nil, nil) — the strongest revert there is — not
// an error.
func (c ifaceCtl) Addrs(_ context.Context, iface string) ([]netip.Addr, error) {
	aas, err := adapterAddresses()
	if err != nil {
		return nil, err
	}
	aa, ok := findAdapter(aas, iface)
	if !ok {
		return nil, nil
	}
	return unicastAddrsOf(aa), nil
}

// setUnicastRow writes cfg's Local address, ifIndex, and the decided
// OnLinkPrefixLength onto row. It is pure — no syscall, no I/O — so it is the
// one part of Configure and Unconfigure a table-driven test can pin without a
// Windows host, the same role routeRow plays for RouteController in route.go.
//
// It touches exactly three fields and nothing else. On Configure, row has
// already been through InitializeUnicastIpAddressEntry, which fills every
// OTHER field CreateUnicastIpAddressEntry needs (PrefixOrigin, SuffixOrigin,
// the lifetimes, DadState, ScopeId, CreationTimeStamp); on Unconfigure,
// DeleteUnicastIpAddressEntry does not read those fields at all, so a
// zero-valued row is fine there too. Either way, the order this function runs
// in relative to InitializeUnicastIpAddressEntry does not matter: the two
// touch disjoint fields.
//
// # What Peer means here, and why leaving it unread is still correct
//
// On macOS a utun is a genuine BSD point-to-point interface:
// `ifconfig utun4 inet 10.255.0.1 10.255.0.2` both names the peer AND creates
// a /32 interface route to it in the same call — see scdarwin's
// configureArgs. MIB_UNICASTIPADDRESS_ROW has no equivalent member. The
// adapters dpb opens on Windows (Wintun-class) are ordinary Layer-3 network
// adapters, not PPP/RAS links, and the unicast-address API that configures
// them was never given a peer/destination field to carry one —
// OnLinkPrefixLength is the only sizing knob it offers, and it describes a
// SUBNET, not a single endpoint.
//
// cfg.Peer is therefore read NOWHERE in this file, on purpose, and the
// consequence is contained rather than silent: the only reason a macOS utun
// needs a peer at all is so ifconfig's point-to-point mode can install a /32
// interface route to that one address without a prefix length. Setting
// OnLinkPrefixLength to 32 for an IPv4 local address reproduces exactly that
// outcome by a different route — "this address, and nothing else, is
// on-link" — which is the same reachability statement a p2p /32 gives macOS,
// expressed as a prefix length instead of a named peer. Every destination the
// tunnel must actually reach, the configured peer included, gets there
// through routeCtl's own interface routes (route.go) on both platforms; it
// was never reachability THROUGH this address's own on-link scope. If a
// caller ever needed the peer's exact address recorded ON the interface
// itself (not merely reachable through it), MIB_UNICASTIPADDRESS_ROW cannot
// provide that on any adapter type dpb uses, and no amount of clever field
// mapping changes that.
//
// v6 gets a flat 64 regardless of Peer (which tunfe never sets for a v6
// config — see internal/front/tunfe/stack.go) for the same reason scdarwin
// hardcodes "prefixlen 64": IfaceConfig carries no prefix-length field at
// all, and 64 is the value already chosen for macOS, so this keeps the two
// platforms' on-link semantics identical instead of inventing a second answer
// nothing asked for.
func setUnicastRow(row *windows.MibUnicastIpAddressRow, cfg sysport.IfaceConfig, ifIndex uint32) error {
	addr, err := netip.ParseAddr(cfg.Local)
	if err != nil {
		return fmt.Errorf("netstate: interface address %q: %w", cfg.Local, err)
	}
	// row.Address is declared RawSockaddrInet6 (x/sys), which is the same 28
	// bytes as RawSockaddrInet — see rib.go's sockaddrAddr for the layout this
	// package already relies on. Reinterpreting it is the same unsafe
	// conversion x/sys/windows' own doc comment on RawSockaddrInet prescribes,
	// not a hand-copied struct.
	setSockaddr((*windows.RawSockaddrInet)(unsafe.Pointer(&row.Address)), addr, 0)
	row.InterfaceIndex = ifIndex
	row.OnLinkPrefixLength = onLinkPrefixLength(addr)
	return nil
}

// onLinkPrefixLength decides MIB_UNICASTIPADDRESS_ROW.OnLinkPrefixLength for a
// local address. See setUnicastRow's doc comment for why 32 stands in for a
// v4 point-to-point peer, and why v6 matches scdarwin's literal 64.
func onLinkPrefixLength(addr netip.Addr) uint8 {
	if addr.Is4() {
		return 32
	}
	return 64
}

// setInterfaceMTU sets NlMtu on the interface at ifIndex for family.
// SetIpInterfaceEntry's own MSDN contract requires the row be filled by
// GetIpInterfaceEntry first — "the caller needs to first call the
// GetIpInterfaceEntry ... to get the current values ... and then set the ...
// members ... that need to change" (quoted in full on the wrapper in
// iphlp.go) — so a zeroed row here would report ERROR_INVALID_PARAMETER on
// fields this call is not trying to change at all, exactly like Initialize is
// required before CreateUnicastIpAddressEntry above.
//
// family is required in addition to the interface index because a single
// interface has TWO MIB_IPINTERFACE_ROW rows, one per address family; nothing
// else in the row says which is meant (see GetIpInterfaceEntry's wrapper).
func setInterfaceMTU(ifIndex uint32, family uint16, mtu int) error {
	row := windows.MibIpInterfaceRow{Family: family, InterfaceIndex: ifIndex}
	if err := GetIpInterfaceEntry(&row); err != nil {
		return fmt.Errorf("netstate: read interface %d (family %d) to set its MTU: %w", ifIndex, family, err)
	}
	applyMTU(&row, mtu)
	if err := SetIpInterfaceEntry(&row); err != nil {
		return fmt.Errorf("netstate: set MTU %d on interface %d: %w", mtu, ifIndex, err)
	}
	return nil
}

// applyMTU sets NlMtu and nothing else. It is split out of setInterfaceMTU,
// which cannot run without a Windows host (GetIpInterfaceEntry is a real
// syscall), so that the one thing this package controls about the row it
// just read back — which field changes — is still pinned by a test.
func applyMTU(row *windows.MibIpInterfaceRow, mtu int) {
	row.NlMtu = uint32(mtu)
}

// adaptersAddressesFlags skips everything Addrs never reads. MSDN documents
// each SKIP flag as removing exactly one linked list from the returned
// IP_ADAPTER_ADDRESSES, which is real work GetAdaptersAddresses would
// otherwise do (and real buffer it would otherwise need) for lists this file
// never walks. GAA_FLAG_SKIP_FRIENDLY_NAME is deliberately NOT set: Addrs
// matches an adapter by FriendlyName, the same field net.Interfaces uses (see
// rib.go's interfaceLister comment) — asking the kernel to skip resolving it
// would break that match for every interface, not just tunnels.
const adaptersAddressesFlags = windows.GAA_FLAG_SKIP_ANYCAST |
	windows.GAA_FLAG_SKIP_MULTICAST |
	windows.GAA_FLAG_SKIP_DNS_SERVER

// adapterAddresses reads the whole adapter list through GetAdaptersAddresses.
//
// MSDN recommends starting with a 15KB buffer and growing it if the call
// answers ERROR_BUFFER_OVERFLOW, filling SizePointer with the size actually
// needed; this loop follows that contract exactly, the same way
// $GOROOT/src/net/interface_windows.go's adapterAddresses does for
// net.Interfaces() on Windows — verified by reading that file before writing
// this one, per Plan 2's rule about Windows APIs that compile, look right and
// always fail. The `l <= uint32(len(b))` guard matches stdlib's own: MSDN does
// not promise SizePointer grows on every failure, and retrying with a
// buffer that is not actually bigger would loop forever instead of failing.
func adapterAddresses() ([]*windows.IpAdapterAddresses, error) {
	var b []byte
	l := uint32(15000)
	for {
		b = make([]byte, l)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, adaptersAddressesFlags, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &l)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || l <= uint32(len(b)) {
			return nil, fmt.Errorf("netstate: enumerate adapters: %w", err)
		}
	}
	if l == 0 {
		return nil, nil
	}

	// The returned buffer is a linked list of IP_ADAPTER_ADDRESSES headed at
	// its first byte; walking .Next is GetAdaptersAddresses' own documented
	// shape, not an assumption this file invents.
	var aas []*windows.IpAdapterAddresses
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); aa != nil; aa = aa.Next {
		aas = append(aas, aa)
	}
	return aas, nil
}

// findAdapter finds the adapter named iface, matching on FriendlyName — the
// same field net.Interfaces() fills Interface.Name from on Windows (see
// rib.go's interfaceLister comment), so a name that resolves through
// net.Interfaces (as ifaceIndex uses for Configure/Unconfigure) resolves here
// too.
func findAdapter(aas []*windows.IpAdapterAddresses, iface string) (*windows.IpAdapterAddresses, bool) {
	for _, aa := range aas {
		if windows.UTF16PtrToString(aa.FriendlyName) == iface {
			return aa, true
		}
	}
	return nil, false
}

// unicastAddrsOf reads every address off aa's FirstUnicastAddress list.
//
// Each entry's Address field is a SocketAddress: x/sys/windows' wrapper for a
// SOCKADDR_INET held behind a *syscall.RawSockaddrAny — the stdlib's generic,
// oversized sockaddr storage, guaranteed at least as large as any concrete
// sockaddr GetAdaptersAddresses can report. Its first 28 bytes are
// byte-for-byte the SOCKADDR_IN / SOCKADDR_IN6 layout windows.RawSockaddrInet
// already documents itself convertible to (see rib.go's sockaddrAddr and the
// x/sys/windows doc comment it quotes), so this reuses sockaddrAddr rather
// than inventing a second decoder with its own chance to get an offset wrong.
func unicastAddrsOf(aa *windows.IpAdapterAddresses) []netip.Addr {
	var out []netip.Addr
	for u := aa.FirstUnicastAddress; u != nil; u = u.Next {
		if u.Address.Sockaddr == nil {
			continue
		}
		sa := (*windows.RawSockaddrInet)(unsafe.Pointer(u.Address.Sockaddr))
		if a, ok := sockaddrAddr(sa); ok {
			out = append(out, a)
		}
	}
	return out
}
