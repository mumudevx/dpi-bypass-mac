//go:build windows

package scwindows

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/mumudevx/dpb/internal/sysport"
)

// dnsCtl is scwindows's DNSController.
//
// Set and Clear shell out to netsh(1) and, per windows.go's Contract 1,
// consult ONLY its EXIT STATUS — never a word of its printed text. netsh
// renders every sentence it prints in the system UI language, and unlike a
// child process on macOS there is no LC_ALL=C a parent can force onto it:
// Windows has no mechanism for overriding another process's (let alone one
// specific thread's) UI language from outside it. On a Turkish Windows
// install every string netsh prints is Turkish, and a parser written against
// the English text would read a live, correctly-configured machine as having
// "no DNS servers" set. This project has already paid for exactly that class
// of bug once, on the other platform: `ps` reordering its own column headers
// under LANG=tr_TR made a live dpb process look dead to a table parser that
// assumed English column names. The fix there, and here, is the same one:
// never read the tool's text, only whether it exited zero. sysport.Result's
// own liar table (runner.go) has no "netsh" entry, so Result.Error() already
// reduces to exactly that for every call in this file — see Set's and
// Clear's doc comments for why that must stay true.
//
// Configured (capture) and Live (verify) both read the SAME observer,
// GetAdaptersAddresses, rather than mirroring proxy.go's registry/WinHTTP
// split. That is not a weaker contract: Contract 1 only requires that
// whatever verifies a Set is not the thing that wrote it, and here the writer
// is netsh — a command-line tool Contract 1 already forbids reading text
// from for ANY purpose, capture included, because netsh's own
// `show dnsservers` is exactly as localized as `set dnsservers`. So both
// readers go through the one subsystem that is not netsh: the same
// separation scdarwin's networksetup-writes/scutil-reads split gives DNS on
// macOS, just with both of THIS package's readers landing on the API side of
// it instead of splitting one CLI reader between two purposes.
//
// Configured consults ONE more thing Live does not: the registry value that
// says whether a family's resolvers were configured statically or handed out
// by DHCP. GetAdaptersAddresses cannot answer that and a capture is wrong
// without it — see Configured and dnsIsStatic, including why a registry read
// is not the localized-text read Contract 1 forbids.
type dnsCtl struct{ p *port }

var _ sysport.DNSController = dnsCtl{}

// dnsFamilies is netsh's own vocabulary: Windows keeps IPv4 and IPv6 DNS
// configuration as two separate `netsh interface <family>` contexts with no
// combined verb, unlike macOS's single `networksetup -setdnsservers`.
var dnsFamilies = []string{"ipv4", "ipv6"}

// Set makes servers svc's authoritative DNS server list, replacing whatever
// that protocol had.
//
// It shells out to `netsh interface ipv4|ipv6 set/add dnsservers`; see this
// type's doc comment for why only netsh's exit status is ever consulted.
//
// servers is split by address family first (splitDNSServersByFamily) because
// netsh has no verb that accepts both in one call. Today's only caller
// (cliapp/tunrun.go's tunResolverList) never mixes them — it filters to IPv4
// only — but sysport.DNSController's contract does not promise that, so this
// does not assume it either.
//
// Within a family, `netsh ... set dnsservers` accepts exactly one
// [address=] per its own documented syntax
// ("[[address=]<IP address>|none]", singular); every server after the first
// is installed with a separate `netsh ... add dnsservers` call, indexed from
// 2 so the `set`-installed primary keeps index 1. `validate=no` is passed on
// every call: the alternative, netsh's own default (validate=yes), has netsh
// itself try to CONTACT each address before accepting it — turning a local
// configuration change into a network operation with its own timeout — and
// the first address Set is ever asked to install is dpb's own loopback
// resolver, which races the datapath's own start() (see
// internal/front/tunfe/stack.go's BringUp, which calls this after start).
// Reading a validation failure's text to tell "not up yet" from "genuinely
// broken" apart is exactly what Contract 1 forbids, so the probe that would
// need distinguishing is skipped instead.
func (c dnsCtl) Set(ctx context.Context, svc string, servers []string) error {
	if len(servers) == 0 {
		return fmt.Errorf("netstate: no DNS servers given for %s", svc)
	}
	v4, v6, err := splitDNSServersByFamily(servers)
	if err != nil {
		return err
	}
	if len(v4) > 0 {
		if err := c.setFamilyServers(ctx, "ipv4", svc, v4); err != nil {
			return err
		}
	}
	if len(v6) > 0 {
		if err := c.setFamilyServers(ctx, "ipv6", svc, v6); err != nil {
			return err
		}
	}
	return nil
}

// setFamilyServers installs servers (all one family, non-empty) as svc's
// resolver list for that protocol.
func (c dnsCtl) setFamilyServers(ctx context.Context, family, svc string, servers []string) error {
	args := []string{
		"interface", family, "set", "dnsservers",
		"name=" + svc, "source=static", "address=" + servers[0], "register=primary", "validate=no",
	}
	if err := c.p.run.Run(ctx, "netsh", args...).Error(); err != nil {
		return fmt.Errorf("netstate: netsh interface %s set dnsservers name=%s: %w", family, svc, err)
	}
	for i, s := range servers[1:] {
		addArgs := []string{
			"interface", family, "add", "dnsservers",
			"name=" + svc, "address=" + s, "index=" + strconv.Itoa(i+2), "validate=no",
		}
		if err := c.p.run.Run(ctx, "netsh", addArgs...).Error(); err != nil {
			return fmt.Errorf("netstate: netsh interface %s add dnsservers name=%s: %w", family, svc, err)
		}
	}
	return nil
}

// Clear restores svc to DHCP-supplied resolvers on both protocols, the
// Windows analogue of `networksetup -setdnsservers <svc> Empty`.
//
// Both `ipv4` and `ipv6` are always attempted, even though Set only ever
// touches the family(ies) actually present in its server list: this
// controller does not track, between calls, which protocol a previous Set
// used, and `netsh ... set dnsservers ... source=dhcp` is idempotent against
// a protocol that was already DHCP-sourced — running it there is a no-op,
// not a destructive one, the same way networksetup's Empty is harmless
// against a service that already had no static resolvers.
//
// Both calls are attempted even if the first fails, and the FIRST error is
// what is returned — the same fail() pattern proxyCtl.Restore uses and for
// the same reason: getting one protocol back onto DHCP is strictly better
// than stopping after the first failure and leaving the other still
// captured. This is the one place in this file two netsh calls can fail
// independently without either one being conditional on the other's result.
func (c dnsCtl) Clear(ctx context.Context, svc string) error {
	var firstErr error
	for _, family := range dnsFamilies {
		args := []string{"interface", family, "set", "dnsservers", "name=" + svc, "source=dhcp"}
		if err := c.p.run.Run(ctx, "netsh", args...).Error(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("netstate: netsh interface %s set dnsservers name=%s source=dhcp: %w", family, svc, err)
		}
	}
	return firstErr
}

// Configured reads svc's currently-configured DNS server list through
// GetAdaptersAddresses — the CAPTURE read; see this type's doc comment for
// why that is the same subsystem Live reads rather than a mirror of the
// netsh writer. It is for capture, never verification.
//
// An svc that does not resolve to an adapter is reported as an error, not as
// an empty list — unlike Live below. This is the capture that
// internal/netstate/op_dns.go's dnsOp.prepare records as "what has to be put
// back", and a name that resolves to nothing is a wiring bug in whatever
// built the service list (Facts.Services, in the real call path), not a
// legitimate "nothing configured" answer; silently returning (nil, nil)
// would hide that bug behind a capture that looks like an empty resolver
// list and let a later Set/Verify pair fail confusingly instead. Compare
// scdarwin's dnsCtl.Configured, where the equivalent mistake surfaces as
// networksetup's own "is not a recognized network service" failure via
// runner.go's liar table; there is no netsh call here to fail on our behalf,
// so this function fails the same way explicitly.
//
// # A DHCP adapter captures as EMPTY, and it has to
//
// GetAdaptersAddresses reports the EFFECTIVE resolver list, which is populated
// for a DHCP adapter exactly as it is for a static one — there is no flag on
// IP_ADAPTER_ADDRESSES saying where the list came from. Handing that list back
// as "what has to be put back" is what turns a clean revert into permanent
// damage: internal/netstate/op_dns.go's Revert branches on `len(prev) > 0`,
// calling Set (source=static) for a non-empty capture and Clear (source=dhcp)
// for an empty one. If Configured is never empty, Clear can never run, and one
// dpb run on an ordinary DHCP laptop PINS the adapter to whatever resolvers it
// happened to have — plus Windows' own fec0:0:0:ffff::1/2/3 site-local
// defaults for v6. The user carries the laptop to another network and nothing
// resolves, forever, after a teardown that verified clean.
//
// scdarwin cannot hit this because `networksetup -getdnsservers` answers
// "There aren't any DNS Servers set" for a DHCP service, so prev is empty and
// Clear runs. The platforms genuinely differ, and Windows is made to agree
// here rather than in op_dns.go, because "is this list DHCP-sourced" is a
// platform question with a platform answer.
//
// So each family's servers are kept only when that family is STATICALLY
// configured; see dnsIsStatic for the registry value that says so and why
// reading it does not violate this package's no-netsh-text contract.
func (c dnsCtl) Configured(_ context.Context, svc string) ([]string, error) {
	aas, err := dnsAdapterAddresses()
	if err != nil {
		return nil, err
	}
	aa, ok := findAdapter(aas, svc)
	if !ok {
		return nil, fmt.Errorf("netstate: interface %q not found for a DNS capture", svc)
	}

	// MSDN, IP_ADAPTER_ADDRESSES: AdapterName is "the name of the adapter",
	// and it is the adapter's GUID in the {…} form the Tcpip Interfaces keys
	// are named with — an ANSI string, unlike the wide FriendlyName beside it.
	guid := windows.BytePtrToString(aa.AdapterName)
	v4Static, err := dnsIsStatic(tcpip4InterfacesKey, guid)
	if err != nil {
		return nil, err
	}
	v6Static, err := dnsIsStatic(tcpip6InterfacesKey, guid)
	if err != nil {
		return nil, err
	}
	return dnsServerAddrsOfFamilies(aa, v4Static, v6Static), nil
}

// Where Windows records a STATICALLY configured resolver list, per address
// family. Tcpip is IPv4 and Tcpip6 is IPv6; each has one subkey per adapter,
// named with the adapter's GUID.
//
// # This is a registry read, not tool text, and that distinction is the point
//
// It LOOKS like the thing windows.go's Contract 1 forbids — asking the system
// where a setting came from — and it is not. Contract 1 forbids PARSING THE
// TEXT A LOCALIZED TOOL PRINTS: `netsh interface ipv4 show dnsservers` renders
// "Statically Configured DNS Servers" in the system UI language, so a parser
// written against the English wording reads a Turkish machine wrongly. A
// registry value name is not localized. NameServer is NameServer on every
// install of Windows in every language, and its CONTENT is a machine-readable
// list of addresses, not a sentence. This is the same class of read as
// proxy.go's Internet Settings values, which Contract 1 already blesses as the
// capture side of the proxy controller.
//
// The contract on the value itself: NameServer holds the resolvers an
// administrator set explicitly, and is absent or empty when the adapter takes
// its resolvers from DHCP — which stores them separately, in DhcpNameServer.
// `netsh ... set dnsservers source=static` writes NameServer and
// `source=dhcp` clears it, which is precisely why dnsCtl.Clear restoring DHCP
// makes this read answer "not static" again afterwards.
const (
	tcpip4InterfacesKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
	tcpip6InterfacesKey = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`
	valNameServer       = "NameServer"
)

// dnsIsStatic reports whether the adapter with this GUID has statically
// configured resolvers under hive.
//
// A missing key or a missing value is "not static" and NOT an error: an
// adapter with no Tcpip6 subkey has no IPv6 stack bound, and a subkey with no
// NameServer value has never had a static list written — both are the
// registry's own POSITIVE statement that there is nothing here, the same
// reading proxy.go's regString and env.go's Get give registry.ErrNotExist.
//
// Any OTHER failure is returned. A capture that cannot be read must fail
// loudly rather than default to "DHCP": defaulting would make a genuinely
// static machine take Revert's Clear branch and lose the administrator's
// resolver list, which is the mirror image of the bug this function exists to
// fix.
func dnsIsStatic(hive, guid string) (bool, error) {
	if guid == "" {
		return false, fmt.Errorf("netstate: the adapter for a DNS capture reports no GUID")
	}
	path := hive + `\` + guid
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("netstate: open HKLM\\%s: %w", path, err)
	}
	defer key.Close()

	v, _, err := key.GetStringValue(valNameServer)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("netstate: read HKLM\\%s\\%s: %w", path, valNameServer, err)
	}
	// Some Windows versions leave an EMPTY NameServer behind when an adapter
	// is switched back to DHCP rather than deleting the value, so emptiness
	// has to mean the same thing as absence.
	return strings.TrimSpace(v) != "", nil
}

// Live reads the resolvers the system's DEFAULT-ROUTE interface is
// configured with — the VERIFIER internal/netstate/op_dns.go's Verify and
// VerifyReverted call.
//
// sysport.DNSController.Live takes no service argument: on macOS that maps
// onto `scutil --dns`'s first unscoped resolver, which is whichever network
// service is primary. Windows keeps DNS configuration per adapter with no
// single "primary resolver" API of its own, so the Windows analogue of "the
// service everything else is using" is the interface c.p.rib — windows.go's
// RIBReader, the SAME independent route verifier route.go's RouteController
// uses — reports for the default route. That interface is, in the real call
// path, the same one Set was told to configure (cliapp/tunrun.go passes the
// uplink's own Facts.Services), so this is not a second guess at which
// adapter matters; it is asking the kernel's own route selection to name it
// again, independently of whatever Set was told.
//
// A machine with no default route at all (no ok from Default) answers with
// no servers rather than an error: there is nothing this machine currently
// treats as "the" resolver, which is an honest "verify failed" for
// op_dns.go's hasPrefixList check to report, not a reason to fail Live
// itself. The same applies if the default-route interface has vanished
// between the route read and the adapter read — the same tolerance
// ifaceCtl.Addrs (iface.go) gives a tunnel adapter that closed out from under
// it.
func (c dnsCtl) Live(_ context.Context) ([]string, error) {
	def, ok, err := c.p.rib.Default()
	if err != nil {
		return nil, fmt.Errorf("netstate: find the default-route interface for a DNS verify: %w", err)
	}
	if !ok {
		return nil, nil
	}
	aas, err := dnsAdapterAddresses()
	if err != nil {
		return nil, err
	}
	aa, ok := findAdapter(aas, def.Iface)
	if !ok {
		return nil, nil
	}
	return dnsServerAddrsOf(aa), nil
}

// splitDNSServersByFamily separates servers into v4 and v6 address lists,
// preserving each family's relative order, and normalises every address to
// netip.Addr's canonical string form so that what Set sends netsh, and what
// Configured/Live later read back out of the adapter, are directly
// comparable.
//
// A 4-in-6 address (Is4In6, e.g. "::ffff:1.2.3.4") is Unmap()ped before its
// String() is taken, not just routed to the v4 list: netip.Addr.String()
// renders an UN-unmapped 4-in-6 value as "::ffff:1.2.3.4", and handing that
// to `netsh interface ipv4`, which expects dotted-decimal, would fail —
// silently as far as this package's own rules go, since Contract 1 forbids
// reading netsh's text to find out why. Unmap is a no-op on a plain v4
// address, so this is safe to apply unconditionally in the v4 branch.
func splitDNSServersByFamily(servers []string) (v4, v6 []string, err error) {
	for _, s := range servers {
		addr, perr := netip.ParseAddr(s)
		if perr != nil {
			return nil, nil, fmt.Errorf("netstate: DNS server %q is not an IP address: %w", s, perr)
		}
		if addr.Is4() || addr.Is4In6() {
			v4 = append(v4, addr.Unmap().String())
		} else {
			v6 = append(v6, addr.String())
		}
	}
	return v4, v6, nil
}

// dnsAdaptersAddressesFlags mirrors iface.go's own adaptersAddressesFlags,
// skipping every linked list this file never walks (unicast, anycast,
// multicast) — WITH ONE DELIBERATE DIFFERENCE: it does NOT set
// GAA_FLAG_SKIP_DNS_SERVER. That flag is exactly why this file cannot reuse
// iface.go's adapterAddresses(): iface.go sets it (it never reads DNS server
// data), which would make every server this file exists to read invisible.
// GAA_FLAG_SKIP_FRIENDLY_NAME stays unset for the reason iface.go's own
// comment gives: findAdapter (shared with iface.go) matches on FriendlyName.
const dnsAdaptersAddressesFlags = windows.GAA_FLAG_SKIP_UNICAST |
	windows.GAA_FLAG_SKIP_ANYCAST |
	windows.GAA_FLAG_SKIP_MULTICAST

// dnsAdapterAddresses reads the whole adapter list through
// GetAdaptersAddresses, with DNS server addresses included.
//
// The buffer-growth loop is otherwise identical to iface.go's
// adapterAddresses, which cannot be reused here for the flags reason given on
// dnsAdaptersAddressesFlags above: MSDN's own documented contract is to start
// with a 15KB buffer and retry on ERROR_BUFFER_OVERFLOW with SizePointer's
// answer, the same contract $GOROOT/src/net/interface_windows.go's
// adapterAddresses follows for net.Interfaces() on Windows — verified by
// reading that file before writing this one, per Plan 2's rule about Windows
// APIs that compile, look right and always fail. The `l <= uint32(len(b))`
// guard matches stdlib's own, for the same reason iface.go's copy gives: MSDN
// does not promise SizePointer grows on every failure, and retrying with a
// buffer that is not actually bigger would loop forever instead of failing.
func dnsAdapterAddresses() ([]*windows.IpAdapterAddresses, error) {
	var b []byte
	l := uint32(15000)
	for {
		b = make([]byte, l)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, dnsAdaptersAddressesFlags, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &l)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || l <= uint32(len(b)) {
			return nil, fmt.Errorf("netstate: enumerate adapters for DNS: %w", err)
		}
	}
	if l == 0 {
		return nil, nil
	}

	var aas []*windows.IpAdapterAddresses
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); aa != nil; aa = aa.Next {
		aas = append(aas, aa)
	}
	return aas, nil
}

// dnsServerAddrsOf reads aa's whole DNS server list off FirstDnsServerAddress
// — the EFFECTIVE resolvers, whatever their origin. That is what Live wants:
// a verify asks whether the machine is actually using our resolver, not how it
// was told to.
//
// Each entry's Address field is a SocketAddress — the same
// *syscall.RawSockaddrAny-backed wrapper iface.go's unicastAddrsOf decodes
// for FirstUnicastAddress — so this reuses rib.go's sockaddrAddr rather than
// inventing a second decoder with its own chance to get an offset wrong.
func dnsServerAddrsOf(aa *windows.IpAdapterAddresses) []string {
	return dnsServerAddrsOfFamilies(aa, true, true)
}

// dnsServerAddrsOfFamilies is the same walk, keeping only the families the
// caller asks for. Configured uses it to drop a family whose resolvers came
// from DHCP; see Configured for why a DHCP family must capture as nothing at
// all rather than as its current addresses.
//
// A 4-in-6 address counts as v4, matching splitDNSServersByFamily's own
// reading — Set would send it to `netsh interface ipv4`, so a capture must not
// file it under v6 and strand it when only v6 is static.
func dnsServerAddrsOfFamilies(aa *windows.IpAdapterAddresses, v4, v6 bool) []string {
	var out []string
	for d := aa.FirstDnsServerAddress; d != nil; d = d.Next {
		if d.Address.Sockaddr == nil {
			continue
		}
		sa := (*windows.RawSockaddrInet)(unsafe.Pointer(d.Address.Sockaddr))
		a, ok := sockaddrAddr(sa)
		if !ok {
			continue
		}
		if a.Is4() || a.Is4In6() {
			if !v4 {
				continue
			}
		} else if !v6 {
			continue
		}
		out = append(out, a.String())
	}
	return out
}
