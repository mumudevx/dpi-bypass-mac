//go:build windows

package scwindows

import (
	"net/netip"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/mumudevx/dpb/internal/sysport"
)

// These tests can only run on a Windows host, and CI does not yet have one;
// see iphlp_test.go. GOOS=windows go vet compiles them and nothing more. They
// exist anyway for the same reason route_test.go's do: a wrong field mapping
// here does not fail to compile, it writes (or fails to remove) a wrong
// address on a real machine's tunnel adapter.

// asRowAddress reinterprets a SOCKADDR_INET built with route_test.go's
// sockaddrIn/sockaddrIn6 (typed windows.RawSockaddrInet there) as the
// windows.RawSockaddrInet6 x/sys declares MibUnicastIpAddressRow.Address to
// be. Both are the same 28-byte SOCKADDR_INET union — RawSockaddrInet6 is
// simply the other arm x/sys chose to name that field with — so this is the
// same unsafe conversion setUnicastRow itself performs, run in the test to
// build an expectation independent of the code under test.
func asRowAddress(t *testing.T, sa windows.RawSockaddrInet) windows.RawSockaddrInet6 {
	t.Helper()
	return *(*windows.RawSockaddrInet6)(unsafe.Pointer(&sa))
}

// TestSetUnicastRowMapsIfaceConfig pins IfaceConfig -> MIB_UNICASTIPADDRESS_ROW
// field for field, for both address families. Whole-struct comparison is
// deliberate, exactly as in route_test.go's TestRouteRowMapsEverySpecShape: a
// field nobody thought to assert is exactly the field that ends up wrong, and
// setUnicastRow's own contract is that it touches ONLY Address, InterfaceIndex
// and OnLinkPrefixLength — so starting from a zero row and comparing the whole
// struct also proves nothing else was touched.
func TestSetUnicastRowMapsIfaceConfig(t *testing.T) {
	const ifIndex = 9

	cases := []struct {
		name string
		cfg  sysport.IfaceConfig
		want windows.MibUnicastIpAddressRow
	}{
		{
			// The v4 point-to-point case. Peer is set, exactly as tunfe always
			// sets it for v4 (internal/front/tunfe/stack.go), and is read
			// nowhere — see setUnicastRow's doc comment for why OnLinkPrefixLength
			// 32 is the substitute.
			name: "v4 point-to-point address",
			cfg:  sysport.IfaceConfig{Local: "10.255.0.1", Peer: "10.255.0.2", MTU: 1500},
			want: windows.MibUnicastIpAddressRow{
				Address:            asRowAddress(t, sockaddrIn(t, "10.255.0.1")),
				InterfaceIndex:     ifIndex,
				OnLinkPrefixLength: 32,
			},
		},
		{
			// v6 carries no Peer — tunfe never sets one for it — and gets the
			// same 64 scdarwin hardcodes for `ifconfig ... prefixlen 64`.
			name: "v6 address",
			cfg:  sysport.IfaceConfig{Local: "2001:db8::1", MTU: 1500},
			want: windows.MibUnicastIpAddressRow{
				Address:            asRowAddress(t, sockaddrIn6(t, "2001:db8::1", 0)),
				InterfaceIndex:     ifIndex,
				OnLinkPrefixLength: 64,
			},
		},
		{
			// No MTU requested: setUnicastRow does not look at cfg.MTU at all,
			// only Configure does (to decide whether to call setInterfaceMTU).
			name: "no MTU requested still fills the address",
			cfg:  sysport.IfaceConfig{Local: "192.168.99.1", Peer: "192.168.99.2"},
			want: windows.MibUnicastIpAddressRow{
				Address:            asRowAddress(t, sockaddrIn(t, "192.168.99.1")),
				InterfaceIndex:     ifIndex,
				OnLinkPrefixLength: 32,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var row windows.MibUnicastIpAddressRow
			if err := setUnicastRow(&row, tc.cfg, ifIndex); err != nil {
				t.Fatalf("setUnicastRow(%+v): %v", tc.cfg, err)
			}
			if row != tc.want {
				t.Errorf("setUnicastRow(%+v) mismatch\n got %+v\nwant %+v", tc.cfg, row, tc.want)
			}
		})
	}
}

// TestSetUnicastRowDoesNotTouchOtherFields guards the claim in setUnicastRow's
// own doc comment: it sets exactly three fields. A row reaching Configure has
// already been through InitializeUnicastIpAddressEntry, and clobbering what
// that call filled in — by, say, a future rewrite using `*row =
// MibUnicastIpAddressRow{...}` instead of setting fields individually — would
// resurrect exactly the ERROR_INVALID_PARAMETER defect iphlp.go's own comment
// on InitializeUnicastIpAddressEntry warns about, just one layer further up.
func TestSetUnicastRowDoesNotTouchOtherFields(t *testing.T) {
	row := windows.MibUnicastIpAddressRow{
		PrefixOrigin:      7,
		SuffixOrigin:      8,
		ValidLifetime:     0xffffffff,
		PreferredLifetime: 0xffffffff,
		SkipAsSource:      1,
		DadState:          3,
		ScopeId:           5,
	}
	want := row
	if err := setUnicastRow(&row, sysport.IfaceConfig{Local: "10.0.0.1"}, 4); err != nil {
		t.Fatalf("setUnicastRow: %v", err)
	}
	if row.PrefixOrigin != want.PrefixOrigin || row.SuffixOrigin != want.SuffixOrigin ||
		row.ValidLifetime != want.ValidLifetime || row.PreferredLifetime != want.PreferredLifetime ||
		row.SkipAsSource != want.SkipAsSource || row.DadState != want.DadState || row.ScopeId != want.ScopeId {
		t.Errorf("setUnicastRow touched a field InitializeUnicastIpAddressEntry owns\n got %+v\nwant those fields unchanged from %+v", row, want)
	}
}

// TestSetUnicastRowRejectsAnUnparseableAddress: IfaceConfig.Local is a bare
// string, and netstate revives an ifconfigOp from a journal file
// (op_iface.go's reviveIfconfig) that could in principle hand back one that
// no longer parses. Failing loudly here beats writing a zeroed, AF_UNSPEC
// SOCKADDR_INET that CreateUnicastIpAddressEntry would reject anyway, for the
// same reason route.go's routeRow refuses instead of guessing.
func TestSetUnicastRowRejectsAnUnparseableAddress(t *testing.T) {
	var row windows.MibUnicastIpAddressRow
	if err := setUnicastRow(&row, sysport.IfaceConfig{Local: "not-an-address"}, 1); err == nil {
		t.Fatal("setUnicastRow accepted an unparseable Local address")
	}
}

// TestSetUnicastRowAddressRoundTrips walks a config through setUnicastRow (the
// writer) and straight back through sockaddrAddr (rib.go's reader, reused by
// unicastAddrsOf below), the same round trip TestScopedAgreesBetweenWriterAndReader
// makes for routes in rib_test.go. If the two ever disagreed about the
// SOCKADDR_INET layout, this is where it would show up.
func TestSetUnicastRowAddressRoundTrips(t *testing.T) {
	for _, want := range []string{"10.255.0.1", "2001:db8::1", "::"} {
		var row windows.MibUnicastIpAddressRow
		if err := setUnicastRow(&row, sysport.IfaceConfig{Local: want}, 3); err != nil {
			t.Fatalf("setUnicastRow(%s): %v", want, err)
		}
		got, ok := sockaddrAddr((*windows.RawSockaddrInet)(unsafe.Pointer(&row.Address)))
		if !ok {
			t.Fatalf("sockaddrAddr could not decode the row setUnicastRow just wrote for %s", want)
		}
		if got.String() != want {
			t.Errorf("round-tripped address = %v, want %v", got, want)
		}
	}
}

func TestOnLinkPrefixLength(t *testing.T) {
	if got := onLinkPrefixLength(netip.MustParseAddr("10.0.0.1")); got != 32 {
		t.Errorf("onLinkPrefixLength(v4) = %d, want 32", got)
	}
	if got := onLinkPrefixLength(netip.MustParseAddr("2001:db8::1")); got != 64 {
		t.Errorf("onLinkPrefixLength(v6) = %d, want 64", got)
	}
}

// TestApplyMTUTouchesOnlyNlMtu is the pure half of setInterfaceMTU:
// GetIpInterfaceEntry itself cannot run here, but the one thing this package
// controls about the row it reads back — which field changes before
// SetIpInterfaceEntry is called — is still pinned.
func TestApplyMTUTouchesOnlyNlMtu(t *testing.T) {
	row := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: 9, Metric: 42, Connected: 1}
	want := row
	applyMTU(&row, 1400)
	if row.NlMtu != 1400 {
		t.Errorf("NlMtu = %d, want 1400", row.NlMtu)
	}
	row.NlMtu = want.NlMtu // ignore the field applyMTU is meant to change
	if row != want {
		t.Errorf("applyMTU touched a field it should not have\n got %+v\nwant %+v", row, want)
	}
}

func utf16Ptr(t *testing.T, s string) *uint16 {
	t.Helper()
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		t.Fatalf("UTF16PtrFromString(%q): %v", s, err)
	}
	return p
}

// TestFindAdapterMatchesFriendlyName: Addrs matches an adapter by the same
// FriendlyName field net.Interfaces() uses to fill Interface.Name (see
// rib.go's interfaceLister comment), so a name Configure resolved through
// ifaceIndex must resolve here too.
func TestFindAdapterMatchesFriendlyName(t *testing.T) {
	wifi := utf16Ptr(t, "Wi-Fi")
	dpb0 := utf16Ptr(t, "dpb0")
	aas := []*windows.IpAdapterAddresses{
		{FriendlyName: wifi},
		{FriendlyName: dpb0},
	}
	got, ok := findAdapter(aas, "dpb0")
	if !ok || got.FriendlyName != dpb0 {
		t.Fatalf("findAdapter(dpb0): ok=%v got=%v", ok, got)
	}
	if _, ok := findAdapter(aas, "nope"); ok {
		t.Error("findAdapter matched a name that is not in the list")
	}
}

// rawAny reinterprets sa as the *syscall.RawSockaddrAny type
// windows.SocketAddress.Sockaddr is declared as, the same conversion
// unicastAddrsOf performs in the opposite direction. sa must outlive the
// returned pointer's use, which every caller below satisfies by keeping sa as
// a local for the duration of the test.
func rawAny(sa *windows.RawSockaddrInet) *syscall.RawSockaddrAny {
	return (*syscall.RawSockaddrAny)(unsafe.Pointer(sa))
}

// TestUnicastAddrsOfDecodesTheList builds the same linked-list shape
// GetAdaptersAddresses hands back — IpAdapterAddresses.FirstUnicastAddress, a
// chain of IpAdapterUnicastAddress — by hand, and checks unicastAddrsOf walks
// it and decodes each entry, skipping one it cannot express (AF_UNSPEC),
// mirroring routeEntryFrom's refusal of the same family in rib.go.
func TestUnicastAddrsOfDecodesTheList(t *testing.T) {
	v4 := sockaddrIn(t, "10.255.0.1")
	v6 := sockaddrIn6(t, "2001:db8::1", 0)
	var unspec windows.RawSockaddrInet // Family 0 == AF_UNSPEC; sockaddrAddr rejects it

	third := &windows.IpAdapterUnicastAddress{Address: windows.SocketAddress{Sockaddr: rawAny(&unspec)}}
	second := &windows.IpAdapterUnicastAddress{Address: windows.SocketAddress{Sockaddr: rawAny(&v6)}, Next: third}
	first := &windows.IpAdapterUnicastAddress{Address: windows.SocketAddress{Sockaddr: rawAny(&v4)}, Next: second}
	aa := &windows.IpAdapterAddresses{FirstUnicastAddress: first}

	got := unicastAddrsOf(aa)
	want := []netip.Addr{netip.MustParseAddr("10.255.0.1"), netip.MustParseAddr("2001:db8::1")}
	if len(got) != len(want) {
		t.Fatalf("unicastAddrsOf = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("unicastAddrsOf[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

// TestUnicastAddrsOfSkipsANilSockaddr: GetAdaptersAddresses' own docs do not
// promise every unicast entry carries a non-nil Sockaddr, and dereferencing
// one that is nil would panic rather than simply skip an address this file
// cannot read anyway.
func TestUnicastAddrsOfSkipsANilSockaddr(t *testing.T) {
	aa := &windows.IpAdapterAddresses{
		FirstUnicastAddress: &windows.IpAdapterUnicastAddress{Address: windows.SocketAddress{}},
	}
	if got := unicastAddrsOf(aa); len(got) != 0 {
		t.Errorf("unicastAddrsOf(nil Sockaddr) = %v, want none", got)
	}
}

// TestUnicastAddrsOfEmptyList: an adapter with no unicast addresses at all
// (FirstUnicastAddress nil) must not panic walking a list that never starts.
func TestUnicastAddrsOfEmptyList(t *testing.T) {
	if got := unicastAddrsOf(&windows.IpAdapterAddresses{}); got != nil {
		t.Errorf("unicastAddrsOf(empty) = %v, want nil", got)
	}
}

// TestAdaptersAddressesFlagsKeepsFriendlyName pins the one flag choice that
// would silently break findAdapter if it were ever set: skipping friendly
// name resolution would make every adapter's FriendlyName nil, and
// findAdapter would then match nothing, ever.
func TestAdaptersAddressesFlagsKeepsFriendlyName(t *testing.T) {
	if adaptersAddressesFlags&windows.GAA_FLAG_SKIP_FRIENDLY_NAME != 0 {
		t.Error("adaptersAddressesFlags skips friendly names; findAdapter matches by name and would find nothing")
	}
}
