//go:build windows

package scwindows

import (
	"context"
	"sort"
	"strings"
	"testing"
	"unsafe"

	"github.com/google/go-cmp/cmp"

	"github.com/mumudevx/dpb/internal/sysport"
)

// Like every other test in this package, these can only RUN on a Windows host
// and CI does not yet have one (see iphlp_test.go). `GOOS=windows go vet`
// compiles them and `go test -c` proves they link; neither proves an assertion
// has ever passed.
//
// The pure ones below — the parser, the formatter and the translation — are
// nonetheless the strongest defence this task has, because they are the only
// part of proxy.go whose failure mode is silent. A wrong registry write throws
// a Win32 error someone can read; a wrong scutil key name makes
// netstate/op_proxy.go's Verify agree that a proxy it never set is present.

// TestGlobalFreeProcedureResolves pins the thirteenth Win32 procedure — the one
// iphlp_test.go's list of twelve deliberately does not carry, because
// GlobalFree belongs to proxy.go's own allocation contract. Same reasoning as
// TestIphlpProceduresResolve: LazyProc resolves lazily, so a typo'd name would
// otherwise surface as a panic on a user's machine, mid-revert.
func TestGlobalFreeProcedureResolves(t *testing.T) {
	if err := procGlobalFree.Find(); err != nil {
		t.Errorf("GlobalFree: does not resolve: %v", err)
	}
	// A procedure that resolves must still come from the DLL we think it does:
	// NewLazySystemDLL is what keeps this off a DLL-preloading path, and it
	// only helps if the name it was given is the system one.
	if got := modkernel32.Name; !strings.EqualFold(got, "kernel32.dll") {
		t.Errorf("GlobalFree comes from %q, want kernel32.dll", got)
	}
}

// TestWinhttpProxyConfigLayout is the guard on the struct Task 1 could not
// declare, and it is written in terms of the C contract rather than the
// numbers that contract produces on this machine: BOOL is 4 bytes, each LPWSTR
// is one pointer, and the compiler pads fAutoDetect out to the pointer's
// alignment. On amd64 and arm64 that gives 0/8/16/24 and size 32; on a 32-bit
// Windows target it gives 0/4/8/12 and size 16. Hard-coding either set would
// pass on one and be a wrong-offset memory read on the other — the exact
// failure iphlp.go's package comment refuses to risk by hand-copying layouts.
func TestWinhttpProxyConfigLayout(t *testing.T) {
	var cfg winhttpCurrentUserIEProxyConfig
	ptr := unsafe.Sizeof(uintptr(0))

	// BOOL is `typedef int BOOL` — 32 bits, never a Go bool.
	if got := unsafe.Sizeof(cfg.fAutoDetect); got != 4 {
		t.Errorf("fAutoDetect is %d bytes, want 4 (BOOL is a 32-bit int)", got)
	}
	if got := unsafe.Offsetof(cfg.fAutoDetect); got != 0 {
		t.Errorf("fAutoDetect at offset %d, want 0", got)
	}

	// The three LPWSTR follow, each pointer-aligned, in declaration order.
	for _, c := range []struct {
		name string
		off  uintptr
		want uintptr
	}{
		{"lpszAutoConfigUrl", unsafe.Offsetof(cfg.lpszAutoConfigURL), ptr},
		{"lpszProxy", unsafe.Offsetof(cfg.lpszProxy), 2 * ptr},
		{"lpszProxyBypass", unsafe.Offsetof(cfg.lpszProxyBypass), 3 * ptr},
	} {
		if c.off != c.want {
			t.Errorf("%s at offset %d, want %d", c.name, c.off, c.want)
		}
	}
	if got, want := unsafe.Sizeof(cfg), 4*ptr; got != want {
		t.Errorf("struct is %d bytes, want %d", got, want)
	}
}

// TestFreeIsSafeOnAZeroConfig pins the property Live's `defer cfg.free(...)`
// depends on: the defer is armed BEFORE the syscall, so free must do nothing —
// and above all must not hand GlobalFree a nil — on a struct WinHTTP never
// filled in. Anything else would turn every failed read into a crash.
func TestFreeIsSafeOnAZeroConfig(t *testing.T) {
	var cfg winhttpCurrentUserIEProxyConfig
	logged := 0
	cfg.free(func(string, ...any) { logged++ })
	cfg.free(func(string, ...any) { logged++ })
	if logged != 0 {
		t.Errorf("freeing a zero config logged %d times, want 0", logged)
	}
}

// TestParseProxyServer covers every shape MSDN's grammar for lpszProxy admits
// —"([<scheme>=][<scheme>"://"]<server>[":"<port>][";"...])" — plus the ones
// the wild produces. It is the only defence against a parser that quietly
// drops one of the user's proxies on the way through SetManual.
func TestParseProxyServer(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []proxyEntry
	}{
		{
			name: "empty string is no proxies at all",
			in:   "",
			want: nil,
		},
		{
			// The shape IE writes for "use the same proxy server for all
			// protocols". socks is deliberately NOT covered; see
			// bareProxySchemes for why claiming it would be a lie.
			//
			// Bare is set on all three: nothing downstream may mistake an
			// entry this parser invented for one the user wrote. See
			// proxyEntry.Bare.
			name: "a bare entry is the default for every scheme but socks",
			in:   "10.0.0.1:8080",
			want: []proxyEntry{
				{Scheme: "http", Host: "10.0.0.1", Port: 8080, Bare: true},
				{Scheme: "https", Host: "10.0.0.1", Port: 8080, Bare: true},
				{Scheme: "ftp", Host: "10.0.0.1", Port: 8080, Bare: true},
			},
		},
		{
			name: "the per-scheme form IE writes",
			in:   "http=a.example:8080;https=b.example:8443;socks=c.example:1080",
			want: []proxyEntry{
				{Scheme: "http", Host: "a.example", Port: 8080},
				{Scheme: "https", Host: "b.example", Port: 8443},
				{Scheme: "socks", Host: "c.example", Port: 1080},
			},
		},
		{
			// The two-pass rule. A single "last wins" loop would let the bare
			// entry overwrite the explicit http one on its way past.
			name: "a bare entry never overrides a scheme named explicitly",
			in:   "http=a.example:1;b.example:2",
			want: []proxyEntry{
				{Scheme: "http", Host: "a.example", Port: 1},
				{Scheme: "https", Host: "b.example", Port: 2, Bare: true},
				{Scheme: "ftp", Host: "b.example", Port: 2, Bare: true},
			},
		},
		{
			name: "a bare entry written first still loses to an explicit one",
			in:   "b.example:2;http=a.example:1",
			want: []proxyEntry{
				{Scheme: "http", Host: "a.example", Port: 1},
				{Scheme: "https", Host: "b.example", Port: 2, Bare: true},
				{Scheme: "ftp", Host: "b.example", Port: 2, Bare: true},
			},
		},
		{
			name: "whitespace separates entries as well as semicolons",
			in:   "http=a.example:1 https=b.example:2\tsocks=c.example:3",
			want: []proxyEntry{
				{Scheme: "http", Host: "a.example", Port: 1},
				{Scheme: "https", Host: "b.example", Port: 2},
				{Scheme: "socks", Host: "c.example", Port: 3},
			},
		},
		{
			name: "scheme names are matched case-insensitively and emitted lower",
			in:   "HTTP=a.example:1;HttpS=b.example:2",
			want: []proxyEntry{
				{Scheme: "http", Host: "a.example", Port: 1},
				{Scheme: "https", Host: "b.example", Port: 2},
			},
		},
		{
			name: "a scheme prefix inside the value is dropped",
			in:   "http=http://a.example:8080/;https=https://b.example:8443",
			want: []proxyEntry{
				{Scheme: "http", Host: "a.example", Port: 8080},
				{Scheme: "https", Host: "b.example", Port: 8443},
			},
		},
		{
			// Brackets are KEPT, so Restore writes back what the user had.
			name: "a bracketed IPv6 literal keeps its brackets and loses its port",
			in:   "http=[2001:db8::1]:8080;https=[::1]",
			want: []proxyEntry{
				{Scheme: "http", Host: "[2001:db8::1]", Port: 8080},
				{Scheme: "https", Host: "[::1]", Port: 0},
			},
		},
		{
			// "::1" would otherwise split into host "::" port 1.
			name: "an unbracketed IPv6 literal is not mistaken for host:port",
			in:   "http=::1",
			want: []proxyEntry{{Scheme: "http", Host: "::1", Port: 0}},
		},
		{
			name: "a host with no port parses with port zero",
			in:   "http=proxy.example",
			want: []proxyEntry{{Scheme: "http", Host: "proxy.example", Port: 0}},
		},
		{
			// Garbage in the port stays part of the host so re-emitting is
			// byte-identical; inventing a port would be worse.
			name: "an unparseable port stays part of the host",
			in:   "http=proxy.example:eighty",
			want: []proxyEntry{{Scheme: "http", Host: "proxy.example:eighty", Port: 0}},
		},
		{
			name: "an out-of-range port is not a port",
			in:   "http=proxy.example:70000",
			want: []proxyEntry{{Scheme: "http", Host: "proxy.example:70000", Port: 0}},
		},
		{
			name: "an unknown scheme is preserved rather than dropped",
			in:   "http=a.example:1;gopher=g.example:70",
			want: []proxyEntry{
				{Scheme: "http", Host: "a.example", Port: 1},
				{Scheme: "gopher", Host: "g.example", Port: 70},
			},
		},
		{
			name: "empty entries and stray separators are skipped",
			in:   ";;http=a.example:1;;",
			want: []proxyEntry{{Scheme: "http", Host: "a.example", Port: 1}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseProxyServer(tc.in)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("parseProxyServer(%q) mismatch (-want +got):\n%s", tc.in, diff)
			}
		})
	}
}

// TestFormatProxyServer pins the emitted string, which is what actually lands
// in the user's registry. Canonical ordering is what makes it assertable at
// all; an unknown scheme keeps its place after the four known ones.
func TestFormatProxyServer(t *testing.T) {
	cases := []struct {
		name string
		in   []proxyEntry
		want string
	}{
		{name: "nothing left is the empty string", in: nil, want: ""},
		{
			name: "canonical order regardless of input order",
			in: []proxyEntry{
				{Scheme: "socks", Host: "d.example", Port: 1080},
				{Scheme: "https", Host: "b.example", Port: 8443},
				{Scheme: "ftp", Host: "c.example", Port: 21},
				{Scheme: "http", Host: "a.example", Port: 8080},
			},
			want: "http=a.example:8080;https=b.example:8443;ftp=c.example:21;socks=d.example:1080",
		},
		{
			name: "a port of zero is omitted, not written as :0",
			in:   []proxyEntry{{Scheme: "http", Host: "proxy.example", Port: 0}},
			want: "http=proxy.example",
		},
		{
			name: "unknown schemes come last, in the order they were seen",
			in: []proxyEntry{
				{Scheme: "gopher", Host: "g.example", Port: 70},
				{Scheme: "wais", Host: "w.example", Port: 210},
				{Scheme: "http", Host: "a.example", Port: 1},
			},
			want: "http=a.example:1;gopher=g.example:70;wais=w.example:210",
		},
		{
			// The user's "use the same proxy server for all protocols" value
			// comes back as ITSELF. Expanding it into three explicit entries
			// narrows a setting that covers every protocol down to three, on a
			// machine this tool promised to put back. See proxyEntry.Bare.
			name: "a bare list is re-emitted bare, not expanded",
			in:   parseProxyServer("10.0.0.1:8080"),
			want: "10.0.0.1:8080",
		},
		{
			// What SetManual leaves behind: our http proxy named explicitly,
			// the user's bare token still covering everything else.
			name: "an explicit entry beside a bare token keeps both forms",
			in:   parseProxyServer("http=ours.example:9;10.0.0.1:8080"),
			want: "http=ours.example:9;10.0.0.1:8080",
		},
		{
			// What a web Restore produces on a bare-proxy machine: http and
			// https written back to exactly the value the surviving bare token
			// already gives them. Emitting all three would say the same thing
			// in a shape the user never had.
			name: "explicit entries matching the bare token collapse back into it",
			in: []proxyEntry{
				{Scheme: "http", Host: "10.0.0.1", Port: 8080},
				{Scheme: "https", Host: "10.0.0.1", Port: 8080},
				{Scheme: "ftp", Host: "10.0.0.1", Port: 8080, Bare: true},
			},
			want: "10.0.0.1:8080",
		},
		{
			// socks is not in bareProxySchemes, so an explicit socks entry can
			// never be folded into a bare token however equal its value looks.
			name: "a socks entry never collapses into a bare token",
			in: []proxyEntry{
				{Scheme: "socks", Host: "10.0.0.1", Port: 8080},
				{Scheme: "http", Host: "10.0.0.1", Port: 8080, Bare: true},
			},
			want: "socks=10.0.0.1:8080;10.0.0.1:8080",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatProxyServer(tc.in); got != tc.want {
				t.Errorf("formatProxyServer() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestProxyServerRoundTrip is the property SetManual's "parse and re-emit"
// contract rests on: whatever we write back must parse to the same thing, or
// the next SetManual reads its own output wrongly and the user's other proxies
// drift away one apply at a time.
func TestProxyServerRoundTrip(t *testing.T) {
	for _, in := range []string{
		"http=a.example:8080;https=b.example:8443;socks=c.example:1080",
		"10.0.0.1:8080",
		"http=[2001:db8::1]:8080",
		"http=proxy.example",
		"http=a.example:1;gopher=g.example:70",
		"http=ours.example:9;10.0.0.1:8080",
	} {
		first := parseProxyServer(in)
		second := parseProxyServer(formatProxyServer(first))
		if diff := cmp.Diff(first, second); diff != "" {
			t.Errorf("round trip of %q lost information (-first +second):\n%s", in, diff)
		}
	}
}

// TestSetManualRewritesOnlyItsOwnSchemes is the defect the brief names
// outright: Windows packs every scheme into ONE string, so a SetManual that
// overwrote ProxyServer instead of editing it would delete the user's other
// proxies as a side effect. This exercises the parse/edit/emit core SetManual
// runs between its two registry calls, without a registry.
func TestSetManualRewritesOnlyItsOwnSchemes(t *testing.T) {
	const existing = "http=user.example:3128;https=user.example:3128;ftp=ftp.example:21;socks=socks.example:1080"

	cases := []struct {
		name    string
		schemes []string
		want    string
	}{
		{
			// sysport.ProxyWeb sets BOTH, matching what op_proxy.go's Verify
			// then demands for OpProxyHTTP.
			name:    "a web proxy replaces http and https and nothing else",
			schemes: []string{schemeHTTP, schemeHTTPS},
			want:    "http=127.0.0.1:8080;https=127.0.0.1:8080;ftp=ftp.example:21;socks=socks.example:1080",
		},
		{
			name:    "a SOCKS proxy leaves the user's http proxy alone",
			schemes: []string{schemeSOCKS},
			want:    "http=user.example:3128;https=user.example:3128;ftp=ftp.example:21;socks=127.0.0.1:8080",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := parseProxyServer(existing)
			for _, s := range tc.schemes {
				list = setProxyEntry(list, proxyEntry{Scheme: s, Host: "127.0.0.1", Port: 8080})
			}
			if got := formatProxyServer(list); got != tc.want {
				t.Errorf("ProxyServer = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSetManualExpandsABareProxy is the same defect one step subtler. A user
// whose ProxyServer is a bare "p:8080" has ONE entry covering http, https and
// ftp; writing "https=ours" over it would drop all three. Expanding the bare
// form at parse time is what keeps the untouched schemes.
func TestSetManualExpandsABareProxy(t *testing.T) {
	list := parseProxyServer("user.example:3128")
	list = setProxyEntry(list, proxyEntry{Scheme: schemeHTTPS, Host: "127.0.0.1", Port: 8080})

	const want = "http=user.example:3128;https=127.0.0.1:8080;ftp=user.example:3128"
	if got := formatProxyServer(list); got != want {
		t.Errorf("ProxyServer = %q, want %q", got, want)
	}
}

// TestProxyStateFromIETranslatesToScutilKeys is the highest-stakes table in
// this package.
//
// sysport.ProxyState.Keys is a shared vocabulary that platform-free code —
// netstate/op_proxy.go's checkProxyPair, cliapp/doctor.go, cliapp/coverage.go —
// indexes BY LITERAL NAME. The names are asserted here as literals rather than
// through the package's own constants on purpose: writing keyAutoConfigEnable
// on both sides of the assertion would pin the two to each other and to
// nothing else, so a rename would stay green while Verify silently stopped
// finding the key. ProxyState.Str returns "" and On returns false for an
// absent key, so a misspelling has no loud failure mode at all.
func TestProxyStateFromIETranslatesToScutilKeys(t *testing.T) {
	cases := []struct {
		name           string
		autoDetect     bool
		autoConfigURL  string
		proxy          string
		bypass         string
		wantKeys       map[string]string
		wantExceptions []string
	}{
		{
			name: "nothing configured is every switch explicitly off",
			wantKeys: map[string]string{
				"ProxyAutoDiscoveryEnable": "0",
				"ProxyAutoConfigEnable":    "0",
				"HTTPEnable":               "0",
				"HTTPSEnable":              "0",
				"SOCKSEnable":              "0",
			},
		},
		{
			// The PAC path op_proxy.go's OpProxyPAC Verify reads: it checks
			// ProxyAutoConfigEnable and then compares ProxyAutoConfigURLString
			// against the URL it installed.
			name:          "a PAC URL sets the enable and the URL string",
			autoConfigURL: "http://127.0.0.1:8080/proxy.pac",
			wantKeys: map[string]string{
				"ProxyAutoDiscoveryEnable": "0",
				"ProxyAutoConfigEnable":    "1",
				"ProxyAutoConfigURLString": "http://127.0.0.1:8080/proxy.pac",
				"HTTPEnable":               "0",
				"HTTPSEnable":              "0",
				"SOCKSEnable":              "0",
			},
		},
		{
			name:       "WPAD is ProxyAutoDiscoveryEnable, not ProxyAutoConfigEnable",
			autoDetect: true,
			wantKeys: map[string]string{
				"ProxyAutoDiscoveryEnable": "1",
				"ProxyAutoConfigEnable":    "0",
				"HTTPEnable":               "0",
				"HTTPSEnable":              "0",
				"SOCKSEnable":              "0",
			},
		},
		{
			// The pair-of-pairs op_proxy.go's OpProxyHTTP Verify reads: it
			// calls checkProxyPair for "HTTP" AND for "HTTPS".
			name:  "a web proxy fills both the HTTP and the HTTPS triple",
			proxy: "http=127.0.0.1:8080;https=127.0.0.1:8080",
			wantKeys: map[string]string{
				"ProxyAutoDiscoveryEnable": "0",
				"ProxyAutoConfigEnable":    "0",
				"HTTPEnable":               "1",
				"HTTPProxy":                "127.0.0.1",
				"HTTPPort":                 "8080",
				"HTTPSEnable":              "1",
				"HTTPSProxy":               "127.0.0.1",
				"HTTPSPort":                "8080",
				"SOCKSEnable":              "0",
			},
		},
		{
			name:  "a SOCKS proxy fills the SOCKS triple and leaves the rest off",
			proxy: "socks=127.0.0.1:1080",
			wantKeys: map[string]string{
				"ProxyAutoDiscoveryEnable": "0",
				"ProxyAutoConfigEnable":    "0",
				"HTTPEnable":               "0",
				"HTTPSEnable":              "0",
				"SOCKSEnable":              "1",
				"SOCKSProxy":               "127.0.0.1",
				"SOCKSPort":                "1080",
			},
		},
		{
			// A bare entry is not a SOCKS proxy — see bareProxySchemes. If it
			// were published as one, VerifyReverted would read the user's own
			// blanket proxy as ours still being in place.
			name:  "a bare entry reaches HTTP and HTTPS but never SOCKS",
			proxy: "10.0.0.1:8080",
			wantKeys: map[string]string{
				"ProxyAutoDiscoveryEnable": "0",
				"ProxyAutoConfigEnable":    "0",
				"HTTPEnable":               "1",
				"HTTPProxy":                "10.0.0.1",
				"HTTPPort":                 "8080",
				"HTTPSEnable":              "1",
				"HTTPSProxy":               "10.0.0.1",
				"HTTPSPort":                "8080",
				"SOCKSEnable":              "0",
			},
		},
		{
			// No Port key rather than a fabricated 80: ProxyState.Int must
			// answer "not ok" so checkProxyPair reports the port it could not
			// confirm instead of comparing against a number invented here.
			name:  "a proxy with no port publishes no port key",
			proxy: "http=proxy.example",
			wantKeys: map[string]string{
				"ProxyAutoDiscoveryEnable": "0",
				"ProxyAutoConfigEnable":    "0",
				"HTTPEnable":               "1",
				"HTTPProxy":                "proxy.example",
				"HTTPSEnable":              "0",
				"SOCKSEnable":              "0",
			},
		},
		{
			name:   "the bypass list becomes the exceptions list verbatim",
			proxy:  "http=127.0.0.1:8080",
			bypass: "<local>;*.internal.example; 10.0.0.0/8",
			wantKeys: map[string]string{
				"ProxyAutoDiscoveryEnable": "0",
				"ProxyAutoConfigEnable":    "0",
				"HTTPEnable":               "1",
				"HTTPProxy":                "127.0.0.1",
				"HTTPPort":                 "8080",
				"HTTPSEnable":              "0",
				"SOCKSEnable":              "0",
			},
			wantExceptions: []string{"<local>", "*.internal.example", "10.0.0.0/8"},
		},
		{
			name:          "everything at once",
			autoDetect:    true,
			autoConfigURL: "http://wpad.example/wpad.dat",
			proxy:         "http=a.example:1;https=b.example:2;socks=c.example:3;ftp=d.example:4",
			wantKeys: map[string]string{
				"ProxyAutoDiscoveryEnable": "1",
				"ProxyAutoConfigEnable":    "1",
				"ProxyAutoConfigURLString": "http://wpad.example/wpad.dat",
				"HTTPEnable":               "1",
				"HTTPProxy":                "a.example",
				"HTTPPort":                 "1",
				"HTTPSEnable":              "1",
				"HTTPSProxy":               "b.example",
				"HTTPSPort":                "2",
				"SOCKSEnable":              "1",
				"SOCKSProxy":               "c.example",
				"SOCKSPort":                "3",
				// ftp has no scutil analogue and no consumer; it is preserved
				// through parse/emit but deliberately not published.
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := proxyStateFromIE(tc.autoDetect, tc.autoConfigURL, tc.proxy, tc.bypass)
			if diff := cmp.Diff(tc.wantKeys, st.Keys); diff != "" {
				t.Errorf("Keys mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantExceptions, st.Exceptions); diff != "" {
				t.Errorf("Exceptions mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestProxyStateKeyNamesAreTheAgreedVocabulary states the whole contract in one
// place: these eleven names, spelled exactly this way, are what platform-free
// code reads. The list is transcribed from netstate/op_proxy.go (Verify,
// VerifyReverted, checkProxyPair) and cliapp/doctor.go, and it is duplicated
// here rather than imported because scwindows cannot import netstate — on
// Windows, netstate imports THIS package.
func TestProxyStateKeyNamesAreTheAgreedVocabulary(t *testing.T) {
	want := []string{
		"HTTPEnable", "HTTPPort", "HTTPProxy",
		"HTTPSEnable", "HTTPSPort", "HTTPSProxy",
		"ProxyAutoConfigEnable", "ProxyAutoConfigURLString",
		"SOCKSEnable", "SOCKSPort", "SOCKSProxy",
	}

	// A configuration that exercises every one of them at once.
	st := proxyStateFromIE(false, "http://pac.example/p.pac",
		"http=a.example:1;https=b.example:2;socks=c.example:3", "")

	var got []string
	for k := range st.Keys {
		// ProxyAutoDiscoveryEnable is published for doctor's benefit and is
		// not part of the agreed set netstate reads; it is excluded here so
		// this assertion stays about the eleven that matter.
		if k == "ProxyAutoDiscoveryEnable" {
			continue
		}
		got = append(got, k)
	}
	sort.Strings(got)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("the published key names have drifted from the shared vocabulary (-want +got):\n%s", diff)
	}
}

// TestRestoreSchemeRemovesWhatTheCaptureNoLongerHolds pins the empty-host
// branch. An empty host in a capture means either "there was nothing here" or
// "what was here was ours and notSelf stripped it"; both must delete the entry,
// because re-emitting our own dead 127.0.0.1 would be the outage the notSelf
// guard exists to prevent.
func TestRestoreSchemeRemovesWhatTheCaptureNoLongerHolds(t *testing.T) {
	list := parseProxyServer("http=127.0.0.1:8080;https=127.0.0.1:8080;socks=user.example:1080")
	list = restoreScheme(list, schemeHTTP, "", 0)
	list = restoreScheme(list, schemeHTTPS, "", 0)

	const want = "socks=user.example:1080"
	if got := formatProxyServer(list); got != want {
		t.Errorf("ProxyServer after restore = %q, want %q", got, want)
	}
}

// TestHasUndescribedProxy pins the three-way ProxyEnable decision's hinge. The
// global switch may only be turned off when nothing a capture never described
// is still relying on it.
func TestHasUndescribedProxy(t *testing.T) {
	cases := []struct {
		name      string
		list      string
		described []string
		want      bool
	}{
		{
			name:      "an empty list has nothing undescribed",
			list:      "",
			described: []string{schemeHTTP, schemeHTTPS},
			want:      false,
		},
		{
			name:      "only what the capture described survives",
			list:      "http=a.example:1;https=b.example:2",
			described: []string{schemeHTTP, schemeHTTPS},
			want:      false,
		},
		{
			// A web revert must not switch off the user's SOCKS proxy.
			name:      "a SOCKS proxy survives a web-only capture",
			list:      "http=a.example:1;socks=c.example:3",
			described: []string{schemeHTTP, schemeHTTPS},
			want:      true,
		},
		{
			// An ftp proxy the USER wrote is described by no ProxyKind, so it
			// holds the switch on. Note "the user wrote": the case below is
			// the same scheme with different provenance and the opposite
			// answer.
			name:      "an explicit ftp proxy is undescribed by every kind",
			list:      "ftp=d.example:4",
			described: []string{schemeHTTP, schemeHTTPS, schemeSOCKS},
			want:      true,
		},
		{
			// The ex-corporate laptop. A bare ProxyServer is ONE proxy that
			// parseProxyServer expands into http, https and ftp; the ftp entry
			// is not a second proxy the capture missed, it is the same value
			// already recorded as WebHost. Reading it as undescribed is what
			// left ProxyEnable switched ON for a user who had it OFF — every
			// browser routed through a proxy they had disabled, across
			// reboots, with VerifyReverted passing.
			name:      "a bare entry's invented ftp is not an undescribed proxy",
			list:      "proxy.corp:8080",
			described: []string{schemeHTTP, schemeHTTPS},
			want:      false,
		},
		{
			// The same bare token during a SOCKS-only revert, where the
			// capture described NONE of the schemes it covers. Now it really
			// is untouched user configuration and the switch must be left
			// alone: turning it off would disable the user's own http proxy.
			name:      "a bare entry IS undescribed when no scheme it covers was captured",
			list:      "proxy.corp:8080",
			described: []string{schemeSOCKS},
			want:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasUndescribedProxy(parseProxyServer(tc.list), tc.described); got != tc.want {
				t.Errorf("hasUndescribedProxy(%q, %v) = %v, want %v", tc.list, tc.described, got, tc.want)
			}
		})
	}
}

// TestDecideProxyEnable pins the whole global-switch decision, which is the
// difference between a clean revert and a laptop that reaches nothing.
//
// The names below describe machines, not branches, because that is what the
// decision is actually about: every case is a shape a real Windows install
// arrives in, and the wrong answer to any of them is silent — VerifyReverted
// only ever looks at the HOST.
func TestDecideProxyEnable(t *testing.T) {
	web := []sysport.ProxyKind{sysport.ProxyWeb}
	socks := []sysport.ProxyKind{sysport.ProxySOCKS}

	cases := []struct {
		name      string
		prev      sysport.ProxySettings
		list      string
		described []string
		want      proxyEnableDecision
	}{
		{
			// THE CRITICAL CASE. ProxyEnable was 0 with a stale bare
			// ProxyServer; Configured recorded the host with On false, which
			// IS the DWORD. The switch must go back to 0 even though our own
			// SetManual left an ftp entry in the string.
			name: "an ex-corporate laptop gets its disabled switch back",
			prev: sysport.ProxySettings{
				Kinds: web, WebHost: "proxy.corp", WebPort: 8080, WebOn: false,
				SecureHost: "proxy.corp", SecurePort: 8080, SecureOn: false,
			},
			list:      "http=proxy.corp:8080;https=proxy.corp:8080;proxy.corp:8080",
			described: []string{schemeHTTP, schemeHTTPS},
			want:      proxyEnableOff,
		},
		{
			name: "a machine whose proxy was on gets it back on",
			prev: sysport.ProxySettings{
				Kinds: web, WebHost: "proxy.corp", WebPort: 8080, WebOn: true,
				SecureHost: "proxy.corp", SecurePort: 8080, SecureOn: true,
			},
			list:      "http=proxy.corp:8080;https=proxy.corp:8080",
			described: []string{schemeHTTP, schemeHTTPS},
			want:      proxyEnableOn,
		},
		{
			// The residual cost the old three-way decision admitted in a
			// comment: an explicit SOCKS proxy that was configured but OFF
			// used to hold the switch at the 1 we set. The capture knows the
			// DWORD from the http host, so it no longer does.
			name: "a disabled web proxy beside a disabled SOCKS proxy still goes off",
			prev: sysport.ProxySettings{
				Kinds: web, WebHost: "a.example", WebPort: 1, WebOn: false,
			},
			list:      "http=a.example:1;socks=c.example:3",
			described: []string{schemeHTTP, schemeHTTPS},
			want:      proxyEnableOff,
		},
		{
			// Nothing was configured at all, so nothing can still be relying
			// on the switch.
			name:      "a machine with no proxy at all ends with the switch off",
			prev:      sysport.ProxySettings{Kinds: web},
			list:      "",
			described: []string{schemeHTTP, schemeHTTPS},
			want:      proxyEnableOff,
		},
		{
			// The capture determines nothing (no SOCKS proxy to record) and
			// the user's own bare http proxy is still there. Switching it off
			// would break a proxy this revert never touched.
			name:      "a SOCKS revert leaves the user's bare http proxy's switch alone",
			prev:      sysport.ProxySettings{Kinds: socks},
			list:      "proxy.corp:8080",
			described: []string{schemeSOCKS},
			want:      proxyEnableLeaveAlone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideProxyEnable(tc.prev, parseProxyServer(tc.list), tc.described)
			if got != tc.want {
				t.Errorf("decideProxyEnable(%q) = %s, want %s",
					tc.list, proxyEnableName(got), proxyEnableName(tc.want))
			}
		})
	}
}

// proxyEnableName spells a decision out in the failure message. It lives here
// rather than as a String method on the type so that a decision nobody has to
// print costs the production package nothing.
func proxyEnableName(d proxyEnableDecision) string {
	switch d {
	case proxyEnableOn:
		return "ProxyEnable=1"
	case proxyEnableOff:
		return "ProxyEnable=0"
	default:
		return "leave the switch alone"
	}
}

// TestServicesIsOnePseudoService pins both halves of the Windows answer: there
// is exactly one, and its name is written to read as English where callers put
// it — netstate's proxyOp.Describe says "set auto-proxy URL %s on %s".
func TestServicesIsOnePseudoService(t *testing.T) {
	got, err := proxyCtl{}.Services(context.Background())
	if err != nil {
		t.Fatalf("Services: %v", err)
	}
	if len(got) != 1 || got[0] != proxyService {
		t.Fatalf("Services = %v, want exactly [%q]", got, proxyService)
	}
	if sentence := "set the auto-proxy URL on " + got[0]; !strings.Contains(sentence, "Internet Settings") {
		t.Errorf("the service name does not read correctly in an error message: %q", sentence)
	}
}

// TestSetManualRefusesPAC pins the refusal scdarwin makes for the same reason:
// a PAC URL is not a host:port, and refusing BY NAME beats writing something
// meaningless into ProxyServer. It reaches the refusal before touching the
// registry, which is why it can run anywhere the test binary does.
func TestSetManualRefusesPAC(t *testing.T) {
	err := proxyCtl{}.SetManual(context.Background(), proxyService, sysport.ProxyAuto, "127.0.0.1", 8080)
	if err == nil {
		t.Fatal("SetManual accepted a PAC kind; it must refuse and name SetAuto")
	}
	if !strings.Contains(err.Error(), "SetAuto") {
		t.Errorf("SetManual refusal does not name the right verb: %v", err)
	}
	if !strings.Contains(err.Error(), proxyService) {
		t.Errorf("SetManual refusal does not name the service: %v", err)
	}
}

// TestRestoreRefusesAnEmptyKinds pins sysport.CheckRestorable being called
// FIRST. A zero-value ProxySettings would otherwise delete AutoConfigURL and
// strip every scheme out of ProxyServer — the whole user's proxy
// configuration, wiped because a caller forgot a field. The check runs before
// the registry is opened, so this test needs no registry.
func TestRestoreRefusesAnEmptyKinds(t *testing.T) {
	err := proxyCtl{}.Restore(context.Background(), proxyService, sysport.ProxySettings{})
	if err == nil {
		t.Fatal("Restore accepted a capture naming no kinds; it must refuse")
	}
	if !strings.Contains(err.Error(), "no kinds") {
		t.Errorf("Restore refusal does not explain itself: %v", err)
	}
}

// TestProxyWantsNarrowing pins the reading Configured and Restore disagree
// about: an empty Kinds is "all of them" to a read, and is refused outright by
// Restore before it can reach here.
func TestProxyWantsNarrowing(t *testing.T) {
	all := sysport.ProxySettings{}
	for _, k := range allProxyKinds {
		if !proxyWants(all, k) {
			t.Errorf("a nil Kinds must read as every kind; %v was excluded", k)
		}
	}

	only := sysport.ProxySettings{Kinds: []sysport.ProxyKind{sysport.ProxySOCKS}}
	if proxyWants(only, sysport.ProxyAuto) || proxyWants(only, sysport.ProxyWeb) {
		t.Error("a SOCKS-only capture must not describe the PAC or web settings")
	}
	if !proxyWants(only, sysport.ProxySOCKS) {
		t.Error("a SOCKS-only capture must describe SOCKS")
	}
}
