package netstate

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const pacURL = "http://127.0.0.1:8080/dpb.pac"

// prep runs the Manager-side preparation step an Op relies on, so a test can
// drive an Op directly without a journal.
func prep(t *testing.T, op Op, e Env) {
	t.Helper()
	if p, ok := op.(preparer); ok {
		if err := p.prepare(context.Background(), e); err != nil {
			t.Fatalf("prepare %s: %v", op.ID(), err)
		}
	}
}

func applyVerify(t *testing.T, op Op, e Env) {
	t.Helper()
	ctx := context.Background()
	if err := op.Apply(ctx, e); err != nil {
		t.Fatalf("Apply %s: %v", op.ID(), err)
	}
	if err := op.Verify(ctx, e); err != nil {
		t.Fatalf("Verify %s: %v", op.ID(), err)
	}
}

func revertVerify(t *testing.T, op Op, e Env) {
	t.Helper()
	ctx := context.Background()
	if err := op.Revert(ctx, e); err != nil {
		t.Fatalf("Revert %s: %v", op.ID(), err)
	}
	if err := op.VerifyReverted(ctx, e); err != nil {
		t.Fatalf("VerifyReverted %s: %v", op.ID(), err)
	}
}

func TestPACOpRoundTrip(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	f.svc["Wi-Fi"].pacURL = "http://corp.example/proxy.pac"
	f.svc["Wi-Fi"].pacOn = true
	before := f.snapshot()

	op := NewPAC(f, pacURL, []string{"Wi-Fi"})
	prep(t, op, e)
	if op.Kind() != OpProxyPAC {
		t.Fatalf("Kind = %q", op.Kind())
	}
	if !strings.Contains(op.Describe(), pacURL) {
		t.Fatalf("Describe = %q", op.Describe())
	}
	applyVerify(t, op, e)

	if f.svc["Wi-Fi"].pacURL != pacURL {
		t.Fatalf("PAC URL = %q", f.svc["Wi-Fi"].pacURL)
	}
	revertVerify(t, op, e)

	if got := f.snapshot(); got != before {
		t.Fatalf("state did not converge:\n before %s\n after  %s", before, got)
	}
}

func TestPACOpResolvesAllServicesWhenNoneGiven(t *testing.T) {
	f := newFakeSystem()
	op := NewPAC(f, pacURL, nil)
	prep(t, op, f.env0())
	if got := op.(*proxyOp).services; !reflect.DeepEqual(got, []string{"Wi-Fi", "Thunderbolt Bridge"}) {
		t.Fatalf("services = %v", got)
	}
}

// TestNotSelfPACIsRecordedAsOff is the guard against a hard kill leaving the
// machine pinned to a dead listener: a captured PAC URL that is EXACTLY the one
// we are about to install can only be our own residue, so Revert disables the
// PAC rather than restoring a pointer at a port nobody is on.
func TestNotSelfPACIsRecordedAsOff(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	const ours = "http://127.0.0.1:9999/dpb.pac"
	f.svc["Wi-Fi"].pacURL, f.svc["Wi-Fi"].pacOn = ours, true

	op := NewPAC(f, ours, []string{"Wi-Fi"})
	prep(t, op, e)
	if got := op.(*proxyOp).prev["Wi-Fi"].PACURL; got != "" {
		t.Fatalf("captured previous PAC URL = %q, want it discarded as our own", got)
	}
	applyVerify(t, op, e)
	revertVerify(t, op, e)
	if f.svc["Wi-Fi"].pacOn {
		t.Fatal("Revert restored a PAC pointing at our own listener")
	}
}

// TestNotSelfKeepsTheUsersLoopbackServices is MF5. A loopback address is not a
// signature of dpb: a user running dnscrypt-proxy or AdGuard Home on 127.0.0.1
// — the standard defence against exactly the DNS interference MEASUREMENTS.md
// §2 records — and a local web proxy or PAC on 127.0.0.1 are ordinary
// configurations that
// a clean exit must give back. Deciding "ours" from isLoopbackHost() alone
// captured all of them as empty and reverted the machine to the ISP's resolver
// with `-setdnsservers Wi-Fi Empty`, unrecoverably: the emptied list is what
// goes in the journal, so Replay could not restore it either.
func TestNotSelfKeepsTheUsersLoopbackServices(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	f.svc["Wi-Fi"].pacURL, f.svc["Wi-Fi"].pacOn = "http://127.0.0.1:3000/user.pac", true
	f.svc["Wi-Fi"].webHost, f.svc["Wi-Fi"].webPort, f.svc["Wi-Fi"].webOn = "127.0.0.1", 8888, true
	f.svc["Wi-Fi"].secHost, f.svc["Wi-Fi"].secPort, f.svc["Wi-Fi"].secOn = "127.0.0.1", 8888, true
	f.svc["Wi-Fi"].dns = []string{"127.0.0.1"}
	f.env["HTTPS_PROXY"], f.env["HTTP_PROXY"] = "http://127.0.0.1:8888", "http://127.0.0.1:8888"
	before := f.snapshot()

	ops := []Op{
		NewPAC(f, "http://127.0.0.1:9090/dpb.pac", []string{"Wi-Fi"}),
		NewWebProxy(f, "127.0.0.1", 9090, []string{"Wi-Fi"}),
		NewDNSServers(f, []string{"127.0.0.1", "9.9.9.9"}, []string{"Wi-Fi"}),
		NewLaunchEnv(f, "http://127.0.0.1:9090", nil),
	}
	for _, op := range ops {
		prep(t, op, e)
		applyVerify(t, op, e)
	}
	for i := len(ops) - 1; i >= 0; i-- {
		revertVerify(t, ops[i], e)
	}

	if got := f.snapshot(); got != before {
		t.Fatalf("a clean exit destroyed the user's own loopback services:\n before %s\n after  %s", before, got)
	}
}

// TestNotSelfDiscardsResidueAfterAnUncleanRun: when the journal or lock file
// says a previous run died, a loopback value we cannot match exactly is more
// likely to be that run's dead listener than the user's configuration, so
// Env.PriorResidue widens the test back out.
func TestNotSelfDiscardsResidueAfterAnUncleanRun(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	e.PriorResidue = true
	// A previous run bound port 8080; this one wants 9090.
	f.svc["Wi-Fi"].pacURL, f.svc["Wi-Fi"].pacOn = "http://127.0.0.1:8080/dpb.pac", true
	f.svc["Wi-Fi"].dns = []string{"127.0.0.1", "192.168.0.1"}

	pac := NewPAC(f, "http://127.0.0.1:9090/dpb.pac", []string{"Wi-Fi"})
	prep(t, pac, e)
	if got := pac.(*proxyOp).prev["Wi-Fi"].PACURL; got != "" {
		t.Fatalf("captured PAC URL = %q, want the stale loopback PAC discarded", got)
	}
	dns := NewDNSServers(f, []string{"127.0.0.1", "192.168.0.1"}, []string{"Wi-Fi"})
	prep(t, dns, e)
	if got := dns.(*dnsOp).prev["Wi-Fi"]; !reflect.DeepEqual(got, []string{"192.168.0.1"}) {
		t.Fatalf("captured resolvers = %v, want our own entry stripped", got)
	}
}

func TestNotSelfHelpers(t *testing.T) {
	const ours = "http://127.0.0.1:8080/dpb.pac"

	// Identity, not loopback: only the URL we are about to install is ours.
	if got := notSelfPAC(ours, ours, false); got != "" {
		t.Fatalf("notSelfPAC(exactly ours) = %q", got)
	}
	const userPAC = "http://127.0.0.1:3000/user.pac"
	if got := notSelfPAC(userPAC, ours, false); got != userPAC {
		t.Fatalf("notSelfPAC(the user's own loopback PAC) = %q, want it kept", got)
	}
	// ...until a previous run is known to have died mid-flight.
	if got := notSelfPAC(userPAC, ours, true); got != "" {
		t.Fatalf("notSelfPAC(loopback, priorResidue) = %q", got)
	}
	if got := notSelfPAC("http://[::1]:8080/x.pac", ours, true); got != "" {
		t.Fatalf("notSelfPAC(v6 loopback, priorResidue) = %q", got)
	}
	if got := notSelfPAC("http://localhost:8080/x.pac", ours, true); got != "" {
		t.Fatalf("notSelfPAC(localhost, priorResidue) = %q", got)
	}
	const corp = "http://corp.example/proxy.pac"
	if got := notSelfPAC(corp, ours, true); got != corp {
		t.Fatalf("notSelfPAC(corp) = %q", got)
	}
	if got := notSelfPAC("", ours, true); got != "" {
		t.Fatalf("notSelfPAC(empty) = %q", got)
	}
	// An unparseable value is kept: discarding it would silently drop a setting
	// we do not understand, which is worse than restoring it verbatim.
	if got := notSelfPAC("://nonsense", ours, true); got != "://nonsense" {
		t.Fatalf("notSelfPAC(garbage) = %q", got)
	}

	// notSelfServers: our resolver is stripped only when it is one we are about
	// to install AND a previous run died. The user's own 127.0.0.1 survives.
	mine := []string{"127.0.0.1", "9.9.9.9"}
	if got := notSelfServers([]string{"127.0.0.1", "192.168.0.1", " ", "::1"}, mine, false); !reflect.DeepEqual(got, []string{"127.0.0.1", "192.168.0.1", "::1"}) {
		t.Fatalf("notSelfServers(no residue) = %v, want the user's list intact", got)
	}
	if got := notSelfServers([]string{"127.0.0.1", "192.168.0.1", " ", "::1"}, mine, true); !reflect.DeepEqual(got, []string{"192.168.0.1", "::1"}) {
		t.Fatalf("notSelfServers(residue) = %v", got)
	}

	// notSelfHost: host AND port must both match ours.
	if got := notSelfHost("127.0.0.1", 8080, "127.0.0.1", 8080, false); got != "" {
		t.Fatalf("notSelfHost(exactly ours) = %q", got)
	}
	if got := notSelfHost("127.0.0.1", 8888, "127.0.0.1", 8080, false); got != "127.0.0.1" {
		t.Fatalf("notSelfHost(the user's loopback proxy on another port) = %q, want it kept", got)
	}
	if got := notSelfHost("127.0.0.1", 8888, "127.0.0.1", 8080, true); got != "" {
		t.Fatalf("notSelfHost(loopback, priorResidue) = %q", got)
	}
	if got := notSelfHost("proxy.corp", 3128, "127.0.0.1", 8080, true); got != "proxy.corp" {
		t.Fatalf("notSelfHost(corp) = %q", got)
	}
	if got := notSelfHost("", 0, "127.0.0.1", 8080, false); got != "" {
		t.Fatalf("notSelfHost(empty) = %q", got)
	}

	if !sameHost("[::1]", "::1") || !sameHost("LOCALHOST", "localhost") || sameHost("127.0.0.1", "") {
		t.Fatal("sameHost mis-compared equivalent spellings of the same host")
	}
	if isLoopbackHost("") || isLoopbackHost("example.com") {
		t.Fatal("isLoopbackHost matched a non-loopback host")
	}
}

func TestWebProxyOpRoundTrip(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	// The residue of a previous run: disabled, but still pointing at us.
	f.svc["Wi-Fi"].webHost, f.svc["Wi-Fi"].webPort = "127.0.0.1", 8080
	f.svc["Wi-Fi"].secHost, f.svc["Wi-Fi"].secPort = "127.0.0.1", 8080

	op := NewWebProxy(f, "127.0.0.1", 8080, []string{"Wi-Fi"})
	prep(t, op, e)
	if got := op.(*proxyOp).prev["Wi-Fi"].WebHost; got != "" {
		t.Fatalf("captured previous web proxy host = %q, want it discarded as our own", got)
	}
	applyVerify(t, op, e)
	if !f.svc["Wi-Fi"].webOn || !f.svc["Wi-Fi"].secOn {
		t.Fatal("web and secure proxies must both be enabled")
	}
	revertVerify(t, op, e)
	if f.svc["Wi-Fi"].webOn || f.svc["Wi-Fi"].secOn {
		t.Fatal("Revert left a proxy enabled")
	}
}

func TestWebProxyOpRestoresForeignSettings(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	f.svc["Wi-Fi"].webHost, f.svc["Wi-Fi"].webPort, f.svc["Wi-Fi"].webOn = "proxy.corp", 3128, true
	f.svc["Wi-Fi"].secHost, f.svc["Wi-Fi"].secPort, f.svc["Wi-Fi"].secOn = "proxy.corp", 3128, true
	before := f.snapshot()

	op := NewWebProxy(f, "127.0.0.1", 8080, []string{"Wi-Fi"})
	prep(t, op, e)
	applyVerify(t, op, e)
	revertVerify(t, op, e)

	if got := f.snapshot(); got != before {
		t.Fatalf("the user's corporate proxy was not restored:\n before %s\n after  %s", before, got)
	}
}

func TestSOCKSOpRoundTrip(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	before := f.snapshotEffective()
	op := NewSOCKSProxy(f, "127.0.0.1", 1080, []string{"Wi-Fi"})
	prep(t, op, e)
	if op.Kind() != OpProxySOCKS {
		t.Fatalf("Kind = %q", op.Kind())
	}
	applyVerify(t, op, e)
	revertVerify(t, op, e)
	if got := f.snapshotEffective(); got != before {
		t.Fatalf("state did not converge:\n before %s\n after  %s", before, got)
	}
}

func TestProxyOpVerifyFailsWhenTheSettingDidNotLand(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	op := NewPAC(f, pacURL, []string{"Wi-Fi"})
	prep(t, op, e)
	// Apply succeeds at the command level but the setting never reaches the
	// dynamic store — exactly the case exit statuses cannot detect.
	f.svc["Wi-Fi"].pacOn = false
	if err := op.Verify(context.Background(), e); err == nil {
		t.Fatal("Verify passed while scutil reported the PAC disabled")
	}
}

func TestProxyOpUnknownServiceIsAnError(t *testing.T) {
	f := newFakeSystem()
	op := NewPAC(f, pacURL, []string{"No Such Service"})
	if p, ok := op.(preparer); ok {
		if err := p.prepare(context.Background(), f.env0()); err == nil {
			t.Fatal("prepare accepted a service networksetup does not recognise")
		}
	}
}

func TestLaunchEnvRoundTrip(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	f.env["HTTP_PROXY"] = "http://corp.example:3128"
	f.env["HTTPS_PROXY"] = pacURL // our own residue: exactly what we export
	before := f.snapshot()

	op := NewLaunchEnv(f, pacURL, []string{"*.local", "169.254/16"})
	prep(t, op, e)
	le := op.(*launchEnvOp)
	if !le.prevSet["HTTP_PROXY"] {
		t.Fatal("a foreign HTTP_PROXY must be captured for restoration")
	}
	if le.prevSet["HTTPS_PROXY"] {
		t.Fatal("a captured HTTPS_PROXY holding exactly our value must be treated as unset")
	}
	applyVerify(t, op, e)
	if f.env["NO_PROXY"] != "*.local,169.254/16" {
		t.Fatalf("NO_PROXY = %q", f.env["NO_PROXY"])
	}
	revertVerify(t, op, e)

	if f.env["HTTP_PROXY"] != "http://corp.example:3128" {
		t.Fatalf("HTTP_PROXY was not restored: %q", f.env["HTTP_PROXY"])
	}
	if _, ok := f.env["HTTPS_PROXY"]; ok {
		t.Fatalf("HTTPS_PROXY should have been unset, got %q", f.env["HTTPS_PROXY"])
	}
	if _, ok := f.env["NO_PROXY"]; ok {
		t.Fatal("NO_PROXY should have been unset")
	}
	_ = before
}

func TestLaunchEnvWithoutNoProxy(t *testing.T) {
	f := newFakeSystem()
	op := NewLaunchEnv(f, pacURL, nil)
	if got := op.(*launchEnvOp).names(); !reflect.DeepEqual(got, []string{"HTTPS_PROXY", "HTTP_PROXY"}) {
		t.Fatalf("names = %v; NO_PROXY must not be managed when there is nothing to exclude", got)
	}
	if !strings.Contains(op.Describe(), "HTTPS_PROXY="+pacURL) {
		t.Fatalf("Describe = %q", op.Describe())
	}
}

func TestPACFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "dpb.pac")
	e := Env{}

	op := NewPACFile(path, []byte("function FindProxyForURL(u,h){return \"DIRECT\";}"))
	prep(t, op, e)
	applyVerify(t, op, e)

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Browsers fetch the PAC as another user's process; 0600 would break them.
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("PAC mode = %v, want 0644", fi.Mode().Perm())
	}

	// A corrupted file must fail Verify: WriteFile returning nil proves nothing
	// about what is on disk now.
	if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := op.Verify(context.Background(), e); err == nil {
		t.Fatal("Verify passed on a tampered PAC file")
	}

	revertVerify(t, op, e)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("PAC file survived Revert: %v", err)
	}
	// Revert is idempotent.
	revertVerify(t, op, e)
}

func TestPACFileRestoresPreviousContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dpb.pac")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := Env{}
	op := NewPACFile(path, []byte("ours"))
	prep(t, op, e)
	applyVerify(t, op, e)
	revertVerify(t, op, e)

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(b) != "previous" {
		t.Fatalf("restored content = %q, want %q", b, "previous")
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("restored mode = %v, want the captured 0600", fi.Mode().Perm())
	}
}

func TestDNSOpRoundTrip(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	f.svc["Wi-Fi"].dns = []string{"192.168.0.1"}
	before := f.snapshot()

	op := NewDNSServers(f, []string{"127.0.0.1", "192.168.0.1"}, []string{"Wi-Fi"})
	prep(t, op, e)
	applyVerify(t, op, e)
	revertVerify(t, op, e)

	if got := f.snapshot(); got != before {
		t.Fatalf("state did not converge:\n before %s\n after  %s", before, got)
	}
}

func TestDNSOpNotSelfClearsRatherThanRestoringUs(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	// The residue of a hard kill. PriorResidue is what says so: without it a
	// lone 127.0.0.1 is indistinguishable from the user's own dnscrypt-proxy,
	// and clearing it would drop the machine back to the ISP's resolver.
	e.PriorResidue = true
	f.svc["Wi-Fi"].dns = []string{"127.0.0.1"}

	op := NewDNSServers(f, []string{"127.0.0.1", "9.9.9.9"}, []string{"Wi-Fi"})
	prep(t, op, e)
	if got := op.(*dnsOp).prev["Wi-Fi"]; len(got) != 0 {
		t.Fatalf("captured previous resolvers = %v, want them discarded as our own", got)
	}
	applyVerify(t, op, e)
	revertVerify(t, op, e)
	if len(f.svc["Wi-Fi"].dns) != 0 {
		t.Fatalf("Revert restored %v instead of clearing to DHCP", f.svc["Wi-Fi"].dns)
	}
	if calls := f.callsContaining("-setdnsservers Wi-Fi Empty"); len(calls) != 1 {
		t.Fatalf("expected exactly one clear-to-DHCP call, got %v", calls)
	}
}

func TestDNSOpNoServersIsAnError(t *testing.T) {
	f := newFakeSystem()
	op := NewDNSServers(f, nil, []string{"Wi-Fi"})
	if err := op.(preparer).prepare(context.Background(), f.env0()); err == nil {
		t.Fatal("prepare accepted an empty server list")
	}
}

func TestRouteOpInterfaceRoute(t *testing.T) {
	f := newFakeSystem()
	f.ifaces["utun4"] = &fakeIface{index: 22, mtu: 1500, up: true}
	e := f.env0()
	before := f.snapshot()

	op := NewRoute(f, netip.MustParsePrefix("0.0.0.0/1"), netip.Addr{}, "utun4")
	if op.ID() != "route:0.0.0.0/1@utun4" {
		t.Fatalf("ID = %q", op.ID())
	}
	applyVerify(t, op, e)

	if calls := f.callsContaining("route -n add -inet -net 0.0.0.0/1 -interface utun4"); len(calls) != 1 {
		t.Fatalf("unexpected route argv: %v", f.callsContaining("route"))
	}
	revertVerify(t, op, e)
	if got := f.snapshot(); got != before {
		t.Fatalf("state did not converge:\n before %s\n after  %s", before, got)
	}
}

func TestRouteOpScopedDefault(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	gw := netip.MustParseAddr("192.168.0.1")
	op := NewRoute(f, netip.MustParsePrefix("0.0.0.0/0"), gw, "en0")
	applyVerify(t, op, e)

	if calls := f.callsContaining("route -n add -inet default 192.168.0.1 -ifscope en0"); len(calls) != 1 {
		t.Fatalf("unexpected route argv: %v", f.callsContaining("route"))
	}
	// The RIB must show the scope flag. A scoped add that landed unscoped is the
	// failure that lets a run report Ready while capturing nothing.
	rs, _ := f.Routes()
	found := false
	for _, r := range rs {
		if r.Dst.Bits() == 0 && r.Scoped && r.Iface == "en0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no scoped default in the RIB: %v", rs)
	}
	revertVerify(t, op, e)
}

func TestRouteOpV6(t *testing.T) {
	f := newFakeSystem()
	f.ifaces["utun4"] = &fakeIface{index: 22, mtu: 1500, up: true}
	e := f.env0()
	op := NewRoute(f, netip.MustParsePrefix("::/1"), netip.Addr{}, "utun4")
	applyVerify(t, op, e)
	if calls := f.callsContaining("route -n add -inet6 -net ::/1 -interface utun4"); len(calls) != 1 {
		t.Fatalf("unexpected route argv: %v", f.callsContaining("route"))
	}
	revertVerify(t, op, e)
}

// TestRouteOpVerifyIgnoresTheExitStatus is the behavioural half of the liar
// table: the fake route(8) reports "File exists" with exit 0 and changes
// nothing, and only the RIB read can tell us the route we wanted is absent.
func TestRouteOpVerifyIgnoresTheExitStatus(t *testing.T) {
	f := newFakeSystem()
	f.ifaces["utun4"] = &fakeIface{index: 22, mtu: 1500, up: true}
	e := f.env0()
	ctx := context.Background()

	// Pre-seed a conflicting route on a different interface so the add is
	// rejected by the kernel while route(8) still exits 0.
	f.routes = append(f.routes, RouteEntry{Dst: netip.MustParsePrefix("0.0.0.0/1"), Iface: "en0", Index: 14})

	op := NewRoute(f, netip.MustParsePrefix("0.0.0.0/1"), netip.Addr{}, "utun4")
	err := op.Apply(ctx, e)
	if err == nil {
		t.Fatal("Apply returned nil for a route(8) 'File exists' failure that exited 0")
	}
	if !strings.Contains(err.Error(), "exited 0") {
		t.Fatalf("error = %v, want it to name the zero exit", err)
	}
	if err := op.Verify(ctx, e); err == nil {
		t.Fatal("Verify passed for a route that is not in the RIB on our interface")
	}
}

func TestRouteOpRevertToleratesAnAbsentRoute(t *testing.T) {
	f := newFakeSystem()
	f.ifaces["utun4"] = &fakeIface{index: 22, up: true}
	e := f.env0()
	op := NewRoute(f, netip.MustParsePrefix("0.0.0.0/1"), netip.Addr{}, "utun4")
	// Nothing was ever applied. Revert must still succeed: the journal is
	// deliberately over-approximate, so replay reverts things that never landed.
	// It must not issue the delete, either — RTM_DELETE resolves by destination
	// and scope alone, so a delete for a route that is not in the table is a
	// delete aimed at whatever turns up there next.
	revertVerify(t, op, e)
	if calls := f.callsContaining("route -n delete"); len(calls) != 0 {
		t.Fatalf("a route that is not in the RIB must not be deleted, calls: %v", calls)
	}
}

// TestRouteOpRevertDeletesOnlyOurOwnEntry: the RIB says who owns a destination,
// and only an entry on our own interface may be deleted. A coexisting tunnel's
// half-default sitting at the same prefix is left alone.
func TestRouteOpRevertDeletesOnlyOurOwnEntry(t *testing.T) {
	dst := netip.MustParsePrefix("0.0.0.0/1")

	t.Run("ours", func(t *testing.T) {
		f := newFakeSystem()
		f.ifaces["utun4"] = &fakeIface{index: 22, up: true}
		f.routes = append(f.routes, RouteEntry{Dst: dst, Iface: "utun4", Index: 22})
		op := NewRoute(f, dst, netip.Addr{}, "utun4")
		revertVerify(t, op, f.env0())
		if calls := f.callsContaining("route -n delete"); len(calls) != 1 {
			t.Fatalf("our own route must be deleted, calls: %v", f.callsContaining("route"))
		}
	})

	t.Run("somebody else's", func(t *testing.T) {
		f := newFakeSystem()
		f.ifaces["utun4"] = &fakeIface{index: 22, up: true}
		f.ifaces["utun6"] = &fakeIface{index: 20, up: true}
		f.routes = append(f.routes, RouteEntry{Dst: dst, Iface: "utun6", Index: 20})
		op := NewRoute(f, dst, netip.Addr{}, "utun4")
		if err := op.Revert(context.Background(), f.env0()); err != nil {
			t.Fatalf("Revert: %v", err)
		}
		if calls := f.callsContaining("route -n delete"); len(calls) != 0 {
			t.Fatalf("a foreign route at our destination must not be deleted, calls: %v", calls)
		}
		if ok, _ := f.Exists(dst, "utun6"); !ok {
			t.Fatal("the other tunnel's route was deleted")
		}
	})
}

func TestRouteOpNeedsARIB(t *testing.T) {
	f := newFakeSystem()
	op := NewRoute(f, netip.MustParsePrefix("0.0.0.0/1"), netip.Addr{}, "utun4")
	e := Env{Runner: f}
	if err := op.Verify(context.Background(), e); err == nil {
		t.Fatal("Verify passed with no RIB reader; there would be nothing verifying it")
	}
	if err := op.VerifyReverted(context.Background(), e); err == nil {
		t.Fatal("VerifyReverted passed with no RIB reader")
	}
}

func TestIfconfigOpRoundTrip(t *testing.T) {
	f := newFakeSystem()
	f.install(t)
	f.ifaces["utun4"] = &fakeIface{index: 22, mtu: 1500}
	e := f.env0()

	op := NewIfconfig(f, "utun4", "10.255.0.1", "10.255.0.2", 1500)
	applyVerify(t, op, e)
	if calls := f.callsContaining("ifconfig utun4 inet 10.255.0.1 10.255.0.2 mtu 1500 up"); len(calls) != 1 {
		t.Fatalf("unexpected ifconfig argv: %v", f.callsContaining("ifconfig"))
	}
	if !f.ifaces["utun4"].up {
		t.Fatal("interface was not brought up")
	}
	revertVerify(t, op, e)
	if len(f.ifaces["utun4"].addrs) != 0 {
		t.Fatalf("address survived revert: %v", f.ifaces["utun4"].addrs)
	}
}

func TestIfconfigOpV6(t *testing.T) {
	f := newFakeSystem()
	f.install(t)
	f.ifaces["utun4"] = &fakeIface{index: 22, mtu: 1500}
	e := f.env0()
	op := NewIfconfig(f, "utun4", "fd00:d9b::1", "", 1500)
	applyVerify(t, op, e)
	if calls := f.callsContaining("ifconfig utun4 inet6 fd00:d9b::1 prefixlen 64 mtu 1500 up"); len(calls) != 1 {
		t.Fatalf("unexpected ifconfig argv: %v", f.callsContaining("ifconfig"))
	}
	revertVerify(t, op, e)
}

func TestIfconfigOpVerifyDetail(t *testing.T) {
	f := newFakeSystem()
	f.install(t)
	e := f.env0()
	ctx := context.Background()

	op := NewIfconfig(f, "utun9", "10.255.0.1", "10.255.0.2", 1500)
	if err := op.Verify(ctx, e); err == nil {
		t.Fatal("Verify passed for an interface that does not exist")
	}
	// A missing interface is the strongest possible revert.
	if err := op.VerifyReverted(ctx, e); err != nil {
		t.Fatalf("VerifyReverted on a missing interface: %v", err)
	}

	f.ifaces["utun9"] = &fakeIface{index: 30, mtu: 1400}
	if err := op.Apply(ctx, e); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	f.ifaces["utun9"].mtu = 1400 // ifconfig "succeeded" but the MTU did not take
	if err := op.Verify(ctx, e); err == nil || !strings.Contains(err.Error(), "MTU") {
		t.Fatalf("Verify err = %v, want an MTU complaint", err)
	}
	f.ifaces["utun9"].mtu = 1500
	f.ifaces["utun9"].up = false
	if err := op.Verify(ctx, e); err == nil || !strings.Contains(err.Error(), "not up") {
		t.Fatalf("Verify err = %v, want an 'not up' complaint", err)
	}
}

func TestIfconfigOpRejectsANonAddress(t *testing.T) {
	f := newFakeSystem()
	f.install(t)
	f.ifaces["utun4"] = &fakeIface{index: 22, mtu: 1500, up: true, addrs: []string{"10.0.0.1/32"}}
	op := NewIfconfig(f, "utun4", "not-an-ip", "", 1500)
	if err := op.Verify(context.Background(), f.env0()); err == nil {
		t.Fatal("Verify accepted an address that is not an IP")
	}
}

// TestProxyVerifyRevertedCoversEveryService is SF17. Apply and Revert loop
// o.services; Verify/VerifyReverted read `scutil --proxy`, which answers for the
// primary service only. That covered 1 of N mutations while UndoAll closed the
// journal entry on that basis.
func TestProxyVerifyRevertedCoversEveryService(t *testing.T) {
	svcs := []string{"Wi-Fi", "Thunderbolt Bridge"}

	t.Run("pac", func(t *testing.T) {
		f := newFakeSystem()
		e := f.env0()
		op := NewPAC(f, pacURL, svcs)
		prep(t, op, e)
		applyVerify(t, op, e)
		// Only the primary service is put back — the shape a partial revert
		// leaves, and the shape scutil cannot see.
		f.svc["Wi-Fi"].pacOn, f.svc["Wi-Fi"].pacURL = false, ""
		if err := op.VerifyReverted(context.Background(), e); err == nil {
			t.Fatal("VerifyReverted passed while a secondary service still carried our PAC")
		}
	})

	t.Run("web", func(t *testing.T) {
		f := newFakeSystem()
		e := f.env0()
		op := NewWebProxy(f, "127.0.0.1", 8080, svcs)
		prep(t, op, e)
		applyVerify(t, op, e)
		f.svc["Wi-Fi"].webOn, f.svc["Wi-Fi"].secOn = false, false
		if err := op.VerifyReverted(context.Background(), e); err == nil {
			t.Fatal("VerifyReverted passed while a secondary service still carried our web proxy")
		}
	})

	t.Run("socks", func(t *testing.T) {
		f := newFakeSystem()
		e := f.env0()
		op := NewSOCKSProxy(f, "127.0.0.1", 1080, svcs)
		prep(t, op, e)
		applyVerify(t, op, e)
		f.svc["Wi-Fi"].sockOn = false
		if err := op.VerifyReverted(context.Background(), e); err == nil {
			t.Fatal("VerifyReverted passed while a secondary service still carried our SOCKS proxy")
		}
	})

	t.Run("dns", func(t *testing.T) {
		f := newFakeSystem()
		e := f.env0()
		op := NewDNSServers(f, []string{"127.0.0.1", "9.9.9.9"}, svcs)
		prep(t, op, e)
		applyVerify(t, op, e)
		f.svc["Wi-Fi"].dns = nil
		if err := op.VerifyReverted(context.Background(), e); err == nil {
			t.Fatal("VerifyReverted passed while a secondary service still carried our resolvers")
		}
	})
}

// TestProxyRevertClearsAbandonedFields is the second half of MF5. macOS keeps a
// disabled proxy's Server and Port — confirmed live on this machine:
// `networksetup -getwebproxy Wi-Fi` reports "Enabled: No, Server: 127.0.0.1,
// Port: 8080" left by an earlier dpb. Emitting only `-setwebproxystate off`
// abandons the fields pointing at our dead port, and the next time the user
// ticks the box in System Settings they get a total HTTP/HTTPS outage.
func TestProxyRevertClearsAbandonedFields(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	op := NewWebProxy(f, "127.0.0.1", 8080, []string{"Wi-Fi"})
	prep(t, op, e)
	applyVerify(t, op, e)
	revertVerify(t, op, e)

	s := f.svc["Wi-Fi"]
	if s.webOn || s.secOn {
		t.Fatal("Revert left a proxy enabled")
	}
	if s.webHost != "" || s.webPort != 0 || s.secHost != "" || s.secPort != 0 {
		t.Fatalf("Revert abandoned our address behind a disabled toggle: web=%s:%d secure=%s:%d",
			s.webHost, s.webPort, s.secHost, s.secPort)
	}
}

// TestProxyRevertSoftCommandsDoNotFailTheRevert: clearing a stored field is
// tidying. If networksetup refuses it, the state command is still what the user
// needs, and the journal entry must not be left pending forever.
func TestProxyRevertSoftCommandsDoNotFailTheRevert(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	op := NewPAC(f, pacURL, []string{"Wi-Fi"})
	prep(t, op, e)
	applyVerify(t, op, e)
	f.failNext("networksetup -setautoproxyurl Wi-Fi ", 1)
	revertVerify(t, op, e)
	if f.svc["Wi-Fi"].pacOn {
		t.Fatal("a failed tidy-up command stopped the PAC being switched off")
	}
}

// TestLaunchEnvVerifiesThroughLaunchctlByDesign is SF18. This is the one
// documented exception to "Verify reads through a different subsystem than
// Apply wrote through": launchd's store is the only place a user-session
// variable lives, and docs/PLAN.md's mutated-state table row 2 specifies
// `launchctl getenv`. The test pins the exception so a future reviewer replaces
// it deliberately rather than by accident — and so the real gap stays visible:
// setenv only reaches processes started after the call, so a passing Verify
// says nothing about the already-running apps the Op exists for.
func TestLaunchEnvVerifiesThroughLaunchctlByDesign(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	op := NewLaunchEnv(f, pacURL, nil)
	prep(t, op, e)
	applyVerify(t, op, e)

	var verifiers []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "launchctl getenv") {
			verifiers = append(verifiers, c)
		}
	}
	if len(verifiers) == 0 {
		t.Fatal("launchEnvOp.Verify no longer reads launchd's own store; if that is deliberate, update the Op contract's carve-out too")
	}
	// And the caveat the carve-out exists alongside: a passing Verify is about
	// launchd's store, not about any running process.
	if err := op.Verify(context.Background(), e); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestPACFileApplyFsyncsItsDirectory is the second half of SF27: a rename is a
// directory operation, so syncing the file's contents says nothing about the
// name now pointing at them.
func TestPACFileApplyFsyncsItsDirectory(t *testing.T) {
	var synced []string
	old := dirSyncer
	t.Cleanup(func() { dirSyncer = old })
	dirSyncer = func(dir string) error {
		synced = append(synced, dir)
		return old(dir)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "dpb.pac")
	op := NewPACFile(path, []byte("function FindProxyForURL(){return \"DIRECT\";}"))
	prep(t, op, Env{})
	applyVerify(t, op, Env{})
	if len(synced) != 1 || synced[0] != dir {
		t.Fatalf("directories fsynced after the PAC rename = %v, want [%s]", synced, dir)
	}
}

// TestVerifyRevertedReportsAFailedPerServiceRead: a getter we cannot run means
// we cannot confirm the revert, so the record must stay pending for Replay
// rather than be closed on a guess.
func TestVerifyRevertedReportsAFailedPerServiceRead(t *testing.T) {
	cases := []struct {
		name string
		op   func(*fakeSystem) Op
		fail string
	}{
		{"pac", func(f *fakeSystem) Op { return NewPAC(f, pacURL, []string{"Wi-Fi"}) }, "networksetup -getautoproxyurl"},
		{"web", func(f *fakeSystem) Op { return NewWebProxy(f, "127.0.0.1", 8080, []string{"Wi-Fi"}) }, "networksetup -getwebproxy"},
		{"socks", func(f *fakeSystem) Op { return NewSOCKSProxy(f, "127.0.0.1", 1080, []string{"Wi-Fi"}) }, "networksetup -getsocksfirewallproxy"},
		{"dns", func(f *fakeSystem) Op {
			return NewDNSServers(f, []string{"127.0.0.1", "9.9.9.9"}, []string{"Wi-Fi"})
		}, "networksetup -getdnsservers"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeSystem()
			e := f.env0()
			op := c.op(f)
			prep(t, op, e)
			applyVerify(t, op, e)
			if err := op.Revert(context.Background(), e); err != nil {
				t.Fatalf("Revert: %v", err)
			}
			f.failNext(c.fail, 1)
			if err := op.VerifyReverted(context.Background(), e); err == nil {
				t.Fatal("VerifyReverted passed despite being unable to read a service back")
			}
		})
	}
}

// TestRouteOpRevertFallsBackWhenTheRIBIsUnreadable: refusing outright would
// strand our own capture route, so the delete is issued and VerifyReverted
// decides.
func TestRouteOpRevertFallsBackWhenTheRIBIsUnreadable(t *testing.T) {
	f := newFakeSystem()
	e := Env{Runner: f, Logf: func(string, ...any) {}} // no RIB
	op := NewRoute(f, netip.MustParsePrefix("0.0.0.0/1"), netip.Addr{}, "utun4")
	if err := op.Revert(context.Background(), e); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if calls := f.callsContaining("route -n delete"); len(calls) != 1 {
		t.Fatalf("expected the delete to still be attempted, calls: %v", f.callsContaining("route"))
	}
}
