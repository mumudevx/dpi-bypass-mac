package scdarwin

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// fakeSystem is netstate's fake, copied verbatim rather than moved.
//
// Moved is not an option: roughly sixty netstate tests drive their Ops through
// it and still will, because an Op reaches macOS through a Port built from that
// same Runner. Go cannot share an unexported test helper across a package
// boundary, so the tests that followed their subjects here bring the model they
// were written against with them. Task 2 set the precedent when it duplicated
// sysport's fixture() helper and its testdata for exactly this reason.
//
// The whole file is copied, not an abridgement of it, so that a divergence
// between the two fakes is a real disagreement about what macOS does rather
// than an accident of transcription.
//
// fakeSystem is an in-memory macOS: it answers networksetup, scutil, launchctl,
// route and ifconfig from one shared state, and implements RIBReader over the
// same routes. That single source of truth is what makes the chaos table
// meaningful — an Op that "succeeds" without changing anything is caught,
// because the verifier reads the state the applier wrote rather than a
// recording of the commands it issued.
//
// It reproduces the failure shapes captured from the real tools, notably
// route(8)'s exit-0-with-an-error-message behaviour.
type fakeSystem struct {
	mu sync.Mutex

	order  []string
	svc    map[string]*fakeService
	env    map[string]string
	routes []RouteEntry
	ifaces map[string]*fakeIface
	vpn    []NCService

	calls []string

	// failCmd injects a failure the next time a command whose joined argv has
	// the given prefix runs. The value is how many more times to fail.
	failCmd map[string]int
}

type fakeService struct {
	device   string
	disabled bool

	pacURL string
	pacOn  bool

	webHost string
	webPort int
	webOn   bool

	secHost string
	secPort int
	secOn   bool

	sockHost string
	sockPort int
	sockOn   bool

	dns []string
}

type fakeIface struct {
	index int
	mtu   int
	up    bool
	mac   string
	addrs []string
}

func newFakeSystem() *fakeSystem {
	f := &fakeSystem{
		order: []string{"Wi-Fi", "Thunderbolt Bridge"},
		svc: map[string]*fakeService{
			"Wi-Fi":              {device: "en0"},
			"Thunderbolt Bridge": {device: "bridge0"},
		},
		env:     map[string]string{},
		ifaces:  map[string]*fakeIface{},
		failCmd: map[string]int{},
	}
	f.ifaces["lo0"] = &fakeIface{index: 1, mtu: 16384, up: true, addrs: []string{"127.0.0.1/8"}}
	f.ifaces["en0"] = &fakeIface{index: 14, mtu: 1500, up: true, mac: "aa:bb:cc:dd:ee:ff",
		addrs: []string{"192.168.0.138/24", "2001:db8:1::5/64"}}
	f.routes = []RouteEntry{
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.0.1"), Iface: "en0", Index: 14},
		{Dst: netip.MustParsePrefix("127.0.0.0/8"), Gateway: netip.MustParseAddr("127.0.0.1"), Iface: "lo0", Index: 1},
	}
	return f
}

// install points the package's net.Interfaces seams at this fake for the test's
// lifetime.
func (f *fakeSystem) install(t *testing.T) {
	t.Helper()
	oldL, oldA := interfaceLister, interfaceAddrser
	interfaceLister = f.listInterfaces
	interfaceAddrser = f.addrsOf
	t.Cleanup(func() { interfaceLister, interfaceAddrser = oldL, oldA })
}

func (f *fakeSystem) env0() Env {
	return Env{Runner: f, RIB: f, Logf: func(string, ...any) {}}
}

// ── failure injection ────────────────────────────────────────────────────────

func (f *fakeSystem) failNext(prefix string, times int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failCmd[prefix] = times
}

func (f *fakeSystem) shouldFail(joined string) bool {
	for prefix, n := range f.failCmd {
		if n > 0 && strings.HasPrefix(joined, prefix) {
			f.failCmd[prefix] = n - 1
			return true
		}
	}
	return false
}

// ── Runner ───────────────────────────────────────────────────────────────────

func (f *fakeSystem) Run(_ context.Context, name string, args ...string) Result {
	f.mu.Lock()
	defer f.mu.Unlock()

	argv := append([]string{name}, args...)
	joined := strings.Join(argv, " ")
	f.calls = append(f.calls, joined)

	res := Result{Argv: argv}
	if f.shouldFail(joined) {
		res.Combined = "injected failure"
		res.Code = 1
		return res
	}

	switch name {
	case "networksetup":
		res.Combined, res.Code = f.networksetup(args)
	case "scutil":
		res.Combined, res.Code = f.scutil(args)
	case "launchctl":
		res.Combined, res.Code = f.launchctl(args)
	case "route":
		res.Combined, res.Code = f.route(args)
	case "ifconfig":
		res.Combined, res.Code = f.ifconfig(args)
	case "ps":
		res.Combined, res.Code = "", 1
	default:
		res.Combined, res.Code = name+": command not found", 127
	}
	return res
}

func (f *fakeSystem) service(name string) (*fakeService, bool) {
	s, ok := f.svc[name]
	return s, ok
}

const nsNotAService = "%s is not a recognized network service.\n** Error: The parameters were not valid."

func (f *fakeSystem) networksetup(args []string) (string, int) {
	if len(args) == 0 {
		return "** Error: The parameters were not valid.", 4
	}
	verb := args[0]
	if verb == "-listnetworkserviceorder" {
		var b strings.Builder
		b.WriteString("An asterisk (*) denotes that a network service is disabled.\n")
		for i, name := range f.order {
			s := f.svc[name]
			star := ""
			if s.disabled {
				star = "*"
			}
			fmt.Fprintf(&b, "(%d) %s%s\n(Hardware Port: %s, Device: %s)\n\n", i+1, star, name, name, s.device)
		}
		return strings.TrimRight(b.String(), "\n"), 0
	}
	if len(args) < 2 {
		return "** Error: The parameters were not valid.", 4
	}
	name := args[1]
	s, ok := f.service(name)
	if !ok {
		return fmt.Sprintf(nsNotAService, name), 4
	}
	switch verb {
	case "-getautoproxyurl":
		url := s.pacURL
		if url == "" {
			url = "(null)"
		}
		return fmt.Sprintf("URL: %s\nEnabled: %s", url, yesNo(s.pacOn)), 0
	case "-setautoproxyurl":
		if len(args) < 3 {
			return "** Error: The parameters were not valid.", 4
		}
		s.pacURL, s.pacOn = args[2], true
		return "", 0
	case "-setautoproxystate":
		s.pacOn = len(args) > 2 && args[2] == "on"
		return "", 0
	case "-getwebproxy":
		return proxyGetOut(s.webOn, s.webHost, s.webPort), 0
	case "-getsecurewebproxy":
		return proxyGetOut(s.secOn, s.secHost, s.secPort), 0
	case "-getsocksfirewallproxy":
		return proxyGetOut(s.sockOn, s.sockHost, s.sockPort), 0
	case "-setwebproxy":
		s.webHost, s.webPort, s.webOn = args[2], atoi(args[3]), true
		return "", 0
	case "-setsecurewebproxy":
		s.secHost, s.secPort, s.secOn = args[2], atoi(args[3]), true
		return "", 0
	case "-setsocksfirewallproxy":
		s.sockHost, s.sockPort, s.sockOn = args[2], atoi(args[3]), true
		return "", 0
	case "-setwebproxystate":
		s.webOn = args[2] == "on"
		return "", 0
	case "-setsecurewebproxystate":
		s.secOn = args[2] == "on"
		return "", 0
	case "-setsocksfirewallproxystate":
		s.sockOn = args[2] == "on"
		return "", 0
	case "-getdnsservers":
		if len(s.dns) == 0 {
			return fmt.Sprintf("There aren't any DNS Servers set on %s.", name), 0
		}
		return strings.Join(s.dns, "\n"), 0
	case "-setdnsservers":
		vals := args[2:]
		if len(vals) == 1 && vals[0] == "Empty" {
			s.dns = nil
		} else {
			s.dns = append([]string(nil), vals...)
		}
		return "", 0
	}
	return "** Error: The parameters were not valid.", 4
}

func proxyGetOut(on bool, host string, port int) string {
	return fmt.Sprintf("Enabled: %s\nServer: %s\nPort: %d\nAuthenticated Proxy Enabled: 0",
		yesNo(on), host, port)
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// primary returns the first enabled service, which is what scutil reports on.
func (f *fakeSystem) primary() *fakeService {
	for _, name := range f.order {
		if s := f.svc[name]; !s.disabled {
			return s
		}
	}
	return &fakeService{}
}

func (f *fakeSystem) scutil(args []string) (string, int) {
	switch {
	case len(args) == 1 && args[0] == "--proxy":
		s := f.primary()
		var b strings.Builder
		b.WriteString("<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n    1 : 169.254/16\n  }\n  FTPPassive : 1\n")
		fmt.Fprintf(&b, "  HTTPEnable : %s\n", zeroOne(s.webOn))
		if s.webOn {
			fmt.Fprintf(&b, "  HTTPPort : %d\n  HTTPProxy : %s\n", s.webPort, s.webHost)
		}
		fmt.Fprintf(&b, "  HTTPSEnable : %s\n", zeroOne(s.secOn))
		if s.secOn {
			fmt.Fprintf(&b, "  HTTPSPort : %d\n  HTTPSProxy : %s\n", s.secPort, s.secHost)
		}
		fmt.Fprintf(&b, "  ProxyAutoConfigEnable : %s\n", zeroOne(s.pacOn))
		if s.pacOn {
			fmt.Fprintf(&b, "  ProxyAutoConfigURLString : %s\n", s.pacURL)
		}
		fmt.Fprintf(&b, "  SOCKSEnable : %s\n", zeroOne(s.sockOn))
		if s.sockOn {
			fmt.Fprintf(&b, "  SOCKSPort : %d\n  SOCKSProxy : %s\n", s.sockPort, s.sockHost)
		}
		b.WriteString("}")
		return b.String(), 0

	case len(args) == 1 && args[0] == "--dns":
		s := f.primary()
		var b strings.Builder
		b.WriteString("DNS configuration\n\nresolver #1\n")
		servers := s.dns
		if len(servers) == 0 {
			servers = []string{"192.168.0.1"}
		}
		for i, ns := range servers {
			fmt.Fprintf(&b, "  nameserver[%d] : %s\n", i, ns)
		}
		b.WriteString("  if_index : 14 (en0)\n  flags    : Request A records\n\n")
		b.WriteString("resolver #2\n  domain   : local\n  options  : mdns\n\n")
		b.WriteString("DNS configuration (for scoped queries)\n\nresolver #1\n  nameserver[0] : 192.168.0.1\n  if_index : 14 (en0)\n")
		return b.String(), 0

	case len(args) == 2 && args[0] == "--nc" && args[1] == "list":
		var b strings.Builder
		b.WriteString("Available network connection services in the current set (*=enabled):\n")
		for _, v := range f.vpn {
			star := " "
			if v.Enabled {
				star = "*"
			}
			fmt.Fprintf(&b, "%s (%s) %s %s \"%s\" [%s]\n", star, v.Status, v.ID, v.Type, v.Name, v.Type)
		}
		return strings.TrimRight(b.String(), "\n"), 0
	}
	return "scutil: unknown option", 1
}

func zeroOne(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func (f *fakeSystem) launchctl(args []string) (string, int) {
	if len(args) < 2 {
		return "Usage: launchctl", 1
	}
	switch args[0] {
	case "getenv":
		return f.env[args[1]], 0
	case "setenv":
		if len(args) < 3 {
			return "Usage: launchctl setenv", 1
		}
		f.env[args[1]] = args[2]
		return "", 0
	case "unsetenv":
		delete(f.env, args[1])
		return "", 0
	}
	return "Unrecognized subcommand", 1
}

// route reproduces the behaviour that gives this package its name: every
// failure path prints to stderr and exits 0.
func (f *fakeSystem) route(args []string) (string, int) {
	verb, dst, gw, iface, scoped, err := parseRouteArgs(args)
	if err != nil {
		return "route: " + err.Error(), 1
	}
	// route(8) rejects a second route to the same destination in the same scope,
	// but a scoped route may coexist with an unscoped one.
	conflict := -1
	for i, r := range f.routes {
		if r.Dst == dst && r.Scoped == scoped {
			conflict = i
			break
		}
	}
	// A delete names the same scope it was added in, so an -ifscope delete must
	// not take out the unscoped route that shares the destination.
	//
	// It must NOT be narrowed by the interface an `-interface` add named. The
	// kernel resolves RTM_DELETE by destination + netmask + explicit -ifscope
	// only: rtrequest_common_locked/rt_lookup never compare the link gateway
	// that -interface supplies. A fake that filtered by it would hide the
	// deletion of a coexisting VPN's half-default, which is the whole failure
	// this table exists to expose.
	victim := -1
	for i, r := range f.routes {
		if r.Dst != dst || r.Scoped != scoped {
			continue
		}
		if scoped && iface != "" && r.Iface != iface {
			continue
		}
		victim = i
		break
	}
	switch verb {
	case "add":
		if conflict >= 0 {
			return "route: writing to routing socket: File exists", 0
		}
		e := RouteEntry{Dst: dst, Gateway: gw, Iface: iface, Scoped: scoped}
		if e.Iface == "" {
			e.Iface = "en0"
		}
		if in, ok := f.ifaces[e.Iface]; ok {
			e.Index = in.index
		}
		f.routes = append(f.routes, e)
		return "", 0
	case "delete":
		if victim < 0 {
			return "route: writing to routing socket: not in table", 0
		}
		f.routes = append(f.routes[:victim], f.routes[victim+1:]...)
		return "", 0
	}
	return "route: unknown verb", 1
}

func parseRouteArgs(args []string) (verb string, dst netip.Prefix, gw netip.Addr, iface string, scoped bool, err error) {
	v6 := false
	i := 0
	for ; i < len(args); i++ {
		switch args[i] {
		case "-n":
			continue
		case "add", "delete", "get":
			verb = args[i]
			continue
		case "-inet":
			continue
		case "-inet6":
			v6 = true
			continue
		}
		break
	}
	if verb == "" {
		return "", dst, gw, "", false, fmt.Errorf("no verb")
	}
	for ; i < len(args); i++ {
		switch args[i] {
		case "default":
			if v6 {
				dst = netip.MustParsePrefix("::/0")
			} else {
				dst = netip.MustParsePrefix("0.0.0.0/0")
			}
		case "-net":
			i++
			if i >= len(args) {
				return "", dst, gw, "", false, fmt.Errorf("-net wants an argument")
			}
			p, perr := netip.ParsePrefix(args[i])
			if perr != nil {
				return "", dst, gw, "", false, fmt.Errorf("bad destination %q", args[i])
			}
			dst = p.Masked()
		case "-ifscope":
			i++
			iface, scoped = args[i], true
		case "-interface":
			i++
			iface = args[i]
		default:
			a, aerr := netip.ParseAddr(args[i])
			if aerr != nil {
				return "", dst, gw, "", false, fmt.Errorf("bad gateway %q", args[i])
			}
			gw = a
		}
	}
	if !dst.IsValid() {
		return "", dst, gw, "", false, fmt.Errorf("no destination")
	}
	return verb, dst, gw, iface, scoped, nil
}

func (f *fakeSystem) ifconfig(args []string) (string, int) {
	if len(args) == 0 {
		return "usage: ifconfig", 1
	}
	name := args[0]
	in, ok := f.ifaces[name]
	if !ok {
		return "ifconfig: interface " + name + " does not exist", 1
	}
	if len(args) == 1 {
		return name + ": flags=8051<UP>", 0
	}
	var addr string
	alias := true
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "inet", "inet6":
			i++
			if i < len(args) {
				addr = args[i]
			}
		case "prefixlen":
			i++
		case "mtu":
			i++
			if i < len(args) {
				in.mtu = atoi(args[i])
			}
		case "up":
			in.up = true
		case "-alias":
			alias = false
		}
	}
	if addr == "" {
		return "ifconfig: bad address", 1
	}
	if alias {
		// net.Interface.Addrs always reports a mask; ifconfig's argv may not.
		if !strings.Contains(addr, "/") {
			if strings.Contains(addr, ":") {
				addr += "/64"
			} else {
				addr += "/32"
			}
		}
		in.addrs = append(in.addrs, addr)
	} else {
		out := in.addrs[:0]
		for _, a := range in.addrs {
			if strings.SplitN(a, "/", 2)[0] != addr {
				out = append(out, a)
			}
		}
		in.addrs = out
	}
	return "", 0
}

// ── RIBReader ────────────────────────────────────────────────────────────────

func (f *fakeSystem) Routes() ([]RouteEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]RouteEntry(nil), f.routes...), nil
}

func (f *fakeSystem) Default() (RouteEntry, bool, error) {
	rs, _ := f.Routes()
	return pickDefault(rs, "")
}

func (f *fakeSystem) ScopedDefault(iface string) (RouteEntry, bool, error) {
	rs, _ := f.Routes()
	return pickDefault(rs, iface)
}

func (f *fakeSystem) Exists(dst netip.Prefix, iface string) (bool, error) {
	rs, _ := f.Routes()
	return routeExists(rs, dst, iface), nil
}

// ── net.Interfaces seam ──────────────────────────────────────────────────────

func (f *fakeSystem) listInterfaces() ([]net.Interface, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(f.ifaces))
	for n := range f.ifaces {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]net.Interface, 0, len(names))
	for _, n := range names {
		in := f.ifaces[n]
		var flags net.Flags
		if in.up {
			flags |= net.FlagUp
		}
		mac, _ := net.ParseMAC(in.mac)
		out = append(out, net.Interface{Index: in.index, MTU: in.mtu, Name: n, HardwareAddr: mac, Flags: flags})
	}
	return out, nil
}

func (f *fakeSystem) addrsOf(in *net.Interface) ([]net.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fi, ok := f.ifaces[in.Name]
	if !ok {
		return nil, fmt.Errorf("no such interface %s", in.Name)
	}
	out := make([]net.Addr, 0, len(fi.addrs))
	for _, a := range fi.addrs {
		ip, ipnet, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		// net.Interface.Addrs reports the interface address with the network
		// mask, not the masked network, so mirror that.
		ipnet.IP = ip
		out = append(out, ipnet)
	}
	return out, nil
}

// ── snapshotting ─────────────────────────────────────────────────────────────

// snapshot renders every piece of mutable state in a stable order. Two
// snapshots comparing equal is the definition of "the system converged".
func (f *fakeSystem) snapshot() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b strings.Builder
	for _, name := range f.order {
		s := f.svc[name]
		fmt.Fprintf(&b, "svc %s dev=%s disabled=%v pac=%q/%v web=%s:%d/%v sec=%s:%d/%v socks=%s:%d/%v dns=%v\n",
			name, s.device, s.disabled, s.pacURL, s.pacOn,
			s.webHost, s.webPort, s.webOn, s.secHost, s.secPort, s.secOn,
			s.sockHost, s.sockPort, s.sockOn, s.dns)
	}
	keys := make([]string, 0, len(f.env))
	for k := range f.env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "env %s=%s\n", k, f.env[k])
	}
	rs := append([]RouteEntry(nil), f.routes...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].String() < rs[j].String() })
	for _, r := range rs {
		fmt.Fprintf(&b, "route %s\n", r)
	}
	names := make([]string, 0, len(f.ifaces))
	for n := range f.ifaces {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		in := f.ifaces[n]
		addrs := append([]string(nil), in.addrs...)
		sort.Strings(addrs)
		fmt.Fprintf(&b, "iface %s mtu=%d up=%v addrs=%v\n", n, in.mtu, in.up, addrs)
	}
	return b.String()
}

// snapshotEffective renders only the configuration that has an effect. macOS
// keeps a disabled proxy's server address around — the developer machine this
// was captured on still holds a stale "Server: 127.0.0.1, Enabled: No" from an
// earlier dpb — so a stale address behind an "off" switch is not a leak, and
// convergence is judged on what the system would actually do.
func (f *fakeSystem) snapshotEffective() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b strings.Builder
	for _, name := range f.order {
		s := f.svc[name]
		fmt.Fprintf(&b, "svc %s pac=%s web=%s sec=%s socks=%s dns=%v\n",
			name,
			effProxy(s.pacOn, s.pacURL, 0),
			effProxy(s.webOn, s.webHost, s.webPort),
			effProxy(s.secOn, s.secHost, s.secPort),
			effProxy(s.sockOn, s.sockHost, s.sockPort),
			s.dns)
	}
	keys := make([]string, 0, len(f.env))
	for k := range f.env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "env %s=%s\n", k, f.env[k])
	}
	rs := append([]RouteEntry(nil), f.routes...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].String() < rs[j].String() })
	for _, r := range rs {
		fmt.Fprintf(&b, "route %s\n", r)
	}
	names := make([]string, 0, len(f.ifaces))
	for n := range f.ifaces {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		in := f.ifaces[n]
		addrs := append([]string(nil), in.addrs...)
		sort.Strings(addrs)
		// An interface with no addresses carries no traffic, so the UP flag on its
		// own is not a leak. The ifconfig Op deliberately never brings an interface
		// down on revert: for a utun the device vanishes with its file descriptor,
		// and for anything else downing it would be catastrophic.
		if len(addrs) == 0 {
			fmt.Fprintf(&b, "iface %s mtu=%d unconfigured\n", n, in.mtu)
			continue
		}
		fmt.Fprintf(&b, "iface %s mtu=%d up=%v addrs=%v\n", n, in.mtu, in.up, addrs)
	}
	return b.String()
}

func effProxy(on bool, host string, port int) string {
	if !on {
		return "off"
	}
	if port == 0 {
		return host
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func (f *fakeSystem) callsContaining(sub string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.Contains(c, sub) {
			out = append(out, c)
		}
	}
	return out
}

// fixture reads one of this package's own copies of the captured tool output.
// It duplicates netstate's helper of the same name, for the reason above.
func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return strings.TrimRight(string(b), "\n")
}
