package netstate

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

func init() {
	reviveByKind[OpProxyPAC] = reviveProxy
	reviveByKind[OpProxyHTTP] = reviveProxy
	reviveByKind[OpProxySOCKS] = reviveProxy
}

// proxyPrev is one service's proxy configuration as it stood before we touched
// it. Everything here has already passed the notSelf guard, so restoring it can
// never point the user back at a listener of ours that is no longer there.
type proxyPrev struct {
	PACURL string `json:"pac_url,omitempty"`
	PACOn  bool   `json:"pac_on,omitempty"`

	WebHost string `json:"web_host,omitempty"`
	WebPort int    `json:"web_port,omitempty"`
	WebOn   bool   `json:"web_on,omitempty"`

	SecureHost string `json:"secure_host,omitempty"`
	SecurePort int    `json:"secure_port,omitempty"`
	SecureOn   bool   `json:"secure_on,omitempty"`

	SOCKSHost string `json:"socks_host,omitempty"`
	SOCKSPort int    `json:"socks_port,omitempty"`
	SOCKSOn   bool   `json:"socks_on,omitempty"`
}

type proxyRevert struct {
	Kind     OpKind               `json:"kind"`
	URL      string               `json:"url,omitempty"`
	Host     string               `json:"host,omitempty"`
	Port     int                  `json:"port,omitempty"`
	Services []string             `json:"services"`
	Prev     map[string]proxyPrev `json:"prev"`
}

// proxyOp applies system proxy settings with networksetup(8) and verifies them
// with `scutil --proxy`, which reads the dynamic store the system actually
// consults. networksetup writing the preference and scutil reading the live
// configuration are genuinely different subsystems: a write that lands in the
// plist but never reaches the dynamic store looks identical to success from
// networksetup's side, and looks like failure from scutil's.
type proxyOp struct {
	run      Runner
	kind     OpKind
	url      string
	host     string
	port     int
	services []string
	prev     map[string]proxyPrev
	prepared bool
}

// NewPAC returns an Op that points the given services at a PAC URL. PAC is the
// default mechanism because macOS treats an unfetchable auto-proxy URL as
// DIRECT: if dpb dies, traffic keeps flowing unmodified. An explicit web/secure
// proxy fails closed into a total outage instead.
//
// An empty services list means "every enabled network service", resolved at
// apply time.
func NewPAC(r Runner, url string, services []string) Op {
	return &proxyOp{run: r, kind: OpProxyPAC, url: url, services: append([]string(nil), services...)}
}

// NewWebProxy returns an Op setting both the web and secure web proxies, which
// macOS treats as separate settings but which are never useful apart.
func NewWebProxy(r Runner, host string, port int, services []string) Op {
	return &proxyOp{run: r, kind: OpProxyHTTP, host: host, port: port, services: append([]string(nil), services...)}
}

// NewSOCKSProxy returns an Op setting the SOCKS firewall proxy.
func NewSOCKSProxy(r Runner, host string, port int, services []string) Op {
	return &proxyOp{run: r, kind: OpProxySOCKS, host: host, port: port, services: append([]string(nil), services...)}
}

// canAdopt is always false. The only way a proxy Verify passes before Apply is
// that the system already carries our exact URL or host:port, which means a
// previous run died before restoring the user's settings. Adopting it would make
// our own residue permanent; applying and journalling it means the next clean
// exit removes it.
func (o *proxyOp) canAdopt() bool { return false }

func (o *proxyOp) Kind() OpKind { return o.kind }

func (o *proxyOp) ID() string {
	return fmt.Sprintf("%s:%s", o.kind, strings.Join(o.services, ","))
}

func (o *proxyOp) Describe() string {
	svcs := strings.Join(o.services, ", ")
	if svcs == "" {
		svcs = "every enabled service"
	}
	switch o.kind {
	case OpProxyPAC:
		return fmt.Sprintf("set auto-proxy URL %s on %s", o.url, svcs)
	case OpProxyHTTP:
		return fmt.Sprintf("set web+secure proxy %s:%d on %s", o.host, o.port, svcs)
	default:
		return fmt.Sprintf("set SOCKS proxy %s:%d on %s", o.host, o.port, svcs)
	}
}

func (o *proxyOp) runner(e Env) Runner {
	if o.run != nil {
		return o.run
	}
	return e.runner()
}

// prepare resolves the service list and captures each service's current proxy
// configuration, so the revert payload is complete before the journal fsyncs.
func (o *proxyOp) prepare(ctx context.Context, e Env) error {
	if o.prepared {
		return nil
	}
	env := e
	env.Runner = o.runner(e)
	if len(o.services) == 0 {
		svcs, err := ListServices(ctx, env)
		if err != nil {
			return err
		}
		o.services = serviceNames(svcs)
		if len(o.services) == 0 {
			return fmt.Errorf("netstate: no enabled network services to configure")
		}
	}
	o.prev = make(map[string]proxyPrev, len(o.services))
	for _, svc := range o.services {
		p, err := capturePrev(ctx, env.Runner, o.kind, svc)
		if err != nil {
			return err
		}
		o.prev[svc] = p
	}
	o.prepared = true
	return nil
}

func capturePrev(ctx context.Context, r Runner, kind OpKind, svc string) (proxyPrev, error) {
	var p proxyPrev
	switch kind {
	case OpProxyPAC:
		kv, err := networksetupKV(ctx, r, "-getautoproxyurl", svc)
		if err != nil {
			return p, err
		}
		p.PACURL = notSelfPAC(nullToEmpty(kv["URL"]))
		p.PACOn = yes(kv["Enabled"]) && p.PACURL != ""
	case OpProxyHTTP:
		kv, err := networksetupKV(ctx, r, "-getwebproxy", svc)
		if err != nil {
			return p, err
		}
		p.WebHost = notSelfHost(nullToEmpty(kv["Server"]))
		p.WebPort = atoi(kv["Port"])
		p.WebOn = yes(kv["Enabled"]) && p.WebHost != ""

		kv, err = networksetupKV(ctx, r, "-getsecurewebproxy", svc)
		if err != nil {
			return p, err
		}
		p.SecureHost = notSelfHost(nullToEmpty(kv["Server"]))
		p.SecurePort = atoi(kv["Port"])
		p.SecureOn = yes(kv["Enabled"]) && p.SecureHost != ""
	case OpProxySOCKS:
		kv, err := networksetupKV(ctx, r, "-getsocksfirewallproxy", svc)
		if err != nil {
			return p, err
		}
		p.SOCKSHost = notSelfHost(nullToEmpty(kv["Server"]))
		p.SOCKSPort = atoi(kv["Port"])
		p.SOCKSOn = yes(kv["Enabled"]) && p.SOCKSHost != ""
	}
	return p, nil
}

func (o *proxyOp) Apply(ctx context.Context, e Env) error {
	r := o.runner(e)
	for _, svc := range o.services {
		var cmds [][]string
		switch o.kind {
		case OpProxyPAC:
			cmds = [][]string{
				{"-setautoproxyurl", svc, o.url},
				{"-setautoproxystate", svc, "on"},
			}
		case OpProxyHTTP:
			port := strconv.Itoa(o.port)
			cmds = [][]string{
				{"-setwebproxy", svc, o.host, port},
				{"-setsecurewebproxy", svc, o.host, port},
				{"-setwebproxystate", svc, "on"},
				{"-setsecurewebproxystate", svc, "on"},
			}
		case OpProxySOCKS:
			cmds = [][]string{
				{"-setsocksfirewallproxy", svc, o.host, strconv.Itoa(o.port)},
				{"-setsocksfirewallproxystate", svc, "on"},
			}
		}
		for _, args := range cmds {
			if err := r.Run(ctx, "networksetup", args...).Error(); err != nil {
				return err
			}
		}
	}
	return nil
}

// Verify reads scutil, never networksetup. A proxy set on a service that is not
// the primary one does not appear here, and that is the correct answer: traffic
// would not be proxied either.
func (o *proxyOp) Verify(ctx context.Context, e Env) error {
	env := e
	env.Runner = o.runner(e)
	st, err := readProxyState(ctx, env)
	if err != nil {
		return err
	}
	switch o.kind {
	case OpProxyPAC:
		if !st.On("ProxyAutoConfigEnable") {
			return fmt.Errorf("scutil --proxy reports auto-proxy disabled")
		}
		if got := st.Str("ProxyAutoConfigURLString"); got != o.url {
			return fmt.Errorf("scutil --proxy reports auto-proxy URL %q, want %q", got, o.url)
		}
	case OpProxyHTTP:
		if err := checkProxyPair(st, "HTTP", o.host, o.port); err != nil {
			return err
		}
		if err := checkProxyPair(st, "HTTPS", o.host, o.port); err != nil {
			return err
		}
	case OpProxySOCKS:
		if err := checkProxyPair(st, "SOCKS", o.host, o.port); err != nil {
			return err
		}
	}
	return nil
}

func checkProxyPair(st ProxyState, prefix, host string, port int) error {
	if !st.On(prefix + "Enable") {
		return fmt.Errorf("scutil --proxy reports %s proxy disabled", prefix)
	}
	if got := st.Str(prefix + "Proxy"); got != host {
		return fmt.Errorf("scutil --proxy reports %s proxy host %q, want %q", prefix, got, host)
	}
	got, ok := st.Int(prefix + "Port")
	if !ok || got != port {
		return fmt.Errorf("scutil --proxy reports %s proxy port %q, want %d", prefix, st.Str(prefix+"Port"), port)
	}
	return nil
}

// Revert restores each service's captured configuration. It is idempotent: the
// commands it issues set an absolute state rather than toggling one.
func (o *proxyOp) Revert(ctx context.Context, e Env) error {
	r := o.runner(e)
	var firstErr error
	for _, svc := range o.services {
		p := o.prev[svc]
		for _, args := range revertCmds(o.kind, svc, p) {
			if err := r.Run(ctx, "networksetup", args...).Error(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func revertCmds(kind OpKind, svc string, p proxyPrev) [][]string {
	switch kind {
	case OpProxyPAC:
		if p.PACURL == "" {
			// Either there was nothing here, or what was here pointed at us. Both
			// mean "off": pinning the user to a dead PAC URL is worse than no PAC.
			return [][]string{{"-setautoproxystate", svc, "off"}}
		}
		return [][]string{
			{"-setautoproxyurl", svc, p.PACURL},
			{"-setautoproxystate", svc, onOff(p.PACOn)},
		}
	case OpProxyHTTP:
		var cmds [][]string
		if p.WebHost == "" {
			cmds = append(cmds, []string{"-setwebproxystate", svc, "off"})
		} else {
			cmds = append(cmds,
				[]string{"-setwebproxy", svc, p.WebHost, strconv.Itoa(p.WebPort)},
				[]string{"-setwebproxystate", svc, onOff(p.WebOn)})
		}
		if p.SecureHost == "" {
			cmds = append(cmds, []string{"-setsecurewebproxystate", svc, "off"})
		} else {
			cmds = append(cmds,
				[]string{"-setsecurewebproxy", svc, p.SecureHost, strconv.Itoa(p.SecurePort)},
				[]string{"-setsecurewebproxystate", svc, onOff(p.SecureOn)})
		}
		return cmds
	default:
		if p.SOCKSHost == "" {
			return [][]string{{"-setsocksfirewallproxystate", svc, "off"}}
		}
		return [][]string{
			{"-setsocksfirewallproxy", svc, p.SOCKSHost, strconv.Itoa(p.SOCKSPort)},
			{"-setsocksfirewallproxystate", svc, onOff(p.SOCKSOn)},
		}
	}
}

// VerifyReverted only asserts that our own setting is gone. It deliberately
// does not assert the previous value came back: the user may have changed it
// themselves while we ran, and overriding that would be its own bug.
func (o *proxyOp) VerifyReverted(ctx context.Context, e Env) error {
	env := e
	env.Runner = o.runner(e)
	st, err := readProxyState(ctx, env)
	if err != nil {
		return err
	}
	switch o.kind {
	case OpProxyPAC:
		if st.On("ProxyAutoConfigEnable") && st.Str("ProxyAutoConfigURLString") == o.url {
			return fmt.Errorf("scutil --proxy still reports our auto-proxy URL %s", o.url)
		}
	case OpProxyHTTP:
		if checkProxyPair(st, "HTTP", o.host, o.port) == nil {
			return fmt.Errorf("scutil --proxy still reports our web proxy %s:%d", o.host, o.port)
		}
		if checkProxyPair(st, "HTTPS", o.host, o.port) == nil {
			return fmt.Errorf("scutil --proxy still reports our secure proxy %s:%d", o.host, o.port)
		}
	case OpProxySOCKS:
		if checkProxyPair(st, "SOCKS", o.host, o.port) == nil {
			return fmt.Errorf("scutil --proxy still reports our SOCKS proxy %s:%d", o.host, o.port)
		}
	}
	return nil
}

func (o *proxyOp) Record() Record {
	raw, err := marshalRevert(proxyRevert{
		Kind:     o.kind,
		URL:      o.url,
		Host:     o.host,
		Port:     o.port,
		Services: o.services,
		Prev:     o.prev,
	})
	rec := Record{Kind: o.kind, ID: o.ID(), Revert: raw}
	if err != nil {
		rec.Note = err.Error()
	}
	return rec
}

func reviveProxy(r Record) (Op, error) {
	var p proxyRevert
	if err := unmarshalRevert(r.Revert, &p); err != nil {
		return nil, err
	}
	if p.Prev == nil {
		p.Prev = map[string]proxyPrev{}
	}
	return &proxyOp{
		kind:     p.Kind,
		url:      p.URL,
		host:     p.Host,
		port:     p.Port,
		services: p.Services,
		prev:     p.Prev,
		prepared: true,
	}, nil
}

// networksetupKV runs a networksetup getter and parses its "Key: value" output.
func networksetupKV(ctx context.Context, r Runner, args ...string) (map[string]string, error) {
	res := r.Run(ctx, "networksetup", args...)
	if err := res.Error(); err != nil {
		return nil, err
	}
	return parseColonKV(res.Combined), nil
}

func parseColonKV(out string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return kv
}

func nullToEmpty(s string) string {
	if s == "(null)" {
		return ""
	}
	return s
}

func yes(s string) bool { return strings.EqualFold(strings.TrimSpace(s), "yes") }

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func atoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}
