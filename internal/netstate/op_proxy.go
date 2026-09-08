package netstate

import (
	"context"
	"fmt"
	"strings"

	"github.com/mumudevx/dpb/internal/sysport"
)

func init() {
	reviveByKind[OpProxyPAC] = reviveProxy
	reviveByKind[OpProxyHTTP] = reviveProxy
	reviveByKind[OpProxySOCKS] = reviveProxy
}

// proxyPrev is one service's proxy configuration as it stood before we touched
// it. Everything here has already passed the notSelf guard, so restoring it can
// never point the user back at a listener of ours that is no longer there.
//
// It stays as the journal's wire type rather than being replaced by
// sysport.ProxySettings, which carries the same eleven values under different
// names. A journal written by the previous version must still be revertible —
// that is what Record's "self-sufficient" contract demands — and renaming
// `pac_url` to `AutoURL` on disk would silently decode every stored capture as
// zero, i.e. as "there was nothing here". The conversion happens at the Restore
// call instead; see settings.
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

// settings turns the captured previous configuration into the value Restore
// takes. Kinds names ONLY this Op's own kind, which is what keeps the revert
// honest: capturePrev read the getters for one kind, so the other groups are
// zero because they were never asked about. Without that marker a PAC revert
// would emit `-setwebproxy <svc> "" 0` and switch off a web proxy this Op never
// touched — undoing, in TestNotSelfKeepsTheUsersLoopbackServices' sequence, the
// web-proxy revert that ran a moment earlier. It is also six networksetup
// invocations the mutation never needed.
func (p proxyPrev) settings(kind ProxyKind) ProxySettings {
	return ProxySettings{
		Kinds:      []ProxyKind{kind},
		AutoURL:    p.PACURL,
		AutoOn:     p.PACOn,
		WebHost:    p.WebHost,
		WebPort:    p.WebPort,
		WebOn:      p.WebOn,
		SecureHost: p.SecureHost,
		SecurePort: p.SecurePort,
		SecureOn:   p.SecureOn,
		SOCKSHost:  p.SOCKSHost,
		SOCKSPort:  p.SOCKSPort,
		SOCKSOn:    p.SOCKSOn,
	}
}

// proxyOp applies system proxy settings through the Port's writer and verifies
// them through its live reader — on macOS, networksetup(8) writing the
// preference and `scutil --proxy` reading the dynamic store the system actually
// consults. Those are genuinely different subsystems: a write that lands in the
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

// sys is the Port this Op mutates through, built from the Op's own Runner when
// it has one. See routeOp.sys.
func (o *proxyOp) sys(e Env) Port {
	env := e
	env.Runner = o.runner(e)
	return env.sys()
}

// kindOf maps this Op's OpKind onto the Port's ProxyKind. They are separate
// vocabularies on purpose: OpKind is what the journal records and what a user
// sees, ProxyKind is what a platform is asked to set.
func (o *proxyOp) kindOf() ProxyKind {
	switch o.kind {
	case OpProxyPAC:
		return sysport.ProxyAuto
	case OpProxyHTTP:
		return sysport.ProxyWeb
	default:
		return sysport.ProxySOCKS
	}
}

// prepare resolves the service list and captures each service's current proxy
// configuration, so the revert payload is complete before the journal fsyncs.
func (o *proxyOp) prepare(ctx context.Context, e Env) error {
	if o.prepared {
		return nil
	}
	sys := o.sys(e)
	if len(o.services) == 0 {
		svcs, err := sys.Proxy().Services(ctx)
		if err != nil {
			return err
		}
		o.services = svcs
		if len(o.services) == 0 {
			return fmt.Errorf("netstate: no enabled network services to configure")
		}
	}
	o.prev = make(map[string]proxyPrev, len(o.services))
	for _, svc := range o.services {
		// Only this Op's own kind is read. A getter that fails for a setting
		// this Op will never touch must not abort the apply.
		st, err := sys.Proxy().Configured(ctx, svc, o.kindOf())
		if err != nil {
			return err
		}
		o.prev[svc] = o.capturePrev(st, e.PriorResidue)
	}
	o.prepared = true
	return nil
}

// capturePrev is a method so the notSelf guards can compare what they read
// against the exact URL / host:port this Op is about to install. Deciding
// "ours" from loopback alone destroys the user's own local proxy.
//
// Only this Op's own kind is kept out of the whole-service read. The rest stays
// zero deliberately, and proxyPrev.settings marks it as "not described" so the
// revert cannot mistake it for "there was nothing here".
func (o *proxyOp) capturePrev(st ProxySettings, priorResidue bool) proxyPrev {
	var p proxyPrev
	switch o.kind {
	case OpProxyPAC:
		p.PACURL = notSelfPAC(st.AutoURL, o.url, priorResidue)
		p.PACOn = st.AutoOn && p.PACURL != ""
	case OpProxyHTTP:
		p.WebPort = st.WebPort
		p.WebHost = notSelfHost(st.WebHost, p.WebPort, o.host, o.port, priorResidue)
		p.WebOn = st.WebOn && p.WebHost != ""

		p.SecurePort = st.SecurePort
		p.SecureHost = notSelfHost(st.SecureHost, p.SecurePort, o.host, o.port, priorResidue)
		p.SecureOn = st.SecureOn && p.SecureHost != ""
	case OpProxySOCKS:
		p.SOCKSPort = st.SOCKSPort
		p.SOCKSHost = notSelfHost(st.SOCKSHost, p.SOCKSPort, o.host, o.port, priorResidue)
		p.SOCKSOn = st.SOCKSOn && p.SOCKSHost != ""
	}
	return p
}

func (o *proxyOp) Apply(ctx context.Context, e Env) error {
	pc := o.sys(e).Proxy()
	for _, svc := range o.services {
		var err error
		if o.kind == OpProxyPAC {
			err = pc.SetAuto(ctx, svc, o.url)
		} else {
			err = pc.SetManual(ctx, svc, o.kindOf(), o.host, o.port)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Verify reads scutil, never networksetup. A proxy set on a service that is not
// the primary one does not appear here, and that is the correct answer: traffic
// would not be proxied either.
func (o *proxyOp) Verify(ctx context.Context, e Env) error {
	st, err := o.sys(e).Proxy().Live(ctx)
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
	pc := o.sys(e).Proxy()
	var firstErr error
	for _, svc := range o.services {
		// The soft/hard distinction lives inside Restore: clearing a stored
		// field is tidying and must not fail the revert, while the state
		// command is what the user actually needs.
		if err := pc.Restore(ctx, svc, o.prev[svc].settings(o.kindOf())); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// VerifyReverted only asserts that our own setting is gone. It deliberately
// does not assert the previous value came back: the user may have changed it
// themselves while we ran, and overriding that would be its own bug.
func (o *proxyOp) VerifyReverted(ctx context.Context, e Env) error {
	sys := o.sys(e)
	st, err := sys.Proxy().Live(ctx)
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
	// scutil answers for the primary service only, but Revert mutated every
	// service in o.services, so on its own it covers 1 of N mutations while
	// UndoAll closes the journal entry on that basis. Read each service back to
	// cover the rest. This is not a second subsystem — networksetup is what
	// wrote — so the scutil assertion above stays as the independent one.
	for _, svc := range o.services {
		if err := o.verifyServiceReverted(ctx, sys, svc); err != nil {
			return err
		}
	}
	return nil
}

func (o *proxyOp) verifyServiceReverted(ctx context.Context, sys Port, svc string) error {
	st, err := sys.Proxy().Configured(ctx, svc, o.kindOf())
	if err != nil {
		return err
	}
	switch o.kind {
	case OpProxyPAC:
		if st.AutoOn && st.AutoURL == o.url {
			return fmt.Errorf("networksetup still reports our auto-proxy URL %s on %s", o.url, svc)
		}
	case OpProxyHTTP:
		if err := o.checkServiceOff("-getwebproxy", svc, st.WebOn, st.WebHost, st.WebPort); err != nil {
			return err
		}
		if err := o.checkServiceOff("-getsecurewebproxy", svc, st.SecureOn, st.SecureHost, st.SecurePort); err != nil {
			return err
		}
	case OpProxySOCKS:
		if err := o.checkServiceOff("-getsocksfirewallproxy", svc, st.SOCKSOn, st.SOCKSHost, st.SOCKSPort); err != nil {
			return err
		}
	}
	return nil
}

// checkServiceOff keeps the networksetup verb in its message. The verb is what
// a user retypes to see the same answer for themselves, and the message is the
// only thing that tells them which of the two web proxies was still ours.
func (o *proxyOp) checkServiceOff(verb, svc string, on bool, host string, port int) error {
	if on && host == o.host && port == o.port {
		return fmt.Errorf("networksetup %s %s still reports our proxy %s:%d", verb, svc, o.host, o.port)
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
