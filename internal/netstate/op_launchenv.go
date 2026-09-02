package netstate

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

func init() { reviveByKind[OpLaunchEnv] = reviveLaunchEnv }

// Environment variables we manage. Electron's updater.node is an in-process
// reqwest addon that reads only HTTP(S)_PROXY/NO_PROXY — it ignores the system
// proxy entirely — which is what makes `launchctl setenv` a coverage lever
// rather than a nicety.
const (
	envHTTPProxy  = "HTTP_PROXY"
	envHTTPSProxy = "HTTPS_PROXY"
	envNoProxy    = "NO_PROXY"
)

type launchEnvRevert struct {
	Vars    map[string]string `json:"vars"`
	Prev    map[string]string `json:"prev"`
	PrevSet map[string]bool   `json:"prev_set"`
}

// launchEnvOp sets user-session environment variables through launchctl.
// Verification reads them back with `launchctl getenv`, which is what the
// lifecycle table specifies: launchd's own store is the only place these live,
// so there is no second subsystem to consult.
type launchEnvOp struct {
	run      Runner
	vars     map[string]string
	prev     map[string]string
	prevSet  map[string]bool
	prepared bool
}

// NewLaunchEnv returns an Op exporting httpsProxy as both HTTP_PROXY and
// HTTPS_PROXY, plus NO_PROXY when noProxy is non-empty.
func NewLaunchEnv(r Runner, httpsProxy string, noProxy []string) Op {
	vars := map[string]string{
		envHTTPProxy:  httpsProxy,
		envHTTPSProxy: httpsProxy,
	}
	if len(noProxy) > 0 {
		vars[envNoProxy] = strings.Join(noProxy, ",")
	}
	return &launchEnvOp{run: r, vars: vars}
}

// canAdopt is always false: environment variables that already hold our proxy
// URL are our own residue. See proxyOp.canAdopt.
func (o *launchEnvOp) canAdopt() bool { return false }

func (o *launchEnvOp) Kind() OpKind { return OpLaunchEnv }

func (o *launchEnvOp) ID() string {
	return "proxy.launchenv:" + strings.Join(o.names(), ",")
}

func (o *launchEnvOp) names() []string {
	names := make([]string, 0, len(o.vars))
	for k := range o.vars {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func (o *launchEnvOp) Describe() string {
	parts := make([]string, 0, len(o.vars))
	for _, k := range o.names() {
		parts = append(parts, fmt.Sprintf("%s=%s", k, o.vars[k]))
	}
	return "launchctl setenv " + strings.Join(parts, " ")
}

func (o *launchEnvOp) runner(e Env) Runner {
	if o.run != nil {
		return o.run
	}
	return e.runner()
}

func (o *launchEnvOp) prepare(ctx context.Context, e Env) error {
	if o.prepared {
		return nil
	}
	r := o.runner(e)
	o.prev = make(map[string]string, len(o.vars))
	o.prevSet = make(map[string]bool, len(o.vars))
	for _, name := range o.names() {
		res := r.Run(ctx, "launchctl", "getenv", name)
		if err := res.Error(); err != nil {
			return err
		}
		// launchctl prints nothing and exits 0 for an unset variable.
		val := strings.TrimSpace(res.Combined)
		// notSelf: a leftover value from a SIGKILLed run points at a port nobody
		// is listening on. Record it as unset so Revert clears it.
		if val != "" && !isSelfProxyValue(name, val) {
			o.prev[name] = val
			o.prevSet[name] = true
		}
	}
	o.prepared = true
	return nil
}

// isSelfProxyValue reports whether a captured environment value points at one
// of our own loopback listeners. NO_PROXY is a host list, never a URL, so it is
// never "ours".
func isSelfProxyValue(name, val string) bool {
	if name == envNoProxy {
		return false
	}
	return notSelfPAC(val) == ""
}

func (o *launchEnvOp) Apply(ctx context.Context, e Env) error {
	r := o.runner(e)
	for _, name := range o.names() {
		if err := r.Run(ctx, "launchctl", "setenv", name, o.vars[name]).Error(); err != nil {
			return err
		}
	}
	return nil
}

func (o *launchEnvOp) Verify(ctx context.Context, e Env) error {
	r := o.runner(e)
	for _, name := range o.names() {
		res := r.Run(ctx, "launchctl", "getenv", name)
		if err := res.Error(); err != nil {
			return err
		}
		if got := strings.TrimSpace(res.Combined); got != o.vars[name] {
			return fmt.Errorf("launchctl getenv %s returned %q, want %q", name, got, o.vars[name])
		}
	}
	return nil
}

func (o *launchEnvOp) Revert(ctx context.Context, e Env) error {
	r := o.runner(e)
	var firstErr error
	for _, name := range o.names() {
		var res Result
		if o.prevSet[name] {
			res = r.Run(ctx, "launchctl", "setenv", name, o.prev[name])
		} else {
			res = r.Run(ctx, "launchctl", "unsetenv", name)
		}
		if err := res.Error(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (o *launchEnvOp) VerifyReverted(ctx context.Context, e Env) error {
	r := o.runner(e)
	for _, name := range o.names() {
		res := r.Run(ctx, "launchctl", "getenv", name)
		if err := res.Error(); err != nil {
			return err
		}
		if got := strings.TrimSpace(res.Combined); got == o.vars[name] && got != "" {
			return fmt.Errorf("launchctl getenv %s still returns our value %q", name, got)
		}
	}
	return nil
}

func (o *launchEnvOp) Record() Record {
	raw, err := marshalRevert(launchEnvRevert{Vars: o.vars, Prev: o.prev, PrevSet: o.prevSet})
	rec := Record{Kind: OpLaunchEnv, ID: o.ID(), Revert: raw}
	if err != nil {
		rec.Note = err.Error()
	}
	return rec
}

func reviveLaunchEnv(r Record) (Op, error) {
	var p launchEnvRevert
	if err := unmarshalRevert(r.Revert, &p); err != nil {
		return nil, err
	}
	if p.Vars == nil {
		return nil, fmt.Errorf("netstate: launchenv record lists no variables")
	}
	if p.Prev == nil {
		p.Prev = map[string]string{}
	}
	if p.PrevSet == nil {
		p.PrevSet = map[string]bool{}
	}
	return &launchEnvOp{vars: p.Vars, prev: p.Prev, prevSet: p.PrevSet, prepared: true}, nil
}
