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
//
// Verification reads them back with `launchctl getenv`. That is the one
// documented exception to the Op contract's "Verify reads through a different
// subsystem" rule (see the Op doc comment), and it is what docs/PLAN.md's
// mutated-state table row 2 specifies: launchd's own store is the only place a
// user-session variable lives, so there is no second observer to consult.
//
// Caveat worth stating plainly rather than hiding behind a green Verify:
// `launchctl setenv` only affects processes started AFTER the call. A passing
// Verify says the variable is in launchd's store; it says nothing about the
// already-running Electron apps whose in-process reqwest addon is the reason
// this Op exists. Those pick it up on their next launch, or not at all.
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

// sys is the Port this Op mutates through, built from the Op's own Runner when
// it has one. See routeOp.sys.
func (o *launchEnvOp) sys(e Env) Port {
	env := e
	env.Runner = o.runner(e)
	return env.sys()
}

func (o *launchEnvOp) prepare(ctx context.Context, e Env) error {
	if o.prepared {
		return nil
	}
	ec := o.sys(e).Env()
	o.prev = make(map[string]string, len(o.vars))
	o.prevSet = make(map[string]bool, len(o.vars))
	for _, name := range o.names() {
		// An unset variable reads as ("", false, nil): launchctl prints nothing
		// for one, and some builds exit non-zero while doing so.
		val, _, err := ec.Get(ctx, name)
		if err != nil {
			return err
		}
		// notSelf: a leftover value from a SIGKILLed run points at a port nobody
		// is listening on. Record it as unset so Revert clears it. "Leftover" is
		// an exact match against the value we are about to export — a user who
		// exports HTTPS_PROXY=http://127.0.0.1:8080 for their own local proxy
		// keeps it.
		if val != "" && !o.isSelfValue(name, val, e.PriorResidue) {
			o.prev[name] = val
			o.prevSet[name] = true
		}
	}
	o.prepared = true
	return nil
}

// isSelfValue reports whether a captured environment value is ours: exactly the
// value this Op is about to export, or — when a previous run is known to have
// died mid-flight — any loopback proxy URL, since that run may have bound a
// different port. NO_PROXY is a host list rather than a URL, so only the exact
// match applies to it.
func (o *launchEnvOp) isSelfValue(name, val string, priorResidue bool) bool {
	ours := o.vars[name]
	if strings.TrimSpace(val) == strings.TrimSpace(ours) {
		return true
	}
	if name == envNoProxy {
		return false
	}
	return notSelfPAC(val, ours, priorResidue) == ""
}

func (o *launchEnvOp) Apply(ctx context.Context, e Env) error {
	ec := o.sys(e).Env()
	for _, name := range o.names() {
		if err := ec.Set(ctx, name, o.vars[name]); err != nil {
			return err
		}
	}
	return nil
}

func (o *launchEnvOp) Verify(ctx context.Context, e Env) error {
	ec := o.sys(e).Env()
	for _, name := range o.names() {
		got, _, err := ec.Get(ctx, name)
		if err != nil {
			return err
		}
		if got != o.vars[name] {
			return fmt.Errorf("launchctl getenv %s returned %q, want %q", name, got, o.vars[name])
		}
	}
	return nil
}

func (o *launchEnvOp) Revert(ctx context.Context, e Env) error {
	ec := o.sys(e).Env()
	var firstErr error
	for _, name := range o.names() {
		var err error
		if o.prevSet[name] {
			err = ec.Set(ctx, name, o.prev[name])
		} else {
			err = ec.Unset(ctx, name)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (o *launchEnvOp) VerifyReverted(ctx context.Context, e Env) error {
	ec := o.sys(e).Env()
	for _, name := range o.names() {
		got, _, err := ec.Get(ctx, name)
		if err != nil {
			return err
		}
		if got == o.vars[name] && got != "" {
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
