package strategy

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Kind fixes the order in which ops execute. Steps always run in Kind order,
// never in the order they were typed, so "chunk:size=12|hostcase" and
// "hostcase|chunk:size=12" are the same strategy and canonicalise identically.
type Kind uint8

const (
	KindMutate   Kind = iota // rewrites payload bytes (host mangling)
	KindReframe              // rewrites the L5 record layer. At most ONE per spec.
	KindSchedule             // maps bytes onto ordered write ops. At most ONE per spec.
	KindSide                 // emits alongside (quicfake)
)

var kindNames = [...]string{"mutate", "reframe", "schedule", "side"}

func (k Kind) String() string {
	if int(k) >= len(kindNames) {
		return fmt.Sprintf("kind(%d)", uint8(k))
	}
	return kindNames[k]
}

// Determinism separates an op whose correctness follows from a measured RULE
// (tlsfrag: cut anywhere <= sniEnd-1) from one whose parameter is an empirical
// constant (chunk: size=12 worked today). Ranking prefers rule-based ops.
type Determinism uint8

const (
	DetEmpirical Determinism = iota
	DetRuleBased
)

func (d Determinism) String() string {
	if d == DetRuleBased {
		return "rule-based"
	}
	return "empirical"
}

// Requirement is what an op needs from the parsed first message. It is checked
// by Strategy.CheckAgainst before a byte moves, so "this strategy cannot apply
// to this connection" is a typed answer rather than a corrupted plan.
type Requirement uint8

const (
	ReqComplete Requirement = 1 << iota
	ReqSNI
	ReqHost
)

func (r Requirement) String() string {
	if r == 0 {
		return "none"
	}
	var parts []string
	for _, e := range []struct {
		r Requirement
		n string
	}{{ReqComplete, "complete"}, {ReqSNI, "sni"}, {ReqHost, "host"}} {
		if r&e.r != 0 {
			parts = append(parts, e.n)
		}
	}
	return strings.Join(parts, "|")
}

type ParamDoc struct {
	Name    string
	Default string
	Probe   []string // values the prober sweeps, in prior order
	Doc     string
}

type OpDoc struct {
	Name        string
	Kind        Kind
	Caps        Cap
	Determinism Determinism
	Requires    Requirement
	Params      []ParamDoc
	Summary     string
	Source      string // e.g. "MEASUREMENTS.md §3.2"
	Risk        int    // 0..100
	Rejected    string // non-empty if the op exists only to give an honest error
}

// Param returns the documentation for one parameter.
func (d OpDoc) Param(name string) (ParamDoc, bool) {
	for _, p := range d.Params {
		if p.Name == name {
			return p, true
		}
	}
	return ParamDoc{}, false
}

// ParamNames lists the accepted parameter names, in declaration order.
func (d OpDoc) ParamNames() []string {
	out := make([]string, 0, len(d.Params))
	for _, p := range d.Params {
		out = append(out, p.Name)
	}
	return out
}

type Op interface {
	Name() string
	Kind() Kind
	Caps() Cap
	Doc() OpDoc
	Compile(a Args) (Step, error)
}

type Step interface {
	Name() string
	Caps() Cap
	Apply(b *Builder) error
}

// Base derives Name/Kind/Caps from an op's own OpDoc so the two can never drift
// apart. An Op implementation embeds it and supplies only Compile.
type Base struct{ D OpDoc }

func (b Base) Name() string { return b.D.Name }
func (b Base) Kind() Kind   { return b.D.Kind }
func (b Base) Caps() Cap    { return b.D.Caps }
func (b Base) Doc() OpDoc   { return b.D }

type stepFunc struct {
	name string
	caps Cap
	fn   func(*Builder) error
}

func (s stepFunc) Name() string           { return s.name }
func (s stepFunc) Caps() Cap              { return s.caps }
func (s stepFunc) Apply(b *Builder) error { return s.fn(b) }

// StepFunc adapts a closure to Step. A compiled op is a closure over already
// validated parameters, so this is the shape almost every op wants.
func StepFunc(name string, caps Cap, fn func(*Builder) error) Step {
	return stepFunc{name: name, caps: caps, fn: fn}
}

// Registry maps op names to implementations. The zero value is not usable; call
// NewRegistry.
type Registry struct {
	mu  sync.RWMutex
	ops map[string]Op
}

func NewRegistry() *Registry { return &Registry{ops: make(map[string]Op)} }

var (
	defaultOnce sync.Once
	defaultReg  *Registry
)

// Default is the registry package-level Parse and Ladder consult. Ops register
// themselves into it from init, so importing internal/ops is what makes a spec
// parseable.
func Default() *Registry {
	defaultOnce.Do(func() { defaultReg = NewRegistry() })
	return defaultReg
}

// Register adds an op to the default registry.
func Register(o Op) { Default().Register(o) }

// Register panics rather than returning an error: registration happens in init,
// where a bad op is a programming error that must not survive to runtime. It
// also enforces that OpDoc agrees with the interface methods, that parameter
// names are identifiers, and that every declared default is already canonical —
// a non-canonical default would make spec canonicalisation non-idempotent.
func (r *Registry) Register(o Op) {
	if o == nil {
		panic("strategy: Register(nil)")
	}
	d := o.Doc()
	switch {
	case !isIdent(d.Name):
		panic(fmt.Sprintf("strategy: op name %q is not an identifier", d.Name))
	case d.Name == plainName:
		panic("strategy: op name \"plain\" is reserved for the empty strategy")
	case d.Name != o.Name():
		panic(fmt.Sprintf("strategy: op %q: Doc().Name is %q", o.Name(), d.Name))
	case d.Kind != o.Kind():
		panic(fmt.Sprintf("strategy: op %q: Doc().Kind is %s, Kind() is %s", d.Name, d.Kind, o.Kind()))
	case d.Caps != o.Caps():
		panic(fmt.Sprintf("strategy: op %q: Doc().Caps is %s, Caps() is %s", d.Name, d.Caps, o.Caps()))
	}
	seen := make(map[string]bool, len(d.Params))
	for _, p := range d.Params {
		if !isIdent(p.Name) {
			panic(fmt.Sprintf("strategy: op %q: parameter name %q is not an identifier", d.Name, p.Name))
		}
		if seen[p.Name] {
			panic(fmt.Sprintf("strategy: op %q: parameter %q declared twice", d.Name, p.Name))
		}
		seen[p.Name] = true
		if c := canonValue(p.Default); c != p.Default {
			panic(fmt.Sprintf("strategy: op %q: default %q for %q is not canonical (want %q)", d.Name, p.Default, p.Name, c))
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ops == nil {
		r.ops = make(map[string]Op)
	}
	if _, dup := r.ops[d.Name]; dup {
		panic(fmt.Sprintf("strategy: op %q registered twice", d.Name))
	}
	r.ops[d.Name] = o
}

func (r *Registry) lookup(name string) (Op, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	o, ok := r.ops[name]
	return o, ok
}

// Names lists the registered op names, sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.ops))
	for n := range r.ops {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Docs returns every registered op's documentation, ordered the way the ops
// execute — by (Kind, Name) — so `dpb strategy list` reads as a pipeline.
func (r *Registry) Docs() []OpDoc {
	r.mu.RLock()
	out := make([]OpDoc, 0, len(r.ops))
	for _, o := range r.ops {
		out = append(out, o.Doc())
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Docs reports the default registry's op documentation.
func Docs() []OpDoc { return Default().Docs() }

// Ladder resolves a named ladder against this registry. Every rung is parsed,
// so a ladder naming an op this build does not register fails loudly at load
// rather than at the moment a user needs the rung.
func (r *Registry) Ladder(name string) ([]Strategy, error) {
	specs, ok := LadderSpecs(name)
	if !ok {
		return nil, fmt.Errorf("%w: %q; have %s", ErrUnknownLadder, name, strings.Join(LadderNames(), ", "))
	}
	out := make([]Strategy, 0, len(specs))
	for i, s := range specs {
		st, err := r.Get(s)
		if err != nil {
			return nil, fmt.Errorf("ladder %q rung %d (%q): %w", name, i+1, s, err)
		}
		out = append(out, st)
	}
	return out, nil
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		case c == '_' && i > 0:
		default:
			return false
		}
	}
	return true
}
