package strategy

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// plainName is the spelling of the empty strategy. "plain" and "" are the same
// value; the canonical form is "".
const plainName = "plain"

// Args are an op's parsed parameters, still as text. The accessors do the type
// conversion so every op reports a bad value the same way, naming the key.
type Args map[string]string

// Int returns the integer value of k, or def when k is absent.
func (a Args) Int(k string, def int) (int, error) {
	v, ok := a[k]
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def, fmt.Errorf("%w: %s=%q is not an integer", ErrBadValue, k, v)
	}
	return n, nil
}

// IntRange is Int with an inclusive bound. Gate 1 of the validator requires an
// out-of-range value to be an error naming the token, and an op that has to
// remember to range-check by hand eventually forgets.
func (a Args) IntRange(k string, def, lo, hi int) (int, error) {
	n, err := a.Int(k, def)
	if err != nil {
		return def, err
	}
	if n < lo || n > hi {
		return def, fmt.Errorf("%w: %s=%d outside %d..%d", ErrBadValue, k, n, lo, hi)
	}
	return n, nil
}

// Str returns the raw value of k, or def when k is absent.
func (a Args) Str(k, def string) string {
	if v, ok := a[k]; ok {
		return v
	}
	return def
}

// Bool accepts true/false, 1/0, yes/no and on/off.
func (a Args) Bool(k string, def bool) (bool, error) {
	v, ok := a[k]
	if !ok {
		return def, nil
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return def, fmt.Errorf("%w: %s=%q is not a boolean (true/false, 1/0, yes/no, on/off)", ErrBadValue, k, v)
}

// Pos returns the position value of k, or def when k is absent.
func (a Args) Pos(k string, def Pos) (Pos, error) {
	v, ok := a[k]
	if !ok {
		return def, nil
	}
	p, err := ParsePos(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", k, err)
	}
	return p, nil
}

// Unknown returns the keys that are not in known, sorted. An op calls it so a
// mistyped parameter is an error rather than a setting that silently does
// nothing — the defect class MEASUREMENTS.md §3.5 names.
func (a Args) Unknown(known ...string) []string {
	set := make(map[string]bool, len(known))
	for _, k := range known {
		set[k] = true
	}
	var out []string
	for k := range a {
		if !set[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Strategy is an ordered pipeline. Steps are held in Kind order, which is the
// order they execute, which is also the order the canonical Spec lists them in.
type Strategy struct {
	Spec  string
	Steps []Step

	ops  []Op   // parallel to Steps; carries Doc() for Explain and ranking
	args []Args // parallel to Steps; the values the user actually supplied
}

// Parse compiles a spec against the default registry.
func Parse(spec string) (Strategy, error) { return Default().Get(spec) }

// MustParse is Parse for compiled-in specs. It panics, because a ladder or
// profile that ships with an unparseable spec is a build defect.
func MustParse(spec string) Strategy {
	s, err := Parse(spec)
	if err != nil {
		panic(fmt.Sprintf("strategy: MustParse(%q): %v", spec, err))
	}
	return s
}

// String returns the canonical spec: ops sorted by (Kind, Name), parameters
// sorted by key, defaults elided, "plain" spelled "".
func (s Strategy) String() string { return s.Spec }

// Label is String with the empty strategy spelled out, for logs and tables
// where "" would read as missing data.
func (s Strategy) Label() string {
	if s.Spec == "" {
		return plainName
	}
	return s.Spec
}

// IsPlain reports whether this strategy touches nothing. Rung 1 of every ladder
// is plain, and MEASUREMENTS.md §5.2 makes that a correctness requirement, not
// an optimisation.
func (s Strategy) IsPlain() bool { return len(s.Steps) == 0 }

// Caps is what a transport must provide to execute this strategy. Every
// strategy writes the stream, so CapStreamWrite is always included.
func (s Strategy) Caps() Cap {
	c := CapStreamWrite
	for _, st := range s.Steps {
		c |= st.Caps()
	}
	return c
}

// Requires is what this strategy needs from the parsed first message. Every
// reframing op needs a complete message by construction: reframing a prefix is
// exactly the silent degradation MEASUREMENTS.md §3.5 records.
func (s Strategy) Requires() Requirement {
	var r Requirement
	for _, o := range s.ops {
		r |= o.Doc().Requires
		if o.Kind() == KindReframe {
			r |= ReqComplete
		}
	}
	return r
}

// Determinism is rule-based only when every op is. One empirical constant in
// the pipeline makes the whole result an empirical constant, and probe ranking
// key 3 must not be fooled by a composite. The empty strategy is rule-based:
// there is no parameter that could have been tuned to today's line.
func (s Strategy) Determinism() Determinism {
	d := DetRuleBased
	for _, o := range s.ops {
		if o.Doc().Determinism == DetEmpirical {
			d = DetEmpirical
		}
	}
	return d
}

// Explain renders the decision chain behind a spec for `dpb strategy explain`
// and `dpb why`: what each op does, where the claim comes from, and how risky
// it is to a fragile TLS terminator.
func (s Strategy) Explain() []string {
	out := []string{fmt.Sprintf("spec %s", s.Label())}
	if s.IsPlain() {
		return append(out, "plain: the first message is sent unmodified (MEASUREMENTS.md §5.2 — always rung 1)")
	}
	for i, o := range s.ops {
		d := o.Doc()
		line := fmt.Sprintf("%d. %s (%s, %s, caps %s, risk %d): %s",
			i+1, canonToken(o, s.args[i]), d.Kind, d.Determinism, d.Caps, d.Risk, d.Summary)
		if d.Source != "" {
			line += " [" + d.Source + "]"
		}
		out = append(out, line)
	}
	return out
}

// Get parses, validates and canonicalises a spec against this registry.
func (r *Registry) Get(spec string) (Strategy, error) {
	toks, err := splitSpec(spec)
	if err != nil {
		return Strategy{}, err
	}

	type entry struct {
		op    Op
		args  Args
		step  Step
		token string
	}
	entries := make([]entry, 0, len(toks))
	seen := make(map[string]bool, len(toks))

	for _, tok := range toks {
		name, rawArgs, hasArgs := strings.Cut(tok, ":")
		name = strings.TrimSpace(name)
		if !isIdent(name) {
			return Strategy{}, fmt.Errorf("%w: %q is not an op name", ErrBadSpec, name)
		}
		op, ok := r.lookup(name)
		if !ok {
			return Strategy{}, fmt.Errorf("%w: %q; registered ops are %s",
				ErrUnknownOp, name, strings.Join(orNone(r.Names()), ", "))
		}
		if seen[name] {
			return Strategy{}, fmt.Errorf("%w: %q appears more than once in %q", ErrDuplicateOp, name, spec)
		}
		seen[name] = true
		// An op that exists only to give an honest error says so before its
		// parameters are looked at: the citation is the whole point of keeping
		// it registered instead of deleting it.
		if rej := op.Doc().Rejected; rej != "" {
			return Strategy{}, fmt.Errorf("%w: %s — %s", ErrOpRejected, name, rej)
		}

		args, err := parseArgs(name, rawArgs, hasArgs)
		if err != nil {
			return Strategy{}, err
		}
		doc := op.Doc()
		if unknown := args.Unknown(doc.ParamNames()...); len(unknown) > 0 {
			return Strategy{}, fmt.Errorf("%w: %s has no parameter %q; it accepts %s",
				ErrUnknownParam, name, unknown[0], strings.Join(orNone(doc.ParamNames()), ", "))
		}
		step, err := op.Compile(args)
		if err != nil {
			return Strategy{}, fmt.Errorf("%s: %w", name, err)
		}
		if step == nil {
			return Strategy{}, fmt.Errorf("%w: %s compiled to a nil step", ErrBadSpec, name)
		}
		entries = append(entries, entry{op: op, args: args, step: step, token: canonToken(op, args)})
	}

	ops := make([]Op, len(entries))
	for i, e := range entries {
		ops[i] = e.op
	}
	if err := checkComposition(ops); err != nil {
		return Strategy{}, err
	}

	// Kind order is execution order. The token tiebreak keeps the sort total
	// even for inputs the duplicate check does not reach, so canonicalisation
	// can never depend on the order the user happened to type.
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.op.Kind() != b.op.Kind() {
			return a.op.Kind() < b.op.Kind()
		}
		if a.op.Name() != b.op.Name() {
			return a.op.Name() < b.op.Name()
		}
		return a.token < b.token
	})

	s := Strategy{
		Steps: make([]Step, len(entries)),
		ops:   make([]Op, len(entries)),
		args:  make([]Args, len(entries)),
	}
	parts := make([]string, len(entries))
	for i, e := range entries {
		s.Steps[i], s.ops[i], s.args[i], parts[i] = e.step, e.op, e.args, e.token
	}
	s.Spec = strings.Join(parts, "|")
	return s, nil
}

// splitSpec breaks a pipeline into op tokens. "plain" is dropped: it names the
// absence of every op, so "plain" and "" parse to the same value.
func splitSpec(spec string) ([]string, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	raw := strings.Split(spec, "|")
	out := make([]string, 0, len(raw))
	for i, t := range raw {
		t = strings.TrimSpace(t)
		if t == "" {
			return nil, fmt.Errorf("%w: element %d of %q is empty", ErrBadSpec, i+1, spec)
		}
		if t == plainName {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

func parseArgs(op, raw string, hasArgs bool) (Args, error) {
	args := Args{}
	if !hasArgs {
		return args, nil
	}
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%w: %s has a ':' but no parameters", ErrBadSpec, op)
	}
	for _, kv := range strings.Split(raw, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			return nil, fmt.Errorf("%w: %s has an empty parameter", ErrBadSpec, op)
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("%w: %s parameter %q has no value; want key=value", ErrBadSpec, op, kv)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !isIdent(k) {
			return nil, fmt.Errorf("%w: %s parameter name %q is not an identifier", ErrBadSpec, op, k)
		}
		if v == "" {
			return nil, fmt.Errorf("%w: %s parameter %q has an empty value", ErrBadValue, op, k)
		}
		if _, dup := args[k]; dup {
			return nil, fmt.Errorf("%w: %s sets %q twice", ErrBadSpec, op, k)
		}
		args[k] = v
	}
	return args, nil
}

// canonToken renders one op in canonical form: parameters sorted by key, values
// normalised, values equal to the declared default omitted.
func canonToken(o Op, args Args) string {
	doc := o.Doc()
	defaults := make(map[string]string, len(doc.Params))
	for _, p := range doc.Params {
		defaults[p.Name] = p.Default
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := canonValue(args[k])
		if d, ok := defaults[k]; ok && d == v {
			continue
		}
		parts = append(parts, k+"="+v)
	}
	if len(parts) == 0 {
		return doc.Name
	}
	return doc.Name + ":" + strings.Join(parts, ",")
}

// canonValue normalises a parameter value so that equal values have equal text.
// It is idempotent by construction: an integer round-trips through Itoa, a
// position through Pos.String, and anything else is left alone.
func canonValue(v string) string {
	t := strings.TrimSpace(v)
	if t == "" {
		return t
	}
	if n, err := strconv.Atoi(t); err == nil {
		return strconv.Itoa(n)
	}
	if p, err := ParsePos(t); err == nil {
		return p.String()
	}
	return t
}

func orNone(s []string) []string {
	if len(s) == 0 {
		return []string{"(none registered)"}
	}
	return s
}
