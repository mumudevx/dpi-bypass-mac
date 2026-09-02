package strategy

import (
	"fmt"
	"sort"
	"strings"
)

// Ladders are data, not code. Each rung is a spec string; Registry.Ladder
// parses them, which is also what proves at load time that every op a ladder
// names is actually registered in this build.
//
// Rung 1 of every escalation ladder is plain. MEASUREMENTS.md §5.2: no emitter
// is both a bypass and universally safe (§5.1 measures tlsrec at 1/20 on
// fragile hosts and oob at 0/20), so connecting undesynced first is a
// correctness requirement rather than an optimisation.
var ladders = map[string][]string{
	// tr is lifted verbatim from MEASUREMENTS.md §5.3, with each rung's measured
	// two-axis score. Türk Telekom AS9121, 2026-09-02.
	//
	//   1. ""                  plain      0/6 bypass · 8/8 controls · 20/20 fragile
	//   2. tlsfrag:pos=snimid  §3.2/§5.1  6/6 bypass · 8/8 controls ·  1/20 fragile
	//   3. chunk:size=12       §3.4/§5.1  6/6 bypass · 8/8 controls · 14/20 fragile
	//   4. chunk:size=4        §3.4/§5.1  6/6 bypass · 6/8 controls · 13/20 fragile
	//   5. oob:pos=1           §3/§5.1    6/6 bypass · 6/8 controls ·  0/20 fragile
	//
	// disorder (0/10, §3.5) and split (0/5, §3.1) are registered, tested ops and
	// are deliberately absent: the DPI reassembles TCP, so neither can help on
	// this line. They stay in probe-full because another ISP may differ and the
	// prober measures rather than assumes.
	"tr": {
		"",
		"tlsfrag:pos=snimid",
		"chunk:size=12",
		"chunk:size=4",
		"oob:pos=1",
	},

	// global is the ladder for a line nobody has measured. It is a structural
	// choice, not a measurement: rule-based ops first (their correctness follows
	// from the record predicate rather than from a constant that worked once),
	// then the empirical ones, and no oob — §5.1 scores it 0/20 against fragile
	// terminators, which is too destructive to reach for on an unknown network.
	// The shipped global.toml still selects ladder = "tr", because TR is the
	// only line this project has first-hand data for.
	"global": {
		"",
		"tlsfrag:pos=snimid",
		"tlsevery:period=64",
		"chunk:size=12",
		"chunk:size=4",
	},

	// probe-full is the prober's sweep: the discrete points actually measured in
	// MEASUREMENTS.md §3 and §3.4, never a binary search, because §3.4's chunk
	// curve is non-monotonic and unexplained by any model. Known-failing points
	// are included on purpose — the prober's job is to measure this line, not to
	// replay Kayseri.
	"probe-full": {
		"",

		// §3.2's cut positions, the fourteen points the record rule was derived
		// from. Everything at or past sniEnd is refused by the validator, so the
		// sweep stops at sniend-1.
		"tlsfrag:pos=snistart-20",
		"tlsfrag:pos=snistart-1",
		"tlsfrag:pos=snistart",
		"tlsfrag:pos=snistart+1",
		"tlsfrag:pos=snimid",
		"tlsfrag:pos=sniend-1",

		// §3: every-16 and every-64 pass, every-256 fails, and the record rule
		// explains all three. 128 is the untested midpoint.
		"tlsevery:period=16",
		"tlsevery:period=64",
		"tlsevery:period=128",
		"tlsevery:period=256",

		// §3.4 runs A and B, verbatim.
		"chunk:size=1",
		"chunk:size=2",
		"chunk:size=3",
		"chunk:size=4",
		"chunk:size=5",
		"chunk:size=8",
		"chunk:size=12",
		"chunk:size=20",
		"chunk:size=35",
		"chunk:size=40",
		"chunk:size=60",
		"chunk:size=120",

		// §3.1 measures every plain TCP split at 0/5 and §3.5 measures disorder
		// at 0/10 on this DPI. Swept anyway: a middlebox that does not reassemble
		// TCP would light both up.
		"split:pos=1",
		"split:pos=2",
		"split:pos=3",
		"split:pos=5",
		"split:pos=snimid",
		"disorder:pos=1",
		"disorder:pos=3",
		"disorder:pos=snimid",
		"oob:pos=1",
		"oob:pos=3",

		// Composites: whether reframing and chunking are independent axes here.
		"tlsfrag:pos=snimid|chunk:size=12",
		"tlsevery:period=64|chunk:size=4",

		// Port 80.
		"hostcase|hostdot|chunk:size=12",
		"hostpad",
	},
}

// LadderNames lists the built-in ladders, sorted.
func LadderNames() []string {
	out := make([]string, 0, len(ladders))
	for n := range ladders {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// LadderSpecs returns a named ladder's raw spec strings. The slice is a copy,
// so a caller cannot rewrite the shipped data.
func LadderSpecs(name string) ([]string, bool) {
	s, ok := ladders[name]
	if !ok {
		return nil, false
	}
	return append([]string(nil), s...), true
}

// Ladder resolves a named ladder against the default registry.
func Ladder(name string) ([]Strategy, error) { return Default().Ladder(name) }

// ParseLadder resolves the `--ladder` flag, which takes either a built-in
// ladder's name or a comma-separated list of specs. An explicit list is used
// exactly as given, including its first rung: an operator who writes one is
// overriding policy on purpose.
func ParseLadder(s string) ([]Strategy, error) { return Default().ParseLadder(s) }

// ParseLadder resolves a name or a comma-separated spec list against this
// registry.
func (r *Registry) ParseLadder(s string) ([]Strategy, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return nil, fmt.Errorf("%w: empty ladder", ErrUnknownLadder)
	}
	if _, ok := ladders[t]; ok {
		return r.Ladder(t)
	}
	if !strings.Contains(t, ",") && isIdent(t) && !strings.Contains(t, ":") {
		// A bare identifier that is neither a ladder nor an op reads as a typoed
		// ladder name, and "unknown op" would send the reader in the wrong
		// direction.
		if _, isOp := r.lookup(t); !isOp {
			return nil, fmt.Errorf("%w: %q; have %s", ErrUnknownLadder, t, strings.Join(LadderNames(), ", "))
		}
	}
	parts := strings.Split(t, ",")
	out := make([]Strategy, 0, len(parts))
	for i, p := range parts {
		st, err := r.Get(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("ladder rung %d (%q): %w", i+1, p, err)
		}
		out = append(out, st)
	}
	return out, nil
}
