package probe

import (
	"sort"
	"strings"

	"github.com/mumudevx/dpb/internal/strategy"
)

// Sweep depths. The depth changes how much of the measured space is swept and
// how many reps each point gets — never what the points are, because there is
// no honest source for a point MEASUREMENTS.md did not measure.
const (
	DepthQuick    = "quick"
	DepthFull     = "full"
	DepthParanoid = "paranoid"
)

// DepthReps is the rep count a depth implies when the caller did not set one.
//
// full is 3, the rep count MEASUREMENTS.md used throughout. quick is 2, which
// is enough to eliminate but not to rank confidently — Confidence downgrades a
// run below three reps for exactly that reason. paranoid is 5, and that is the
// only thing paranoid changes: the sweep set is identical to full, because
// §3.4 forbids inventing chunk sizes and there is no larger measured set to
// reach for.
func DepthReps(depth string) int {
	switch normDepth(depth) {
	case DepthQuick:
		return 2
	case DepthParanoid:
		return 5
	default:
		return 3
	}
}

func normDepth(d string) string {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case DepthQuick:
		return DepthQuick
	case DepthParanoid:
		return DepthParanoid
	default:
		return DepthFull
	}
}

// quickSpecs is the shortest sweep that can still separate the four mechanisms:
// one record reframer, one periodic reframer, one chunker, one urgent-byte
// rung, plus plain as the reference every rate is read against.
var quickSpecs = []string{
	"",
	"tlsfrag:pos=snimid",
	"tlsevery:period=64",
	"chunk:size=12",
	"oob:pos=1",
}

// Candidates expands the sweep against the default registry.
//
// It sweeps the discrete points MEASUREMENTS.md §3 and §3.4 actually measured
// and never binary-searches over chunk size: §3.4 records a curve that is
// non-monotonic and not explained by any simple model, so an interpolated size
// would be a number with no evidence behind it wearing the same label as one
// with evidence.
func Candidates(depth string, c Classification, caps strategy.Cap) []strategy.Strategy {
	return CandidatesWith(strategy.Default(), depth, c, caps)
}

// CandidatesWith expands the sweep against an explicit registry.
//
// The registry is a parameter because the default one is only populated by
// importing internal/ops, and a prober that silently swept an empty registry
// would report "nothing works here" on a line where everything does.
func CandidatesWith(reg *strategy.Registry, depth string, c Classification, caps strategy.Cap) []strategy.Strategy {
	if reg == nil {
		reg = strategy.Default()
	}
	specs := sweepSpecs(normDepth(depth))

	out := make([]strategy.Strategy, 0, len(specs))
	seen := make(map[string]bool, len(specs))
	for _, spec := range specs {
		s, err := reg.Get(spec)
		if err != nil {
			// An op this build does not register, or one registered only to
			// give a cited refusal. Either way it cannot be emitted, so it is
			// unmeasurable and must not enter the sweep as a candidate that
			// will then score 0 and look blocked.
			continue
		}
		if seen[s.Spec] {
			continue
		}
		if caps != 0 && !caps.Has(s.Caps()) {
			// The transport cannot carry this strategy. Same reasoning: an
			// unbuildable rung is unmeasurable, not blocked.
			continue
		}
		seen[s.Spec] = true
		out = append(out, s)
	}
	orderByClassification(out, c)
	return out
}

func sweepSpecs(depth string) []string {
	if depth == DepthQuick {
		return append([]string(nil), quickSpecs...)
	}
	specs, ok := strategy.LadderSpecs("probe-full")
	if !ok {
		return append([]string(nil), quickSpecs...)
	}
	return specs
}

// orderByClassification sorts the sweep so the axis the classifier saw working
// is tried first.
//
// This is ORDER, not membership. The whole set is still measured — a classifier
// that removed candidates would make the sweep incapable of contradicting it,
// and MEASUREMENTS.md §4 is explicit that one afternoon on one line is not a
// law. Ordering still matters: a run that hits its budget has measured the
// most promising family first, and elimination happens earliest where it is
// most likely.
//
// The sort is stable within a family, so the ladder order shipped in
// strategy.LadderSpecs survives, and plain is pinned first because every rate
// in the report is read against it.
func orderByClassification(ss []strategy.Strategy, c Classification) {
	prio := func(s strategy.Strategy) int {
		if s.IsPlain() {
			return 0
		}
		switch {
		case c.RecordFrag && isFamily(s.Spec, "tlsfrag", "tlsevery"):
			return 1
		case c.Chunking && isFamily(s.Spec, "chunk"):
			return 2
		case c.TCPSplit && isFamily(s.Spec, "split", "disorder"):
			return 3
		}
		return 4
	}
	sort.SliceStable(ss, func(i, j int) bool { return prio(ss[i]) < prio(ss[j]) })
}

// isFamily reports whether any op in the spec is one of the named ops. A
// composite counts as a member of every family it draws from, so
// "tlsfrag:pos=snimid|chunk:size=12" is promoted when either axis is live.
func isFamily(spec string, names ...string) bool {
	for _, tok := range strings.Split(spec, "|") {
		op := tok
		if i := strings.IndexByte(op, ':'); i >= 0 {
			op = op[:i]
		}
		op = strings.TrimSpace(op)
		for _, n := range names {
			if op == n {
				return true
			}
		}
	}
	return false
}
