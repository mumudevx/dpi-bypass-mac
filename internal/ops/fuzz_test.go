package ops

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// FuzzPlanPreservesPayload is the invariant that makes this tool safe to leave
// running: a strategy can never corrupt a stream. The worst any op may do is
// fail to help.
//
// It fuzzes the first message, not the spec, because the spec grammar is fuzzed
// in internal/strategy and the interesting failure here is an op computing an
// offset against a buffer that does not have the shape it assumed — a truncated
// hello, a hello whose declared lengths lie, a plaintext request with no Host.
func FuzzPlanPreservesPayload(f *testing.F) {
	tls, _ := ttHello(f)
	http, _ := httpFixture("discord.com")
	quic, _ := quicFixture()
	f.Add(tls, 443, 0)
	f.Add(http, 80, 3)
	f.Add(quic, 443, 11)
	f.Add(tls[:200], 443, 1)
	f.Add([]byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01}, 443, 2)
	f.Add([]byte{}, 443, 4)

	r := NewRegistry()
	specs := fuzzSpecs()
	bud := strategy.DefaultBudget()
	mutators := map[string]bool{}
	for _, d := range r.Docs() {
		if d.Kind == strategy.KindMutate {
			mutators[d.Name] = true
		}
	}

	f.Fuzz(func(t *testing.T, payload []byte, port, which int) {
		if len(payload) > 1<<16 {
			t.Skip()
		}
		spec := specs[((which%len(specs))+len(specs))%len(specs)]
		s, err := r.Get(spec)
		if err != nil {
			t.Fatalf("shipped spec %q does not parse: %v", spec, err)
		}
		m := tlsmsg.Parse(payload, port)
		p, err := s.Build(payload, m, allCaps, bud)
		if err != nil {
			// A refusal is always allowed; an untyped one is not, because it is
			// how a caller ends up unable to tell "cannot apply here" from "the
			// emitter is broken".
			if !isTypedRefusal(err) {
				t.Fatalf("%s: untyped refusal: %v", spec, err)
			}
			return
		}
		if err := p.Validate(bud); err != nil {
			t.Fatalf("%s: plan does not validate: %v", spec, err)
		}
		if !bytes.Equal(p.StreamBytes(), p.Payload) {
			t.Fatalf("%s: StreamBytes() != Payload (%d vs %d bytes)", spec, len(p.StreamBytes()), len(p.Payload))
		}
		if p.WriteCount() > bud.MaxSegments {
			t.Fatalf("%s: %d writes, budget %d", spec, p.WriteCount(), bud.MaxSegments)
		}
		// A reframing op may only re-head the record layer: with no mutator in
		// the pipeline, the bytes the peer's TLS stack sees once it strips the
		// record headers must be exactly what the client wrote. (A KindMutate op
		// rewrites the handshake message on purpose, so the invariant does not
		// apply to a spec that carries one.)
		if !hasMutator(spec, mutators) {
			if body, ok := recordBodies(p.Payload); ok {
				orig, _ := recordBodies(payload)
				if !bytes.Equal(body, orig) {
					t.Fatalf("%s: record bodies changed", spec)
				}
			}
		}
	})
}

// hasMutator reports whether a spec names any KindMutate op.
func hasMutator(spec string, mutators map[string]bool) bool {
	for _, tok := range strings.Split(spec, "|") {
		name, _, _ := strings.Cut(tok, ":")
		if mutators[name] {
			return true
		}
	}
	return false
}

// recordBodies concatenates the bodies of every complete TLS record in b. ok is
// false when b is not a run of whole records, in which case there is nothing to
// compare.
func recordBodies(b []byte) ([]byte, bool) {
	var out []byte
	for len(b) > 0 {
		h, ok := tlsmsg.ParseHeader(b)
		if !ok || len(b) < 5+h.Length {
			return nil, false
		}
		out = append(out, b[5:5+h.Length]...)
		b = b[5+h.Length:]
	}
	return out, true
}

// fuzzSpecs is every shipped ladder rung plus the compositions the prober uses,
// deduplicated. Fuzzing the ops that actually ship is the point; the rejected
// family cannot be compiled at all.
func fuzzSpecs() []string {
	seen := map[string]bool{}
	var out []string
	for _, name := range strategy.LadderNames() {
		specs, _ := strategy.LadderSpecs(name)
		for _, s := range specs {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	for _, s := range []string{"tlspad:to=600", "quicfake:count=2,ttl=4", "hostspell:spell=HOST", "hostdot|hostcase"} {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// TestParameterIsLive fails if any numeric parameter of any op produces
// byte-identical output across its sweep.
//
// This is the regression test for the defect MEASUREMENTS.md §3.5 records: the
// previous implementation's record-fragmentation emitter shipped a frag_window
// knob that was read nowhere and changed nothing, and nobody noticed because
// nothing compared two settings' output. Every parameter here must move bytes,
// or move a segment boundary, or move a socket option — and if it cannot, it
// must not exist.
func TestParameterIsLive(t *testing.T) {
	tls, tm := ttHello(t)
	http, hm := httpFixture("discord.com")
	quic, qm := quicFixture()
	// A hello padded far enough that a 1200-byte sweep value still fits before
	// the SNI, so tlspad's own sweep can be exercised end to end.
	wide := helloAt(t, ttHost, 120, 4000)
	wm := tlsmsg.Parse(wide, 443)

	fixtures := []struct {
		name    string
		payload []byte
		meta    tlsmsg.Meta
	}{
		{"tls", tls, tm},
		{"wide", wide, wm},
		{"http", http, hm},
		{"quic", quic, qm},
	}

	for _, d := range NewRegistry().Docs() {
		if d.Rejected != "" {
			continue
		}
		for _, param := range d.Params {
			values := sweepValues(param)
			if len(values) < 2 {
				t.Errorf("%s: parameter %s declares %d probe values; a parameter with nothing to sweep "+
					"cannot be shown to be live", d.Name, param.Name, len(values))
				continue
			}
			t.Run(d.Name+"/"+param.Name, func(t *testing.T) {
				digests := map[string][]string{}
				for _, v := range values {
					spec := d.Name + ":" + param.Name + "=" + v
					if other, ok := otherRequired(d, param.Name); ok {
						spec += "," + other
					}
					for _, f := range fixtures {
						p, err := buildSpec(t, spec, f.payload, f.meta)
						if err != nil {
							continue // this parameter value does not apply to this message
						}
						digests[f.name] = append(digests[f.name], planDigest(p))
					}
				}
				live := false
				for _, ds := range digests {
					if len(ds) < 2 {
						continue
					}
					distinct := map[string]bool{}
					for _, d := range ds {
						distinct[d] = true
					}
					if len(distinct) > 1 {
						live = true
					}
				}
				if !live {
					t.Errorf("%s: %s produced byte-identical plans across %v on every fixture: the knob is inert",
						d.Name, param.Name, values)
				}
			})
		}
	}
}

// sweepValues is a parameter's declared probe set, with its default folded in.
func sweepValues(p strategy.ParamDoc) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range append(append([]string{}, p.Probe...), p.Default) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// otherRequired supplies the op's OTHER mandatory parameter, so that sweeping
// disorder's ttl or oob's junk still yields a compilable spec.
func otherRequired(d strategy.OpDoc, sweeping string) (string, bool) {
	for _, p := range d.Params {
		if p.Name == sweeping || p.Default != "" || len(p.Probe) == 0 {
			continue
		}
		return p.Name + "=" + p.Probe[0], true
	}
	return "", false
}

// planDigest renders a plan as the bytes and socket options that will reach the
// wire: segment kind, TTL, delay and content. Notes are excluded on purpose —
// a knob that only changes a log line is exactly the inert knob this test hunts.
func planDigest(p strategy.Plan) string {
	h := sha256.New()
	for _, s := range p.Segments {
		fmt.Fprintf(h, "%d|%d|%d|%d;", s.Kind, s.TTL, s.Delay, len(s.Data))
		h.Write(s.Data)
	}
	return strconv.Itoa(len(p.Segments)) + ":" + fmt.Sprintf("%x", h.Sum(nil)[:8])
}
