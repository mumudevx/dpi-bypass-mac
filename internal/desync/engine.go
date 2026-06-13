package desync

import (
	"context"
	"fmt"
)

// Parse classifies the first client payload and extracts the SNI (TLS) or Host
// (HTTP) location so strategies do not each re-parse.
func Parse(data []byte, dstPort int) Meta {
	m := Meta{Protocol: ProtoUnknown, DstPort: dstPort, SNIOffset: -1, HostStart: -1}
	switch {
	case len(data) > 0 && data[0] == recordTypeHandshake:
		m.Protocol = ProtoTLS
		if sni, off, l, ok := parseClientHello(data); ok {
			m.SNI, m.SNIOffset, m.SNILen = sni, off, l
		}
	case looksLikeHTTP(data):
		m.Protocol = ProtoHTTP
		if h, vs, vl, ok := parseHTTPHost(data); ok {
			m.Host, m.HostStart, m.HostLen = h, vs, vl
		}
	}
	return m
}

// Spec is the primitive engine configuration the config package builds from a
// region profile. It is intentionally free of any config-package types so the
// desync package stays dependency-free.
type Spec struct {
	Transformers []string // e.g. ["host-case"]
	Emitter      string   // exactly one; empty defaults to "split-at-sni"
	SplitOffset  int      // for split-at-offset
	SplitSizes   []int    // for multi-split
	FragWindow   int      // SpoofDPI-style: bytes before the first split point
	FakeTTL      int      // for fake-packet emitters (TUN only)
}

// Engine applies a transformer chain followed by a single emitter.
type Engine struct {
	transformers []Transformer
	emitter      Emitter
	spec         Spec
}

// New builds an Engine from a Spec, validating the composition rule.
func New(spec Spec) (*Engine, error) {
	e := &Engine{spec: spec}
	for _, name := range spec.Transformers {
		t, err := newTransformer(name)
		if err != nil {
			return nil, err
		}
		e.transformers = append(e.transformers, t)
	}
	emitterName := spec.Emitter
	if emitterName == "" {
		emitterName = "split-at-sni"
	}
	em, err := newEmitter(emitterName, spec)
	if err != nil {
		return nil, err
	}
	e.emitter = em
	return e, nil
}

// Emitter returns the active emitter's name (for the startup banner).
func (e *Engine) EmitterName() string { return e.emitter.Name() }

// TransformerNames returns the transformer chain names (for the banner).
func (e *Engine) TransformerNames() []string {
	names := make([]string, len(e.transformers))
	for i, t := range e.transformers {
		names[i] = t.Name()
	}
	return names
}

// Apply runs the chain against the first payload and writes it to conn.
func (e *Engine) Apply(ctx context.Context, conn Conn, first []byte, dstPort int) error {
	meta := Parse(first, dstPort)
	payload := first
	for _, t := range e.transformers {
		np, err := t.Transform(payload, &meta)
		if err != nil {
			return fmt.Errorf("transformer %s: %w", t.Name(), err)
		}
		payload = np
	}
	if len(e.transformers) > 0 {
		// Re-parse after mutation so offsets are valid for the emitter.
		meta = Parse(payload, dstPort)
	}
	return e.emitter.Emit(ctx, conn, payload, &meta)
}

func newTransformer(name string) (Transformer, error) {
	switch name {
	case "host-case":
		return hostCase{}, nil
	case "host-dot":
		return hostDot{}, nil
	default:
		return nil, fmt.Errorf("unknown transformer %q", name)
	}
}

func newEmitter(name string, spec Spec) (Emitter, error) {
	switch name {
	case "split-at-offset":
		return splitAtOffset{offset: spec.SplitOffset, window: spec.FragWindow}, nil
	case "split-at-sni":
		return splitAtSNI{window: spec.FragWindow}, nil
	case "multi-split":
		return multiSplit{sizes: spec.SplitSizes, window: spec.FragWindow}, nil
	case "tls-record-frag":
		return tlsRecordFrag{window: spec.FragWindow}, nil
	default:
		return nil, fmt.Errorf("unknown emitter %q", name)
	}
}

// KnownEmitters / KnownTransformers power `dpb profiles` validation and help.
func KnownEmitters() []string {
	return []string{"split-at-offset", "split-at-sni", "multi-split", "tls-record-frag"}
}

func KnownTransformers() []string {
	return []string{"host-case", "host-dot"}
}
