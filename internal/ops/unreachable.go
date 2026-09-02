package ops

import (
	"fmt"

	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
)

// The unreachable family: ops that every other DPI-bypass tool ships and that
// cannot work on Darwin from user space.
//
// They are REGISTERED, not absent, and strategy.Registry.Get refuses them with
// their citation before it even looks at their parameters. That is deliberate.
// A user pasting a zapret or byedpi strategy string from a forum must be told
// which mechanism is impossible here and why, not "unknown op" — and the two
// answers send them in opposite directions. It also keeps the shape of the day
// a netstack-owned upstream endpoint exists: granting CapRawSeq lights the
// first four up unchanged.
//
// Two different reasons are represented:
//
//   - The sequence-number family needs the upstream connection's snd_nxt to
//     craft a segment that overlaps or precedes real data. On Darwin the only
//     user-space window into a TCP connection's state is
//     struct tcp_connection_info in netinet/tcp.h (TCP_CONNECTION_INFO), which
//     has no such field — verified against the macOS 26 SDK, zero matches. A
//     kernel socket therefore cannot report where its sequence space is, so
//     CapRawSeq is never granted and these ops can never be satisfied.
//
//   - The receive-window family needs socket knobs macOS does not honour:
//     SO_RCVBUF=1024 still advertises roughly 32 KB, TCP_MAXSEG returns EINVAL
//     on a connected socket, and macOS BPF is a device rather than an attachable
//     socket filter, so SACK cannot be suppressed per connection.
func unreachableOps() []strategy.Op {
	const seqReason = "needs the upstream connection's snd_nxt, and struct tcp_connection_info in " +
		"netinet/tcp.h has no such field on macOS (verified against the macOS 26 SDK), so a kernel " +
		"socket cannot report its sequence space and CapRawSeq is never granted"

	rejected := []struct {
		name    string
		kind    strategy.Kind
		caps    strategy.Cap
		params  []strategy.ParamDoc
		summary string
		why     string
	}{
		{
			name: "fake", kind: strategy.KindSchedule, caps: strategy.CapRawSeq,
			params:  []strategy.ParamDoc{{Name: "pos", Doc: "offset the decoy segment covers"}},
			summary: "inject a decoy TCP segment the origin never accepts",
			why:     seqReason,
		},
		{
			name: "seqovl", kind: strategy.KindSchedule, caps: strategy.CapRawSeq,
			params:  []strategy.ParamDoc{{Name: "pos", Doc: "overlap offset"}},
			summary: "sequence-overlapping decoy segment (zapret multidisorder seqovl)",
			why:     seqReason,
		},
		{
			name: "fakedsplit", kind: strategy.KindSchedule, caps: strategy.CapRawSeq,
			params:  []strategy.ParamDoc{{Name: "pos", Doc: "split offset"}},
			summary: "split with a decoy segment covering the first half",
			why:     seqReason,
		},
		{
			name: "hostfakesplit", kind: strategy.KindSchedule, caps: strategy.CapRawSeq,
			params:  []strategy.ParamDoc{{Name: "pos", Doc: "split offset inside the Host header"}},
			summary: "fakedsplit aimed at a plaintext Host header",
			why:     seqReason,
		},
		{
			name: "wssize", kind: strategy.KindSchedule,
			params:  []strategy.ParamDoc{{Name: "size", Doc: "receive window to advertise"}},
			summary: "shrink the advertised receive window so the server's response is split",
			why: "macOS does not honour a small SO_RCVBUF for the advertised window: setting it to 1024 " +
				"still advertises roughly 32 KB, so the server never splits its response",
		},
		{
			name: "mss", kind: strategy.KindSchedule,
			params:  []strategy.ParamDoc{{Name: "size", Doc: "maximum segment size to advertise"}},
			summary: "advertise a small MSS so the server's response is split",
			why:     "TCP_MAXSEG returns EINVAL on a connected socket on macOS; the option is read-only there",
		},
		{
			name: "dropsack", kind: strategy.KindSchedule,
			summary: "suppress SACK so a middlebox loses track of the stream",
			why: "macOS BPF is a device, not an attachable socket filter, so outbound SACK options cannot " +
				"be suppressed per connection from user space",
		},
	}

	out := make([]strategy.Op, 0, len(rejected))
	for _, r := range rejected {
		d := strategy.OpDoc{
			Name:        r.name,
			Kind:        r.kind,
			Caps:        r.caps,
			Determinism: strategy.DetEmpirical,
			Params:      r.params,
			Summary:     r.summary,
			Source:      "PLAN \"Capabilities per mode\"; DOSSIER §3 (P3)",
			Risk:        100,
			Rejected:    r.why,
		}
		out = append(out, newOp(d, func(strategy.Args) (strategy.Step, error) {
			// Unreachable in practice: Registry.Get refuses a Rejected op before
			// it compiles. Kept honest rather than returning nil, so a future
			// caller that bypasses Get still cannot emit anything.
			return strategy.StepFunc(d.Name, d.Caps, func(*strategy.Builder) error {
				return fmt.Errorf("%w: %s — %s", strategy.ErrOpRejected, d.Name, d.Rejected)
			}), nil
		}))
	}
	return out
}
