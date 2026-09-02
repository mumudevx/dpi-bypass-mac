package testcensor

import "net/netip"

// BlockedTT are the hostnames measured blocked on Türk Telekom AS9121 on
// 2026-09-02 (MEASUREMENTS.md §1). media.discordapp.net and discord.media are
// deliberately absent: both reach the origin (401 and 520), so listing them
// would make a prober chase a block that does not exist.
var BlockedTT = []string{
	"discord.com",
	"discord.gg",
	"gateway.discord.gg",
	"cdn.discordapp.com",
	"updates.discord.com",
}

// TT2026 is the measured Türk Telekom middlebox.
//
// Confidence: high, for the mechanism. 66 shuffled trials on 2026-09-02
// (MEASUREMENTS.md §3.2) walked the first record's end across the SNI hostname's
// extent with both records in ONE TCP segment, and found one clean boundary:
//
//	sniStart-20 .. sniEnd-1   3/3 through
//	sniEnd, +1, +20, +200     0/3 blocked
//
//	> The DPI parses only the first TLS record of a connection as a ClientHello.
//	> If the SNI hostname is not complete within that first record, the flow is
//	> not matched and passes.
//
// Two further measurements pin the other two flags. Every two-segment TCP split
// failed, including one cut inside the hostname, while two records inside a
// single segment passed on all three targets — so ReassembleTCP is true and TCP
// framing is irrelevant (§3.1). And the block is per-flow and stateless: 15
// back-to-back blocked attempts did not escalate to IP-level blackholing and did
// not penalise a benign SNI to the same address afterwards (§6), so
// BlockedAddrs is empty and there is no cross-flow state to model.
//
// What this model deliberately does NOT reproduce: §3.4's chunking results.
// chunk-4 and chunk-12 measured 3/3 through while chunk-5, chunk-8, chunk-20 and
// chunk-40 measured 0/3, which is non-monotonic in segment size and in segment
// count, and no single rule explains it. A model tuned to replay those numbers
// would be a lookup table wearing a hypothesis' clothes, and a prober tested
// against it would be scored on its ability to reproduce one afternoon in
// Kayseri. Under TT2026, chunking is honestly a non-bypass; §3.4's own
// conclusion is that it "belongs in the probe ladder as a fallback, not as the
// shipped default".
func TT2026(blocked ...string) Model {
	if len(blocked) == 0 {
		blocked = BlockedTT
	}
	return Model{
		Name:  "tt2026",
		Doc:   "Türk Telekom AS9121, Kayseri, 2026-09-02; MEASUREMENTS.md §3.1-§3.2, §6; confidence high (mechanism), 66+129 shuffled trials",
		Ports: []int{443},

		Blocked:         append([]string(nil), blocked...),
		RecordAware:     true,
		FirstRecordOnly: true,
		ReassembleTCP:   true,
		Action:          ActionReset,
	}
}

// Naive is the DPI the previous implementation was implicitly designed against:
// it scans the reassembled byte stream for a hostname with no notion of TLS
// records. It is here as a contrast, not as a claim about any real network — a
// strategy that evades Naive but not TT2026 is relying on string matching and
// will not work in Turkey.
func Naive(blocked ...string) Model {
	if len(blocked) == 0 {
		blocked = BlockedTT
	}
	return Model{
		Name:          "naive",
		Doc:           "hypothetical substring matcher; no measurement supports it; contrast model only",
		Ports:         []int{443},
		Blocked:       append([]string(nil), blocked...),
		ReassembleTCP: true,
		Action:        ActionReset,
	}
}

// noReassemblyWindow is how much of a flow NoReassembly reads before it gives
// up and forwards. One ClientHello and a little room: a middlebox that keeps
// scanning a bulk transfer for hostnames does not exist, and without a window
// the model would never reach a decision at all, only run out of segments.
const noReassemblyWindow = 4096

// NoReassembly is a middlebox that inspects each TCP segment on its own.
//
// It is a CONTRAST model and not a claim about Türk Telekom: §3.1 measured
// every two-segment split at 0/5 there, including one cut inside the hostname,
// which is exactly why TT2026 sets ReassembleTCP. This model is the other side
// of that measurement — the class of middlebox that inspects packets rather
// than streams, which is common enough that §3.1 had to be run to rule it out
// here, and which another Turkish ISP may well be.
//
// It exists because of a gap in the suite rather than a gap in the modelling.
// Every model in this package reassembles TCP, so no test anywhere could assert
// that a chunking emitter still chunks: rungs 3 and 4 of the shipped tr ladder
// were scored only as failures (see TestChunkDoesNotEvadeTT2026, which is an
// honest negative and stays), leaving nothing but shape assertions behind them.
// A change that kept the segment count and sizes intact while destroying the
// bypass property — writing the hostname contiguously into one segment — was
// invisible to the whole suite. Under this model that change is a test failure.
//
// The predicate it enforces is a mechanism, not a lookup table: a segment-wise
// scanner matches a hostname only when one segment carries the whole of it. It
// deliberately does NOT reproduce MEASUREMENTS.md §3.4's chunk curve. §3.4's
// own correction gives the measured necessary condition on the real line — the
// chunked prefix must extend past 5+sniEnd — but records in the same breath
// that the condition is not sufficient (size=20 covers 300 bytes and still
// fails), so there is no rule to encode. Modelling it anyway would be the
// lookup-table-in-a-hypothesis'-clothes that TT2026's doc comment refuses.
func NoReassembly(blocked ...string) Model {
	if len(blocked) == 0 {
		blocked = BlockedTT
	}
	return Model{
		Name: "noreassembly",
		Doc: "segment-wise hostname scanner; contrast model only — §3.1 measures Türk Telekom " +
			"as the opposite. Chunking evades it exactly when no single segment carries the " +
			"whole hostname.",
		Ports:         []int{443},
		Blocked:       append([]string(nil), blocked...),
		ReassembleTCP: false,
		InspectBytes:  noReassemblyWindow,
		Action:        ActionReset,
	}
}

// Open is an uncensored network. loss is the fraction of connections that fail
// for ordinary reasons; the prober is required to report "nothing is blocked
// here" against it rather than mistaking loss for censorship and inventing a
// winner.
func Open(loss float64) Model {
	return Model{
		Name:     "open",
		Doc:      "no censorship; LossRate models an ordinary lossy link",
		Action:   ActionDrop,
		LossRate: loss,
	}
}

// IPBlock blocks destinations outright, regardless of SNI. This is the shape a
// prober must recognise and stop on: when the benign-SNI control to the same
// address also fails, no desync strategy can exist, and continuing to search
// wastes the user's time on an unanswerable question.
func IPBlock(prefixes ...netip.Prefix) Model {
	return Model{
		Name:         "ipblock",
		Doc:          "address-level block; hypothetical for TT (§1 measures the opposite) but a real shape elsewhere",
		BlockedAddrs: append([]netip.Prefix(nil), prefixes...),
		Action:       ActionReset,
	}
}
