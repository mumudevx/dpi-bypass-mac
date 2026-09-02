package testcensor

// FragileTR are the ten hosts that regressed under record splitting when 41
// Turkish sites were probed plain vs record-split on 2026-09-02
// (MEASUREMENTS.md §5). All ten are banks or .gov.tr. Not fragile, and therefore
// absent: garantibbva.com.tr, qnbfinansbank.com, teb.com.tr, nvi.gov.tr.
var FragileTR = []string{
	"www.akbank.com",
	"www.isbank.com.tr",
	"www.yapikredi.com.tr",
	"www.ziraatbank.com.tr",
	"www.vakifbank.com.tr",
	"www.denizbank.com",
	"www.turkiye.gov.tr",
	"www.gib.gov.tr",
	"www.mhrs.gov.tr",
	"www.btk.gov.tr",
}

// Fragile is a TLS terminator that refuses a ClientHello split across two
// records, modelling www.yapikredi.com.tr.
//
// Confidence: high, and it is the finding that decides the architecture.
// MEASUREMENTS.md §5: 10 of 41 Turkish hosts regressed under record splitting,
// and all ten were banks or .gov.tr. yapikredi answered with an explicit
// "remote error: tls: illegal parameter", which is the server rejecting a
// handshake message spanning two records — legal per RFC 8446 §5.1, but not
// universally implemented. The other nine failed with EOF or reset; see
// FragileEOF and FragileReset for those shapes.
//
// Nothing here is censorship. Fragile blocks no hostname and inspects no
// blocklist: a plain connection to it always succeeds. That is the whole point.
// §5.2 is a correctness requirement, not an optimisation — desync must be
// applied only after a plain attempt has failed, or this tool breaks online
// banking for the people it is meant to help.
func Fragile() Model {
	return Model{
		Name:                  "fragile",
		Doc:                   "Turkish bank / .gov.tr TLS terminator; MEASUREMENTS.md §5, www.yapikredi.com.tr; confidence high, 41 hosts probed",
		Ports:                 []int{443},
		RecordAware:           true,
		ReassembleTCP:         true,
		RejectSpanningRecords: true,
		RejectOOB:             true,
		Action:                ActionAlert,
		AlertDesc:             AlertIllegalParameter,
	}
}

// FragileEOF is the same terminator failing the way six of the ten measured
// hosts did — www.akbank.com, www.ziraatbank.com.tr, www.turkiye.gov.tr,
// www.gib.gov.tr, www.mhrs.gov.tr and www.btk.gov.tr all reported
// "handshake: EOF" (MEASUREMENTS.md §5). A ladder that only recognises a reset
// as a failure would hang here, so the shape is worth testing separately.
func FragileEOF() Model {
	m := Fragile()
	m.Name = "fragile-eof"
	m.Action = ActionEOF
	m.AlertDesc = 0
	return m
}

// FragileReset is the shape www.isbank.com.tr, www.vakifbank.com.tr and
// www.denizbank.com produced: "connection reset by peer" (MEASUREMENTS.md §5).
//
// This one is the trap. A reset before any server byte is exactly the signature
// the ladder escalates on, so a fragile bank looks identical to a censored host
// on the first attempt. What separates them is that the bank fails on the
// desynced rung and succeeds on plain, which is why the ladder must try plain
// FIRST and must cache "plain works" durably (§5.2, steps 1 and 4).
func FragileReset() Model {
	m := Fragile()
	m.Name = "fragile-reset"
	m.Action = ActionReset
	m.AlertDesc = 0
	return m
}
