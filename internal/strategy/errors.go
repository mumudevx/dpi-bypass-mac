package strategy

import "errors"

var (
	// ErrCutAfterSNI is the load-bearing validator. It fires when a reframing op
	// would leave the SNI hostname complete inside the first TLS record.
	//
	// MEASUREMENTS.md §3.2: at body=1497 with the SNI at [112,122), every first
	// record ending at sniEnd-1 or below passed 3/3 on two targets, and sniEnd,
	// sniEnd+1, sniEnd+20 and sniEnd+200 were blocked 0/3.
	ErrCutAfterSNI    = errors.New("strategy: first TLS record ends at or after sniEnd; the DPI would still match")
	ErrNeedComplete   = errors.New("strategy: op requires a complete first message")
	ErrNeedSNI        = errors.New("strategy: op requires a parsed server name")
	ErrCapUnavailable = errors.New("strategy: transport lacks a required capability")
	ErrBudget         = errors.New("strategy: plan exceeds the segment budget")
)

var (
	// ErrNeedHost is ErrNeedSNI's plaintext-HTTP counterpart, for the port-80
	// host mutators.
	ErrNeedHost = errors.New("strategy: op requires a parsed HTTP Host header")

	// ErrBadSpec covers a malformed expression: an empty pipeline element, a
	// parameter without a value, a duplicated parameter, a non-identifier name.
	ErrBadSpec = errors.New("strategy: malformed strategy expression")

	// ErrUnknownOp and ErrUnknownParam always name the offending token and list
	// what would have been accepted. A silently ignored key is the sni_match
	// class of trap this package exists to make impossible.
	ErrUnknownOp    = errors.New("strategy: unknown op")
	ErrUnknownParam = errors.New("strategy: unknown parameter")
	ErrBadValue     = errors.New("strategy: bad parameter value")

	// ErrDuplicateOp keeps canonicalisation total: two instances of the same op
	// have no defined relative order, so the spec would not round-trip.
	ErrDuplicateOp = errors.New("strategy: op named twice")

	ErrOneReframe   = errors.New("strategy: at most one reframing op per spec")
	ErrOneSchedule  = errors.New("strategy: at most one scheduling op per spec")
	ErrIncompatible = errors.New("strategy: ops cannot be combined")

	// ErrOpRejected is returned for an op that is registered only so that asking
	// for it produces an honest, cited error instead of "unknown op".
	ErrOpRejected = errors.New("strategy: op is registered but can never work here")

	// ErrStreamCorrupt fires when a plan's stream segments do not reassemble
	// into its payload. A bypass tool that corrupts a stream is worse than no
	// tool, so this is checked on every Build and fuzzed.
	ErrStreamCorrupt = errors.New("strategy: plan does not reproduce the payload byte for byte")

	// ErrDowngrade is what Builder.Strict turns a silent fallback into. The
	// prober must never score a strategy it did not actually emit.
	ErrDowngrade = errors.New("strategy: strict mode refuses a downgrade")

	ErrUnknownLadder = errors.New("strategy: unknown ladder")
)
