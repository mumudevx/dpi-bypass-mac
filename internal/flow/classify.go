package flow

import (
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/mumudevx/dpi-bypass-mac/internal/httpmsg"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// Failure is why an attempt ended. Retryable() is the whole point of the type:
// it separates the failures that are censorship-shaped, and therefore worth
// escalating the ladder for, from the ones where a retry would duplicate bytes
// the client has already seen.
type Failure uint8

const (
	FailNone Failure = iota
	FailDial
	FailResetBeforeResponse   // censorship-shaped: retry
	FailTimeoutBeforeResponse // censorship-shaped: retry
	FailResetAfterResponse    // NOT censorship-shaped: never retry
	FailNotReplayable
	FailBudget
)

func (f Failure) Retryable() bool {
	return f == FailResetBeforeResponse || f == FailTimeoutBeforeResponse
}

var failureNames = [...]string{
	"none", "dial", "reset-before-response", "timeout-before-response",
	"reset-after-response", "not-replayable", "budget",
}

func (f Failure) String() string {
	if int(f) >= len(failureNames) {
		return "invalid"
	}
	return failureNames[f]
}

// ErrNotReplayable is the failure a plaintext request with side effects gets
// instead of a ladder walk.
var ErrNotReplayable = errors.New("flow: the buffered first message may not be replayed on a fresh connection")

// Classify maps a wire error to a Failure.
//
// committed IS the commit guard, and it is the single most important input in
// this package. Retry is transparent for exactly one window: from the moment
// the client's first message is buffered until the moment the first upstream
// byte is about to reach the client. Inside that window nothing has been
// delivered in either direction, so re-dialling is invisible — MEASUREMENTS.md
// §5.2, and validated on the wire in §6 at 18/18 immediate retries. Outside it,
// a retry would replay bytes the client has already consumed, so every failure
// becomes FailResetAfterResponse and the error is surfaced instead.
//
// The default for an unrecognised error before commit is FailResetBeforeResponse.
// That is deliberate: a censor's failure modes are diverse (RST, silent drop,
// forged FIN, a truncated alert), nothing has been delivered yet, and the cost
// of being wrong is one extra round trip against a cost of a silently unbypassed
// connection.
func Classify(err error, committed bool) Failure {
	if err == nil {
		return FailNone
	}
	if committed {
		return FailResetAfterResponse
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return FailDial
	}
	if errors.Is(err, ErrNotReplayable) {
		return FailNotReplayable
	}
	if isTimeout(err) {
		return FailTimeoutBeforeResponse
	}
	// Everything else, IsReset(err) included, lands here.
	return FailResetBeforeResponse
}

// IsReset reports whether err is the abrupt end of a connection: an injected
// RST, a peer that vanished, or a clean close where a protocol reply was due.
//
// EOF counts. Six of the ten fragile Turkish hosts in MEASUREMENTS.md §5 failed
// with "handshake: EOF" rather than a reset, and a ladder that only recognises
// ECONNRESET as a failure hangs on them until a deadline.
func IsReset(err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, syscall.ECONNRESET),
		errors.Is(err, syscall.EPIPE),
		errors.Is(err, syscall.ECONNABORTED),
		errors.Is(err, io.EOF),
		errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, io.ErrClosedPipe):
		return true
	}
	return false
}

// IsTimeout reports whether err is a deadline rather than a refusal.
func IsTimeout(err error) bool { return isTimeout(err) }

// Replayable reports whether a buffered first message may be re-sent on a fresh
// upstream connection.
//
// A TLS ClientHello always may: it is the first thing on the wire and the
// handshake it opens either completed or did not. A plaintext HTTP request may
// only if it is idempotent and carries no body — replaying a POST would submit
// it twice, and the user would never know. Anything else is refused, because we
// cannot prove the protocol has not already committed the client to something.
func Replayable(payload []byte, m tlsmsg.Meta) bool {
	if len(payload) == 0 {
		// Nothing was sent, so a "retry" would send nothing again on a fresh
		// socket: identical inputs, identical result, one wasted round trip.
		return false
	}
	switch m.Proto {
	case tlsmsg.ProtoTLS:
		return true
	case tlsmsg.ProtoHTTP:
		return httpmsg.Replayable(payload)
	}
	return false
}
