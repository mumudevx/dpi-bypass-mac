package flow

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mumudevx/dpb/internal/tlsmsg"
)

// MsgKind is what the first-message reader found on a connection.
type MsgKind uint8

const (
	MsgTLS MsgKind = iota
	MsgHTTP
	MsgOpaque
	MsgServerFirst // nothing arrived in FirstByteWait: relay now, buffer nothing
)

var msgKindNames = [...]string{"tls", "http", "opaque", "server-first"}

func (k MsgKind) String() string {
	if int(k) >= len(msgKindNames) {
		return "invalid"
	}
	return msgKindNames[k]
}

// FirstMsgOpts bounds the first-message read in both time and size. Every field
// is a bound, never a target: the reader returns the moment the message is
// complete.
type FirstMsgOpts struct {
	// FirstByteWait is how long we wait for the client to say anything at all.
	// Expiring is not an error: it is the positive detection of a server-first
	// protocol.
	FirstByteWait time.Duration
	// CompleteWait is how long we keep reading, after the first byte, for the
	// rest of the declared message. It is a PROGRESS deadline: every read that
	// adds bytes renews it, because a client that keeps handing over its hello
	// steadily is healthy however long it takes in total. Treating it as a
	// total budget truncated a genuine 1506-byte hello written in 200-byte
	// pieces 120 ms apart, and a truncated first message is refused by every
	// reframing op, so the connection goes out plain and unbypassed.
	CompleteWait time.Duration
	// MaxAssembly bounds the whole assembly from the first byte, so the
	// progress deadline cannot be renewed forever by a peer that dribbles one
	// byte just inside CompleteWait.
	MaxAssembly time.Duration
	// Max caps the buffer. A message larger than this is handed on truncated
	// rather than buffered without limit.
	Max int
}

// DefaultFirstMsgOpts is the shipped bound.
//
// 250 ms for the first byte is ~11x the 22 ms RST latency measured on the line
// this tool was built against (MEASUREMENTS.md §6) and is well inside the
// window in which a mail or FTP server sends its greeting, so a server-first
// protocol is detected in a quarter of a second and never buffered. 64 KiB
// matches httpmsg.MaxHead, so a request head this reader would truncate is one
// the parser would refuse to walk anyway.
//
// 2 s of MaxAssembly is the outer bound on a client that keeps making progress.
// It is ~90x the 22 ms RST latency of MEASUREMENTS.md §6 and far longer than any
// local application needs to hand over a hello it has already computed, so it
// bounds a pathological peer without ever cutting off a descheduled healthy one.
func DefaultFirstMsgOpts() FirstMsgOpts {
	return FirstMsgOpts{
		FirstByteWait: 250 * time.Millisecond,
		CompleteWait:  250 * time.Millisecond,
		MaxAssembly:   2 * time.Second,
		Max:           64 << 10,
	}
}

func (o FirstMsgOpts) withDefaults() FirstMsgOpts {
	d := DefaultFirstMsgOpts()
	if o.FirstByteWait <= 0 {
		o.FirstByteWait = d.FirstByteWait
	}
	if o.CompleteWait <= 0 {
		o.CompleteWait = d.CompleteWait
	}
	if o.MaxAssembly <= 0 {
		o.MaxAssembly = d.MaxAssembly
	}
	if o.Max <= 0 {
		o.Max = d.Max
	}
	return o
}

// readChunk is the per-Read buffer. A post-quantum ClientHello is ~1.5 KiB and
// arrives in two segments on a 1500-byte MTU, so 4 KiB assembles one in two
// reads without ever over-allocating for the common small hello.
const readChunk = 4 << 10

// deadliner is the part of net.Conn this reader needs. It is an interface
// rather than a net.Conn parameter so the reader stays testable against a
// bytes.Reader, but note the consequence documented on ReadFirstMessage: a
// reader without deadlines cannot express "the client said nothing".
type deadliner interface {
	SetReadDeadline(t time.Time) error
}

// ReadFirstMessage loops until the DECLARED first application message is
// complete. It NEVER performs a single un-looped Read: a post-quantum
// ClientHello is ~1512-1601 bytes and spans two segments on a 1500-byte MTU, and
// silently operating on a prefix is how the previous implementation degraded a
// record split into a 1-byte TCP split — the exact shape MEASUREMENTS.md §3.1
// measures at 0/5 while it looks like a working strategy in the logs.
//
// Three outcomes, all of them normal:
//
//   - The message completed. kind is MsgTLS/MsgHTTP/MsgOpaque and m.Complete is
//     true, so a reframing op may run.
//   - Nothing arrived within FirstByteWait. kind is MsgServerFirst, payload is
//     empty, err is nil, and the caller must relay both directions immediately.
//     SMTP, IMAP, POP3, FTP and MySQL all speak first; making them wait is the
//     deadlock the previous implementation shipped.
//   - A deadline or the size cap fired mid-message. The bytes read so far are
//     returned with m.Truncated set and m.Complete false, so every op requiring
//     a complete message refuses and the payload goes out plain.
//
// A non-nil error means the connection is unusable; payload may still hold
// whatever was read, for diagnostics only.
//
// If r does not implement SetReadDeadline, no bound is applied and
// MsgServerFirst can never be reported. Both front-ends pass a net.Conn.
func ReadFirstMessage(r io.Reader, port int, o FirstMsgOpts) (payload []byte, kind MsgKind, m tlsmsg.Meta, err error) {
	if r == nil {
		return nil, MsgOpaque, emptyMeta(port), errors.New("flow: read first message: nil reader")
	}
	o = o.withDefaults()

	dl, timed := r.(deadliner)
	if timed {
		// The relay that follows must not inherit our deadline.
		defer func() { _ = dl.SetReadDeadline(time.Time{}) }()
		if derr := dl.SetReadDeadline(time.Now().Add(o.FirstByteWait)); derr != nil {
			return nil, MsgOpaque, emptyMeta(port), fmt.Errorf("flow: read first message: set first-byte deadline: %w", derr)
		}
	}

	buf := make([]byte, 0, readChunk)
	tmp := make([]byte, readChunk)
	proto := tlsmsg.ProtoUnknown
	// assemblyEnds is the outer bound, armed by the first byte. Zero means
	// assembly has not started, so FirstByteWait is still the governing bound.
	var assemblyEnds time.Time

	for {
		room := o.Max - len(buf)
		if room <= 0 {
			return buf, kindOf(tlsmsg.Classify(buf, port)), parseWith(buf, port, true), nil
		}
		if room > len(tmp) {
			room = len(tmp)
		}
		n, rerr := r.Read(tmp[:room])
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if timed {
				// Renew the deadline on EVERY read that made progress.
				// Arming it once made CompleteWait a total assembly budget,
				// which contradicts this function's contract and cut off a
				// healthy client that simply took longer than 250 ms of wall
				// time to hand over its hello — a descheduled process, or an
				// app that computes between writes. MaxAssembly keeps the
				// renewal from being unbounded.
				now := time.Now()
				if assemblyEnds.IsZero() {
					assemblyEnds = now.Add(o.MaxAssembly)
				}
				deadline := now.Add(o.CompleteWait)
				if deadline.After(assemblyEnds) {
					deadline = assemblyEnds
				}
				if derr := dl.SetReadDeadline(deadline); derr != nil {
					return buf, kindOf(tlsmsg.Classify(buf, port)), parseWith(buf, port, true),
						fmt.Errorf("flow: read first message: set completion deadline: %w", derr)
				}
			}
		}

		if rerr != nil {
			if isTimeout(rerr) {
				if len(buf) == 0 {
					// The positive detection, not a failure: this peer speaks
					// second, so nothing may be buffered and nothing delayed.
					return nil, MsgServerFirst, emptyMeta(port), nil
				}
				return buf, kindOf(tlsmsg.Classify(buf, port)), parseWith(buf, port, true), nil
			}
			meta := parseWith(buf, port, len(buf) > 0)
			return buf, kindOf(meta.Proto), meta, fmt.Errorf("flow: read first message after %d byte(s): %w", len(buf), rerr)
		}
		if len(buf) == 0 {
			continue // a legal, empty, non-error Read
		}

		proto = tlsmsg.Classify(buf, port)
		want, ok := tlsmsg.Need(buf, proto)
		if !ok {
			// The shape is unrecognisable. Waiting for more of it would stall
			// the connection until a deadline for no gain, so hand it on as an
			// opaque prefix and let the ladder send it verbatim.
			return buf, MsgOpaque, parseWith(buf, port, false), nil
		}
		if want == 0 {
			return buf, kindOf(proto), parseWith(buf, port, false), nil
		}
		if len(buf) >= o.Max {
			return buf, kindOf(proto), parseWith(buf, port, true), nil
		}
	}
}

// parseWith parses the buffer and stamps Truncated, which only the reader can
// know: tlsmsg.Parse cannot tell a message that ended from one that was cut off.
func parseWith(buf []byte, port int, truncated bool) tlsmsg.Meta {
	m := tlsmsg.Parse(buf, port)
	if truncated && !m.Complete {
		m.Truncated = true
	}
	return m
}

func emptyMeta(port int) tlsmsg.Meta { return tlsmsg.Parse(nil, port) }

func kindOf(p tlsmsg.Proto) MsgKind {
	switch p {
	case tlsmsg.ProtoTLS:
		return MsgTLS
	case tlsmsg.ProtoHTTP:
		return MsgHTTP
	}
	return MsgOpaque
}

// isTimeout recognises a deadline, however it was spelled. os.ErrDeadlineExceeded
// is what net.Conn returns; context.DeadlineExceeded arrives from a cancelled
// dial; the net.Error probe catches everything else that calls itself a timeout.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}
