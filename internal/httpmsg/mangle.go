package httpmsg

import (
	"errors"
	"fmt"
)

// DefaultSpell is the Host header spelling used by HostCase. A DPI that matches
// the literal bytes "Host:" misses it; every RFC 9110 §5.1 conformant origin
// accepts it, because field names are case-insensitive.
const DefaultSpell = "hoSt"

// PadHeaderName is the name of the filler header HostPad inserts. The shortest
// line it can produce is len("X-Pad: \r\n") == MinPad bytes.
const PadHeaderName = "X-Pad"

// MinPad is the smallest pad that can be expressed as one well-formed header
// line, and MaxPad bounds the inflation so a mutator can never push the request
// head past MaxHead.
const (
	MinPad = len(PadHeaderName) + len(": ") + len("\r\n")
	MaxPad = 16 << 10
)

var (
	// ErrBadSpell means the requested Host spelling is not a case variant of
	// "host". Rewriting the name to anything else would change the header, not
	// its spelling.
	ErrBadSpell = errors.New("httpmsg: spelling is not a case variant of \"host\"")
	// ErrAlreadyDotted means the hostname already ends in a dot, so HostDot
	// would produce "example.com.." — invalid, and a mutator that silently
	// returns the input unchanged is the frag_window defect class.
	ErrAlreadyDotted = errors.New("httpmsg: hostname already ends with a dot")
	// ErrPadRange means the requested pad cannot be expressed as one header line.
	ErrPadRange = errors.New("httpmsg: pad size out of range")
	// ErrHostIsLiteral means the Host header carries an IP address rather than a
	// DNS name, where a trailing root dot is meaningless and, for a bracketed
	// IPv6 literal, would land outside the brackets and change nothing.
	ErrHostIsLiteral = errors.New("httpmsg: Host is an IP literal, not a DNS name")
)

// hostReq parses b and insists on a complete head with a Host header, which is
// the precondition every mutator shares. Mutating a prefix would move offsets
// onto bytes the client has not sent yet.
func hostReq(b []byte) (Request, error) {
	r, err := Parse(b)
	if err != nil {
		return r, err
	}
	if !r.Complete {
		return r, ErrIncomplete
	}
	if !r.HasHost() {
		return r, ErrNoHost
	}
	return r, nil
}

// HostCase rewrites the Host header name to DefaultSpell.
func HostCase(b []byte) ([]byte, error) { return HostSpell(b, DefaultSpell) }

// HostSpell rewrites the Host header name to the given spelling. The result is a
// fresh buffer; the input is never mutated, because a Plan is a pure value and
// the caller may still need the original bytes for a later ladder rung.
func HostSpell(b []byte, spell string) ([]byte, error) {
	if !asciiEqualFold([]byte(spell), "host") {
		return nil, fmt.Errorf("%w: %q", ErrBadSpell, spell)
	}
	r, err := hostReq(b)
	if err != nil {
		return nil, err
	}
	if string(b[r.NameStart:r.NameEnd]) == spell {
		return nil, fmt.Errorf("%w: header is already spelled %q", ErrBadSpell, spell)
	}
	out := make([]byte, len(b))
	copy(out, b)
	copy(out[r.NameStart:r.NameEnd], spell)
	return out, nil
}

// HostDot appends the DNS root dot to the hostname in the Host header
// ("example.com" -> "example.com."). The name still resolves and the origin
// still matches its vhost, but a DPI comparing against a dot-less list misses.
func HostDot(b []byte) ([]byte, error) {
	r, err := hostReq(b)
	if err != nil {
		return nil, err
	}
	if isIPLiteral(b[r.HostStart:r.HostEnd]) {
		return nil, ErrHostIsLiteral
	}
	if b[r.HostEnd-1] == '.' {
		return nil, ErrAlreadyDotted
	}
	out := make([]byte, 0, len(b)+1)
	out = append(out, b[:r.HostEnd]...)
	out = append(out, '.')
	out = append(out, b[r.HostEnd:]...)
	return out, nil
}

// isIPLiteral reports whether a Host value is an address: a bracketed IPv6
// literal, or a run of digits and dots.
func isIPLiteral(h []byte) bool {
	if len(h) == 0 {
		return false
	}
	if h[0] == '[' {
		return true
	}
	for _, c := range h {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

// HostPad inserts n bytes of filler header immediately before the Host header
// line, pushing the hostname further into the request.
//
// DOSSIER.md P2 records why this is a diagnostic rather than a shipped rung: if
// the smallest pad that works approaches the MTU, the DPI is not reassembling
// the stream and a plain split is the better fix. The prober reads the answer;
// the ladder does not carry it.
func HostPad(b []byte, n int) ([]byte, error) {
	if n < MinPad || n > MaxPad {
		return nil, fmt.Errorf("%w: %d not in [%d,%d]", ErrPadRange, n, MinPad, MaxPad)
	}
	r, err := hostReq(b)
	if err != nil {
		return nil, err
	}
	pad := make([]byte, 0, n)
	pad = append(pad, PadHeaderName...)
	pad = append(pad, ':', ' ')
	for len(pad) < n-2 {
		pad = append(pad, 'a')
	}
	pad = append(pad, '\r', '\n')

	out := make([]byte, 0, len(b)+n)
	out = append(out, b[:r.NameStart]...)
	out = append(out, pad...)
	out = append(out, b[r.NameStart:]...)
	return out, nil
}
