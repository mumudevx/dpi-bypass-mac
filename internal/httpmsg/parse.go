// Package httpmsg parses and rewrites the head of a plaintext HTTP/1.x request.
//
// Every offset it reports is bounded to the header block. DOSSIER.md records
// that the previous implementation's mangleHeaderName searched the whole payload
// for the Host header rather than stopping at the header block, so a request
// body carrying the bytes "Host:" moved the mangling offsets onto
// application-controlled data. Here nothing outside the header block is ever
// looked at.
//
// The package is pure: no net, no os, no time.
package httpmsg

import (
	"bytes"
	"errors"
)

// MaxHead bounds the header-block scan. It matches flow.DefaultFirstMsgOpts.Max,
// so a request whose head is larger than the reader will ever buffer is reported
// as incomplete rather than walked.
const MaxHead = 64 << 10

var (
	// ErrNotRequest means the buffer does not begin with a complete, well-formed
	// HTTP/1.x request line.
	ErrNotRequest = errors.New("httpmsg: not an HTTP/1.x request head")
	// ErrIncomplete means the header block is not terminated in the buffer.
	ErrIncomplete = errors.New("httpmsg: header block is not complete")
	// ErrNoHost means the header block carries no Host header.
	ErrNoHost = errors.New("httpmsg: request carries no Host header")
)

// methods is the set of request methods we are willing to recognise. Anything
// else is not treated as HTTP at all, which keeps a binary protocol whose first
// bytes happen to be printable from being parsed as a request head.
var methods = [...]string{
	"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
}

// Request is the parse of a buffered HTTP/1.x request head.
//
// Every offset is absolute in the buffer that was parsed, and -1 when the field
// is absent. HostStart/HostEnd cover the hostname alone; ValueStart/ValueEnd
// cover the whole trimmed Host value including any ":port".
type Request struct {
	Method string
	Target string
	Minor  int // HTTP/1.<Minor>

	Complete  bool // the header-block terminator was found
	HeaderEnd int  // just past the terminating empty line; -1 when absent

	NameStart  int // the "Host" header's name token
	NameEnd    int
	ValueStart int // the trimmed Host value, port included
	ValueEnd   int
	HostStart  int // the hostname alone, port excluded
	HostEnd    int

	Host string
}

// HasHost reports whether a Host header value was located inside the header
// block.
func (r Request) HasHost() bool { return r.HostStart >= 0 && r.HostEnd > r.HostStart }

func emptyRequest() Request {
	return Request{
		Minor: -1, HeaderEnd: -1,
		NameStart: -1, NameEnd: -1,
		ValueStart: -1, ValueEnd: -1,
		HostStart: -1, HostEnd: -1,
	}
}

// Detect reports whether b could be the start of an HTTP/1.x request. It is
// prefix-tolerant on purpose: the caller sees one byte before it decides how
// long to keep reading, and a wrong "not HTTP" answer there costs a stalled
// connection.
func Detect(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, m := range methods {
		if len(b) < len(m) {
			if string(b) == m[:len(b)] {
				return true
			}
			continue
		}
		if string(b[:len(m)]) != m {
			continue
		}
		// A method name must be followed by a single space; "GETX /" is not a
		// request and must not be parsed as one.
		return len(b) == len(m) || b[len(m)] == ' '
	}
	return false
}

// Need reports how many more bytes are required before the header block is
// complete. ok=false means the buffer is not an HTTP request head and the caller
// must stop waiting instead of operating on a prefix.
//
// While the head is still incomplete the want is 1: HTTP/1.x declares no length
// for its header block, so "at least one more byte" is the only honest answer.
func Need(b []byte) (want int, ok bool) {
	if !Detect(b) {
		return 0, false
	}
	r, err := Parse(b)
	switch {
	case err == nil && r.Complete:
		return 0, true
	case err == nil:
		return 1, true
	case lineComplete(b):
		// The request line is fully buffered and still does not parse, so more
		// bytes will never rescue it.
		return 0, false
	default:
		return 1, true
	}
}

// Parse walks the request line and the header block. It returns ErrNotRequest
// when the request line is absent or malformed; a truncated header block is not
// an error, it is Complete == false with whatever was located so far.
func Parse(b []byte) (Request, error) {
	r := emptyRequest()

	end, next, ok := lineAt(b, 0)
	if !ok {
		return r, ErrNotRequest
	}
	line := b[:end]

	sp1 := bytes.IndexByte(line, ' ')
	if sp1 <= 0 {
		return r, ErrNotRequest
	}
	sp2 := bytes.LastIndexByte(line, ' ')
	if sp2 <= sp1+1 || sp2+1 >= len(line) {
		return r, ErrNotRequest // no target, or no version after it
	}
	method := string(line[:sp1])
	if !knownMethod(method) {
		return r, ErrNotRequest
	}
	ver := line[sp2+1:]
	if len(ver) != 8 || string(ver[:7]) != "HTTP/1." || ver[7] < '0' || ver[7] > '9' {
		return r, ErrNotRequest
	}
	r.Method = method
	r.Target = string(line[sp1+1 : sp2])
	r.Minor = int(ver[7] - '0')

	headerEnd, complete := forEachHeader(b, next, func(ns, ne, vs, ve int) bool {
		if r.HasHost() || !asciiEqualFold(b[ns:ne], "host") {
			return true
		}
		r.NameStart, r.NameEnd = ns, ne
		r.ValueStart, r.ValueEnd = vs, ve
		r.HostStart, r.HostEnd = hostSpan(b, vs, ve)
		r.Host = string(b[r.HostStart:r.HostEnd])
		return true
	})
	r.Complete = complete
	if complete {
		r.HeaderEnd = headerEnd
	}
	return r, nil
}

// forEachHeader walks header lines starting at off, stopping at the header-block
// terminator, at the end of the buffer, or at MaxHead. fn returning false stops
// the walk early. It is the single place that decides what "inside the header
// block" means, so Parse, the mutators and Replayable can never disagree about
// it.
func forEachHeader(b []byte, off int, fn func(nameStart, nameEnd, valStart, valEnd int) bool) (headerEnd int, complete bool) {
	limit := len(b)
	if limit > MaxHead {
		limit = MaxHead
	}
	i := off
	for i <= limit {
		end, next, ok := lineAt(b[:limit], i)
		if !ok {
			return -1, false
		}
		if end == i { // the empty line terminating the header block
			return next, true
		}
		if colon := bytes.IndexByte(b[i:end], ':'); colon > 0 {
			ns, ne := i, i+colon
			vs, ve := ne+1, end
			for vs < ve && isOWS(b[vs]) {
				vs++
			}
			for ve > vs && isOWS(b[ve-1]) {
				ve--
			}
			if !fn(ns, ne, vs, ve) {
				return -1, false
			}
		}
		i = next
	}
	return -1, false
}

// lineAt returns the end of the line starting at off (excluding CRLF or LF) and
// the offset of the next line. ok is false when the line is not terminated in b.
func lineAt(b []byte, off int) (end, next int, ok bool) {
	if off > len(b) {
		return 0, 0, false
	}
	nl := bytes.IndexByte(b[off:], '\n')
	if nl < 0 {
		return 0, 0, false
	}
	end = off + nl
	next = end + 1
	if end > off && b[end-1] == '\r' {
		end--
	}
	return end, next, true
}

// lineComplete reports whether the first line is fully buffered.
func lineComplete(b []byte) bool {
	_, _, ok := lineAt(b, 0)
	return ok
}

// hostSpan trims a ":port" suffix, keeping an IPv6 literal's brackets intact.
func hostSpan(b []byte, vs, ve int) (int, int) {
	if vs >= ve {
		return vs, ve
	}
	if b[vs] == '[' {
		if i := bytes.IndexByte(b[vs:ve], ']'); i >= 0 {
			return vs, vs + i + 1
		}
		return vs, ve
	}
	if i := bytes.LastIndexByte(b[vs:ve], ':'); i >= 0 {
		return vs, vs + i
	}
	return vs, ve
}

func knownMethod(m string) bool {
	for _, k := range methods {
		if k == m {
			return true
		}
	}
	return false
}

func isOWS(c byte) bool { return c == ' ' || c == '\t' }

func asciiLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func asciiEqualFold(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := range b {
		if asciiLower(b[i]) != asciiLower(s[i]) {
			return false
		}
	}
	return true
}
