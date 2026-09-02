package httpmsg

import "bytes"

// idempotentMethods is RFC 9110 §9.2.2's idempotent set. POST and PATCH are
// absent by definition; CONNECT is absent because replaying it would re-open a
// tunnel whose bytes have already been forwarded.
var idempotentMethods = [...]string{"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"}

// Replayable reports whether a buffered plaintext request may be re-sent
// verbatim on a fresh upstream connection.
//
// The ladder retries by redialling and rewriting the same first message. For TLS
// that is always safe — the ClientHello is the first thing on the wire, so a
// failed handshake has delivered nothing in either direction. Plaintext HTTP has
// no such guarantee, so this is the gate: an idempotent method, no request body,
// no protocol upgrade, and nothing buffered past the header block.
func Replayable(b []byte) bool {
	ok, _ := ReplayableReason(b)
	return ok
}

// ReplayableReason is Replayable with the reason it said no, for `dpb why` and
// for log lines that have to attribute a refusal to something concrete.
func ReplayableReason(b []byte) (bool, string) {
	r, err := Parse(b)
	if err != nil {
		return false, "not an HTTP/1.x request head"
	}
	if !r.Complete {
		return false, "header block is incomplete"
	}
	if !idempotentMethod(r.Method) {
		return false, "method " + r.Method + " is not idempotent"
	}
	if r.HeaderEnd < len(b) {
		// A body, or a pipelined second request. Either way, replaying the head
		// alone would truncate the stream and replaying everything would
		// duplicate bytes the origin may already have acted on.
		return false, "bytes follow the header block"
	}

	_, hdrStart, _ := lineAt(b, 0) // skip the request line; Parse proved it exists
	reason := ""
	forEachHeader(b, hdrStart, func(ns, ne, vs, ve int) bool {
		name, val := b[ns:ne], b[vs:ve]
		switch {
		case asciiEqualFold(name, "transfer-encoding"):
			reason = "request is chunked"
		case asciiEqualFold(name, "content-length") && !isZeroLength(val):
			reason = "request carries a body"
		case asciiEqualFold(name, "expect"):
			reason = "request uses Expect"
		case asciiEqualFold(name, "upgrade"):
			reason = "request asks for a protocol upgrade"
		case asciiEqualFold(name, "connection") && containsToken(val, "upgrade"):
			reason = "request asks for a protocol upgrade"
		}
		return reason == ""
	})
	if reason != "" {
		return false, reason
	}
	return true, ""
}

func idempotentMethod(m string) bool {
	for _, k := range idempotentMethods {
		if k == m {
			return true
		}
	}
	return false
}

// isZeroLength treats an explicit "Content-Length: 0" as bodyless and anything
// else — including a malformed value — as carrying a body.
func isZeroLength(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	for _, c := range v {
		if c != '0' {
			return false
		}
	}
	return true
}

// containsToken reports whether a comma-separated header value carries tok.
func containsToken(v []byte, tok string) bool {
	for _, f := range bytes.Split(v, []byte(",")) {
		f = bytes.TrimFunc(f, func(r rune) bool { return r == ' ' || r == '\t' })
		if asciiEqualFold(f, tok) {
			return true
		}
	}
	return false
}
