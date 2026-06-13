package desync

import "bytes"

// httpMethods are the request-line prefixes used to detect a plaintext HTTP
// request as the first payload.
var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
	[]byte("TRACE "),
}

func looksLikeHTTP(data []byte) bool {
	for _, m := range httpMethods {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}
	return false
}

// parseHTTPHost finds the Host header value span within an HTTP request.
// It returns the host, the absolute offset of the value, its length, and ok.
// The header name match is case-insensitive; leading optional whitespace after
// the colon is skipped so the returned offset points at the host value itself.
func parseHTTPHost(data []byte) (host string, valStart, valLen int, ok bool) {
	// Restrict the search to the header block (up to the blank line) so we do
	// not match a "Host:" appearing in a request body.
	block := data
	if idx := bytes.Index(data, []byte("\r\n\r\n")); idx >= 0 {
		block = data[:idx]
	}
	const needle = "\nhost:"
	lower := bytes.ToLower(block)
	rel := bytes.Index(lower, []byte(needle))
	if rel < 0 {
		return "", -1, 0, false
	}
	p := rel + len(needle) // points just past the colon
	// Skip optional whitespace between colon and value.
	for p < len(block) && (block[p] == ' ' || block[p] == '\t') {
		p++
	}
	// Value runs to end of line.
	q := p
	for q < len(block) && block[q] != '\r' && block[q] != '\n' {
		q++
	}
	if q <= p {
		return "", -1, 0, false
	}
	return string(block[p:q]), p, q - p, true
}
