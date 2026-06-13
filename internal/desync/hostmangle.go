package desync

import "bytes"

// hostCase rewrites the plaintext HTTP "Host" header name to mixed case
// ("hOsT"). HTTP header names are case-insensitive (RFC 9110) so the server
// still routes correctly, but DPI matching the literal "Host:" fails.
type hostCase struct{}

func (hostCase) Name() string { return "host-case" }

func (hostCase) Transform(payload []byte, meta *Meta) ([]byte, error) {
	if meta.Protocol != ProtoHTTP {
		return payload, nil
	}
	return mangleHeaderName(payload, "host", "hOsT"), nil
}

// hostDot appends a trailing dot to the HTTP Host value (FQDN form). Servers
// treat "example.com." as "example.com" but exact-match DPI misses it.
type hostDot struct{}

func (hostDot) Name() string { return "host-dot" }

func (hostDot) Transform(payload []byte, meta *Meta) ([]byte, error) {
	if meta.Protocol != ProtoHTTP || meta.HostStart < 0 {
		return payload, nil
	}
	at := meta.HostStart + meta.HostLen
	if at > len(payload) {
		return payload, nil
	}
	out := make([]byte, 0, len(payload)+1)
	out = append(out, payload[:at]...)
	out = append(out, '.')
	out = append(out, payload[at:]...)
	return out, nil
}

// mangleHeaderName replaces a header name (matched case-insensitively, anchored
// at a line start) with an equal-length replacement, leaving the rest intact.
func mangleHeaderName(data []byte, lowerName, replacement string) []byte {
	if len(lowerName) != len(replacement) {
		return data
	}
	lower := bytes.ToLower(data)
	needle := append([]byte{'\n'}, append([]byte(lowerName), ':')...)
	idx := bytes.Index(lower, needle)
	if idx < 0 {
		return data
	}
	out := make([]byte, len(data))
	copy(out, data)
	nameStart := idx + 1 // skip the '\n'
	copy(out[nameStart:nameStart+len(replacement)], replacement)
	return out
}
