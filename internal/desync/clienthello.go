package desync

import "encoding/binary"

const (
	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01
	extServerName            = 0x0000
	sniTypeHostName          = 0x00
)

// looksLikeTLS reports whether data begins with a TLS handshake record header.
func looksLikeTLS(data []byte) bool {
	return len(data) >= 3 && data[0] == recordTypeHandshake && data[1] == 0x03
}

// parseClientHello walks a TLS record holding a ClientHello and returns the SNI
// host name together with the absolute byte offset and length of the host-name
// value within data. ok is false when data is not a parseable ClientHello with
// a host_name SNI. The parser is bounds-checked and tolerates a buffer that
// holds only a prefix of the record.
func parseClientHello(data []byte) (sni string, off, length int, ok bool) {
	if len(data) < 5 || data[0] != recordTypeHandshake {
		return "", -1, 0, false
	}
	// Skip the 5-byte record header. We bound parsing by len(data) rather than
	// the declared record length so a truncated capture still parses as far as
	// it can.
	p := 5
	if p+4 > len(data) || data[p] != handshakeTypeClientHello {
		return "", -1, 0, false
	}
	p += 4      // handshake type (1) + handshake length (3)
	p += 2 + 32 // client version (2) + random (32)
	if p+1 > len(data) {
		return "", -1, 0, false
	}
	p += 1 + int(data[p]) // session id length + session id
	if p+2 > len(data) {
		return "", -1, 0, false
	}
	p += 2 + int(binary.BigEndian.Uint16(data[p:p+2])) // cipher suites
	if p+1 > len(data) {
		return "", -1, 0, false
	}
	p += 1 + int(data[p]) // compression methods
	if p+2 > len(data) {
		return "", -1, 0, false
	}
	extLen := int(binary.BigEndian.Uint16(data[p : p+2]))
	p += 2
	end := p + extLen
	if end > len(data) {
		end = len(data)
	}
	for p+4 <= end {
		etype := binary.BigEndian.Uint16(data[p : p+2])
		elen := int(binary.BigEndian.Uint16(data[p+2 : p+4]))
		p += 4
		if p+elen > end {
			break
		}
		if etype == extServerName {
			return parseSNIExtension(data, p, p+elen)
		}
		p += elen
	}
	return "", -1, 0, false
}

// parseSNIExtension parses the server_name extension body in data[start:limit].
func parseSNIExtension(data []byte, start, limit int) (sni string, off, length int, ok bool) {
	q := start
	if q+2 > limit { // server_name_list length
		return "", -1, 0, false
	}
	q += 2
	if q+3 > limit { // name type (1) + host-name length (2)
		return "", -1, 0, false
	}
	nameType := data[q]
	q++
	nameLen := int(binary.BigEndian.Uint16(data[q : q+2]))
	q += 2
	if nameType != sniTypeHostName || q+nameLen > limit {
		return "", -1, 0, false
	}
	return string(data[q : q+nameLen]), q, nameLen, true
}

// recordLength returns the declared TLS record payload length and whether the
// full record is present in data.
func recordLength(data []byte) (n int, complete bool) {
	if len(data) < 5 {
		return 0, false
	}
	n = int(binary.BigEndian.Uint16(data[3:5]))
	return n, 5+n <= len(data)
}
