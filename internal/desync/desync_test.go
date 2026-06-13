package desync

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

// buildClientHello constructs a minimal but valid TLS ClientHello record with
// the given SNI so parser/emitter tests are deterministic.
func buildClientHello(sni string) []byte {
	host := []byte(sni)

	var list bytes.Buffer
	list.WriteByte(sniTypeHostName)
	_ = binary.Write(&list, binary.BigEndian, uint16(len(host)))
	list.Write(host)

	var extData bytes.Buffer
	_ = binary.Write(&extData, binary.BigEndian, uint16(list.Len()))
	extData.Write(list.Bytes())

	var sniExt bytes.Buffer
	sniExt.Write([]byte{0x00, 0x00}) // extension type: server_name
	_ = binary.Write(&sniExt, binary.BigEndian, uint16(extData.Len()))
	sniExt.Write(extData.Bytes())

	var hs bytes.Buffer
	hs.Write([]byte{0x03, 0x03})             // client version
	hs.Write(make([]byte, 32))               // random
	hs.WriteByte(0x00)                       // session id length
	hs.Write([]byte{0x00, 0x02, 0x00, 0x2f}) // cipher suites
	hs.Write([]byte{0x01, 0x00})             // compression methods
	_ = binary.Write(&hs, binary.BigEndian, uint16(sniExt.Len()))
	hs.Write(sniExt.Bytes())

	var handshake bytes.Buffer
	handshake.WriteByte(handshakeTypeClientHello)
	l := hs.Len()
	handshake.Write([]byte{byte(l >> 16), byte(l >> 8), byte(l)})
	handshake.Write(hs.Bytes())

	var rec bytes.Buffer
	rec.WriteByte(recordTypeHandshake)
	rec.Write([]byte{0x03, 0x01})
	_ = binary.Write(&rec, binary.BigEndian, uint16(handshake.Len()))
	rec.Write(handshake.Bytes())
	return rec.Bytes()
}

// fakeConn records each Write separately so tests can assert split boundaries.
type fakeConn struct{ writes [][]byte }

func (f *fakeConn) Write(p []byte) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	f.writes = append(f.writes, b)
	return len(p), nil
}
func (f *fakeConn) SetTTL(int) error         { return ErrUnsupported }
func (f *fakeConn) RawInjector() RawInjector { return nil }
func (f *fakeConn) joined() []byte           { return bytes.Join(f.writes, nil) }

func TestParseClientHello(t *testing.T) {
	data := buildClientHello("example.com")
	sni, off, l, ok := parseClientHello(data)
	if !ok {
		t.Fatal("expected SNI to parse")
	}
	if sni != "example.com" {
		t.Fatalf("sni = %q, want example.com", sni)
	}
	if got := string(data[off : off+l]); got != "example.com" {
		t.Fatalf("offset points at %q, want example.com", got)
	}
}

func TestParseClientHelloTruncated(t *testing.T) {
	data := buildClientHello("example.com")
	for n := 0; n < len(data); n++ {
		// Must never panic on a truncated buffer.
		_, _, _, _ = parseClientHello(data[:n])
	}
}

func TestParseNonTLS(t *testing.T) {
	m := Parse([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), 80)
	if m.Protocol != ProtoHTTP {
		t.Fatalf("protocol = %v, want http", m.Protocol)
	}
	if m.Host != "example.com" {
		t.Fatalf("host = %q", m.Host)
	}
}

func applyEmitter(t *testing.T, spec Spec, data []byte) *fakeConn {
	t.Helper()
	e, err := New(spec)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fc := &fakeConn{}
	port := 443
	if !looksLikeTLS(data) {
		port = 80
	}
	if err := e.Apply(context.Background(), fc, data, port); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return fc
}

func TestSplitAtSNIBreaksDomain(t *testing.T) {
	data := buildClientHello("blocked-site.example")
	_, sniOff, sniLen, _ := parseClientHello(data)
	fc := applyEmitter(t, Spec{Emitter: "split-at-sni"}, data)

	if len(fc.writes) != 2 {
		t.Fatalf("got %d writes, want 2", len(fc.writes))
	}
	if !bytes.Equal(fc.joined(), data) {
		t.Fatal("reassembled stream differs from original")
	}
	boundary := len(fc.writes[0])
	if boundary <= sniOff || boundary >= sniOff+sniLen {
		t.Fatalf("split boundary %d not inside SNI [%d,%d)", boundary, sniOff, sniOff+sniLen)
	}
}

func TestSplitAtOffset(t *testing.T) {
	data := buildClientHello("example.com")
	fc := applyEmitter(t, Spec{Emitter: "split-at-offset", SplitOffset: 3}, data)
	if len(fc.writes) != 2 || len(fc.writes[0]) != 3 {
		t.Fatalf("writes=%d first=%d, want 2 writes first=3", len(fc.writes), len(fc.writes[0]))
	}
	if !bytes.Equal(fc.joined(), data) {
		t.Fatal("stream corrupted")
	}
}

func TestMultiSplit(t *testing.T) {
	data := buildClientHello("example.com")
	fc := applyEmitter(t, Spec{Emitter: "multi-split", SplitSizes: []int{2, 3}}, data)
	if len(fc.writes) != 3 {
		t.Fatalf("got %d writes, want 3", len(fc.writes))
	}
	if len(fc.writes[0]) != 2 || len(fc.writes[1]) != 3 {
		t.Fatalf("chunk sizes = %d,%d want 2,3", len(fc.writes[0]), len(fc.writes[1]))
	}
	if !bytes.Equal(fc.joined(), data) {
		t.Fatal("stream corrupted")
	}
}

func TestTLSRecordFrag(t *testing.T) {
	data := buildClientHello("example.com")
	fc := applyEmitter(t, Spec{Emitter: "tls-record-frag"}, data)

	out := fc.joined()
	// Expect two handshake records that reassemble to the original handshake.
	r1Len, ok := recordLength(out)
	if !ok {
		t.Fatal("first record incomplete")
	}
	if out[0] != recordTypeHandshake {
		t.Fatal("first record not a handshake record")
	}
	rest := out[5+r1Len:]
	if len(rest) < 5 || rest[0] != recordTypeHandshake {
		t.Fatal("expected a second handshake record")
	}
	// Reassembled record payloads must equal the original record payload.
	origLen, _ := recordLength(data)
	r2Len, _ := recordLength(rest)
	reassembled := append(append([]byte{}, out[5:5+r1Len]...), rest[5:5+r2Len]...)
	if !bytes.Equal(reassembled, data[5:5+origLen]) {
		t.Fatal("fragmented records do not reassemble to original payload")
	}
}

func TestHostCaseTransform(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	fc := applyEmitter(t, Spec{Transformers: []string{"host-case"}, Emitter: "split-at-offset", SplitOffset: 5}, req)
	out := fc.joined()
	if !bytes.Contains(out, []byte("hOsT: example.com")) {
		t.Fatalf("host header not mangled: %q", out)
	}
	if bytes.Contains(out, []byte("Host:")) {
		t.Fatal("original Host: still present")
	}
}

func TestUnknownEmitter(t *testing.T) {
	if _, err := New(Spec{Emitter: "nope"}); err == nil {
		t.Fatal("expected error for unknown emitter")
	}
}
