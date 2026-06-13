package desync

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
)

// injConn is a fake Conn whose RawInjector records injected segments.
type injConn struct {
	writes   [][]byte
	injector *recordingInjector
}

func (c *injConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte{}, p...))
	return len(p), nil
}
func (c *injConn) SetTTL(int) error { return ErrUnsupported }
func (c *injConn) RawInjector() RawInjector {
	if c.injector == nil {
		return nil
	}
	return c.injector
}

type recordingInjector struct {
	src, dst netip.AddrPort
	seq      uint32
	injected [][]byte
}

func (r *recordingInjector) InjectSegment(seg []byte) error {
	r.injected = append(r.injected, append([]byte{}, seg...))
	return nil
}
func (r *recordingInjector) Endpoints() (netip.AddrPort, netip.AddrPort) { return r.src, r.dst }
func (r *recordingInjector) BaseSeq() uint32                             { return r.seq }

func TestFakeTTLInjectsDecoyThenRealData(t *testing.T) {
	inj := &recordingInjector{
		src: netip.MustParseAddrPort("192.168.1.5:40000"),
		dst: netip.MustParseAddrPort("93.184.216.34:443"),
		seq: 1000,
	}
	conn := &injConn{injector: inj}
	e, err := New(Spec{Emitter: "fake-ttl", FakeTTL: 7, FakeSNI: "www.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	real := buildClientHello("blocked.example")
	if err := e.Apply(context.Background(), conn, real, 443); err != nil {
		t.Fatal(err)
	}

	if len(inj.injected) != 1 {
		t.Fatalf("injected %d decoys, want 1", len(inj.injected))
	}
	seg := inj.injected[0]
	if seg[8] != 7 {
		t.Fatalf("decoy TTL = %d, want 7", seg[8])
	}
	if sni, _, _, ok := parseClientHello(seg[40:]); !ok || sni != "www.example.org" {
		t.Fatalf("decoy SNI = %q ok=%v", sni, ok)
	}
	// The real ClientHello must be written verbatim after the decoy.
	if len(conn.writes) != 1 || !bytes.Equal(conn.writes[0], real) {
		t.Fatal("real ClientHello not written after decoy")
	}
}

func TestFakeSeqUsesWrongSequence(t *testing.T) {
	inj := &recordingInjector{
		src: netip.MustParseAddrPort("192.168.1.5:40000"),
		dst: netip.MustParseAddrPort("93.184.216.34:443"),
		seq: 0x20000,
	}
	conn := &injConn{injector: inj}
	e, _ := New(Spec{Emitter: "fake-seq"})
	if err := e.Apply(context.Background(), conn, buildClientHello("x.example"), 443); err != nil {
		t.Fatal(err)
	}
	if len(inj.injected) != 1 {
		t.Fatalf("injected %d, want 1", len(inj.injected))
	}
	// seq must be the wrong (out-of-window) value: base - 0x10000.
	got := uint32(inj.injected[0][24])<<24 | uint32(inj.injected[0][25])<<16 |
		uint32(inj.injected[0][26])<<8 | uint32(inj.injected[0][27])
	if got != 0x20000-0x10000 {
		t.Fatalf("decoy seq = %#x, want %#x", got, 0x20000-0x10000)
	}
}

func TestFakePacketFallsBackWithoutInjector(t *testing.T) {
	// No injector (proxy mode): fake-ttl must degrade to TLS record
	// fragmentation — not a no-op, and without corrupting the handshake.
	conn := &injConn{injector: nil}
	e, _ := New(Spec{Emitter: "fake-ttl"})
	data := buildClientHello("example.com")
	if err := e.Apply(context.Background(), conn, data, 443); err != nil {
		t.Fatal(err)
	}
	out := bytes.Join(conn.writes, nil)
	r1Len, ok := recordLength(out)
	if !ok || out[0] != recordTypeHandshake {
		t.Fatal("fallback did not produce a TLS record")
	}
	rest := out[5+r1Len:]
	if len(rest) < 5 || rest[0] != recordTypeHandshake {
		t.Fatal("expected a second handshake record from record fragmentation")
	}
	origLen, _ := recordLength(data)
	r2Len, _ := recordLength(rest)
	reassembled := append(append([]byte{}, out[5:5+r1Len]...), rest[5:5+r2Len]...)
	if !bytes.Equal(reassembled, data[5:5+origLen]) {
		t.Fatal("fallback corrupted the handshake payload")
	}
}
