package desync

import "context"

// defaultDecoySNI is the benign hostname used in fake decoy ClientHellos.
const defaultDecoySNI = "www.google.com"

// fakeTTL implements GoodbyeDPI's auto-ttl family: before the real ClientHello
// it injects a decoy ClientHello (benign SNI) with a TTL low enough to expire
// between the DPI box and the server. The DPI inspects the decoy SNI and
// whitelists the flow; the decoy dies in transit so the server never sees it;
// the real ClientHello then goes through normally.
//
// Packet-level; only effective on the TUN path where a RawInjector is present.
// In proxy mode (no injector) it degrades to a plain SNI split.
type fakeTTL struct {
	ttl     int
	decoSNI string
}

func (fakeTTL) Name() string { return "fake-ttl" }

func (f fakeTTL) Emit(ctx context.Context, conn Conn, data []byte, meta *Meta) error {
	inj := conn.RawInjector()
	if inj == nil {
		return tlsRecordFrag{}.Emit(ctx, conn, data, meta)
	}
	src, dst := inj.Endpoints()
	if !dst.Addr().Is4() || !src.Addr().Is4() {
		return tlsRecordFrag{}.Emit(ctx, conn, data, meta)
	}
	ttl := f.ttl
	if ttl <= 0 {
		ttl = 6
	}
	seg := buildIPv4TCP(segParams{
		src:     src,
		dst:     dst,
		seq:     inj.BaseSeq(),
		flags:   tcpFlagPSH | tcpFlagACK,
		ttl:     uint8(ttl),
		payload: buildDecoyClientHello(orString(f.decoSNI, defaultDecoySNI)),
	})
	_ = inj.InjectSegment(seg) // best effort; the real write is what must succeed
	_, err := conn.Write(data)
	return err
}

// fakeSeq injects a decoy ClientHello with a wrong (out-of-window) sequence
// number so the server discards it while the DPI still inspects the decoy SNI.
type fakeSeq struct {
	decoSNI string
}

func (fakeSeq) Name() string { return "fake-seq" }

func (f fakeSeq) Emit(ctx context.Context, conn Conn, data []byte, meta *Meta) error {
	inj := conn.RawInjector()
	if inj == nil {
		return tlsRecordFrag{}.Emit(ctx, conn, data, meta)
	}
	src, dst := inj.Endpoints()
	if !dst.Addr().Is4() || !src.Addr().Is4() {
		return tlsRecordFrag{}.Emit(ctx, conn, data, meta)
	}
	seg := buildIPv4TCP(segParams{
		src:     src,
		dst:     dst,
		seq:     inj.BaseSeq() - 0x10000, // far outside the window → server drops it
		flags:   tcpFlagPSH | tcpFlagACK,
		ttl:     64,
		payload: buildDecoyClientHello(orString(f.decoSNI, defaultDecoySNI)),
	})
	_ = inj.InjectSegment(seg)
	_, err := conn.Write(data)
	return err
}

func orString(s, def string) string {
	if s != "" {
		return s
	}
	return def
}
