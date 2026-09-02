package strategy_test

// The golden table: every shipped spec compiled against every canned first
// message, pinned to the exact bytes it produces.
//
// This is the regression net for the whole emitter set. A spec is a wire format
// — the prober serialises it, the verdict store caches it under a hostname,
// `dpb apply` imports one a stranger pasted into a forum — so a change that
// silently moves a record boundary, drops a segment, or renames a canonical
// form invalidates every cached verdict and every measurement taken before it.
// The digest is over what actually reaches the wire (segment kind, TTL, delay
// and bytes) and nothing else: a change to a note or a summary must NOT break
// these, and a change to a byte must.
//
// The table lives here rather than in internal/ops because it is the contract
// BETWEEN the two packages: strategy owns the Plan shape and the canonical
// spec, ops owns the bytes.
//
// This file is an external test package on purpose. internal/strategy's own
// test binary registers a stub op set into strategy.Default(), so the real set
// is compiled into a private registry here (ops.NewRegistry) and the two never
// collide.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/ops"
	"github.com/mumudevx/dpi-bypass-mac/internal/strategy"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

const goldenCaps = strategy.CapStreamWrite | strategy.CapNoDelay | strategy.CapSockTTL |
	strategy.CapOOB | strategy.CapUDPTTL | strategy.CapRawInject | strategy.CapDatagram

// goldenSpecs is every rung of every shipped ladder plus the ops that no ladder
// carries, so the table covers the whole emitter set rather than only the TR
// path.
func goldenSpecs(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, name := range strategy.LadderNames() {
		specs, ok := strategy.LadderSpecs(name)
		if !ok {
			t.Fatalf("ladder %q vanished", name)
		}
		for _, s := range specs {
			add(s)
		}
	}
	for _, s := range []string{
		"tlsfrag:pos=sniend-1",
		"tlsfrag:pos=1",
		"tlspad:to=600",
		"tlspad:to=600|tlsfrag:pos=snimid",
		"quicfake:count=2,ttl=4",
		"hostspell:spell=HOST",
		"hostdot|hostcase",
		"disorder:pos=3,ttl=2",
		"oob:pos=1,junk=97",
	} {
		add(s)
	}
	sort.Strings(out)
	return out
}

// The five canned first messages.
//
// tt is MEASUREMENTS.md §3.2's exact geometry: a 1497-byte ClientHello body
// with the SNI hostname at [112,122). classic is a small hello, wide is one
// whose hostname sits deep enough for a padding sweep, http is a plaintext
// request, and quic is a v1 Initial datagram.
func goldenFixtures(t *testing.T) []goldenFixture {
	t.Helper()
	return []goldenFixture{
		{name: "tt", payload: hello(t, "discord.gg", 112, 1497), port: 443},
		{name: "classic", payload: hello(t, "discord.com", 60, 300), port: 443},
		{name: "wide", payload: hello(t, "cdn.discordapp.com", 120, 4000), port: 443},
		{name: "http", payload: []byte("GET /api/v9/gateway HTTP/1.1\r\nHost: discord.com\r\nAccept: */*\r\n\r\n"), port: 80},
		{name: "quic", payload: quicInitial(), port: 443},
	}
}

type goldenFixture struct {
	name    string
	payload []byte
	port    int
}

func TestGoldenPlans(t *testing.T) {
	reg := ops.NewRegistry()
	bud := strategy.DefaultBudget()
	fixtures := goldenFixtures(t)
	specs := goldenSpecs(t)

	var missing []string
	for _, f := range fixtures {
		m := tlsmsg.Parse(f.payload, f.port)
		for _, spec := range specs {
			key := f.name + "|" + spec
			got := goldenLine(reg, spec, f.payload, m, bud)
			want, ok := golden[key]
			switch {
			case !ok:
				missing = append(missing, fmt.Sprintf("%q: %q,", key, got))
			case got != want:
				t.Errorf("%s\n got: %s\nwant: %s", key, got, want)
			}
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d golden entries missing; add to the table:\n%s", len(missing), strings.Join(missing, "\n"))
	}
	if len(golden) != len(specs)*len(fixtures) {
		t.Errorf("golden table has %d entries for %d specs x %d fixtures",
			len(golden), len(specs), len(fixtures))
	}
}

// goldenLine renders one (fixture, spec) outcome: either the typed refusal, or
// the plan's segment geometry and a digest of the bytes that reach the wire.
func goldenLine(reg *strategy.Registry, spec string, payload []byte, m tlsmsg.Meta, bud strategy.Budget) string {
	s, err := reg.Get(spec)
	if err != nil {
		return "parse-error: " + sentinel(err)
	}
	p, err := s.Build(payload, m, goldenCaps, bud)
	if err != nil {
		return "refused: " + sentinel(err)
	}
	if err := p.Validate(bud); err != nil {
		return "invalid: " + sentinel(err)
	}
	h := sha256.New()
	parts := make([]string, 0, len(p.Segments))
	for _, seg := range p.Segments {
		fmt.Fprintf(h, "%d|%d|%d|%d;", seg.Kind, seg.TTL, seg.Delay, len(seg.Data))
		h.Write(seg.Data)
		part := fmt.Sprintf("%s:%d", seg.Kind, len(seg.Data))
		if seg.TTL != 0 {
			part += fmt.Sprintf("/ttl%d", seg.TTL)
		}
		parts = append(parts, part)
	}
	return fmt.Sprintf("canon=%q %s sha=%x", s.String(), strings.Join(parts, ","), h.Sum(nil)[:6])
}

// sentinel names the typed error a refusal carries. The golden table records
// the sentinel, never the message text, so improving an error message does not
// break 200 test cases while a change of refusal REASON still does.
func sentinel(err error) string {
	for _, e := range []struct {
		name string
		err  error
	}{
		{"ErrCutAfterSNI", strategy.ErrCutAfterSNI},
		{"ErrNeedComplete", strategy.ErrNeedComplete},
		{"ErrNeedSNI", strategy.ErrNeedSNI},
		{"ErrNeedHost", strategy.ErrNeedHost},
		{"ErrCapUnavailable", strategy.ErrCapUnavailable},
		{"ErrBudget", strategy.ErrBudget},
		{"ErrOpRejected", strategy.ErrOpRejected},
		{"ErrStreamCorrupt", strategy.ErrStreamCorrupt},
		{"ErrNeedQUIC", ops.ErrNeedQUIC},
		{"ErrNotClientHello", ops.ErrNotClientHello},
		{"ErrAlreadyPadded", ops.ErrAlreadyPadded},
		{"ErrNotApplicable", ops.ErrNotApplicable},
		{"ErrBadValue", strategy.ErrBadValue},
	} {
		if errors.Is(err, e.err) {
			return e.name
		}
	}
	return "UNTYPED(" + err.Error() + ")"
}

// hello builds a ClientHello whose server_name hostname starts at body offset
// sniStart inside a record body of bodyLen bytes, and checks that tlsmsg.Parse
// agrees — a golden table keyed on coordinates the parser does not actually
// produce would pin the wrong thing.
func hello(t *testing.T, name string, sniStart, bodyLen int) []byte {
	t.Helper()
	const fixed = 47      // handshake header, version, random, session id, ciphers, compression, ext length
	const sniOverhead = 9 // ext type, ext len, list len, name type, name len
	const fillerExt = 0x1a1a

	lead := sniStart - fixed - sniOverhead
	tail := bodyLen - fixed - lead - sniOverhead - len(name)
	if lead < 4 || (tail != 0 && tail < 4) {
		t.Fatalf("hello(%q, %d, %d): impossible geometry", name, sniStart, bodyLen)
	}
	ext := func(typ uint16, n int) []byte {
		b := make([]byte, n)
		binary.BigEndian.PutUint16(b[0:2], typ)
		binary.BigEndian.PutUint16(b[2:4], uint16(n-4))
		return b
	}
	sni := []byte{0x00, 0x00}
	sni = binary.BigEndian.AppendUint16(sni, uint16(5+len(name)))
	sni = binary.BigEndian.AppendUint16(sni, uint16(3+len(name)))
	sni = append(sni, 0x00)
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(name)))
	sni = append(sni, name...)

	exts := append(ext(fillerExt, lead), sni...)
	if tail > 0 {
		exts = append(exts, ext(fillerExt, tail)...)
	}

	body := []byte{0x01, 0, 0, 0, 0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)
	msgLen := len(body) - 4
	body[1], body[2], body[3] = byte(msgLen>>16), byte(msgLen>>8), byte(msgLen)

	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(body)))
	rec = append(rec, body...)

	m := tlsmsg.Parse(rec, 443)
	if m.ServerName != name || m.SNIStart != sniStart || m.BodyLen != bodyLen || !m.Complete {
		t.Fatalf("fixture %q: parsed %q at [%d,%d), body %d, complete %v",
			name, m.ServerName, m.SNIStart, m.SNIEnd, m.BodyLen, m.Complete)
	}
	return rec
}

func quicInitial() []byte {
	d := []byte{0xc3}
	d = binary.BigEndian.AppendUint32(d, tlsmsg.QUICVersion1)
	d = append(d, 8, 1, 2, 3, 4, 5, 6, 7, 8)
	d = append(d, 4, 9, 9, 9, 9)
	d = append(d, 0x00)
	body := 1200 - len(d) - 2
	d = binary.BigEndian.AppendUint16(d, uint16(body)|0x4000)
	return append(d, make([]byte, body)...)
}

// golden is the pinned table. Regenerate by clearing it and running the test:
// every missing entry is printed in paste-ready form.
var golden = map[string]string{
	"classic|":                                 "canon=\"\" stream:305 sha=91659a4323e1",
	"classic|chunk:size=1":                     "refused: ErrBudget",
	"classic|chunk:size=12":                    "canon=\"chunk:size=12\" stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:125 sha=c159e1598a14",
	"classic|chunk:size=120":                   "canon=\"chunk:size=120\" stream:120,stream:120,stream:65 sha=c503be77b9f9",
	"classic|chunk:size=2":                     "refused: ErrBudget",
	"classic|chunk:size=20":                    "canon=\"chunk:size=20\" stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:5 sha=4a21175b9ff9",
	"classic|chunk:size=3":                     "refused: ErrBudget",
	"classic|chunk:size=35":                    "canon=\"chunk:size=35\" stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:25 sha=7099095e8bc8",
	"classic|chunk:size=4":                     "refused: ErrBudget",
	"classic|chunk:size=40":                    "canon=\"chunk:size=40\" stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:25 sha=743d86889576",
	"classic|chunk:size=5":                     "refused: ErrBudget",
	"classic|chunk:size=60":                    "canon=\"chunk:size=60\" stream:60,stream:60,stream:60,stream:60,stream:60,stream:5 sha=692b89d8d3ef",
	"classic|chunk:size=8":                     "canon=\"chunk:size=8\" stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:185 sha=ba1de3e352ff",
	"classic|disorder:pos=1":                   "canon=\"disorder:pos=1\" stream:1/ttl1,stream:304 sha=4321c653faec",
	"classic|disorder:pos=3":                   "canon=\"disorder:pos=3\" stream:3/ttl1,stream:302 sha=8ecad97a9b61",
	"classic|disorder:pos=3,ttl=2":             "canon=\"disorder:pos=3,ttl=2\" stream:3/ttl2,stream:302 sha=f21d4322522b",
	"classic|disorder:pos=snimid":              "canon=\"disorder:pos=snimid\" stream:70/ttl1,stream:235 sha=9efe39561d15",
	"classic|hostcase|hostdot|chunk:size=12":   "refused: ErrNeedHost",
	"classic|hostdot|hostcase":                 "refused: ErrNeedHost",
	"classic|hostpad":                          "refused: ErrNeedHost",
	"classic|hostspell:spell=HOST":             "refused: ErrNeedHost",
	"classic|oob:pos=1":                        "canon=\"oob:pos=1\" stream:1,oob:1,stream:304 sha=64e917329f58",
	"classic|oob:pos=1,junk=97":                "canon=\"oob:junk=97,pos=1\" stream:1,oob:1,stream:304 sha=6d553c83df1d",
	"classic|oob:pos=3":                        "canon=\"oob:pos=3\" stream:3,oob:1,stream:302 sha=01f63a429b10",
	"classic|quicfake:count=2,ttl=4":           "refused: ErrNeedQUIC",
	"classic|split:pos=1":                      "canon=\"split:pos=1\" stream:1,stream:304 sha=04c71b770312",
	"classic|split:pos=2":                      "canon=\"split:pos=2\" stream:2,stream:303 sha=415bb37005d9",
	"classic|split:pos=3":                      "canon=\"split:pos=3\" stream:3,stream:302 sha=f7e8e4f7581c",
	"classic|split:pos=5":                      "canon=\"split:pos=5\" stream:5,stream:300 sha=a26f2920a18a",
	"classic|split:pos=snimid":                 "canon=\"split:pos=snimid\" stream:70,stream:235 sha=0c0e6e3db78c",
	"classic|tlsevery:period=128":              "refused: ErrCutAfterSNI",
	"classic|tlsevery:period=16":               "canon=\"tlsevery:period=16\" stream:395 sha=e62321248624",
	"classic|tlsevery:period=256":              "refused: ErrCutAfterSNI",
	"classic|tlsevery:period=64":               "canon=\"tlsevery:period=64\" stream:325 sha=0265e3b0983c",
	"classic|tlsevery:period=64|chunk:size=4":  "refused: ErrBudget",
	"classic|tlsfrag:pos=1":                    "canon=\"tlsfrag:pos=1\" stream:310 sha=9e2d9e1aa8cf",
	"classic|tlsfrag:pos=sniend-1":             "canon=\"tlsfrag:pos=sniend-1\" stream:310 sha=a173ae0f2bda",
	"classic|tlsfrag:pos=snimid":               "canon=\"tlsfrag:pos=snimid\" stream:310 sha=c0a1f32f0425",
	"classic|tlsfrag:pos=snimid|chunk:size=12": "canon=\"tlsfrag:pos=snimid|chunk:size=12\" stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:130 sha=cb97503bd399",
	"classic|tlsfrag:pos=snistart":             "canon=\"tlsfrag:pos=snistart\" stream:310 sha=28a5f76b7e6a",
	"classic|tlsfrag:pos=snistart+1":           "canon=\"tlsfrag:pos=snistart+1\" stream:310 sha=98de89fe1730",
	"classic|tlsfrag:pos=snistart-1":           "canon=\"tlsfrag:pos=snistart-1\" stream:310 sha=de02b406ea9f",
	"classic|tlsfrag:pos=snistart-20":          "canon=\"tlsfrag:pos=snistart-20\" stream:310 sha=febfd74e8714",
	"classic|tlspad:to=600":                    "parse-error: ErrOpRejected",
	"classic|tlspad:to=600|tlsfrag:pos=snimid": "parse-error: ErrOpRejected",
	"http|":                                 "canon=\"\" stream:64 sha=cb6876186b75",
	"http|chunk:size=1":                     "canon=\"chunk:size=1\" stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:49 sha=57e177eaaac4",
	"http|chunk:size=12":                    "canon=\"chunk:size=12\" stream:12,stream:12,stream:12,stream:12,stream:12,stream:4 sha=906cdde7d634",
	"http|chunk:size=120":                   "refused: ErrBadValue",
	"http|chunk:size=2":                     "canon=\"chunk:size=2\" stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:34 sha=f3dcfe900590",
	"http|chunk:size=20":                    "canon=\"chunk:size=20\" stream:20,stream:20,stream:20,stream:4 sha=d2158d7ed9f3",
	"http|chunk:size=3":                     "canon=\"chunk:size=3\" stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:19 sha=6a7445ce43b3",
	"http|chunk:size=35":                    "canon=\"chunk:size=35\" stream:35,stream:29 sha=0f19769d47ce",
	"http|chunk:size=4":                     "canon=\"chunk:size=4\" stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4 sha=aa68be293638",
	"http|chunk:size=40":                    "canon=\"chunk:size=40\" stream:40,stream:24 sha=cf48b648e302",
	"http|chunk:size=5":                     "canon=\"chunk:size=5\" stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:4 sha=ae7489a59755",
	"http|chunk:size=60":                    "canon=\"chunk:size=60\" stream:60,stream:4 sha=cb4c91ec36a2",
	"http|chunk:size=8":                     "canon=\"chunk:size=8\" stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8 sha=9d6e1f4e0d50",
	"http|disorder:pos=1":                   "canon=\"disorder:pos=1\" stream:1/ttl1,stream:63 sha=fb6223bdc285",
	"http|disorder:pos=3":                   "canon=\"disorder:pos=3\" stream:3/ttl1,stream:61 sha=6e30b52ef3dd",
	"http|disorder:pos=3,ttl=2":             "canon=\"disorder:pos=3,ttl=2\" stream:3/ttl2,stream:61 sha=608491c10937",
	"http|disorder:pos=snimid":              "refused: ErrNeedSNI",
	"http|hostcase|hostdot|chunk:size=12":   "canon=\"hostcase|hostdot|chunk:size=12\" stream:12,stream:12,stream:12,stream:12,stream:12,stream:5 sha=c882ac8a68e0",
	"http|hostdot|hostcase":                 "canon=\"hostcase|hostdot\" stream:65 sha=4a9860d0fb55",
	"http|hostpad":                          "canon=\"hostpad\" stream:128 sha=bed587f73070",
	"http|hostspell:spell=HOST":             "canon=\"hostspell:spell=HOST\" stream:64 sha=edb614047cbd",
	"http|oob:pos=1":                        "canon=\"oob:pos=1\" stream:1,oob:1,stream:63 sha=88d69d6a4d87",
	"http|oob:pos=1,junk=97":                "canon=\"oob:junk=97,pos=1\" stream:1,oob:1,stream:63 sha=e48e5367d767",
	"http|oob:pos=3":                        "canon=\"oob:pos=3\" stream:3,oob:1,stream:61 sha=50c31b1f7f33",
	"http|quicfake:count=2,ttl=4":           "refused: ErrNeedQUIC",
	"http|split:pos=1":                      "canon=\"split:pos=1\" stream:1,stream:63 sha=ecf54d650393",
	"http|split:pos=2":                      "canon=\"split:pos=2\" stream:2,stream:62 sha=ad4c560dcd56",
	"http|split:pos=3":                      "canon=\"split:pos=3\" stream:3,stream:61 sha=28d19d5585c0",
	"http|split:pos=5":                      "canon=\"split:pos=5\" stream:5,stream:59 sha=2bd3d40b624c",
	"http|split:pos=snimid":                 "refused: ErrNeedSNI",
	"http|tlsevery:period=128":              "refused: ErrNeedComplete",
	"http|tlsevery:period=16":               "refused: ErrNeedComplete",
	"http|tlsevery:period=256":              "refused: ErrNeedComplete",
	"http|tlsevery:period=64":               "refused: ErrNeedComplete",
	"http|tlsevery:period=64|chunk:size=4":  "refused: ErrNeedComplete",
	"http|tlsfrag:pos=1":                    "refused: ErrNeedSNI",
	"http|tlsfrag:pos=sniend-1":             "refused: ErrNeedSNI",
	"http|tlsfrag:pos=snimid":               "refused: ErrNeedSNI",
	"http|tlsfrag:pos=snimid|chunk:size=12": "refused: ErrNeedSNI",
	"http|tlsfrag:pos=snistart":             "refused: ErrNeedSNI",
	"http|tlsfrag:pos=snistart+1":           "refused: ErrNeedSNI",
	"http|tlsfrag:pos=snistart-1":           "refused: ErrNeedSNI",
	"http|tlsfrag:pos=snistart-20":          "refused: ErrNeedSNI",
	"http|tlspad:to=600":                    "parse-error: ErrOpRejected",
	"http|tlspad:to=600|tlsfrag:pos=snimid": "parse-error: ErrOpRejected",
	"quic|":                                 "canon=\"\" stream:1200 sha=33114c629849",
	"quic|chunk:size=1":                     "canon=\"chunk:size=1\" stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1,stream:1185 sha=5267698a1bec",
	"quic|chunk:size=12":                    "canon=\"chunk:size=12\" stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:1020 sha=5bd6b100a6a2",
	"quic|chunk:size=120":                   "canon=\"chunk:size=120\" stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120 sha=2b73204033e8",
	"quic|chunk:size=2":                     "canon=\"chunk:size=2\" stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:2,stream:1170 sha=faaf4751b0ff",
	"quic|chunk:size=20":                    "canon=\"chunk:size=20\" stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:900 sha=0f296f2db748",
	"quic|chunk:size=3":                     "canon=\"chunk:size=3\" stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:3,stream:1155 sha=9097cd691181",
	"quic|chunk:size=35":                    "canon=\"chunk:size=35\" stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:675 sha=2f8c220ed7cf",
	"quic|chunk:size=4":                     "canon=\"chunk:size=4\" stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:4,stream:1140 sha=ee01b0435c92",
	"quic|chunk:size=40":                    "canon=\"chunk:size=40\" stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:600 sha=38f170dd6c41",
	"quic|chunk:size=5":                     "canon=\"chunk:size=5\" stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:5,stream:1125 sha=664efd30d8a3",
	"quic|chunk:size=60":                    "canon=\"chunk:size=60\" stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:300 sha=cd43ed329d99",
	"quic|chunk:size=8":                     "canon=\"chunk:size=8\" stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:8,stream:1080 sha=475ef3e4d8df",
	"quic|disorder:pos=1":                   "canon=\"disorder:pos=1\" stream:1/ttl1,stream:1199 sha=3c441eedfa92",
	"quic|disorder:pos=3":                   "canon=\"disorder:pos=3\" stream:3/ttl1,stream:1197 sha=0643e6e70710",
	"quic|disorder:pos=3,ttl=2":             "canon=\"disorder:pos=3,ttl=2\" stream:3/ttl2,stream:1197 sha=96b3609c3825",
	"quic|disorder:pos=snimid":              "refused: ErrNeedSNI",
	"quic|hostcase|hostdot|chunk:size=12":   "refused: ErrNeedHost",
	"quic|hostdot|hostcase":                 "refused: ErrNeedHost",
	"quic|hostpad":                          "refused: ErrNeedHost",
	"quic|hostspell:spell=HOST":             "refused: ErrNeedHost",
	"quic|oob:pos=1":                        "canon=\"oob:pos=1\" stream:1,oob:1,stream:1199 sha=95fe3452b24d",
	"quic|oob:pos=1,junk=97":                "canon=\"oob:junk=97,pos=1\" stream:1,oob:1,stream:1199 sha=03f2289538f3",
	"quic|oob:pos=3":                        "canon=\"oob:pos=3\" stream:3,oob:1,stream:1197 sha=c8fdb66a5f83",
	"quic|quicfake:count=2,ttl=4":           "canon=\"quicfake\" fakedgram:1200/ttl4,fakedgram:1200/ttl4,stream:1200 sha=ad0b41708560",
	"quic|split:pos=1":                      "canon=\"split:pos=1\" stream:1,stream:1199 sha=487f9b83b4b2",
	"quic|split:pos=2":                      "canon=\"split:pos=2\" stream:2,stream:1198 sha=5d5b51b4bb09",
	"quic|split:pos=3":                      "canon=\"split:pos=3\" stream:3,stream:1197 sha=a7218e52ab03",
	"quic|split:pos=5":                      "canon=\"split:pos=5\" stream:5,stream:1195 sha=23f5614b561e",
	"quic|split:pos=snimid":                 "refused: ErrNeedSNI",
	"quic|tlsevery:period=128":              "refused: ErrNeedComplete",
	"quic|tlsevery:period=16":               "refused: ErrNeedComplete",
	"quic|tlsevery:period=256":              "refused: ErrNeedComplete",
	"quic|tlsevery:period=64":               "refused: ErrNeedComplete",
	"quic|tlsevery:period=64|chunk:size=4":  "refused: ErrNeedComplete",
	"quic|tlsfrag:pos=1":                    "refused: ErrNeedSNI",
	"quic|tlsfrag:pos=sniend-1":             "refused: ErrNeedSNI",
	"quic|tlsfrag:pos=snimid":               "refused: ErrNeedSNI",
	"quic|tlsfrag:pos=snimid|chunk:size=12": "refused: ErrNeedSNI",
	"quic|tlsfrag:pos=snistart":             "refused: ErrNeedSNI",
	"quic|tlsfrag:pos=snistart+1":           "refused: ErrNeedSNI",
	"quic|tlsfrag:pos=snistart-1":           "refused: ErrNeedSNI",
	"quic|tlsfrag:pos=snistart-20":          "refused: ErrNeedSNI",
	"quic|tlspad:to=600":                    "parse-error: ErrOpRejected",
	"quic|tlspad:to=600|tlsfrag:pos=snimid": "parse-error: ErrOpRejected",
	"tt|":                                   "canon=\"\" stream:1502 sha=a0023c15b609",
	"tt|chunk:size=1":                       "refused: ErrBudget",
	"tt|chunk:size=12":                      "canon=\"chunk:size=12\" stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:1322 sha=91ba3e1cedc9",
	"tt|chunk:size=120":                     "canon=\"chunk:size=120\" stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:62 sha=7a3ae4a73be8",
	"tt|chunk:size=2":                       "refused: ErrBudget",
	"tt|chunk:size=20":                      "canon=\"chunk:size=20\" stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:1202 sha=afd3fbf941cc",
	"tt|chunk:size=3":                       "refused: ErrBudget",
	"tt|chunk:size=35":                      "canon=\"chunk:size=35\" stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:977 sha=13be63825d0e",
	"tt|chunk:size=4":                       "refused: ErrBudget",
	"tt|chunk:size=40":                      "canon=\"chunk:size=40\" stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:902 sha=2fd37b6186c6",
	"tt|chunk:size=5":                       "refused: ErrBudget",
	"tt|chunk:size=60":                      "canon=\"chunk:size=60\" stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:602 sha=9f525f1198d7",
	"tt|chunk:size=8":                       "refused: ErrBudget",
	"tt|disorder:pos=1":                     "canon=\"disorder:pos=1\" stream:1/ttl1,stream:1501 sha=132bbd1fdfb0",
	"tt|disorder:pos=3":                     "canon=\"disorder:pos=3\" stream:3/ttl1,stream:1499 sha=42e36f9c11b1",
	"tt|disorder:pos=3,ttl=2":               "canon=\"disorder:pos=3,ttl=2\" stream:3/ttl2,stream:1499 sha=2ed4a68f0417",
	"tt|disorder:pos=snimid":                "canon=\"disorder:pos=snimid\" stream:122/ttl1,stream:1380 sha=03769772c96c",
	"tt|hostcase|hostdot|chunk:size=12":     "refused: ErrNeedHost",
	"tt|hostdot|hostcase":                   "refused: ErrNeedHost",
	"tt|hostpad":                            "refused: ErrNeedHost",
	"tt|hostspell:spell=HOST":               "refused: ErrNeedHost",
	"tt|oob:pos=1":                          "canon=\"oob:pos=1\" stream:1,oob:1,stream:1501 sha=f19e3b2ee6b2",
	"tt|oob:pos=1,junk=97":                  "canon=\"oob:junk=97,pos=1\" stream:1,oob:1,stream:1501 sha=b4345e8d2a8c",
	"tt|oob:pos=3":                          "canon=\"oob:pos=3\" stream:3,oob:1,stream:1499 sha=3550bb2ed5d6",
	"tt|quicfake:count=2,ttl=4":             "refused: ErrNeedQUIC",
	"tt|split:pos=1":                        "canon=\"split:pos=1\" stream:1,stream:1501 sha=e875b0406779",
	"tt|split:pos=2":                        "canon=\"split:pos=2\" stream:2,stream:1500 sha=426c2c3006e9",
	"tt|split:pos=3":                        "canon=\"split:pos=3\" stream:3,stream:1499 sha=ce5aedbbd02b",
	"tt|split:pos=5":                        "canon=\"split:pos=5\" stream:5,stream:1497 sha=bd24564a73a2",
	"tt|split:pos=snimid":                   "canon=\"split:pos=snimid\" stream:122,stream:1380 sha=9759279d48b9",
	"tt|tlsevery:period=128":                "refused: ErrCutAfterSNI",
	"tt|tlsevery:period=16":                 "canon=\"tlsevery:period=16\" stream:1967 sha=90e314fa9a4b",
	"tt|tlsevery:period=256":                "refused: ErrCutAfterSNI",
	"tt|tlsevery:period=64":                 "canon=\"tlsevery:period=64\" stream:1617 sha=95c6ecac59b3",
	"tt|tlsevery:period=64|chunk:size=4":    "refused: ErrBudget",
	"tt|tlsfrag:pos=1":                      "canon=\"tlsfrag:pos=1\" stream:1507 sha=635dd2165d26",
	"tt|tlsfrag:pos=sniend-1":               "canon=\"tlsfrag:pos=sniend-1\" stream:1507 sha=6c7a127780c3",
	"tt|tlsfrag:pos=snimid":                 "canon=\"tlsfrag:pos=snimid\" stream:1507 sha=4907f1b7d3b4",
	"tt|tlsfrag:pos=snimid|chunk:size=12":   "canon=\"tlsfrag:pos=snimid|chunk:size=12\" stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:1327 sha=01664c9ae996",
	"tt|tlsfrag:pos=snistart":               "canon=\"tlsfrag:pos=snistart\" stream:1507 sha=1f3fdb258ae3",
	"tt|tlsfrag:pos=snistart+1":             "canon=\"tlsfrag:pos=snistart+1\" stream:1507 sha=4fb1ec805714",
	"tt|tlsfrag:pos=snistart-1":             "canon=\"tlsfrag:pos=snistart-1\" stream:1507 sha=b3c65d4d1d64",
	"tt|tlsfrag:pos=snistart-20":            "canon=\"tlsfrag:pos=snistart-20\" stream:1507 sha=74a44a580130",
	"tt|tlspad:to=600":                      "parse-error: ErrOpRejected",
	"tt|tlspad:to=600|tlsfrag:pos=snimid":   "parse-error: ErrOpRejected",
	"wide|":                                 "canon=\"\" stream:4005 sha=30e4b6a41262",
	"wide|chunk:size=1":                     "refused: ErrBudget",
	"wide|chunk:size=12":                    "canon=\"chunk:size=12\" stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:3825 sha=7cbdf4892ae6",
	"wide|chunk:size=120":                   "canon=\"chunk:size=120\" stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:120,stream:2205 sha=2c9fa9dd6571",
	"wide|chunk:size=2":                     "refused: ErrBudget",
	"wide|chunk:size=20":                    "canon=\"chunk:size=20\" stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:20,stream:3705 sha=6126a22fb9fd",
	"wide|chunk:size=3":                     "refused: ErrBudget",
	"wide|chunk:size=35":                    "canon=\"chunk:size=35\" stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:35,stream:3480 sha=4d47f33db11e",
	"wide|chunk:size=4":                     "refused: ErrBudget",
	"wide|chunk:size=40":                    "canon=\"chunk:size=40\" stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:40,stream:3405 sha=42ce12caf0d4",
	"wide|chunk:size=5":                     "refused: ErrBudget",
	"wide|chunk:size=60":                    "canon=\"chunk:size=60\" stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:60,stream:3105 sha=b94d35738296",
	"wide|chunk:size=8":                     "refused: ErrBudget",
	"wide|disorder:pos=1":                   "canon=\"disorder:pos=1\" stream:1/ttl1,stream:4004 sha=02e14189d2d0",
	"wide|disorder:pos=3":                   "canon=\"disorder:pos=3\" stream:3/ttl1,stream:4002 sha=5535ae848dd8",
	"wide|disorder:pos=3,ttl=2":             "canon=\"disorder:pos=3,ttl=2\" stream:3/ttl2,stream:4002 sha=dd7f0eef987d",
	"wide|disorder:pos=snimid":              "canon=\"disorder:pos=snimid\" stream:134/ttl1,stream:3871 sha=39034bafba7d",
	"wide|hostcase|hostdot|chunk:size=12":   "refused: ErrNeedHost",
	"wide|hostdot|hostcase":                 "refused: ErrNeedHost",
	"wide|hostpad":                          "refused: ErrNeedHost",
	"wide|hostspell:spell=HOST":             "refused: ErrNeedHost",
	"wide|oob:pos=1":                        "canon=\"oob:pos=1\" stream:1,oob:1,stream:4004 sha=dc5cd93a3a54",
	"wide|oob:pos=1,junk=97":                "canon=\"oob:junk=97,pos=1\" stream:1,oob:1,stream:4004 sha=de7afa4370d2",
	"wide|oob:pos=3":                        "canon=\"oob:pos=3\" stream:3,oob:1,stream:4002 sha=1d1af59f8206",
	"wide|quicfake:count=2,ttl=4":           "refused: ErrNeedQUIC",
	"wide|split:pos=1":                      "canon=\"split:pos=1\" stream:1,stream:4004 sha=f63f36a40f92",
	"wide|split:pos=2":                      "canon=\"split:pos=2\" stream:2,stream:4003 sha=a0e2e57dd28f",
	"wide|split:pos=3":                      "canon=\"split:pos=3\" stream:3,stream:4002 sha=50a4acc9563f",
	"wide|split:pos=5":                      "canon=\"split:pos=5\" stream:5,stream:4000 sha=cbb2ba628fa8",
	"wide|split:pos=snimid":                 "canon=\"split:pos=snimid\" stream:134,stream:3871 sha=7ac866b88eb9",
	"wide|tlsevery:period=128":              "canon=\"tlsevery:period=128\" stream:4160 sha=a93113a2c5a8",
	"wide|tlsevery:period=16":               "canon=\"tlsevery:period=16\" stream:5250 sha=1fb682fa9ab7",
	"wide|tlsevery:period=256":              "refused: ErrCutAfterSNI",
	"wide|tlsevery:period=64":               "canon=\"tlsevery:period=64\" stream:4315 sha=f26b822bca99",
	"wide|tlsevery:period=64|chunk:size=4":  "refused: ErrBudget",
	"wide|tlsfrag:pos=1":                    "canon=\"tlsfrag:pos=1\" stream:4010 sha=8c159f56599a",
	"wide|tlsfrag:pos=sniend-1":             "canon=\"tlsfrag:pos=sniend-1\" stream:4010 sha=8ce827d21565",
	"wide|tlsfrag:pos=snimid":               "canon=\"tlsfrag:pos=snimid\" stream:4010 sha=895df384e9bf",
	"wide|tlsfrag:pos=snimid|chunk:size=12": "canon=\"tlsfrag:pos=snimid|chunk:size=12\" stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:12,stream:3830 sha=e5ecead7c2b6",
	"wide|tlsfrag:pos=snistart":             "canon=\"tlsfrag:pos=snistart\" stream:4010 sha=5265f8bdf623",
	"wide|tlsfrag:pos=snistart+1":           "canon=\"tlsfrag:pos=snistart+1\" stream:4010 sha=20a7e59f6751",
	"wide|tlsfrag:pos=snistart-1":           "canon=\"tlsfrag:pos=snistart-1\" stream:4010 sha=ae8c9db93309",
	"wide|tlsfrag:pos=snistart-20":          "canon=\"tlsfrag:pos=snistart-20\" stream:4010 sha=21a1905b5ff8",
	"wide|tlspad:to=600":                    "parse-error: ErrOpRejected",
	"wide|tlspad:to=600|tlsfrag:pos=snimid": "parse-error: ErrOpRejected",
}
