package cliapp

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/ops"
	"github.com/mumudevx/dpb/internal/strategy"
	"github.com/mumudevx/dpb/internal/tlsmsg"
)

func TestStrategyList(t *testing.T) {
	t.Parallel()
	r := run(t, "strategy", "list")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{"tlsfrag", "chunk", "oob", "disorder", "MEASUREMENTS.md"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("listing is missing %q:\n%s", want, r.stdout)
		}
	}
	// An op that can never work here is registered on purpose so that asking
	// for it produces a cited refusal rather than "unknown op". The listing has
	// to say which those are, or the refusal is a surprise.
	if !strings.Contains(r.stdout, "registered but never usable here") {
		t.Errorf("the listing must separate the rejected ops:\n%s", r.stdout)
	}
}

// The shipped TR ladder is MEASUREMENTS.md §5.3 verbatim, and rung 1 is plain:
// §5.2 makes connecting undesynced first a correctness requirement, not an
// optimisation, because no emitter is both a bypass and universally safe.
func TestStrategyListLadder(t *testing.T) {
	t.Parallel()
	r := run(t, "strategy", "list", "--ladder", "tr")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d: %s", r.code, r.stderr)
	}
	want := []string{"1. plain", "2. tlsfrag:pos=snimid", "3. chunk:size=12", "4. oob:pos=1"}
	for _, w := range want {
		if !strings.Contains(r.stdout, w) {
			t.Errorf("ladder is missing %q:\n%s", w, r.stdout)
		}
	}
}

func TestStrategyListUnknownLadderIsUsage(t *testing.T) {
	t.Parallel()
	r := run(t, "strategy", "list", "--ladder", "nosuchladder")
	if r.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", r.code, ExitUsage)
	}
}

func TestStrategyExplain(t *testing.T) {
	t.Parallel()
	r := run(t, "strategy", "explain", "tlsfrag:pos=snimid")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d: %s", r.code, r.stderr)
	}
	// An explanation without its provenance is an assertion. The measured rule
	// is the whole basis of the primary emitter, so it must be cited.
	if !strings.Contains(r.stdout, "§3.2") && !strings.Contains(r.stdout, "MEASUREMENTS") {
		t.Errorf("explain must cite its evidence:\n%s", r.stdout)
	}

	plain := run(t, "strategy", "explain", "")
	if plain.code != ExitOK {
		t.Fatalf("explain \"\": exit code = %d: %s", plain.code, plain.stderr)
	}
	if !strings.Contains(plain.stdout, "plain") {
		t.Errorf("the empty spec must explain itself as plain:\n%s", plain.stdout)
	}
}

func TestStrategyExplainUnknownOp(t *testing.T) {
	t.Parallel()
	r := run(t, "strategy", "explain", "nosuchop")
	if r.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", r.code, ExitUsage)
	}
	if !strings.Contains(r.stderr, "nosuchop") {
		t.Errorf("stderr must name the op: %q", r.stderr)
	}
}

// The measured rule, printed. MEASUREMENTS.md §3.2: the first TLS record must
// end at or before sniEnd-1, and the plan a user is shown has to make that
// checkable by eye.
func TestStrategyPlanShowsTheRecordRule(t *testing.T) {
	t.Parallel()
	r := run(t, "strategy", "plan", "tlsfrag:pos=snimid", "--sni", "discord.com")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d: %s", r.code, r.stderr)
	}
	for _, want := range []string{"discord.com", "first record must end at or before", "writes    1"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("plan is missing %q:\n%s", want, r.stdout)
		}
	}
}

func TestStrategyPlanHTTPSample(t *testing.T) {
	t.Parallel()
	r := run(t, "strategy", "plan", "hostcase", "--sample", "http", "--sni", "example.com")
	if r.code != ExitOK {
		t.Fatalf("exit code = %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "http") {
		t.Errorf("plan must report the message kind:\n%s", r.stdout)
	}
}

func TestStrategyPlanRejectsAnUnknownSample(t *testing.T) {
	t.Parallel()
	r := run(t, "strategy", "plan", "", "--sample", "gopher")
	if r.code != ExitUsage {
		t.Errorf("exit code = %d, want %d", r.code, ExitUsage)
	}
}

// A spec that cannot be emitted against this message must fail loudly. Printing
// a silently downgraded plan is worse than printing nothing, because the user
// goes on to trust it.
func TestStrategyPlanRefusesADowngrade(t *testing.T) {
	t.Parallel()
	r := run(t, "strategy", "plan", "hostcase", "--sample", "tls")
	if r.code == ExitOK {
		t.Fatalf("a host mutator has nothing to key on in a ClientHello; plan must fail:\n%s", r.stdout)
	}
}

func TestStrategyValidate(t *testing.T) {
	t.Parallel()
	ok := run(t, "strategy", "validate", "tlsfrag:pos=snimid")
	if ok.code != ExitOK {
		t.Fatalf("exit code = %d: %s", ok.code, ok.stderr)
	}
	if !strings.Contains(ok.stdout, "ok:") {
		t.Errorf("stdout = %q, want an explicit ok", ok.stdout)
	}

	// The load-bearing validator: a cut at or after sniEnd leaves the hostname
	// complete in the first record, and the DPI would still match
	// (MEASUREMENTS.md §3.2 — sniEnd, +1, +20 and +200 all blocked 0/3).
	bad := run(t, "strategy", "validate", "tlsfrag:pos=sniend")
	if bad.code == ExitOK {
		t.Fatal("a cut at sniEnd must be refused")
	}
	if !strings.Contains(bad.stderr, "sniEnd") {
		t.Errorf("the refusal must say why: %q", bad.stderr)
	}
}

func TestStrategyValidateRejectedOpIsCited(t *testing.T) {
	t.Parallel()
	// seqovl is registered only so that asking for it gives an honest, cited
	// error: Darwin's tcp_connection_info has no snd_nxt, so CapRawSeq can
	// never be granted.
	r := run(t, "strategy", "validate", "seqovl")
	if r.code == ExitOK {
		t.Fatal("an unusable op must not validate")
	}
	if len(r.stderr) < 40 {
		t.Errorf("the refusal must explain itself, got %q", r.stderr)
	}
}

// The sample ClientHello comes from crypto/tls itself, so what `strategy plan`
// shows is what the shipped TLS stack actually emits — including its length,
// which is what the record rule is expressed against.
func TestSampleClientHelloIsParseable(t *testing.T) {
	t.Parallel()
	b, err := sampleClientHello("discord.com")
	if err != nil {
		t.Fatalf("sampleClientHello: %v", err)
	}
	m := tlsmsg.Parse(b, 443)
	if m.Proto != tlsmsg.ProtoTLS {
		t.Fatalf("proto = %s, want tls", m.Proto)
	}
	if m.ServerName != "discord.com" {
		t.Errorf("ServerName = %q, want discord.com", m.ServerName)
	}
	if !m.HasSNI() || !m.Complete {
		t.Fatalf("sample must be a complete hello with an SNI extent: %+v", m)
	}
	if _, ok := m.MaxFirstRecordEnd(); !ok {
		t.Error("MaxFirstRecordEnd must resolve on the sample")
	}
}

func TestSamplePayloadKinds(t *testing.T) {
	t.Parallel()
	b, port, err := samplePayload("http", "example.com")
	if err != nil {
		t.Fatalf("http sample: %v", err)
	}
	if port != 80 {
		t.Errorf("port = %d, want 80", port)
	}
	m := tlsmsg.Parse(b, port)
	if !m.HasHost() || m.ServerName != "example.com" {
		t.Errorf("http sample did not parse: %+v", m)
	}

	if _, _, err := samplePayload("", ""); err != nil {
		t.Errorf("an empty kind must default to tls: %v", err)
	}
	if _, _, err := samplePayload("gopher", "x"); err == nil {
		t.Error("an unknown sample kind must be refused")
	}
}

// The capability set is read off a real socket rather than assumed, so a
// capability this platform withholds shows up as a named refusal instead of a
// plan that cannot be emitted.
func TestLocalCapsComeFromARealSocket(t *testing.T) {
	t.Parallel()
	c, err := loopbackCaps()
	if err != nil {
		t.Fatalf("loopbackCaps: %v", err)
	}
	if !c.Has(strategy.CapStreamWrite | strategy.CapNoDelay) {
		t.Errorf("caps = %s, want at least stream+nodelay", c)
	}
	if localCaps() != c {
		t.Errorf("localCaps() = %s, want %s", localCaps(), c)
	}
}

// buildStrict is what both plan and validate go through; it must reject rather
// than degrade.
func TestBuildStrictRejectsInsteadOfDegrading(t *testing.T) {
	t.Parallel()
	reg := ops.Install()
	s, err := reg.Get("tlsfrag:pos=sniend+1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	payload, port, err := samplePayload("tls", "discord.com")
	if err != nil {
		t.Fatalf("sample: %v", err)
	}
	if _, err := buildStrict(s, payload, tlsmsg.Parse(payload, port)); err == nil {
		t.Fatal("a cut past sniEnd must not compile")
	}
}

// The sample conn is a stub, but a broken stub would make sampleClientHello
// fail in a way that looks like a TLS problem, so its contract is asserted.
func TestCaptureConnIsAnInertNetConn(t *testing.T) {
	t.Parallel()
	var c net.Conn = &captureConn{}
	if n, err := c.Write([]byte("hello")); n != 5 || err != nil {
		t.Errorf("Write = %d, %v", n, err)
	}
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("Read err = %v, want EOF", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
	if c.LocalAddr().String() != "sample" || c.RemoteAddr().Network() != "sample" {
		t.Error("addresses must be inert placeholders")
	}
	now := time.Now()
	if c.SetDeadline(now) != nil || c.SetReadDeadline(now) != nil || c.SetWriteDeadline(now) != nil {
		t.Error("deadlines must be no-ops")
	}
}
