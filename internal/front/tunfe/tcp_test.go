package tunfe

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/flow"
	"github.com/mumudevx/dpb/internal/observ"
	"github.com/mumudevx/dpb/internal/policy"
	"github.com/mumudevx/dpb/internal/tlsmsg"
)

// TestServerFirstGreetingIsNotBuffered is the deadlock the previous
// implementation shipped, encoded.
//
// internal/tun/stack_darwin.go relay() did an unconditional, un-deadlined
// client.Read BEFORE it consulted the port policy, so SMTP, IMAP, POP3, FTP and
// MySQL — every protocol where the server greets first — waited for a byte the
// client would never send. Here the greeting must reach the client inside the
// first-byte window with nothing buffered at all.
func TestServerFirstGreetingIsNotBuffered(t *testing.T) {
	o := newOrigin(t)
	// A DELIBERATELY long first-byte window. If anything read from the client
	// before the scope decided, the greeting would sit behind this two-second
	// wait; the assertion below is that it does not, so the bound cannot be met
	// by a datapath that buffers first and happens to be fast.
	fm := flow.DefaultFirstMsgOpts()
	fm.FirstByteWait = 5 * time.Second
	l := newLab(t, labOpts{firstMsg: fm})
	l.up.serveOn(o.addr())

	// Port 25 is not an inspect port, so this flow is never judged at all.
	start := time.Now()
	client, err := l.dial(netip.AddrPortFrom(originIP, 25))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// The upstream connection must be opened without waiting for a byte the
	// client is never going to send. This is the assertion that fails if
	// anything reads from the client before the scope decides.
	up := o.accept()
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Fatalf("the upstream dial took %s, which is inside the %s first-byte window: "+
			"the datapath waited for a client byte before connecting", elapsed, fm.FirstByteWait)
	}

	greeting := "220 mail.example.test ESMTP ready\r\n"
	sent := time.Now()
	if _, err := up.Write([]byte(greeting)); err != nil {
		t.Fatalf("greet: %v", err)
	}
	got := readWithin(t, client, len(greeting), 3*time.Second)
	if string(got) != greeting {
		t.Fatalf("client read %q, want the greeting %q", got, greeting)
	}
	if elapsed := time.Since(sent); elapsed > 2500*time.Millisecond {
		t.Fatalf("the greeting took %s to reach the client; it was buffered", elapsed)
	}

	// And the client's own first line still reaches the origin.
	if _, err := client.Write([]byte("EHLO test\r\n")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if s := string(readWithin(t, up, 11, 3*time.Second)); s != "EHLO test\r\n" {
		t.Fatalf("origin read %q", s)
	}
}

// TestServerFirstOnAnInspectPortIsDetected covers the other half: a flow that
// IS judged, on port 443, where the client says nothing. ReadFirstMessage must
// report MsgServerFirst and the datapath must relay immediately rather than
// stalling until something times out.
func TestServerFirstOnAnInspectPortIsDetected(t *testing.T) {
	o := newOrigin(t)
	l := newLab(t, labOpts{firstMsg: shortFirstMsg()})
	l.up.serveOn(o.addr())

	client, err := l.dial(netip.AddrPortFrom(originIP, 443))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	up := o.accept()
	if _, err := up.Write([]byte("hello-first")); err != nil {
		t.Fatalf("greet: %v", err)
	}
	if got := string(readWithin(t, client, 11, 3*time.Second)); got != "hello-first" {
		t.Fatalf("client read %q, want the server-first greeting", got)
	}
}

// TestSplitClientHelloIsReassembledBeforePlanning is the second shipped defect:
// a single un-looped Read on the first payload. A post-quantum ClientHello is
// ~1.5 KiB and spans two segments on a 1500-byte MTU, and planning on the first
// segment alone silently degrades a record split into a 1-2 byte TCP split,
// which MEASUREMENTS.md §3.1 measures at 0/5 while looking like a working
// strategy in the logs.
//
// The assertion is deliberately not "the origin received every byte" — a relay
// that plans on a prefix still forwards the rest afterwards, so the stream
// stays intact and the defect is invisible. What changes is what the STRATEGY
// saw: tlsfrag requires a complete hello with a locatable SNI, so it is refused
// outright when the parse came from a prefix. This test therefore makes the
// first attempt fail and asserts the escalation produced a real two-record
// hello.
func TestSplitClientHelloIsReassembledBeforePlanning(t *testing.T) {
	o := newResettingOrigin(t)
	// labFirstMsg, not the shipped default: the 60 ms gap below has to fit
	// inside the assembly's progress deadline, and 250 ms on a saturated
	// machine does not hold it. See the comment on labFirstMsg.
	l := newLab(t, labOpts{})
	l.up.serveOn(o.addr())

	hello := clientHello(t, "discord.com")
	if len(hello) < 300 {
		t.Fatalf("the captured hello is only %d bytes; there is nothing to split", len(hello))
	}
	if len(hello) < 1500 {
		t.Logf("note: this Go version emits a %d-byte hello, so it no longer spans two "+
			"1500-byte segments on the wire; the two-segment assembly path is still exercised", len(hello))
	}

	client, err := l.dial(netip.AddrPortFrom(originIP, 443))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	cut := len(hello) / 2
	if _, err := client.Write(hello[:cut]); err != nil {
		t.Fatalf("write first segment: %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	if _, err := client.Write(hello[cut:]); err != nil {
		t.Fatalf("write second segment: %v", err)
	}

	// Attempt 1 is plain and is reset by the censor; attempt 2 must carry the
	// reframed hello.
	first := o.next(t)
	if got := readWithin(t, first, len(hello), 5*time.Second); !bytes.Equal(got, hello) {
		t.Fatalf("attempt 1 carried %d of %d hello bytes; the first message was planned on a prefix",
			matching(got, hello), len(hello))
	}
	o.reset(t, first)

	second := o.next(t)
	got := readWithin(t, second, len(hello)+recordHeaderLen, 5*time.Second)
	if len(got) != len(hello)+recordHeaderLen {
		t.Fatalf("attempt 2 carried %d bytes, want %d: a hello reassembled from two segments "+
			"reframes into two records", len(got), len(hello)+recordHeaderLen)
	}
	// Two structurally valid records whose bodies concatenate to the original
	// handshake message: the strategy may never corrupt the stream.
	m := tlsmsg.Parse(got, 443)
	if !m.Complete {
		t.Fatal("attempt 2 is not a parseable TLS record")
	}
	body1 := got[recordHeaderLen : recordHeaderLen+m.BodyLen]
	rest := got[recordHeaderLen+m.BodyLen:]
	if len(rest) < recordHeaderLen {
		t.Fatalf("attempt 2 has no second record")
	}
	rejoined := append(append([]byte{}, body1...), rest[recordHeaderLen:]...)
	if !bytes.Equal(rejoined, hello[recordHeaderLen:]) {
		t.Fatal("the two records do not carry the original handshake bytes")
	}
	if m.RecordEnd() >= tlsmsg.Parse(hello, 443).SNIEnd+recordHeaderLen {
		t.Fatalf("the first record ends at %d, at or past the SNI: the cut did not hide the hostname",
			m.RecordEnd())
	}

	// Finish the flow so its event is published: the second attempt answers and
	// then BOTH ends go away.
	//
	// Closing both is what makes this test end on a condition rather than on a
	// timer. The relay half-closes, so a client that closes while the origin
	// stays open leaves the relay reading upstream until RelayIdle expires —
	// three seconds of pure waiting per test, and four tests in this package
	// were paying it.
	if _, err := second.Write([]byte("ok")); err != nil {
		t.Fatalf("origin write: %v", err)
	}
	if got := string(readWithin(t, client, 2, 5*time.Second)); got != "ok" {
		t.Fatalf("client read %q after the escalation", got)
	}
	_ = client.Close()
	_ = second.Close()

	waitForEvent(t, l, "the escalation to be recorded", func(ev observ.ConnEvent) bool {
		return ev.Strategy != ""
	})
	if ev := lastEvent(t, l); ev.Strategy != "tlsfrag:pos=snimid" {
		t.Fatalf("winning strategy = %q, want tlsfrag:pos=snimid: a hello planned on a prefix is "+
			"refused by every reframing op, so the connection would go out plain or fail", ev.Strategy)
	}
}

// recordHeaderLen is the 5-byte TLS record header.
const recordHeaderLen = 5

// TestBypassedNameSurvivesTUNMode is the scoping defect. In the previous tree
// the exclusion list reached proxy mode's options and TUN mode had no such
// field, so a user who excluded their bank lost that exclusion in exactly the
// mode where they ran as root.
//
// Here the flow arrives as a bare address with no DNS history, so the ONLY way
// to honour the exclusion is to re-scope on the SNI in the message we just
// buffered. The bank must be relayed with the hello unmodified and never
// escalated.
func TestBypassedNameSurvivesTUNMode(t *testing.T) {
	o := newOrigin(t)
	l := newLab(t, labOpts{rules: []policy.Rule{
		{Pattern: "isbank.com.tr", Class: policy.ScopeBypass, From: policy.FromCompiledIn},
	}})
	l.up.serveOn(o.addr())

	hello := clientHello(t, "www.isbank.com.tr")
	client, err := l.dial(netip.AddrPortFrom(bankIP, 443))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	up := o.accept()
	got := readWithin(t, up, len(hello), 5*time.Second)
	if !bytes.Equal(got, hello) {
		t.Fatalf("the bank's ClientHello reached the origin altered: %d of %d bytes match",
			matching(got, hello), len(hello))
	}

	// Ending BOTH ends is what publishes the event on a condition instead of on
	// RelayIdle: the relay half-closes, so an origin left open holds it for the
	// full three seconds.
	_ = client.Close()
	_ = up.Close()

	waitForEvent(t, l, "the bank flow to finish", func(ev observ.ConnEvent) bool {
		return ev.Host == "www.isbank.com.tr"
	})
	ev := lastEvent(t, l)
	if ev.Scope != policy.ScopeBypass.String() {
		t.Fatalf("scope = %q, want %q: the SNI must re-scope a flow that arrived as a bare address",
			ev.Scope, policy.ScopeBypass)
	}
	if ev.Escalated {
		t.Fatal("a bypassed host was escalated")
	}
	if n := len(l.up.targets()); n != 1 {
		t.Fatalf("%d upstream dials for a bypassed host, want exactly 1", n)
	}
}

// TestReverseMapNamesAnUnnamedFlow: the DNS answer we served ourselves names
// the flow before its first byte is read, which is what lets a rule about a
// name apply to a connection that only ever mentions an address.
func TestReverseMapNamesAnUnnamedFlow(t *testing.T) {
	o := newOrigin(t)
	reverse := policy.NewReverseMap(16)
	reverse.Learn("www.isbank.com.tr", []netip.Addr{bankIP}, time.Hour)
	l := newLab(t, labOpts{
		reverse: reverse,
		rules: []policy.Rule{
			{Pattern: "isbank.com.tr", Class: policy.ScopeBypass, From: policy.FromCompiledIn},
		},
	})
	l.up.serveOn(o.addr())

	client, err := l.dial(netip.AddrPortFrom(bankIP, 443))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	// Nothing is written by the client: a bypassed flow must not be buffered at
	// all, so the upstream connection has to appear anyway.
	up := o.accept()
	if _, err := up.Write([]byte("hi")); err != nil {
		t.Fatalf("origin write: %v", err)
	}
	if got := string(readWithin(t, client, 2, 3*time.Second)); got != "hi" {
		t.Fatalf("client read %q; a bypassed flow was buffered instead of relayed", got)
	}
	ts := l.up.targets()
	if len(ts) != 1 || ts[0].Name != "www.isbank.com.tr" {
		t.Fatalf("dial targets = %+v, want one named from the reverse map", ts)
	}
}

// TestHalfClosePropagates: a client that shuts down its write side and waits
// for the tail of a response must get it. Without CloseWrite propagation the
// relay either hangs or tears the whole connection down.
func TestHalfClosePropagates(t *testing.T) {
	o := newOrigin(t)
	l := newLab(t, labOpts{firstMsg: shortFirstMsg()})
	l.up.serveOn(o.addr())

	client, err := l.dial(netip.AddrPortFrom(originIP, 25))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatalf("write: %v", err)
	}
	cw, ok := client.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("the client connection does not support half-close")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	up := o.accept()
	if got := string(readWithin(t, up, 7, 3*time.Second)); got != "request" {
		t.Fatalf("origin read %q", got)
	}
	// The origin must observe EOF — the half-close crossed the relay — and must
	// still be able to answer.
	if err := up.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := up.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("origin read after the client half-closed = %v, want EOF", err)
	}
	if _, err := up.Write([]byte("late-answer")); err != nil {
		t.Fatalf("origin write after half-close: %v", err)
	}
	if got := string(readWithin(t, client, 11, 3*time.Second)); got != "late-answer" {
		t.Fatalf("client read %q after half-closing; the response tail was lost", got)
	}
}

// TestUnnamedFlowOnAnInspectPortIsJudged: with no name from either source, an
// inspect-port flow is still ScopeWatch and is judged by its own ClientHello.
// That is the property that lets this design ship with no fake-IP layer — an
// unnamed flow is exactly as safe as a named one, so nothing has to be faked to
// name it.
func TestUnnamedFlowOnAnInspectPortIsJudged(t *testing.T) {
	o := newOrigin(t)
	l := newLab(t, labOpts{})
	l.up.serveOn(o.addr())

	hello := clientHello(t, "unknown.example")
	client, err := l.dial(netip.AddrPortFrom(originIP, 443))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := client.Write(hello); err != nil {
		t.Fatalf("write: %v", err)
	}
	up := o.accept()
	if got := readWithin(t, up, len(hello), 5*time.Second); !bytes.Equal(got, hello) {
		t.Fatal("the unnamed flow's hello did not arrive intact on rung 1")
	}
	// Answering commits the connection on rung 1, so the walk ends and the
	// event carries the verdict that was in force.
	if _, err := up.Write([]byte("ok")); err != nil {
		t.Fatalf("origin write: %v", err)
	}
	if got := string(readWithin(t, client, 2, 5*time.Second)); got != "ok" {
		t.Fatalf("client read %q, want the committed response", got)
	}
	// Both ends, so the event lands on the close rather than on RelayIdle.
	_ = client.Close()
	_ = up.Close()

	waitForEvent(t, l, "the unnamed flow to be recorded", func(ev observ.ConnEvent) bool {
		return ev.Addr == netip.AddrPortFrom(originIP, 443).String()
	})
	ev := lastEvent(t, l)
	if ev.Scope != policy.ScopeWatch.String() {
		t.Fatalf("scope = %q, want %q", ev.Scope, policy.ScopeWatch)
	}
	if ev.Escalated {
		t.Fatal("a flow that worked plain was escalated")
	}
	if ev.Strategy != "" {
		t.Fatalf("winning strategy = %q, want plain", ev.Strategy)
	}
}

// TestDialFailureIsReportedNotSwallowed: an upstream that cannot be reached
// closes the client connection and records the failure, rather than leaving the
// client waiting on a tunnel to nowhere.
func TestDialFailureIsReportedNotSwallowed(t *testing.T) {
	l := newLab(t, labOpts{firstMsg: shortFirstMsg()})
	l.up.err = errors.New("scripted: no route to host")

	client, err := l.dial(netip.AddrPortFrom(originIP, 25))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := client.Read(buf); err == nil {
		t.Fatal("the client connection stayed open after the upstream dial failed")
	}
	waitForEvent(t, l, "the failed flow to be recorded", func(ev observ.ConnEvent) bool {
		return ev.Err != ""
	})
	if s := l.server.Stats(); s.Failed == 0 {
		t.Fatal("a failed flow was not counted")
	}
}

// TestSNIOverridesAStaleReverseMapName is the CDN-collision case, and it is a
// safety property rather than an accuracy one.
//
// policy.ReverseMap keeps the most recently learned name for an address, and
// one CDN address serves many names. If a stale reverse-map name outranked the
// SNI, a bank's connection would be judged — and possibly desynced — under some
// other host's verdict. MEASUREMENTS.md §5.1 measured every Turkish bank tested
// breaking under the emitter that defeats the DPI, so that is not a cosmetic
// mistake.
func TestSNIOverridesAStaleReverseMapName(t *testing.T) {
	o := newOrigin(t)
	reverse := policy.NewReverseMap(16)
	// The address was last answered for discord.com, which is watched.
	reverse.Learn("discord.com", []netip.Addr{bankIP}, time.Hour)
	l := newLab(t, labOpts{
		reverse: reverse,
		rules: []policy.Rule{
			{Pattern: "isbank.com.tr", Class: policy.ScopeBypass, From: policy.FromCompiledIn},
		},
	})
	l.up.serveOn(o.addr())

	hello := clientHello(t, "www.isbank.com.tr")
	client, err := l.dial(netip.AddrPortFrom(bankIP, 443))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	up := o.accept()
	if got := readWithin(t, up, len(hello), 5*time.Second); !bytes.Equal(got, hello) {
		t.Fatalf("the bank's ClientHello was altered under the stale name: %d of %d bytes match",
			matching(got, hello), len(hello))
	}
	// Both ends, so the event lands on the close rather than on RelayIdle.
	_ = client.Close()
	_ = up.Close()
	waitForEvent(t, l, "the flow to be re-scoped on its SNI", func(ev observ.ConnEvent) bool {
		return ev.Host == "www.isbank.com.tr"
	})
	if ev := lastEvent(t, l); ev.Scope != policy.ScopeBypass.String() {
		t.Fatalf("scope = %q, want %q: the SNI must outrank a stale reverse-map name",
			ev.Scope, policy.ScopeBypass)
	}
}

// TestAPanicInAFlowKillsTheConnectionNotTheProcess: Go runs only the panicking
// goroutine's deferred functions before killing the whole process, so an
// unguarded goroutine in the datapath turns one malformed input into a process
// death that leaves the capture routes pointing at a device nothing is reading.
// Every flow therefore runs under flow.Safe.
func TestAPanicInAFlowKillsTheConnectionNotTheProcess(t *testing.T) {
	o := newOrigin(t)
	l := newLab(t, labOpts{
		firstMsg:  shortFirstMsg(),
		wrapScope: func(s policy.Scope) policy.Scope { return panicScope{Scope: s, port: 443} },
	})
	l.up.serveOn(o.addr())

	before := flow.PanicCount()
	client, err := l.dial(netip.AddrPortFrom(originIP, 443))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	waitFor(t, 10*time.Second, "the panic to be recovered", func() bool {
		return flow.PanicCount() > before
	})

	// The process is still here, and so is the datapath: a flow the defect does
	// not touch still works.
	client2, err := l.dial(netip.AddrPortFrom(originIP, 25))
	if err != nil {
		t.Fatalf("dial after a recovered panic: %v", err)
	}
	defer client2.Close()
	up := o.accept()
	if _, err := up.Write([]byte("still here")); err != nil {
		t.Fatalf("origin write: %v", err)
	}
	if got := string(readWithin(t, client2, 10, 5*time.Second)); got != "still here" {
		t.Fatalf("second flow read %q", got)
	}
}

// panicScope panics on one port, the way a defect in the policy layer reachable
// from one kind of flow would.
type panicScope struct {
	policy.Scope
	port int
}

func (p panicScope) ForAddr(ap netip.AddrPort) policy.Verdict {
	if int(ap.Port()) == p.port {
		panic("scripted defect in the scope layer")
	}
	return p.Scope.ForAddr(ap)
}
