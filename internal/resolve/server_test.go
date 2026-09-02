package resolve

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testServer(t *testing.T, rs ...Resolver) *Server {
	t.Helper()
	return NewServer(fastChain(t, Options{Resolvers: rs}), nil)
}

func TestServerAnswerNeverReturnsAnError(t *testing.T) {
	s := testServer(t, dropping(t, "a"))

	q := mustQuery(t, "discord.com", dns.TypeA)
	if err := SetMsgID(q, 0x9999); err != nil {
		t.Fatal(err)
	}
	resp := s.Answer(context.Background(), q)
	if Rcode(resp) != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", Rcode(resp))
	}
	if id, _ := MsgID(resp); id != 0x9999 {
		t.Fatalf("id = %#x", id)
	}
	if !SameQuestion(q, resp) {
		t.Fatal("question must be echoed")
	}
}

func TestServerAnswerRejectsNonQueries(t *testing.T) {
	s := testServer(t, answering(t, "a", "doh", genuineAnswer[0]))

	if got := s.Answer(context.Background(), []byte{1, 2, 3}); got != nil {
		t.Fatalf("a sub-header buffer has nothing to reply to, got %v", got)
	}
	// A response arriving as a query is noise or a reflection attempt.
	resp := buildAnswer(t, mustQuery(t, "discord.com", dns.TypeA), 60, genuineAnswer[0])
	if got := s.Answer(context.Background(), resp); got != nil {
		t.Fatalf("a response must not be answered, got %v", got)
	}
	// A header claiming a question with nothing behind it is FORMERR.
	broken := make([]byte, headerLen)
	binary.BigEndian.PutUint16(broken[4:6], 1)
	if rc := Rcode(s.Answer(context.Background(), broken)); rc != dns.RcodeFormatError {
		t.Fatalf("rcode = %d, want FORMERR", rc)
	}
}

func TestServerWithoutAChainStillAnswers(t *testing.T) {
	s := NewServer(nil, nil)
	q := mustQuery(t, "discord.com", dns.TypeA)
	if rc := Rcode(s.Answer(context.Background(), q)); rc != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", rc)
	}
}

func TestServerServeUDP(t *testing.T) {
	s := testServer(t, answering(t, "alt", "udp-alt", genuineAnswer...))
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.ServeUDP(ctx, pc) }()

	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	q := mustQuery(t, "discord.com", dns.TypeA)
	if err := SetMsgID(q, 0x0101); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(q); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if id, _ := MsgID(buf[:n]); id != 0x0101 {
		t.Fatalf("id = %#x", id)
	}
	if got := addrStrings(AnswerAddrs(buf[:n])); got != addrStrings(genuineAnswer) {
		t.Fatalf("answer = %s", got)
	}

	// Garbage must not kill the loop.
	if _, err := client.Write([]byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("ServeUDP returned %v", err)
	}
}

// TestServerServeTCPAnswersLocally is the point of serving TCP at all:
// MEASUREMENTS.md §2 measures upstream TCP DNS as connection-reset at every
// port, so an application that receives TC=1 and retries over TCP only works
// because the retry never leaves the machine.
func TestServerServeTCPAnswersLocally(t *testing.T) {
	s := testServer(t, answering(t, "doh", "doh", genuineAnswer...))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- s.ServeTCP(ctx, l) }()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// Two queries on one connection: RFC 7766 reuse must work.
	for _, id := range []uint16{0x0a0a, 0x0b0b} {
		q := mustQuery(t, "discord.com", dns.TypeA)
		if err := SetMsgID(q, id); err != nil {
			t.Fatal(err)
		}
		framed := make([]byte, 2+len(q))
		binary.BigEndian.PutUint16(framed[0:2], uint16(len(q)))
		copy(framed[2:], q)
		if _, err := conn.Write(framed); err != nil {
			t.Fatal(err)
		}
		var hdr [2]byte
		if _, err := readFull(conn, hdr[:]); err != nil {
			t.Fatalf("read length: %v", err)
		}
		resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := readFull(conn, resp); err != nil {
			t.Fatalf("read body: %v", err)
		}
		if got, _ := MsgID(resp); got != id {
			t.Fatalf("id = %#x, want %#x", got, id)
		}
		if addrStrings(AnswerAddrs(resp)) != addrStrings(genuineAnswer) {
			t.Fatalf("answer = %s", addrStrings(AnswerAddrs(resp)))
		}
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("ServeTCP returned %v", err)
	}
}

func TestServerServeTCPDropsAShortFrame(t *testing.T) {
	s := testServer(t, answering(t, "doh", "doh", genuineAnswer[0]))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- s.ServeTCP(ctx, l) }()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A length below a DNS header is not a query; the connection is dropped
	// rather than answered.
	if _, err := conn.Write([]byte{0, 4, 1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("a short frame must not be answered")
	}
	cancel()
	<-errc
}

func TestServerStopsOnContextCancel(t *testing.T) {
	s := testServer(t, answering(t, "doh", "doh", genuineAnswer[0]))
	ctx, cancel := context.WithCancel(context.Background())

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpErr := make(chan error, 1)
	tcpErr := make(chan error, 1)
	go func() { udpErr <- s.ServeUDP(ctx, pc) }()
	go func() { tcpErr <- s.ServeTCP(ctx, l) }()

	cancel()
	select {
	case err := <-udpErr:
		if err != nil {
			t.Fatalf("ServeUDP = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ServeUDP did not stop")
	}
	select {
	case err := <-tcpErr:
		if err != nil {
			t.Fatalf("ServeTCP = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ServeTCP did not stop")
	}
}

func TestServerServeReportsSocketFailure(t *testing.T) {
	s := testServer(t, answering(t, "doh", "doh", genuineAnswer[0]))
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.Close()
	if err := s.ServeUDP(context.Background(), pc); err == nil {
		t.Fatal("a dead socket must be reported, not looped on")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if err := s.ServeTCP(context.Background(), l); err == nil {
		t.Fatal("a dead listener must be reported")
	}
}

// TestServerDropsRatherThanRunningOnTheReadLoop pins the panic barrier and the
// stall together.
//
// dispatch's over-budget branch used to run the exchange inline, on the very
// goroutine that owns the socket every stub on this machine talks to: measured,
// 4000 queries from one socket against a 300 ms upstream left an unrelated
// single query answered after 6.85 s, and at a 2 s upstream it was never
// answered inside 30 s. That branch was also the only one outside flow.Safe, so
// a panic reachable from Chain.Exchange killed the process under load alone.
func TestServerDropsRatherThanRunningOnTheReadLoop(t *testing.T) {
	s := testServer(t, answering(t, "doh", "doh", genuineAnswer[0]))
	for range inFlightMax {
		s.sem <- struct{}{}
	}
	t.Cleanup(func() {
		for range inFlightMax {
			<-s.sem
		}
	})

	ran := make(chan struct{}, 1)
	done := make(chan bool, 1)
	go func() { done <- s.dispatch("over-budget", func() { ran <- struct{}{} }) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("dispatch must report the query as dropped when the budget is spent")
		}
	case <-time.After(time.Second):
		t.Fatal("dispatch blocked the caller; the read loop must never wait on the budget")
	}
	select {
	case <-ran:
		t.Fatal("the exchange ran on the caller's goroutine, which is the ReadFrom goroutine")
	default:
	}
	if got := s.Dropped(); got != 1 {
		t.Fatalf("Dropped() = %d, want 1", got)
	}

	// A panic in the dropped path must not escape either: nothing runs, so
	// there is nothing outside the barrier left to panic.
	if s.dispatch("over-budget", func() { panic("must never run") }) {
		t.Fatal("a second over-budget query must also be dropped")
	}
	if got := s.Dropped(); got != 2 {
		t.Fatalf("Dropped() = %d, want 2", got)
	}
}

// TestServerReadLoopKeepsReadingWhileTheBudgetIsSpent is the same claim on a
// real socket: with the in-flight budget full, the read loop must keep draining
// the socket instead of blocking on one upstream exchange.
func TestServerReadLoopKeepsReadingWhileTheBudgetIsSpent(t *testing.T) {
	s := testServer(t, dropping(t, "slow"))
	for range inFlightMax {
		s.sem <- struct{}{}
	}
	t.Cleanup(func() {
		for range inFlightMax {
			<-s.sem
		}
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.ServeUDP(ctx, pc) }()

	client, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	const sent = 5
	for range sent {
		if _, err := client.Write(mustQuery(t, "discord.com", dns.TypeA)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.Dropped() < sent && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := s.Dropped(); got < sent {
		t.Fatalf("the read loop drained %d of %d datagrams; it stalled on the first", got, sent)
	}
}

// TestServerNeverServesTruncatedOverTCP: TC is meaningless on a stream, and a
// stub that opened TCP *because* of a TC=1 UDP answer has nowhere left to
// escalate to — MEASUREMENTS.md §2 measures plaintext TCP DNS as
// connection-reset at every port, so there is no second opinion to fetch.
// Answering TC=1 again is a silent resolution failure; SERVFAIL is one the stub
// can see.
func TestServerNeverServesTruncatedOverTCP(t *testing.T) {
	s := testServer(t, truncating(t, "udp-alt", "udp-alt"))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.ServeTCP(ctx, l) }()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	q := mustQuery(t, "discord.com", dns.TypeA)
	out := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(q)))
	copy(out[2:], q)
	if _, err := conn.Write(out); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var hdr [2]byte
	if _, err := readFull(conn, hdr[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := readFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if Truncated(resp) {
		t.Fatal("a TC=1 message must never be served over the TCP listener")
	}
	if rc := Rcode(resp); rc != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", rc)
	}
	if !SameQuestion(q, resp) {
		t.Fatal("the question must still be echoed")
	}
}

func readFull(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}
