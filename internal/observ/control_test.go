package observ

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// sockPath keeps the path well inside darwin's 104-byte sun_path limit; a
// t.TempDir() under a deep home can exceed it and the bind then fails for a
// reason that has nothing to do with what is under test.
func sockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dpbctl")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := filepath.Join(dir, "c.sock")
	if len(p) >= 104 {
		t.Fatalf("socket path %q is %d bytes, past darwin's sun_path limit", p, len(p))
	}
	return p
}

// serve starts a control server and returns a client for it.
func serve(t *testing.T, h Handler) (*ControlServer, *Client) {
	t.Helper()
	path := sockPath(t)
	s, err := NewControlServer(ControlOptions{Path: path, Handler: h, Logf: t.Logf})
	if err != nil {
		t.Fatalf("NewControlServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after cancellation")
		}
	})
	return s, NewClient(path)
}

func TestControlStatusRoundTrip(t *testing.T) {
	want := Status{
		Running: true, PID: 4242, Mode: "watch",
		Listeners: []Listener{{Kind: "http", Addr: "127.0.0.1:8080"}},
		Applied:   []string{"auto-proxy URL"},
		Conns:     Snapshot{Totals: Totals{Conns: 7, Escalated: 2}},
	}
	_, c := serve(t, Handler{
		Status: func(context.Context) (Status, error) { return want, nil },
	})

	got, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !got.Running || got.PID != 4242 || got.Mode != "watch" {
		t.Fatalf("status = %+v", got)
	}
	if len(got.Listeners) != 1 || got.Listeners[0].Addr != "127.0.0.1:8080" {
		t.Errorf("listeners = %+v", got.Listeners)
	}
	if got.Conns.Totals.Conns != 7 || got.Conns.Totals.Escalated != 2 {
		t.Errorf("conns = %+v", got.Conns)
	}
}

func TestControlWhyRoundTrip(t *testing.T) {
	learned := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	_, c := serve(t, Handler{
		Why: func(_ context.Context, host string, port int) (Why, error) {
			return Why{
				Host: host, Port: port, Punycode: host,
				Rules: []WhyRule{{Pattern: "isbank.com.tr", Class: "bypass", Where: "compiled-in"}},
				Verdict: WhyVerdict{
					Class: "desync", Spec: "tlsfrag:pos=snimid", Source: "learned-desync",
					Learned: learned, Expires: learned.Add(7 * 24 * time.Hour),
				},
				Recent: []ConnStat{{At: learned, OK: true, Attempts: 2}},
			}, nil
		},
	})

	got, err := c.Why(context.Background(), "discord.com", 443)
	if err != nil {
		t.Fatalf("Why: %v", err)
	}
	if !got.Live {
		t.Error("the client did not mark a live answer as live")
	}
	if got.Host != "discord.com" || got.Port != 443 {
		t.Errorf("why = %+v", got)
	}
	// Provenance is the whole point of this command: the rule, when the verdict
	// was learned, and when it expires must all survive the wire.
	if len(got.Rules) != 1 || got.Rules[0].Where != "compiled-in" {
		t.Errorf("rules = %+v", got.Rules)
	}
	if !got.Verdict.Learned.Equal(learned) {
		t.Errorf("learned = %v, want %v", got.Verdict.Learned, learned)
	}
	if !got.Verdict.Expires.Equal(learned.Add(7 * 24 * time.Hour)) {
		t.Errorf("expires = %v", got.Verdict.Expires)
	}
	if len(got.Recent) != 1 || !got.Recent[0].OK {
		t.Errorf("recent = %+v", got.Recent)
	}
}

func TestControlWhyNeedsAHost(t *testing.T) {
	_, c := serve(t, Handler{
		Why: func(context.Context, string, int) (Why, error) {
			t.Error("the handler was called for a request with no host")
			return Why{}, nil
		},
	})
	if _, err := c.Do(context.Background(), Request{Cmd: CmdWhy}); err == nil {
		t.Fatal("why with no host was accepted")
	}
}

func TestControlSimpleCommands(t *testing.T) {
	var called []string
	mark := func(name string) func(context.Context) error {
		return func(context.Context) error {
			called = append(called, name)
			return nil
		}
	}
	_, c := serve(t, Handler{
		On: mark("on"), Off: mark("off"), Reload: mark("reload"),
		Reapply: mark("reapply"), Panic: mark("panic"),
	})

	for _, cmd := range []string{CmdOn, CmdOff, CmdReload, CmdReapply, CmdPanic} {
		note, err := c.Command(context.Background(), cmd)
		if err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		if note == "" {
			t.Errorf("%s replied with no note; a kill switch that says nothing is one "+
				"the user cannot tell worked", cmd)
		}
	}
	if len(called) != 5 {
		t.Fatalf("handlers called = %v", called)
	}
}

// A handler this build does not implement must answer with a sentence, not by
// closing the socket: an old client talking to a new daemon has to read a
// reason.
func TestControlUnsupportedCommand(t *testing.T) {
	_, c := serve(t, Handler{})
	_, err := c.Command(context.Background(), CmdOff)
	if err == nil {
		t.Fatal("an unsupported command succeeded")
	}
	if !strings.Contains(err.Error(), "does not support") {
		t.Errorf("error = %v", err)
	}
}

func TestControlHandlerErrorReachesTheClient(t *testing.T) {
	_, c := serve(t, Handler{
		Off: func(context.Context) error { return errors.New("the routes are wedged") },
	})
	_, err := c.Command(context.Background(), CmdOff)
	if err == nil || !strings.Contains(err.Error(), "wedged") {
		t.Fatalf("error = %v, want the handler's own words", err)
	}
}

func TestControlUnknownAndEmptyCommands(t *testing.T) {
	_, c := serve(t, Handler{})
	for _, cmd := range []string{"", "explode"} {
		if _, err := c.Do(context.Background(), Request{Cmd: cmd}); err == nil {
			t.Errorf("command %q was accepted", cmd)
		}
	}
}

func TestControlMalformedRequest(t *testing.T) {
	s, _ := serve(t, Handler{})
	conn, err := net.Dial("unix", s.Path())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("this is not json\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := readLine(conn, 1<<16)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(line), "malformed") {
		t.Fatalf("reply = %q, want an explanation", line)
	}
}

func TestControlRefusesAnOversizedRequest(t *testing.T) {
	s, _ := serve(t, Handler{
		Why: func(context.Context, string, int) (Why, error) {
			t.Error("a request past the size cap reached the handler")
			return Why{}, nil
		},
	})
	conn, err := net.Dial("unix", s.Path())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	big := fmt.Sprintf(`{"cmd":"why","host":%q}`+"\n", strings.Repeat("a", MaxRequestBytes*2))
	_, _ = conn.Write([]byte(big))
	// The server drops the connection rather than allocating; a read returns
	// EOF or a reset, and either is the refusal.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if n, err := conn.Read(buf); err == nil && n > 0 {
		t.Fatalf("the server answered an oversized request with %q", buf[:n])
	}
}

// A panicking handler must kill that one control connection and nothing else.
// The proxy the user is browsing through runs in the same process.
func TestControlSurvivesAPanickingHandler(t *testing.T) {
	_, c := serve(t, Handler{
		Status: func(context.Context) (Status, error) { panic("boom") },
		Off:    func(context.Context) error { return nil },
	})
	if _, err := c.Status(context.Background()); err == nil {
		t.Fatal("a panicking handler produced a successful status")
	}
	// The server is still there.
	if _, err := c.Command(context.Background(), CmdOff); err != nil {
		t.Fatalf("the server did not survive the panic: %v", err)
	}
}

func TestClientReportsNotRunning(t *testing.T) {
	c := NewClient(sockPath(t)) // nothing bound
	if _, err := c.Status(context.Background()); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("err = %v, want ErrNotRunning", err)
	}
	if c.Running(context.Background()) {
		t.Fatal("Running reported true with nothing bound")
	}
}

func TestClientWithNoPath(t *testing.T) {
	c := NewClient("")
	if _, err := c.Status(context.Background()); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("err = %v, want ErrNotRunning", err)
	}
}

// A socket file left behind by a SIGKILLed dpb must be removed, or every later
// run fails to bind. A socket a LIVE dpb is serving must NOT be, or the second
// process steals the first one's socket and the first holds a listener nobody
// can reach.
func TestStaleSocketIsRemovedButALiveOneIsNot(t *testing.T) {
	s, _ := serve(t, Handler{Off: func(context.Context) error { return nil }})

	_, err := NewControlServer(ControlOptions{Path: s.Path()})
	if !errors.Is(err, ErrControlInUse) {
		t.Fatalf("binding over a live socket returned %v, want ErrControlInUse", err)
	}

	// Now make it stale: close the listener but leave the file behind, which is
	// what a SIGKILL produces.
	if err := s.ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	ln, err := net.Listen("unix", s.Path())
	if err != nil {
		t.Fatalf("re-create the socket file: %v", err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	if _, err := os.Stat(s.Path()); err != nil {
		t.Fatalf("the stale socket file is not there: %v", err)
	}

	s2, err := NewControlServer(ControlOptions{Path: s.Path()})
	if err != nil {
		t.Fatalf("binding over a stale socket: %v", err)
	}
	s2.Close()
}

// Something that is not a socket sitting at the path is refused by name rather
// than deleted: it might be anything.
func TestRefusesToDeleteANonSocket(t *testing.T) {
	path := sockPath(t)
	if err := os.WriteFile(path, []byte("important"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := NewControlServer(ControlOptions{Path: path})
	if err == nil {
		t.Fatal("a regular file at the socket path was accepted")
	}
	if b, rerr := os.ReadFile(path); rerr != nil || string(b) != "important" {
		t.Fatalf("the file was destroyed: %v %q", rerr, b)
	}
}

// Filesystem permissions are the whole authentication story for this socket.
func TestSocketIsOwnerOnly(t *testing.T) {
	s, _ := serve(t, Handler{})
	fi, err := os.Stat(s.Path())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode = %o, want 0600", perm)
	}
}

// The client and the server must agree about the path, because a client that
// computed it itself would look in the wrong place on a deep home directory.
func TestClientPathIsTheServerPath(t *testing.T) {
	s, c := serve(t, Handler{})
	if c.Path() != s.Path() {
		t.Fatalf("client path %q, server path %q", c.Path(), s.Path())
	}
}

func TestControlServerNeedsAPath(t *testing.T) {
	if _, err := NewControlServer(ControlOptions{}); err == nil {
		t.Fatal("an empty path was accepted")
	}
}

func TestControlServerChownHookFailureIsFatal(t *testing.T) {
	path := sockPath(t)
	_, err := NewControlServer(ControlOptions{
		Path:  path,
		Chown: func(string) error { return errors.New("no") },
	})
	if err == nil {
		t.Fatal("a failing chown hook was ignored")
	}
	// The listener must not be left behind holding the path.
	if _, serr := os.Stat(path); serr == nil {
		t.Error("the socket file survived a failed chown")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	s, err := NewControlServer(ControlOptions{Path: sockPath(t)})
	if err != nil {
		t.Fatalf("NewControlServer: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// Serve must return when Close is called even with no cancellation, and it must
// wait for in-flight handlers rather than leaving them running.
func TestServeReturnsOnClose(t *testing.T) {
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	s, err := NewControlServer(ControlOptions{
		Path: sockPath(t),
		Handler: Handler{Status: func(context.Context) (Status, error) {
			defer wg.Done()
			<-release
			return Status{}, nil
		}},
	})
	if err != nil {
		t.Fatalf("NewControlServer: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background()) }()

	c := NewClient(s.Path())
	go func() { _, _ = c.Status(context.Background()) }()

	// Give the handler time to be entered, then close underneath it.
	time.Sleep(50 * time.Millisecond)
	s.Close()
	close(release)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
	wg.Wait()
}

func TestReadLineHonoursTheCap(t *testing.T) {
	if _, err := readLine(strings.NewReader(strings.Repeat("x", 100)), 10); err == nil {
		t.Fatal("readLine accepted a line past its cap")
	}
	// A final line with no newline is still a line.
	got, err := readLine(strings.NewReader("hello"), 100)
	if err != nil || string(got) != "hello" {
		t.Fatalf("readLine(%q) = %q, %v", "hello", got, err)
	}
}
