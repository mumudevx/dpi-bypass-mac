package observ

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// The control socket is how a second `dpb` process asks the running one what it
// is doing, and how the kill switch reaches it without a signal.
//
// It is a unix socket with 0600 permissions in the user's own state directory,
// never a TCP port: a bypass tool that exposes an unauthenticated "turn
// yourself off" endpoint on loopback is a bypass tool any web page can turn off
// with a fetch(). Filesystem permissions are the whole authentication story,
// and that is deliberate — they are the same permissions that already protect
// the verdict store and the journal sitting beside it.
//
// The wire format is one JSON object per line, request then response, one
// exchange per connection. It is not a streaming protocol: `dpb status --watch`
// polls, because a long-lived subscription would have to decide what to do when
// the reader stalls, and dropping diagnostics on the floor is a decision better
// made in the Bus than in a socket.

// Control commands. They are the verbs in docs/PLAN.md's CLI surface.
const (
	CmdStatus = "status"
	CmdWhy    = "why"
	CmdOn     = "on"
	CmdOff    = "off"
	CmdPanic  = "panic"
	CmdReload = "reload"
	// CmdReapply asks the running dpb to re-assert the system proxy settings it
	// owns. It is what `dpb coverage --fix` sends: those settings name THIS
	// run's listener ports, so only the process that owns them can restore them.
	CmdReapply = "reapply"
)

// MaxRequestBytes bounds one request line. The protocol's largest legitimate
// request is a hostname, so anything approaching this is either a bug or an
// attempt to make the daemon allocate.
const MaxRequestBytes = 8 << 10

// ControlTimeout bounds one exchange from both ends.
const ControlTimeout = 5 * time.Second

// Request is one control-socket command.
type Request struct {
	Cmd  string `json:"cmd"`
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
}

// Response is the reply. Err is set when the command was understood but could
// not be carried out; a malformed request gets Err too, never a closed socket,
// so an old client talking to a new daemon reads a sentence rather than EOF.
type Response struct {
	OK     bool    `json:"ok"`
	Err    string  `json:"error,omitempty"`
	Note   string  `json:"note,omitempty"`
	Status *Status `json:"status,omitempty"`
	Why    *Why    `json:"why,omitempty"`
}

// Listener is one bound socket, as reported by status.
type Listener struct {
	Kind string `json:"kind"`
	Addr string `json:"addr"`
}

// ResolverHealth is one rung of the DNS chain.
//
// OK=false with an empty Err means the rung has never been tried, which
// `dpb status` and `dpb dns check` must render as "untried" rather than
// "broken": a chain that answered on rung 1 has told us nothing about rung 5.
type ResolverHealth struct {
	Label    string        `json:"label"`
	OK       bool          `json:"ok"`
	Tried    bool          `json:"tried"`
	Latency  time.Duration `json:"latency"`
	Sinkhole bool          `json:"sinkhole"`
	Err      string        `json:"error,omitempty"`
}

// Status is what `dpb status` prints. Every field is filled from a fact the
// process actually observed; nothing here is an intention.
type Status struct {
	Running bool      `json:"running"`
	PID     int       `json:"pid,omitempty"`
	Version string    `json:"version,omitempty"`
	Started time.Time `json:"started,omitempty"`

	Profile    string   `json:"profile,omitempty"`
	Sources    []string `json:"sources,omitempty"`
	Mode       string   `json:"mode,omitempty"`
	ProxyStyle string   `json:"proxy_style,omitempty"`
	// Suspended is the kill switch or the captive-portal suspend: everything is
	// relayed direct and nothing is judged.
	Suspended     bool   `json:"suspended"`
	SuspendReason string `json:"suspend_reason,omitempty"`

	Listeners []Listener `json:"listeners,omitempty"`
	// Applied is what netstate actually confirmed through a second subsystem,
	// so a run that pointed macOS at nothing cannot report that it did.
	Applied []string `json:"applied,omitempty"`
	Notes   []string `json:"notes,omitempty"`

	Strategy  string           `json:"strategy,omitempty"`
	Ladder    []string         `json:"ladder,omitempty"`
	Resolvers []ResolverHealth `json:"resolvers,omitempty"`
	NetworkID string           `json:"network_id,omitempty"`

	// Tuned describes the measured profile on disk, if there is one.
	Tuned *TunedStatus `json:"tuned,omitempty"`
	// Cache is the verdict store's shape for this network.
	Cache CacheStatus `json:"cache"`
	// Journal is the durability picture: pending records mean unfinished
	// system state somewhere.
	Journal JournalStatus `json:"journal"`

	Conns Snapshot `json:"conns"`
}

// TunedStatus summarises ~/.config/dpb/tuned.toml for `dpb status`.
type TunedStatus struct {
	Present    bool          `json:"present"`
	Path       string        `json:"path,omitempty"`
	CreatedAt  time.Time     `json:"created_at,omitempty"`
	Age        time.Duration `json:"age,omitempty"`
	Confidence string        `json:"confidence,omitempty"`
	Strategy   string        `json:"strategy,omitempty"`
	// SameNetwork reports whether the measurement was taken on the network this
	// machine is on now. A tuned profile from a different line is worse than
	// none: it would desync a flow on evidence gathered somewhere else.
	SameNetwork bool   `json:"same_network"`
	Err         string `json:"error,omitempty"`
}

// CacheStatus is the verdict store's shape.
type CacheStatus struct {
	Path    string `json:"path,omitempty"`
	Hosts   int    `json:"hosts"`
	Plain   int    `json:"plain"`
	Desync  int    `json:"desync"`
	Bypass  int    `json:"bypass"`
	Enabled bool   `json:"enabled"`
	Err     string `json:"error,omitempty"`
}

// JournalStatus is the on-disk record of unfinished system mutations.
type JournalStatus struct {
	Path    string `json:"path,omitempty"`
	Pending int    `json:"pending"`
	// OwnedByLive counts pending records whose owning process is still running,
	// which is the healthy state while dpb is up. The rest are residue.
	OwnedByLive int    `json:"owned_by_live"`
	Residue     int    `json:"residue"`
	Err         string `json:"error,omitempty"`
}

// WhyRule is one matched scoping rule with its provenance.
type WhyRule struct {
	Pattern string `json:"pattern"`
	Class   string `json:"class"`
	Where   string `json:"where"`
}

// WhyVerdict is the effective decision, flattened for the wire.
type WhyVerdict struct {
	Class    string    `json:"class"`
	Spec     string    `json:"spec,omitempty"`
	Ladder   []string  `json:"ladder,omitempty"`
	Source   string    `json:"source"`
	Reason   string    `json:"reason,omitempty"`
	RuleText string    `json:"rule_text,omitempty"`
	RuleFrom string    `json:"rule_from,omitempty"`
	Learned  time.Time `json:"learned,omitempty"`
	Expires  time.Time `json:"expires,omitempty"`
	Wins     int       `json:"wins,omitempty"`
	Losses   int       `json:"losses,omitempty"`
}

// Why is the full decision chain for one host.
//
// It mirrors policy.Explanation field for field, in plain types, because observ
// must not import policy. The CLI converts one into the other and renders with
// policy's own renderer, so a live answer and an offline answer are formatted
// by the same code and cannot drift apart.
type Why struct {
	Host     string     `json:"host"`
	Punycode string     `json:"punycode,omitempty"`
	Port     int        `json:"port,omitempty"`
	Rules    []WhyRule  `json:"rules,omitempty"`
	Verdict  WhyVerdict `json:"verdict"`
	Recent   []ConnStat `json:"recent,omitempty"`
	// Network is the NetworkID key the verdict was looked up under. Two
	// different keys are why "it worked yesterday" can be true and the cache
	// still empty: the laptop moved.
	Network string `json:"network,omitempty"`
	// Live reports whether this came from a running dpb rather than from disk.
	Live bool `json:"live"`
}

// Handler is what the control server dispatches to. A nil field means the
// command is not supported by this process, which is answered with a sentence
// rather than a panic.
type Handler struct {
	Status  func(context.Context) (Status, error)
	Why     func(ctx context.Context, host string, port int) (Why, error)
	On      func(context.Context) error
	Off     func(context.Context) error
	Reload  func(context.Context) error
	Reapply func(context.Context) error
	// Panic is the "get me back to normal now" button: revert everything, then
	// arrange for the process to exit. It must RETURN once the revert is done
	// and leave the exit to the caller's main loop, because the reply has to
	// reach the client before the process goes away.
	Panic func(context.Context) error
}

// ControlOptions configures a ControlServer.
type ControlOptions struct {
	// Path is the socket path. Use paths.Layout.ControlSocket(), which already
	// handles darwin's 104-byte sun_path limit; the client computes the same
	// value, so both ends must go through that accessor.
	Path    string
	Handler Handler
	// Chown, when non-nil, is called on the socket after it is bound. It is how
	// a run under sudo leaves a socket the invoking user can still talk to.
	Chown func(path string) error
	Logf  func(string, ...any)
	// Timeout bounds one exchange. Zero means ControlTimeout.
	Timeout time.Duration
}

// ErrControlInUse means another live process already owns the socket.
var ErrControlInUse = errors.New("observ: another dpb already owns the control socket")

// ControlServer serves the control socket.
type ControlServer struct {
	ln      net.Listener
	path    string
	h       Handler
	logf    func(string, ...any)
	timeout time.Duration

	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewControlServer binds the socket. It removes a socket left behind by a
// process that died, but only after proving nothing is listening on it: a
// blind unlink would let a second dpb steal a running one's socket, and the
// first would then hold a listener nobody can reach.
func NewControlServer(o ControlOptions) (*ControlServer, error) {
	if o.Path == "" {
		return nil, errors.New("observ: control socket path is empty")
	}
	if dir := filepath.Dir(o.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("observ: create control socket directory %s: %w", dir, err)
		}
	}
	if err := clearStaleSocket(o.Path); err != nil {
		return nil, err
	}

	ln, err := net.Listen("unix", o.Path)
	if err != nil {
		return nil, fmt.Errorf("observ: listen on control socket %s: %w", o.Path, err)
	}
	// Bind first, then narrow. A socket briefly created with the process umask
	// is still only reachable through a directory the user owns, and chmod
	// failing is worth reporting rather than ignoring.
	if err := os.Chmod(o.Path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("observ: restrict control socket %s: %w", o.Path, err)
	}
	if o.Chown != nil {
		if err := o.Chown(o.Path); err != nil {
			ln.Close()
			return nil, err
		}
	}

	s := &ControlServer{
		ln:      ln,
		path:    o.Path,
		h:       o.Handler,
		logf:    o.Logf,
		timeout: o.Timeout,
	}
	if s.timeout <= 0 {
		s.timeout = ControlTimeout
	}
	return s, nil
}

// clearStaleSocket removes a socket file that no live process is serving.
func clearStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("observ: stat control socket %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		// Something that is not a socket is sitting where ours goes. Removing
		// it would destroy whatever it is; refusing names the file instead.
		return fmt.Errorf("observ: %s exists and is not a socket; move it aside", path)
	}
	c := NewClient(path)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if probe, err := c.dial(ctx); err == nil {
		// Close it at once. A probe connection left open occupies a handler on
		// the live server until its read deadline expires, which turns "is
		// anyone there" into a several-second stall on the other process's
		// shutdown.
		probe.Close()
		return fmt.Errorf("%w (%s)", ErrControlInUse, path)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("observ: remove stale control socket %s: %w", path, err)
	}
	return nil
}

// Path is the bound socket path.
func (s *ControlServer) Path() string { return s.path }

// Serve accepts until ctx is cancelled or Close is called. It returns nil on a
// clean shutdown and a wrapped error on a real socket failure.
func (s *ControlServer) Serve(ctx context.Context) error {
	// Closing the listener is the only way to interrupt a blocking Accept, so
	// cancellation is implemented as a close and the accept loop treats
	// "closed" as success.
	stop := make(chan struct{})
	watching := make(chan struct{})
	go func() {
		defer close(watching)
		select {
		case <-ctx.Done():
			s.Close()
		case <-stop:
		}
	}()

	var serveErr error
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				serveErr = fmt.Errorf("observ: accept on control socket %s: %w", s.path, err)
			}
			break
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			// A panic while answering `dpb status` must not take down the
			// proxy the user is browsing through. observ cannot import
			// internal/flow (flow sits above it), so the guard is written out.
			defer func() {
				if r := recover(); r != nil {
					s.log("observ: control connection panicked: %v", r)
				}
			}()
			defer conn.Close()
			s.handle(ctx, conn)
		}()
	}

	// Stop the watcher before waiting on the handlers: it is the one goroutine
	// that can still be blocked on a context that may never be cancelled.
	close(stop)
	<-watching
	s.wg.Wait()
	return serveErr
}

func (s *ControlServer) log(format string, a ...any) {
	if s.logf != nil {
		s.logf(format, a...)
	}
}

// handle runs one request/response exchange.
func (s *ControlServer) handle(ctx context.Context, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(s.timeout))

	line, err := readLine(conn, MaxRequestBytes)
	if err != nil {
		s.log("observ: control read: %v", err)
		return
	}
	var req Request
	resp := Response{}
	if err := json.Unmarshal(line, &req); err != nil {
		resp.Err = fmt.Sprintf("observ: malformed control request: %v", err)
	} else {
		resp = s.dispatch(ctx, req)
	}

	b, err := json.Marshal(resp)
	if err != nil {
		// Marshalling our own response failed, so the only thing left that can
		// be said honestly is that it failed.
		b, _ = json.Marshal(Response{Err: "observ: could not encode the response"})
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		s.log("observ: control write: %v", err)
	}
}

// dispatch runs one command.
func (s *ControlServer) dispatch(ctx context.Context, req Request) Response {
	simple := func(fn func(context.Context) error, note string) Response {
		if fn == nil {
			return Response{Err: "observ: this dpb does not support " + req.Cmd}
		}
		if err := fn(ctx); err != nil {
			return Response{Err: err.Error()}
		}
		return Response{OK: true, Note: note}
	}

	switch req.Cmd {
	case CmdStatus:
		if s.h.Status == nil {
			return Response{Err: "observ: this dpb does not report status"}
		}
		st, err := s.h.Status(ctx)
		if err != nil {
			return Response{Err: err.Error()}
		}
		return Response{OK: true, Status: &st}
	case CmdWhy:
		if s.h.Why == nil {
			return Response{Err: "observ: this dpb does not answer why"}
		}
		if req.Host == "" {
			return Response{Err: "observ: why needs a host"}
		}
		w, err := s.h.Why(ctx, req.Host, req.Port)
		if err != nil {
			return Response{Err: err.Error()}
		}
		return Response{OK: true, Why: &w}
	case CmdOn:
		return simple(s.h.On, "dpb is on: in-scope hosts are judged again")
	case CmdOff:
		return simple(s.h.Off, "dpb is off: everything relays direct, system settings left in place")
	case CmdReload:
		return simple(s.h.Reload, "configuration reloaded")
	case CmdReapply:
		return simple(s.h.Reapply, "system proxy settings re-applied")
	case CmdPanic:
		return simple(s.h.Panic, "system settings reverted; dpb is exiting")
	case "":
		return Response{Err: "observ: control request has no command"}
	default:
		return Response{Err: fmt.Sprintf("observ: unknown control command %q", req.Cmd)}
	}
}

// Close stops the listener and unlinks the socket. It is idempotent and safe to
// call concurrently with Serve.
func (s *ControlServer) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.ln.Close()
		// net.Listener on a unix socket already unlinks the path on Close, but
		// only when it created it; removing again is harmless and covers the
		// case where it did not.
		if rerr := os.Remove(s.path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			if err == nil {
				err = fmt.Errorf("observ: remove control socket %s: %w", s.path, rerr)
			}
		}
	})
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// readLine reads one newline-terminated message, refusing anything longer than
// max. It does not use bufio.Scanner: Scanner reports a too-long line as a
// generic error with no way to tell it from a read failure, and this is a
// place where the difference matters.
func readLine(r io.Reader, max int) ([]byte, error) {
	br := bufio.NewReaderSize(r, 1024)
	var out []byte
	for {
		chunk, err := br.ReadSlice('\n')
		out = append(out, chunk...)
		if len(out) > max {
			return nil, fmt.Errorf("observ: control request exceeds %d bytes", max)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
		return out, nil
	}
}
