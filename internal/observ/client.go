package observ

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// Client is the control-socket client the CLI uses.
//
// Its most important property is that "no dpb is running" is a first-class,
// distinguishable answer rather than a dial error. Every command in M12 has
// something useful to say with no daemon — `dpb why` reads the rules and the
// verdict store off disk, `dpb status` reads the lock file and the journal —
// and it can only choose that path if it can tell "nothing is listening" from
// "the socket is there but something went wrong".
type Client struct {
	path    string
	Timeout time.Duration
}

// ErrNotRunning means nothing is listening on the control socket.
var ErrNotRunning = errors.New("observ: no dpb is listening on the control socket")

// NewClient returns a client for the socket at path. Use
// paths.Layout.ControlSocket() to compute it: the server uses the same
// accessor, including its darwin sun_path fallback, and a client that joined
// the path itself would look in the wrong place on a deep home directory.
func NewClient(path string) *Client { return &Client{path: path} }

// Path is the socket this client talks to.
func (c *Client) Path() string { return c.path }

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return ControlTimeout
}

// dial opens the socket, translating "nothing there" into ErrNotRunning.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	if c.path == "" {
		return nil, fmt.Errorf("%w: no socket path", ErrNotRunning)
	}
	var d net.Dialer
	// The network is the literal "unix" and the address is a filesystem path,
	// so no name resolution is possible here; see the entry recorded for this
	// file in internal/flow/nohostdial_test.go's reviewedAddrExprs.
	conn, err := d.DialContext(ctx, "unix", c.path)
	if err == nil {
		return conn, nil
	}
	// ENOENT: no socket file at all. ECONNREFUSED: the file survived a SIGKILL
	// but nothing is accepting on it. Both mean "not running"; anything else is
	// a real failure the user needs to see.
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return nil, fmt.Errorf("%w (%s)", ErrNotRunning, c.path)
	}
	return nil, fmt.Errorf("observ: connect to the control socket %s: %w", c.path, err)
}

// Do sends one request and returns the reply.
func (c *Client) Do(ctx context.Context, req Request) (Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	conn, err := c.dial(dctx)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()

	deadline := time.Now().Add(c.timeout())
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	b, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("observ: encode control request: %w", err)
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return Response{}, fmt.Errorf("observ: send control request: %w", err)
	}

	line, err := readLine(conn, 1<<20)
	if err != nil {
		return Response{}, fmt.Errorf("observ: read control response: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, fmt.Errorf("observ: decode control response: %w", err)
	}
	if !resp.OK {
		if resp.Err == "" {
			resp.Err = "observ: the command failed and said nothing about why"
		}
		return resp, errors.New(resp.Err)
	}
	return resp, nil
}

// Status asks the running dpb what it is doing.
func (c *Client) Status(ctx context.Context) (Status, error) {
	resp, err := c.Do(ctx, Request{Cmd: CmdStatus})
	if err != nil {
		return Status{}, err
	}
	if resp.Status == nil {
		return Status{}, errors.New("observ: the control socket returned no status")
	}
	st := *resp.Status
	st.Running = true
	return st, nil
}

// Why asks the running dpb for the live decision chain for a host, including
// the verdicts it has learned since it started that are not yet on disk.
func (c *Client) Why(ctx context.Context, host string, port int) (Why, error) {
	resp, err := c.Do(ctx, Request{Cmd: CmdWhy, Host: host, Port: port})
	if err != nil {
		return Why{}, err
	}
	if resp.Why == nil {
		return Why{}, errors.New("observ: the control socket returned no explanation")
	}
	w := *resp.Why
	w.Live = true
	return w, nil
}

// Command sends one of the verbs that takes no argument and returns the note
// the daemon replied with.
func (c *Client) Command(ctx context.Context, cmd string) (string, error) {
	resp, err := c.Do(ctx, Request{Cmd: cmd})
	if err != nil {
		return "", err
	}
	return resp.Note, nil
}

// Running reports whether a dpb is listening. It is a probe, not a lock: the
// process can go away between this call and the next one, which is why every
// caller still has to handle ErrNotRunning from the command itself.
func (c *Client) Running(ctx context.Context) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	dctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	conn, err := c.dial(dctx)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
