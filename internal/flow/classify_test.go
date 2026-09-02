package flow_test

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/mumudevx/dpi-bypass-mac/internal/flow"
	"github.com/mumudevx/dpi-bypass-mac/internal/tlsmsg"
)

// TestClassifyCommitGuard is the one table in this package that must never be
// wrong. Before commit, a censorship-shaped failure is retried; after commit,
// the identical error must not be, because a retry would duplicate bytes the
// client has already consumed.
func TestClassifyCommitGuard(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		err       error
		committed bool
		want      flow.Failure
		retry     bool
	}{
		{"nil", nil, false, flow.FailNone, false},
		{"nil after commit", nil, true, flow.FailNone, false},
		{"reset before response", resetErr(), false, flow.FailResetBeforeResponse, true},
		{"reset after response", resetErr(), true, flow.FailResetAfterResponse, false},
		{"eof before response", io.EOF, false, flow.FailResetBeforeResponse, true},
		{"eof after response", io.EOF, true, flow.FailResetAfterResponse, false},
		{"broken pipe", syscall.EPIPE, false, flow.FailResetBeforeResponse, true},
		{"closed pipe", io.ErrClosedPipe, false, flow.FailResetBeforeResponse, true},
		{"deadline", os.ErrDeadlineExceeded, false, flow.FailTimeoutBeforeResponse, true},
		{"deadline after response", os.ErrDeadlineExceeded, true, flow.FailResetAfterResponse, false},
		{"context deadline", context.DeadlineExceeded, false, flow.FailTimeoutBeforeResponse, true},
		{"dial", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, false, flow.FailDial, false},
		{"not replayable", flow.ErrNotReplayable, false, flow.FailNotReplayable, false},
		{"unknown", errors.New("something else"), false, flow.FailResetBeforeResponse, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := flow.Classify(c.err, c.committed)
			if got != c.want {
				t.Fatalf("Classify(%v, committed=%v) = %s, want %s", c.err, c.committed, got, c.want)
			}
			if got.Retryable() != c.retry {
				t.Fatalf("%s.Retryable() = %v, want %v", got, got.Retryable(), c.retry)
			}
		})
	}
}

// TestIsResetIncludesEOF: six of the ten fragile Turkish hosts in
// MEASUREMENTS.md §5 failed with "handshake: EOF" rather than a reset, so a
// ladder that only recognises ECONNRESET hangs on them.
func TestIsResetIncludesEOF(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		io.EOF, io.ErrUnexpectedEOF, io.ErrClosedPipe,
		syscall.ECONNRESET, syscall.EPIPE, syscall.ECONNABORTED, resetErr(),
	} {
		if !flow.IsReset(err) {
			t.Errorf("IsReset(%v) = false, want true", err)
		}
	}
	for _, err := range []error{nil, os.ErrDeadlineExceeded, errors.New("nope")} {
		if flow.IsReset(err) {
			t.Errorf("IsReset(%v) = true, want false", err)
		}
	}
}

func TestIsTimeout(t *testing.T) {
	t.Parallel()
	if !flow.IsTimeout(os.ErrDeadlineExceeded) || !flow.IsTimeout(context.DeadlineExceeded) {
		t.Error("a deadline must be recognised as a timeout")
	}
	if flow.IsTimeout(nil) || flow.IsTimeout(resetErr()) {
		t.Error("a reset is not a timeout")
	}
}

func TestFailureString(t *testing.T) {
	t.Parallel()
	for f, want := range map[flow.Failure]string{
		flow.FailNone:                  "none",
		flow.FailDial:                  "dial",
		flow.FailResetBeforeResponse:   "reset-before-response",
		flow.FailTimeoutBeforeResponse: "timeout-before-response",
		flow.FailResetAfterResponse:    "reset-after-response",
		flow.FailNotReplayable:         "not-replayable",
		flow.FailBudget:                "budget",
		flow.Failure(99):               "invalid",
	} {
		if got := f.String(); got != want {
			t.Errorf("Failure(%d) = %q, want %q", f, got, want)
		}
	}
}

// TestReplayable is the retry-safety predicate. A ClientHello is always
// replayable; a plaintext request is only if it is idempotent and bodyless.
func TestReplayable(t *testing.T) {
	t.Parallel()
	h := clientHello(t, "discord.com")
	cases := []struct {
		name    string
		payload []byte
		port    int
		want    bool
	}{
		{"client hello", h, 443, true},
		{"truncated hello", h[:80], 443, true},
		{"GET", []byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"), 80, true},
		{"HEAD", []byte("HEAD / HTTP/1.1\r\nHost: a.example\r\n\r\n"), 80, true},
		{"POST with a body", []byte("POST /pay HTTP/1.1\r\nHost: a.example\r\nContent-Length: 2\r\n\r\nhi"), 80, false},
		{"chunked PUT", []byte("PUT /x HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\n\r\n"), 80, false},
		{"empty", nil, 443, false},
		{"opaque", []byte{0xff, 0x00, 0x11}, 443, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := tlsmsg.Parse(c.payload, c.port)
			if got := flow.Replayable(c.payload, m); got != c.want {
				t.Fatalf("Replayable(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}
