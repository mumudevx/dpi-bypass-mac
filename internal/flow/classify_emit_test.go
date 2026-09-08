package flow_test

import (
	"fmt"
	"testing"

	"github.com/mumudevx/dpb/internal/emit"
	"github.com/mumudevx/dpb/internal/flow"
)

// TestClassifyNeverTurnsAnInternalFailureIntoCensorship is SF15.
//
// Classify's catch-all — reset-before-response, which Retryable() calls
// censorship-shaped — swallowed emit's own error sentinels. A transport that
// cannot do what the plan asked, or one that tore the stream by accepting only
// part of a segment, is a local wiring failure with no evidence in it about the
// network. Recording it as reset-before-response feeds recordLoss and
// Store.Demote, so a bug in our own send path is written into the verdict store
// as the ISP censoring the user, and then read back by `dpb why` and by the
// drift detector.
func TestClassifyNeverTurnsAnInternalFailureIntoCensorship(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want flow.Failure
	}{
		{"cap unavailable", emit.ErrCapUnavailable, flow.FailBudget},
		{
			"cap unavailable, wrapped as emit wraps it",
			fmt.Errorf("%w: %s on %s", emit.ErrCapUnavailable, "sock-ttl", "192.0.2.10:443"),
			flow.FailBudget,
		},
		{"short write", emit.ErrShortWrite, flow.FailTornStream},
		{
			"short write, wrapped as emit wraps it",
			fmt.Errorf("%w: %d of %d bytes", emit.ErrShortWrite, 12, 1503),
			flow.FailTornStream,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := flow.Classify(c.err, false)
			if got != c.want {
				t.Fatalf("Classify(%v) = %s, want %s", c.err, got, c.want)
			}
			if got.Retryable() {
				t.Fatalf("Classify(%v) = %s, which Retryable() calls censorship-shaped; "+
					"an internal failure must never become censorship evidence", c.err, got)
			}
		})
	}
}

// TestClassifyEmitSentinelsAfterCommit: the commit guard still outranks
// everything. Past commit no failure may be retried, whatever its cause.
func TestClassifyEmitSentinelsAfterCommit(t *testing.T) {
	t.Parallel()
	for _, err := range []error{emit.ErrCapUnavailable, emit.ErrShortWrite} {
		if got := flow.Classify(err, true); got != flow.FailResetAfterResponse {
			t.Fatalf("Classify(%v, committed) = %s, want reset-after-response", err, got)
		}
	}
}
