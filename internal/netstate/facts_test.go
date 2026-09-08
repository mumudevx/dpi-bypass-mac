package netstate

import (
	"context"
	"testing"
)

// TestCollectFactsNeedsARIB stayed here when the rest of facts_test.go followed
// the collector into scdarwin. It is the same assertion, run through the entry
// point netstate keeps: CollectFacts goes out through the Port, and an Env with
// no RIB has to stay an Env with no RIB rather than quietly acquiring the
// kernel's own reader — which would turn a refusal to guess into a live read of
// the real routing table.
func TestCollectFactsNeedsARIB(t *testing.T) {
	f := newFakeSystem()
	if _, err := CollectFacts(context.Background(), Env{Runner: f}); err == nil {
		t.Fatal("CollectFacts must refuse to guess the uplink without a RIB")
	}
}
