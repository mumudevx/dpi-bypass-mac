package sysport

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// The two contract guards a second Port implementation inherits rather than
// re-deriving: which read is allowed to guess, and which write is not. Both
// were defects before they were rules, so the assertions here name the damage
// rather than the API.

// guardEnv answers Get with a fixed triple, which is all EnvLookup consults.
type guardEnv struct {
	val string
	ok  bool
	err error
}

func (g guardEnv) Get(context.Context, string) (string, bool, error) { return g.val, g.ok, g.err }
func (guardEnv) Set(context.Context, string, string) error           { return nil }
func (guardEnv) Unset(context.Context, string) error                 { return nil }

// The diagnostic's tolerance, and the only place it exists: `dpb doctor` asks
// "is this variable set", and a line that says "could not tell" where it could
// say "no" is one nobody can act on.
func TestEnvLookupReadsAnUnreadableVariableAsUnset(t *testing.T) {
	ec := guardEnv{err: fmt.Errorf("netstate: launchctl getenv NO_PROXY: exit status 1: %w", ErrEnvUnreadable)}
	v, err := EnvLookup(context.Background(), ec, "NO_PROXY")
	if err != nil {
		t.Fatalf("EnvLookup = %v, want an unreadable variable reported as not set", err)
	}
	if v != "" {
		t.Errorf("value = %q, want the empty string", v)
	}
}

// A failure that said why is a failure. Swallowing it here would turn "launchctl
// could not reach the bootstrap server" into "the variable is not set", which is
// a fact nobody established.
func TestEnvLookupPropagatesAFailureThatSaidWhy(t *testing.T) {
	boom := errors.New("netstate: launchctl getenv X: Could not connect to the bootstrap server")
	if _, err := EnvLookup(context.Background(), guardEnv{err: boom}, "X"); !errors.Is(err, boom) {
		t.Fatalf("EnvLookup = %v, want the underlying failure", err)
	}
}

func TestEnvLookupReturnsAValueItCouldRead(t *testing.T) {
	ec := guardEnv{val: "http://127.0.0.1:8080/dpb.pac", ok: true}
	v, err := EnvLookup(context.Background(), ec, "HTTPS_PROXY")
	if err != nil || v != "http://127.0.0.1:8080/dpb.pac" {
		t.Fatalf("EnvLookup = %q, %v", v, err)
	}
}

// A zero-value ProxySettings is what a caller holds when it forgot to record
// what it captured. Restoring it would write every proxy setting on the
// service — wants() reads an empty Kinds as ALL — so the guard refuses it.
func TestCheckRestorableRefusesACaptureThatNamesNoKinds(t *testing.T) {
	if err := (ProxySettings{}).CheckRestorable(); err == nil {
		t.Fatal("a zero-value ProxySettings was accepted for restore; it would switch off proxies this tool never captured")
	}
	if err := (ProxySettings{Kinds: []ProxyKind{}}).CheckRestorable(); err == nil {
		t.Fatal("an explicitly empty Kinds was accepted for restore")
	}
}

// The asymmetry is deliberate: naming one kind is enough to restore, because
// the caller has then said what it owns.
func TestCheckRestorableAcceptsACaptureThatNamesAKind(t *testing.T) {
	if err := (ProxySettings{Kinds: []ProxyKind{ProxyAuto}}).CheckRestorable(); err != nil {
		t.Fatalf("CheckRestorable = %v on a capture that named ProxyAuto", err)
	}
}
