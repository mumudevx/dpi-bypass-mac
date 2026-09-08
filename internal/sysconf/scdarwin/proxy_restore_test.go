package scdarwin

import (
	"context"
	"strings"
	"testing"

	"github.com/mumudevx/dpb/internal/sysport"
)

// argvLog records what a controller asked the system to run, so a test can
// assert that a refused write ran NOTHING rather than half of something.
type argvLog struct{ calls []string }

func (l *argvLog) Run(_ context.Context, name string, args ...string) Result {
	argv := append([]string{name}, args...)
	l.calls = append(l.calls, strings.Join(argv, " "))
	return Result{Argv: argv}
}

// Restore refuses a capture that names no kinds.
//
// wants() reads an empty Kinds as "all of them", which is the right reading for
// Configured — an over-wide READ costs a getter — and a destructive one here: a
// zero-value ProxySettings would come out of restoreCmds as eight networksetup
// writes that switch off every proxy on the service, including the user's own
// web proxy that this tool never captured.
func TestRestoreRefusesACaptureThatNamesNoKinds(t *testing.T) {
	log := &argvLog{}
	err := New(Env{Runner: log}).Proxy().Restore(context.Background(), "Wi-Fi", sysport.ProxySettings{})
	if err == nil {
		t.Fatal("Restore accepted a ProxySettings with no Kinds; it would have written every proxy setting on Wi-Fi")
	}
	if len(log.calls) != 0 {
		t.Errorf("networksetup ran on a refused restore: %v", log.calls)
	}
}

// The refusal is about the missing declaration, not about the values: a capture
// that names its kind restores, including the empty-previous case that switches
// the setting off.
func TestRestoreAcceptsACaptureThatNamesItsKind(t *testing.T) {
	log := &argvLog{}
	prev := sysport.ProxySettings{Kinds: []sysport.ProxyKind{sysport.ProxyAuto}}
	if err := New(Env{Runner: log}).Proxy().Restore(context.Background(), "Wi-Fi", prev); err != nil {
		t.Fatalf("Restore = %v", err)
	}
	if len(log.calls) == 0 {
		t.Fatal("a restore that named ProxyAuto ran no networksetup at all")
	}
	for _, c := range log.calls {
		if strings.Contains(c, "webproxy") || strings.Contains(c, "socksfirewall") {
			t.Errorf("a ProxyAuto-only restore touched another kind: %s", c)
		}
	}
}
