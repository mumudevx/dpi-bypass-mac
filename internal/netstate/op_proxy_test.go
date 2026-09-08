package netstate

import (
	"context"
	"strings"
	"testing"
)

// TestProxyPrepareOnlyReadsItsOwnKind is the error-surface guard.
//
// Each networksetup getter is a separate invocation with its own failure, and
// they do fail independently on real machines. A capture that read all four
// settings to restore one of them would abort a PAC apply because
// `-getsocksfirewallproxy` errored on a service nobody asked about — an apply
// that used to succeed, refused for a reason unconnected to the mutation.
//
// So: a getter for a kind this Op will never touch must not be run at all, and
// must not be able to fail prepare. The second half of each case proves the
// first half is not vacuous, by arming the Op's OWN getter and requiring that
// prepare does fail.
func TestProxyPrepareOnlyReadsItsOwnKind(t *testing.T) {
	cases := []struct {
		name string
		op   func(*fakeSystem) Op
		// mine are the getters this Op must run; foreign are the ones it must
		// not, whichever way they are broken.
		mine    []string
		foreign []string
	}{
		{
			name:    "pac",
			op:      func(f *fakeSystem) Op { return NewPAC(f, pacURL, []string{"Wi-Fi"}) },
			mine:    []string{"networksetup -getautoproxyurl Wi-Fi"},
			foreign: []string{"networksetup -getwebproxy Wi-Fi", "networksetup -getsecurewebproxy Wi-Fi", "networksetup -getsocksfirewallproxy Wi-Fi"},
		},
		{
			name:    "web",
			op:      func(f *fakeSystem) Op { return NewWebProxy(f, "127.0.0.1", 8080, []string{"Wi-Fi"}) },
			mine:    []string{"networksetup -getwebproxy Wi-Fi", "networksetup -getsecurewebproxy Wi-Fi"},
			foreign: []string{"networksetup -getautoproxyurl Wi-Fi", "networksetup -getsocksfirewallproxy Wi-Fi"},
		},
		{
			name:    "socks",
			op:      func(f *fakeSystem) Op { return NewSOCKSProxy(f, "127.0.0.1", 1080, []string{"Wi-Fi"}) },
			mine:    []string{"networksetup -getsocksfirewallproxy Wi-Fi"},
			foreign: []string{"networksetup -getautoproxyurl Wi-Fi", "networksetup -getwebproxy Wi-Fi", "networksetup -getsecurewebproxy Wi-Fi"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Break every getter this Op has no business reading, all at once.
			f := newFakeSystem()
			for _, cmd := range c.foreign {
				f.failNext(cmd, 1)
			}
			op := c.op(f)
			if err := op.(preparer).prepare(context.Background(), f.env0()); err != nil {
				t.Fatalf("prepare failed because an unrelated getter is broken: %v", err)
			}
			for _, cmd := range c.foreign {
				if got := f.callsContaining(cmd); len(got) != 0 {
					t.Fatalf("prepare read %q, which this Op never restores: %v", cmd, got)
				}
			}
			for _, cmd := range c.mine {
				if got := f.callsContaining(cmd); len(got) != 1 {
					t.Fatalf("prepare ran %q %d times, want exactly 1", cmd, len(got))
				}
			}

			// Not vacuous: its own getter still decides.
			for _, cmd := range c.mine {
				f2 := newFakeSystem()
				f2.failNext(cmd, 1)
				op2 := c.op(f2)
				if err := op2.(preparer).prepare(context.Background(), f2.env0()); err == nil {
					t.Fatalf("prepare succeeded while %q was failing; it captures nothing to restore", cmd)
				}
			}
		})
	}
}

// TestProxyVerifyRevertedOnlyReadsItsOwnKind is the same guard on the other
// call site. VerifyReverted reads each service back because scutil answers for
// the primary one only; a broken getter for a setting this Op never touched
// must not leave the journal entry pending forever.
func TestProxyVerifyRevertedOnlyReadsItsOwnKind(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	op := NewPAC(f, pacURL, []string{"Wi-Fi"})
	prep(t, op, e)
	applyVerify(t, op, e)
	if err := op.Revert(context.Background(), e); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	f.failNext("networksetup -getsocksfirewallproxy Wi-Fi", 1)
	if err := op.VerifyReverted(context.Background(), e); err != nil {
		t.Fatalf("VerifyReverted failed because an unrelated getter is broken: %v", err)
	}
	for _, c := range f.callsContaining("-getsocksfirewallproxy") {
		if strings.Contains(c, "Wi-Fi") {
			t.Fatalf("a PAC Op read the SOCKS setting: %q", c)
		}
	}
}
