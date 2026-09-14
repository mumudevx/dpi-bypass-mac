//go:build darwin

// This file tests validateTunName's macOS rule specifically — utun/utunN
// against real Mac interface names (en0, lo0, awdl0, bridge0, gif0) — so it
// is tagged darwin rather than left portable or tagged !windows: since
// tunname_darwin.go and tunname_windows.go each define their own
// validateTunName with a different rule, a table built from macOS interface
// names would assert nothing meaningful about the Windows one. See
// tunname_windows_test.go for the Windows rule's own table.

package cliapp

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

// --tun-name used to be taken on trust.
//
// `dpb run --tun --tun-name en0 --dry-run` PRINTED A PLAN. It named the
// machine's real uplink and then described configuring it as a point-to-point
// tunnel, hanging 0.0.0.0/1 and 128.0.0.0/1 off it and pointing every network
// service's resolvers at it:
//
//	system settings applied and verified:
//	  - configure en0 10.255.90.1 -> 10.255.90.2 mtu 1500 up
//	  - add route 0.0.0.0/0 via 192.168.0.1 scoped to en0
//	  - add route 0.0.0.0/1 via interface en0
//	  ...
//
// Nothing was applied, so nothing was broken. The defect is that the plan was
// false: OpenDevice would have refused that name under root, so --dry-run
// described a sequence the tool would never have executed — in the one mode
// whose whole purpose is to describe exactly what it would do.

// TestTunNameMustBeAUtun is the check itself, over the names that matter: real
// interfaces on a Mac, the two legitimate spellings, and the edges around them.
func TestTunNameMustBeAUtun(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"utun", true},  // the default: the kernel picks a free unit
		{"utun0", true}, // an explicit unit
		{"utun7", true},
		{"utun12", true},
		{"en0", false},      // the uplink this defect was found with
		{"en1", false},      //
		{"lo0", false},      // loopback
		{"awdl0", false},    // AirDrop
		{"bridge0", false},  // the Thunderbolt bridge
		{"gif0", false},     //
		{"", false},         // an explicitly empty flag is not the default
		{"utunX", false},    // not a unit
		{"utun-1", false},   //
		{"Utun0", false},    // the kernel is case-sensitive here
		{"utun0 ", false},   // a trailing space is a different interface name
		{"utun0;ls", false}, // and nothing that is not a device name at all
		{"../utun0", false},
	} {
		err := validateTunName(tc.name)
		if tc.ok && err != nil {
			t.Errorf("--tun-name %q was refused: %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("--tun-name %q was accepted; dpb would print a plan that ifconfigs it "+
				"and routes the whole address space through it", tc.name)
		}
	}
}

// TestTunNameOnARealInterfaceIsRefusedBeforeAnyPlanExists drives the shipped
// command, unprivileged and under --dry-run, which is exactly the invocation
// that printed the false plan.
//
// The exit code is part of the contract: a bad flag value is ExitUsage, not a
// generic failure, because the LaunchAgent and the wrappers branch on it.
func TestTunNameOnARealInterfaceIsRefusedBeforeAnyPlanExists(t *testing.T) {
	t.Parallel()
	layout := tempLayout(t)
	layout.Elevated = false

	mac := newFakeMac()
	var out, errOut bytes.Buffer
	g := &globals{
		env:    Env{Stdout: &out, Stderr: &errOut},
		layout: &layout,
		runner: mac,
		rib:    mac,
		getenv: func(string) string { return "" },
	}
	root := newRoot(g)
	root.SetArgs([]string{"run", "--tun", "--tun-name", "en0", "--dry-run",
		"--proxy-style", "none", "--port", "0", "--socks-port", fmt.Sprint(freePort(t))})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})

	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("dpb run --tun --tun-name en0 --dry-run succeeded; it printed a plan that " +
			"would ifconfig this machine's uplink and capture every route through it")
	}
	if got := exitCodeFor(err); got != ExitUsage {
		t.Fatalf("exit code %d, want %d (ExitUsage): a bad flag value is a usage error",
			got, ExitUsage)
	}
	msg := err.Error()
	if !strings.Contains(msg, "en0") {
		t.Errorf("the refusal does not name the device that was asked for:\n%s", msg)
	}
	if !strings.Contains(msg, "utun") {
		t.Errorf("the refusal does not say what a valid name looks like:\n%s", msg)
	}
	// And no plan was printed. A refused name must not leave a description of
	// what dpb "would" do to en0 on the user's terminal.
	if s := out.String(); strings.Contains(s, "en0 10.255.90.1") || strings.Contains(s, "via interface en0") {
		t.Fatalf("a plan naming en0 was printed anyway:\n%s", s)
	}
}
