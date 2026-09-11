//go:build !windows

// This file contains tests for the control socket and related run wiring.
// These tests use startRun(), which requires Unix process spawning for the janitor.

package cliapp

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mumudevx/dpb/internal/observ"
	"github.com/mumudevx/dpb/internal/paths"
)

// These tests are about WIRING, not about the subsystems.
//
// internal/janitor, internal/observ's control server and internal/observ's
// counters were each implemented, tested in isolation, and then had no
// non-test caller anywhere in the tree. Every capability they provide was
// therefore absent from the shipped binary: a `kill -9` stranded the user's
// proxy settings, `dpb status` / `dpb why` / `dpb on` / `dpb off` could not see
// a running instance, and the escalation-rate drift detector — the only way a
// user learns their ISP changed tactics rather than that one site broke —
// observed nothing. A test that exercises a subsystem directly cannot catch
// that. These drive `dpb run`.

// assertTeardownOrder checks that the named teardown steps appear in the debug
// log in this order. The order is the whole contract of run's own stack.
func assertTeardownOrder(t *testing.T, log string, steps ...string) {
	t.Helper()
	at := -1
	for _, s := range steps {
		i := strings.Index(log, "run: teardown "+s)
		if i < 0 {
			t.Fatalf("teardown step %q never ran:\n%s", s, log)
		}
		if i < at {
			t.Fatalf("teardown step %q ran out of order (wanted %v):\n%s", s, steps, log)
		}
		at = i
	}
}

// ── the control socket ──────────────────────────────────────────────────────

func liveClient(t *testing.T, l paths.Layout) *observ.Client {
	t.Helper()
	return observ.NewClient(l.ControlSocket())
}

// `dpb status`, `dpb why`, `dpb on` and `dpb off` all reach the running process
// through the control socket. Unwired, every one of them reports that no dpb is
// running while one is.
func TestRunAnswersOnTheControlSocket(t *testing.T) {
	t.Parallel()
	layout := shortLayout(t)
	h := startRun(t, newFakeMac(), layout, "--proxy-style", "none")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := liveClient(t, layout).Status(ctx)
	if err != nil {
		t.Fatalf("status over the control socket: %v\nbanner:\n%s", err, h.out)
	}
	if !st.Running || st.PID != os.Getpid() {
		t.Fatalf("status = running %v pid %d, want this process %d", st.Running, st.PID, os.Getpid())
	}
	// It reports what this run actually bound, which is the fact no offline
	// command can know.
	if len(st.Listeners) == 0 || !strings.HasSuffix(st.Listeners[0].Addr, strconv.Itoa(h.port)) {
		t.Fatalf("status does not name the bound listener: %+v", st.Listeners)
	}
	if len(st.Ladder) == 0 {
		t.Errorf("status carries no ladder: %+v", st)
	}
	if len(st.Resolvers) == 0 {
		t.Errorf("status carries no resolver chain: %+v", st)
	}
	if st.NetworkID == "" {
		t.Errorf("status carries no network identity, so the cache key is unreportable")
	}
}

// The socket is removed on the way out. A socket file left behind is what makes
// the next `dpb status` hang instead of saying "not running".
func TestRunReleasesTheControlSocketOnShutdown(t *testing.T) {
	t.Parallel()
	layout := shortLayout(t)
	h := startRun(t, newFakeMac(), layout, "--proxy-style", "none")
	if fi, err := os.Lstat(layout.ControlSocket()); err != nil {
		t.Fatalf("no control socket at %s while dpb is running: %v", layout.ControlSocket(), err)
	} else if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket: %s", layout.ControlSocket(), fi.Mode())
	}
	h.shutdown(t)

	if _, err := os.Lstat(layout.ControlSocket()); err == nil {
		t.Fatalf("%s survived the run", layout.ControlSocket())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := liveClient(t, layout).Status(ctx); err == nil {
		t.Fatal("the control socket still answers after shutdown")
	}
}

// `dpb off` has to reach every surface that can escalate, not just one: a kill
// switch half the process honours is worse than none.
func TestRunOffAndOnMoveTheKillSwitchEverywhere(t *testing.T) {
	t.Parallel()
	layout := shortLayout(t)
	h := startRun(t, newFakeMac(), layout, "--proxy-style", "none")
	c := liveClient(t, layout)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if _, err := c.Command(ctx, observ.CmdOff); err != nil {
		t.Fatalf("off: %v", err)
	}
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.Suspended || st.SuspendReason == "" {
		t.Fatalf("status after `dpb off` = suspended %v (%q)", st.Suspended, st.SuspendReason)
	}
	// The served PAC is the other surface. It must stop naming the proxy at
	// all, so a browser reading it goes direct without entering dpb.
	if body := fetchDirect(t, "http://"+h.addr()+"/dpb.pac"); strings.Contains(body, "PROXY 127.0.0.1") {
		t.Fatalf("the PAC still points at dpb after `dpb off`:\n%s", body)
	}

	if _, err := c.Command(ctx, observ.CmdOn); err != nil {
		t.Fatalf("on: %v", err)
	}
	if st, err := c.Status(ctx); err != nil {
		t.Fatalf("status: %v", err)
	} else if st.Suspended {
		t.Fatal("`dpb on` did not lift the kill switch")
	}
	if body := fetchDirect(t, "http://"+h.addr()+"/dpb.pac"); !strings.Contains(body, "PROXY 127.0.0.1") {
		t.Fatalf("the PAC did not come back after `dpb on`:\n%s", body)
	}
}

// `dpb panic` reverts every system change and stops the process, and the reply
// has to reach the client before the process goes away.
func TestRunPanicRevertsAndStops(t *testing.T) {
	t.Parallel()
	mac := newFakeMac()
	layout := shortLayout(t)
	before := mac.proxySnapshot()
	h := startRun(t, mac, layout, "--proxy-style", "pac")

	if during := mac.proxySnapshot(); during == before {
		t.Fatalf("nothing was applied, so there is nothing for panic to revert:\n%s", h.out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	note, err := liveClient(t, layout).Command(ctx, observ.CmdPanic)
	if err != nil {
		t.Fatalf("panic: %v", err)
	}
	if note == "" {
		t.Error("panic answered with no note")
	}
	// The revert is already done when the reply lands: that is the difference
	// between a report and a promise.
	if after := mac.proxySnapshot(); after != before {
		t.Fatalf("panic replied before the settings were back.\nbefore:\n%s\nafter:\n%s", before, after)
	}

	select {
	case rerr := <-h.done:
		h.stopped = true
		if rerr != nil {
			t.Fatalf("run returned %v", rerr)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("run did not stop after `dpb panic`")
	}
}

// ── the counters ────────────────────────────────────────────────────────────

// The counters feed `dpb status`, the recent-connection table under `dpb why`,
// and the escalation-rate drift detector. Unwired they observe nothing, and
// every one of those reports zero for a process that has served traffic.
func TestRunCountsFinishedFlows(t *testing.T) {
	t.Parallel()
	origin := newTestOrigin(t)
	layout := shortLayout(t)
	h := startRun(t, newFakeMac(), layout, "--proxy-style", "none")

	if body := fetchThrough(t, h.addr(), "http://"+origin+"/hello"); !strings.Contains(body, "/hello") {
		t.Fatalf("the request did not go through: %q", body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := liveClient(t, layout)

	var st observ.Status
	deadline := time.Now().Add(5 * time.Second)
	for {
		var err error
		st, err = c.Status(ctx)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		if st.Conns.Totals.Conns > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st.Conns.Totals.Conns == 0 {
		t.Fatalf("a request went through the proxy and the counters saw nothing: %+v", st.Conns)
	}

	// And the same history is reachable per host, which is what `dpb why`
	// prints under the verdict that produced it.
	host, _, _ := strings.Cut(origin, ":")
	w, err := c.Why(ctx, host, 80)
	if err != nil {
		t.Fatalf("why: %v", err)
	}
	if len(w.Recent) == 0 {
		t.Fatalf("`why %s` over the control socket carries no connection history: %+v", host, w)
	}
	if !w.Live {
		t.Error("the live answer is not marked live")
	}
}

// `dpb why` and `dpb status` driven through the real command tree against the
// running instance, which is the path a user actually takes.
func TestWhyAndStatusCommandsSeeTheRunningInstance(t *testing.T) {
	t.Parallel()
	layout := shortLayout(t)
	_ = startRun(t, newFakeMac(), layout, "--proxy-style", "none")

	c := &cli{layout: layout, mac: newFakeMac()}
	r := c.exec(t, "status")
	// The listener address is the fact only the live process knows: the offline
	// path reads the run lock and the configuration, neither of which records
	// the port that was actually bound.
	if !strings.Contains(r.stdout, "listening: http") {
		t.Fatalf("`dpb status` did not get its answer from the running instance:\n%s%s",
			r.stdout, r.stderr)
	}
	if strings.Contains(r.stdout, "not answering") {
		t.Fatalf("`dpb status` could not reach the control socket:\n%s", r.stdout)
	}
	r = c.exec(t, "why", "discord.com")
	if r.code != ExitOK {
		t.Fatalf("`dpb why` exited %d:\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "the running dpb") {
		t.Fatalf("`dpb why` answered from disk while a dpb was running:\n%s", r.stdout)
	}
}

// `dpb reload` re-reads the scoping rules in the running process. Without it a
// `dpb scope bypass HOST` typed while dpb is up does nothing until the next
// restart, which is exactly when a user needs it to work: they are adding a
// bank to the veto list because something just broke.
func TestRunReloadPicksUpANewBypassRule(t *testing.T) {
	t.Parallel()
	layout := shortLayout(t)
	_ = startRun(t, newFakeMac(), layout, "--proxy-style", "none")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := liveClient(t, layout)

	const host = "reload-probe.example"
	before, err := c.Why(ctx, host, 443)
	if err != nil {
		t.Fatalf("why before reload: %v", err)
	}
	if before.Verdict.Class == "bypass" {
		t.Fatalf("%s is already bypassed, so the test proves nothing: %+v", host, before.Verdict)
	}

	if err := writeScopeState(layout, scopeState{Bypass: []string{host}}); err != nil {
		t.Fatalf("write scope.toml: %v", err)
	}
	if _, err := c.Command(ctx, observ.CmdReload); err != nil {
		t.Fatalf("reload: %v", err)
	}

	after, err := c.Why(ctx, host, 443)
	if err != nil {
		t.Fatalf("why after reload: %v", err)
	}
	if after.Verdict.Class != "bypass" {
		t.Fatalf("after `dpb reload` %s is still %q; the new rule never reached the "+
			"running engine: %+v", host, after.Verdict.Class, after.Verdict)
	}
}

// `dpb coverage --fix` asks the running process to re-assert the settings it
// owns, because those settings name THIS run's listener ports: a second dpb
// writing them would point macOS at a port nothing is listening on.
func TestRunReappliesSystemSettingsOnRequest(t *testing.T) {
	t.Parallel()
	mac := newFakeMac()
	layout := shortLayout(t)
	h := startRun(t, mac, layout, "--proxy-style", "pac")

	if snap := mac.proxySnapshot(); !strings.Contains(snap, "ProxyAutoConfigEnable : 1") {
		t.Fatalf("nothing was applied, so there is nothing to re-apply:\n%s\n%s", snap, h.out)
	}
	// Something else — a VPN client, a corporate profile, System Settings —
	// turns it off underneath us.
	mac.Run(context.Background(), "networksetup", "-setautoproxystate", "Wi-Fi", "off")
	if snap := mac.proxySnapshot(); strings.Contains(snap, "ProxyAutoConfigEnable : 1") {
		t.Fatalf("the setting was not actually cleared:\n%s", snap)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := liveClient(t, layout).Command(ctx, observ.CmdReapply); err != nil {
		t.Fatalf("reapply: %v", err)
	}

	snap := mac.proxySnapshot()
	if !strings.Contains(snap, "ProxyAutoConfigEnable : 1") {
		t.Fatalf("reapply did not restore the auto-proxy setting:\n%s", snap)
	}
	if want := fmt.Sprintf("ProxyAutoConfigURLString : http://127.0.0.1:%d/dpb.pac", h.port); !strings.Contains(snap, want) {
		t.Fatalf("reapply named the wrong listener:\n%s\nwant %s", snap, want)
	}
}

// A run that changed nothing has nothing to re-assert, and saying so is better
// than reporting a success that moved no setting.
func TestRunRefusesToReapplyWhenItMutatedNothing(t *testing.T) {
	t.Parallel()
	layout := shortLayout(t)
	_ = startRun(t, newFakeMac(), layout, "--proxy-style", "none")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := liveClient(t, layout).Command(ctx, observ.CmdReapply)
	if err == nil {
		t.Fatal("a run with --proxy-style none claimed to re-apply system settings")
	}
	if !strings.Contains(err.Error(), "nothing to re-apply") {
		t.Errorf("err = %v", err)
	}
}
