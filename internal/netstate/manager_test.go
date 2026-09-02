package netstate

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func neverAlive(int, time.Time) bool  { return false }
func alwaysAlive(int, time.Time) bool { return true }

func newTestManager(t *testing.T, f *fakeSystem) (*Manager, Journal) {
	t.Helper()
	j, _ := openTestJournal(t)
	return NewManager(j, f.env0()), j
}

func TestManagerDoAppliesAndCommits(t *testing.T) {
	f := newFakeSystem()
	m, j := newTestManager(t, f)
	ctx := context.Background()

	op := NewPAC(f, pacURL, []string{"Wi-Fi"})
	if err := m.Do(ctx, op); err != nil {
		t.Fatalf("Do: %v", err)
	}
	applied := m.Applied()
	if len(applied) != 1 || !applied[0].Applied || !applied[0].Verified || applied[0].Adopted {
		t.Fatalf("Applied() = %+v", applied)
	}
	if applied[0].Kind != OpProxyPAC || applied[0].ID != op.ID() {
		t.Fatalf("record identity = %s/%s", applied[0].Kind, applied[0].ID)
	}
	pending, _ := j.Pending(ctx)
	if len(pending) != 1 {
		t.Fatalf("journal Pending = %d, want the committed record", len(pending))
	}

	if errs := m.UndoAll(ctx); len(errs) != 0 {
		t.Fatalf("UndoAll: %v", errs)
	}
	if f.svc["Wi-Fi"].pacOn {
		t.Fatal("PAC survived UndoAll")
	}
	pending, _ = j.Pending(ctx)
	if len(pending) != 0 {
		t.Fatalf("journal not drained: %+v", pending)
	}
	if len(m.Applied()) != 0 {
		t.Fatal("Applied() still lists reverted ops")
	}
}

func TestManagerUndoesInReverseOrder(t *testing.T) {
	f := newFakeSystem()
	f.ifaces["utun4"] = &fakeIface{index: 22, mtu: 1500}
	f.install(t)
	m, _ := newTestManager(t, f)
	ctx := context.Background()

	// Bring-up order: interface, then the route that names it. Teardown must be
	// the exact reverse, because a route delete naming a dead interface fails.
	ifOp := NewIfconfig(f, "utun4", "10.255.0.1", "10.255.0.2", 1500)
	rtOp := NewRoute(f, netip.MustParsePrefix("0.0.0.0/1"), netip.Addr{}, "utun4")
	if err := m.Do(ctx, ifOp); err != nil {
		t.Fatalf("Do(ifconfig): %v", err)
	}
	if err := m.Do(ctx, rtOp); err != nil {
		t.Fatalf("Do(route): %v", err)
	}
	if errs := m.UndoAll(ctx); len(errs) != 0 {
		t.Fatalf("UndoAll: %v", errs)
	}

	deleteAt, aliasAt := -1, -1
	for i, c := range f.calls {
		if strings.HasPrefix(c, "route -n delete") {
			deleteAt = i
		}
		if strings.Contains(c, "-alias") {
			aliasAt = i
		}
	}
	if deleteAt < 0 || aliasAt < 0 {
		t.Fatalf("missing teardown calls: %v", f.calls)
	}
	if deleteAt > aliasAt {
		t.Fatalf("route was deleted after the interface address was removed: %v", f.calls)
	}
}

// TestAdoptedNeverReverted pre-seeds a VPN's interface-scoped default route in
// the RIB. Running Verify before Apply sees it already present, so the record is
// Adopted and UndoAll must leave it alone — this is what stops Ctrl-C from
// deleting somebody's VPN routes.
func TestAdoptedNeverReverted(t *testing.T) {
	f := newFakeSystem()
	f.ifaces["utun3"] = &fakeIface{index: 21, mtu: 1400, up: true}
	gw := netip.MustParseAddr("192.168.0.1")
	f.routes = append(f.routes, RouteEntry{
		Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: gw, Iface: "en0", Index: 14, Scoped: true,
	})
	m, j := newTestManager(t, f)
	ctx := context.Background()

	op := NewRoute(f, netip.MustParsePrefix("0.0.0.0/0"), gw, "en0")
	if err := m.Do(ctx, op); err != nil {
		t.Fatalf("Do: %v", err)
	}
	rec := m.Applied()
	if len(rec) != 1 || !rec[0].Adopted {
		t.Fatalf("record = %+v, want Adopted", rec)
	}
	if adds := f.callsContaining("route -n add"); len(adds) != 0 {
		t.Fatalf("an adopted route must not be re-added: %v", adds)
	}

	if errs := m.UndoAll(ctx); len(errs) != 0 {
		t.Fatalf("UndoAll: %v", errs)
	}
	if dels := f.callsContaining("route -n delete"); len(dels) != 0 {
		t.Fatalf("an adopted route must never be deleted: %v", dels)
	}
	if ok, _ := f.Exists(netip.MustParsePrefix("0.0.0.0/0"), "en0"); !ok {
		t.Fatal("the pre-existing VPN scoped default was removed")
	}
	if pending, _ := j.Pending(ctx); len(pending) != 0 {
		t.Fatalf("journal not drained after UndoAll: %+v", pending)
	}
}

func TestAdoptedRecordIsSkippedByReplay(t *testing.T) {
	f := newFakeSystem()
	gw := netip.MustParseAddr("192.168.0.1")
	f.routes = append(f.routes, RouteEntry{
		Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: gw, Iface: "en0", Index: 14, Scoped: true,
	})
	m, j := newTestManager(t, f)
	ctx := context.Background()
	if err := m.Do(ctx, NewRoute(f, netip.MustParsePrefix("0.0.0.0/0"), gw, "en0")); err != nil {
		t.Fatalf("Do: %v", err)
	}

	// A crash: the Manager is gone, only the journal remains.
	rep, err := Replay(ctx, j, f.env0(), neverAlive)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(rep.Reverted) != 0 || len(rep.Skipped) != 1 {
		t.Fatalf("report = %+v, want the adopted record skipped", rep)
	}
	if ok, _ := f.Exists(netip.MustParsePrefix("0.0.0.0/0"), "en0"); !ok {
		t.Fatal("Replay deleted an adopted VPN route")
	}
	if dels := f.callsContaining("route -n delete"); len(dels) != 0 {
		t.Fatalf("Replay issued a delete for an adopted route: %v", dels)
	}
}

// TestNotSelf is the second half of the restoration guarantee: a captured
// proxy entry that already points at our own listener is discarded, so Revert
// turns the setting off instead of pinning the user to a dead port.
func TestNotSelf(t *testing.T) {
	f := newFakeSystem()
	f.svc["Wi-Fi"].pacURL, f.svc["Wi-Fi"].pacOn = "http://127.0.0.1:8080/dpb.pac", true
	f.svc["Wi-Fi"].dns = []string{"127.0.0.1"}
	f.env["HTTPS_PROXY"] = "http://localhost:8080"
	m, _ := newTestManager(t, f)
	ctx := context.Background()

	ops := []Op{
		NewPAC(f, "http://127.0.0.1:9090/dpb.pac", []string{"Wi-Fi"}),
		NewDNSServers(f, []string{"127.0.0.1", "9.9.9.9"}, []string{"Wi-Fi"}),
		NewLaunchEnv(f, "http://127.0.0.1:9090", nil),
	}
	for _, op := range ops {
		if err := m.Do(ctx, op); err != nil {
			t.Fatalf("Do(%s): %v", op.ID(), err)
		}
	}
	if errs := m.UndoAll(ctx); len(errs) != 0 {
		t.Fatalf("UndoAll: %v", errs)
	}

	if f.svc["Wi-Fi"].pacOn {
		t.Fatal("Revert re-enabled a PAC pointing at a listener that no longer exists")
	}
	if len(f.svc["Wi-Fi"].dns) != 0 {
		t.Fatalf("Revert restored our own resolver: %v", f.svc["Wi-Fi"].dns)
	}
	if v, ok := f.env["HTTPS_PROXY"]; ok {
		t.Fatalf("Revert restored HTTPS_PROXY=%q, which points at us", v)
	}
}

func TestManagerDryRunMutatesNothing(t *testing.T) {
	f := newFakeSystem()
	before := f.snapshot()
	j, _ := openTestJournal(t)
	e := f.env0()
	e.DryRun = true
	var logged []string
	e.Logf = func(format string, a ...any) { logged = append(logged, fmt.Sprintf(format, a...)) }
	m := NewManager(j, e)

	if err := m.Do(context.Background(), NewPAC(f, pacURL, []string{"Wi-Fi"})); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := f.snapshot(); got != before {
		t.Fatalf("dry run mutated state:\n before %s\n after  %s", before, got)
	}
	if len(f.calls) != 0 {
		t.Fatalf("dry run ran commands: %v", f.calls)
	}
	if len(m.Applied()) != 0 {
		t.Fatal("dry run recorded an applied op")
	}
	if len(logged) != 1 || !strings.Contains(logged[0], pacURL) {
		t.Fatalf("dry run must describe what it would do, logged %v", logged)
	}
}

func TestManagerRollsBackOnVerifyFailure(t *testing.T) {
	f := newFakeSystem()
	m, j := newTestManager(t, f)
	ctx := context.Background()

	// The command succeeds but the setting never reaches the dynamic store.
	f.failNext("scutil --proxy", 0)
	op := NewPAC(f, pacURL, []string{"Wi-Fi"})
	f.svc["Wi-Fi"].pacOn = false
	f.failNext("networksetup -setautoproxystate Wi-Fi on", 1)

	err := m.Do(ctx, op)
	if err == nil {
		t.Fatal("Do succeeded despite the apply failing")
	}
	if !strings.Contains(err.Error(), "proxy.pac") {
		t.Fatalf("error = %v, want it to name the op", err)
	}
	if f.svc["Wi-Fi"].pacOn {
		t.Fatal("the half-applied PAC was not rolled back")
	}
	if pending, _ := j.Pending(ctx); len(pending) != 0 {
		t.Fatalf("a confirmed rollback must close its journal entry, got %+v", pending)
	}
}

// ── the chaos table ──────────────────────────────────────────────────────────

// chaosOp fails at one point in an Op's lifecycle. It fails exactly once, so
// the Op that Replay rebuilds from the journal record — a fresh one, without
// the injected fault — can still converge the system.
type chaosOp struct {
	Op
	failApply          bool
	failVerify         bool
	failRevert         bool
	failVerifyReverted bool
	fired              map[string]bool
	verifyCalls        int
}

var errChaos = errors.New("injected chaos")

func (c *chaosOp) fire(point string, want bool) bool {
	if !want || c.fired[point] {
		return false
	}
	c.fired[point] = true
	return true
}

func (c *chaosOp) prepare(ctx context.Context, e Env) error {
	if p, ok := c.Op.(preparer); ok {
		return p.prepare(ctx, e)
	}
	return nil
}

func (c *chaosOp) Apply(ctx context.Context, e Env) error {
	if c.fire("apply", c.failApply) {
		return errChaos
	}
	return c.Op.Apply(ctx, e)
}

// Verify fails on the second call. The first is Manager's adoption pre-check,
// where a failure just means "not adopted" and is not an error path at all; the
// lifecycle point this test targets is the post-Apply verification.
func (c *chaosOp) Verify(ctx context.Context, e Env) error {
	c.verifyCalls++
	if c.verifyCalls >= 2 && c.fire("verify", c.failVerify) {
		return errChaos
	}
	return c.Op.Verify(ctx, e)
}

func (c *chaosOp) Revert(ctx context.Context, e Env) error {
	if c.fire("revert", c.failRevert) {
		return errChaos
	}
	return c.Op.Revert(ctx, e)
}

func (c *chaosOp) VerifyReverted(ctx context.Context, e Env) error {
	if c.fire("verifyreverted", c.failVerifyReverted) {
		return errChaos
	}
	return c.Op.VerifyReverted(ctx, e)
}

// chaosJournal fails once at Begin or Commit.
type chaosJournal struct {
	Journal
	failBegin  bool
	failCommit bool
}

func (j *chaosJournal) Begin(ctx context.Context, r Record) (Token, error) {
	if j.failBegin {
		j.failBegin = false
		return 0, errChaos
	}
	return j.Journal.Begin(ctx, r)
}

func (j *chaosJournal) Commit(ctx context.Context, t Token, r Record) error {
	if j.failCommit {
		j.failCommit = false
		return errChaos
	}
	return j.Journal.Commit(ctx, t, r)
}

// TestChaosTable injects a failure at each of the six Op lifecycle points, for
// every Op type, and asserts the system converges to its baseline after Replay
// and that a second Replay is a no-op.
func TestChaosTable(t *testing.T) {
	// The Verify pre-check that detects adoption also runs the first Verify, so
	// a chaos case targeting Verify has to survive being called twice; chaosOp
	// firing once handles that. The pre-check failing is not an error path — it
	// simply means "not adopted".
	points := []struct {
		name string
		mut  func(*chaosOp, *chaosJournal)
	}{
		{"begin", func(_ *chaosOp, j *chaosJournal) { j.failBegin = true }},
		{"apply", func(c *chaosOp, _ *chaosJournal) { c.failApply = true }},
		{"verify", func(c *chaosOp, _ *chaosJournal) { c.failVerify = true }},
		{"commit", func(_ *chaosOp, j *chaosJournal) { j.failCommit = true }},
		{"revert", func(c *chaosOp, _ *chaosJournal) { c.failVerify, c.failRevert = true, true }},
		{"verifyreverted", func(c *chaosOp, _ *chaosJournal) { c.failVerify, c.failVerifyReverted = true, true }},
	}

	kinds := []struct {
		name string
		make func(*fakeSystem, string) Op
	}{
		{"proxy.pac", func(f *fakeSystem, _ string) Op { return NewPAC(f, pacURL, []string{"Wi-Fi"}) }},
		{"proxy.http", func(f *fakeSystem, _ string) Op { return NewWebProxy(f, "127.0.0.1", 8080, []string{"Wi-Fi"}) }},
		{"proxy.socks", func(f *fakeSystem, _ string) Op { return NewSOCKSProxy(f, "127.0.0.1", 1080, []string{"Wi-Fi"}) }},
		{"proxy.launchenv", func(f *fakeSystem, _ string) Op { return NewLaunchEnv(f, pacURL, []string{"*.local"}) }},
		{"proxy.pacfile", func(_ *fakeSystem, path string) Op { return NewPACFile(path, []byte("function FindProxyForURL(){}")) }},
		{"dns.servers", func(f *fakeSystem, _ string) Op {
			return NewDNSServers(f, []string{"127.0.0.1", "192.168.0.1"}, []string{"Wi-Fi"})
		}},
		{"route", func(f *fakeSystem, _ string) Op {
			return NewRoute(f, netip.MustParsePrefix("0.0.0.0/1"), netip.Addr{}, "utun4")
		}},
		{"ifconfig", func(f *fakeSystem, _ string) Op { return NewIfconfig(f, "utun4", "10.255.0.1", "10.255.0.2", 1500) }},
	}

	for _, k := range kinds {
		for _, p := range points {
			t.Run(k.name+"/"+p.name, func(t *testing.T) {
				f := newFakeSystem()
				f.install(t)
				f.ifaces["utun4"] = &fakeIface{index: 22, mtu: 1500}
				// A realistic pre-existing configuration, so "converged" means
				// something stronger than "empty".
				f.svc["Wi-Fi"].pacURL, f.svc["Wi-Fi"].pacOn = "http://corp.example/p.pac", true
				f.svc["Wi-Fi"].dns = []string{"192.168.0.1"}
				f.env["HTTP_PROXY"] = "http://corp.example:3128"

				pacPath := filepath.Join(t.TempDir(), "dpb.pac")
				baseline := worldSnapshot(t, f, pacPath)

				fj, _ := openTestJournal(t)
				cj := &chaosJournal{Journal: fj}
				m := NewManager(cj, f.env0())

				op := &chaosOp{Op: k.make(f, pacPath), fired: map[string]bool{}}
				p.mut(op, cj)

				if err := m.Do(context.Background(), op); err == nil {
					t.Fatalf("Do succeeded despite a failure injected at %s", p.name)
				}

				rep, err := Replay(context.Background(), fj, f.env0(), neverAlive)
				if err != nil {
					t.Fatalf("Replay: %v", err)
				}
				if len(rep.Failed) != 0 {
					t.Fatalf("Replay could not converge: %+v", rep.Failed)
				}
				if got := worldSnapshot(t, f, pacPath); got != baseline {
					t.Fatalf("system did not converge after Replay:\n want %s\n got  %s", baseline, got)
				}
				if pending, _ := fj.Pending(context.Background()); len(pending) != 0 {
					t.Fatalf("journal still holds %+v", pending)
				}

				rep2, err := Replay(context.Background(), fj, f.env0(), neverAlive)
				if err != nil {
					t.Fatalf("second Replay: %v", err)
				}
				if len(rep2.Pending)+len(rep2.Reverted)+len(rep2.Skipped)+len(rep2.Failed) != 0 {
					t.Fatalf("a second Replay must be a no-op, got %+v", rep2)
				}
			})
		}
	}
}

// worldSnapshot captures everything the ops in the chaos table can touch: the
// fake system's effective configuration plus the on-disk PAC file.
func worldSnapshot(t *testing.T, f *fakeSystem, pacPath string) string {
	t.Helper()
	s := f.snapshotEffective()
	b, err := os.ReadFile(pacPath)
	switch {
	case err == nil:
		s += "pacfile present: " + string(b) + "\n"
	case os.IsNotExist(err):
		s += "pacfile absent\n"
	default:
		t.Fatalf("stat PAC file: %v", err)
	}
	return s
}

// ── Replay ───────────────────────────────────────────────────────────────────

func TestReplayLeavesALiveOwnerAlone(t *testing.T) {
	f := newFakeSystem()
	m, j := newTestManager(t, f)
	ctx := context.Background()
	if err := m.Do(ctx, NewPAC(f, pacURL, []string{"Wi-Fi"})); err != nil {
		t.Fatalf("Do: %v", err)
	}

	rep, err := Replay(ctx, j, f.env0(), alwaysAlive)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(rep.Skipped) != 1 || len(rep.Reverted) != 0 {
		t.Fatalf("report = %+v, want the live owner's record skipped", rep)
	}
	if !f.svc["Wi-Fi"].pacOn {
		t.Fatal("Replay tore down a healthy concurrent run's PAC")
	}
	if pending, _ := j.Pending(ctx); len(pending) != 1 {
		t.Fatal("a skipped record must stay pending")
	}
}

func TestReplayDefaultsToOwnerAlive(t *testing.T) {
	f := newFakeSystem()
	j, _ := openTestJournal(t)
	ctx := context.Background()
	// A record owned by an impossible pid: the default ownerAlive must decide it
	// is dead and revert it.
	rec := Record{Kind: OpProxyPAC, ID: "proxy.pac:Wi-Fi", PID: 1 << 30, Applied: true, Verified: true}
	op := NewPAC(f, pacURL, []string{"Wi-Fi"})
	if err := op.(preparer).prepare(ctx, f.env0()); err != nil {
		t.Fatal(err)
	}
	rec.Revert = op.Record().Revert
	if _, err := j.Begin(ctx, rec); err != nil {
		t.Fatal(err)
	}
	rep, err := Replay(ctx, j, f.env0(), nil)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(rep.Reverted) != 1 {
		t.Fatalf("report = %+v", rep)
	}
}

func TestReplayReportsUnrevivableRecords(t *testing.T) {
	j, _ := openTestJournal(t)
	ctx := context.Background()
	f := newFakeSystem()

	if _, err := j.Begin(ctx, Record{Kind: "wat", ID: "mystery"}); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Begin(ctx, Record{Kind: OpRoute, ID: "route:bad", Revert: []byte(`{"dst":"nonsense"}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Begin(ctx, Record{Kind: OpDNSServers, ID: "dns:empty"}); err != nil {
		t.Fatal(err)
	}

	rep, err := Replay(ctx, j, f.env0(), neverAlive)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(rep.Failed) != 3 {
		t.Fatalf("report = %+v, want all three records reported as failed", rep)
	}
	if rep.Clean() {
		t.Fatal("Clean() must be false when records could not be reverted")
	}
	// A record we cannot understand must stay in the journal rather than be
	// quietly dropped: the user can still be told about it.
	if pending, _ := j.Pending(ctx); len(pending) != 3 {
		t.Fatalf("unrevivable records were dropped: %+v", pending)
	}
}

func TestReplaySurvivesAJournalReadFailure(t *testing.T) {
	j, path := openTestJournal(t)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(context.Background(), j, Env{}, neverAlive); err == nil {
		t.Fatal("Replay must report a journal it cannot read")
	}
}

func TestReviveRoundTripsEveryOpKind(t *testing.T) {
	f := newFakeSystem()
	e := f.env0()
	ctx := context.Background()
	pacPath := filepath.Join(t.TempDir(), "dpb.pac")

	ops := []Op{
		NewPAC(f, pacURL, []string{"Wi-Fi"}),
		NewWebProxy(f, "127.0.0.1", 8080, []string{"Wi-Fi"}),
		NewSOCKSProxy(f, "127.0.0.1", 1080, []string{"Wi-Fi"}),
		NewLaunchEnv(f, pacURL, []string{"*.local"}),
		NewPACFile(pacPath, []byte("x")),
		NewDNSServers(f, []string{"127.0.0.1"}, []string{"Wi-Fi"}),
		NewRoute(f, netip.MustParsePrefix("0.0.0.0/1"), netip.Addr{}, "utun4"),
		NewRoute(f, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("192.168.0.1"), "en0"),
		NewIfconfig(f, "utun4", "10.255.0.1", "10.255.0.2", 1500),
	}
	for _, op := range ops {
		t.Run(op.ID(), func(t *testing.T) {
			prep(t, op, e)
			rec := op.Record()
			rec.Kind, rec.ID = op.Kind(), op.ID()
			if rec.Note != "" {
				t.Fatalf("Record() reported an encoding problem: %s", rec.Note)
			}
			back, err := revive(rec)
			if err != nil {
				t.Fatalf("revive: %v", err)
			}
			if back.Kind() != op.Kind() {
				t.Fatalf("revived kind = %q, want %q", back.Kind(), op.Kind())
			}
			if back.ID() != op.ID() {
				t.Fatalf("revived ID = %q, want %q", back.ID(), op.ID())
			}
			// The revived Op must be able to undo without any further preparation:
			// the process that captured the previous state is gone.
			if err := back.Revert(ctx, e); err != nil {
				t.Fatalf("revived Revert: %v", err)
			}
		})
	}
}

func TestReviveRejectsGarbage(t *testing.T) {
	cases := []Record{
		{Kind: OpProxyPAC, ID: "x", Revert: []byte("not json")},
		{Kind: OpLaunchEnv, ID: "x", Revert: []byte(`{}`)},
		{Kind: OpPACFile, ID: "x", Revert: []byte(`{}`)},
		{Kind: OpDNSServers, ID: "x", Revert: []byte(`{"servers":["1.1.1.1"]}`)},
		{Kind: OpRoute, ID: "x", Revert: []byte(`{"dst":"0.0.0.0/1","gw":"not-an-ip"}`)},
		{Kind: OpIfconfig, ID: "x", Revert: []byte(`{"iface":"utun4"}`)},
		{Kind: "nope", ID: "x", Revert: []byte(`{}`)},
	}
	for i, rec := range cases {
		if _, err := revive(rec); err == nil {
			t.Fatalf("case %d (%s): revive accepted a malformed record", i, rec.Kind)
		}
	}
}

// TestOurOwnResidueIsNotAdopted covers the interaction between the two guards.
// After a SIGKILL the machine still carries our PAC, our resolvers and our
// environment variables. A naive adoption check would see "already present",
// mark the records Adopted, and make the residue permanent. Ops that can only
// match their own settings therefore refuse adoption, so the next clean exit
// removes them.
func TestOurOwnResidueIsNotAdopted(t *testing.T) {
	f := newFakeSystem()
	pacPath := filepath.Join(t.TempDir(), "dpb.pac")
	pacBody := []byte("function FindProxyForURL(){return \"DIRECT\";}")

	// The residue of a killed run.
	f.svc["Wi-Fi"].pacURL, f.svc["Wi-Fi"].pacOn = pacURL, true
	f.svc["Wi-Fi"].dns = []string{"127.0.0.1", "192.168.0.1"}
	f.env["HTTP_PROXY"], f.env["HTTPS_PROXY"] = pacURL, pacURL
	if err := os.WriteFile(pacPath, pacBody, 0o644); err != nil {
		t.Fatal(err)
	}

	m, j := newTestManager(t, f)
	ctx := context.Background()
	ops := []Op{
		NewPAC(f, pacURL, []string{"Wi-Fi"}),
		NewDNSServers(f, []string{"127.0.0.1", "192.168.0.1"}, []string{"Wi-Fi"}),
		NewLaunchEnv(f, pacURL, nil),
		NewPACFile(pacPath, pacBody),
	}
	for _, op := range ops {
		if err := m.Do(ctx, op); err != nil {
			t.Fatalf("Do(%s): %v", op.ID(), err)
		}
	}
	for _, rec := range m.Applied() {
		if rec.Adopted {
			t.Fatalf("%s was adopted; our own residue would then never be cleaned up", rec.ID)
		}
	}

	if errs := m.UndoAll(ctx); len(errs) != 0 {
		t.Fatalf("UndoAll: %v", errs)
	}
	if f.svc["Wi-Fi"].pacOn {
		t.Fatal("the leftover PAC survived teardown")
	}
	// --set-dns writes our loopback resolver followed by the machine's originals,
	// so stripping the loopback entry from the residue recovers exactly the list
	// the user started with. (When the journal survives, Replay restores the
	// genuinely captured list instead; this is the degraded path.)
	if !reflect.DeepEqual(f.svc["Wi-Fi"].dns, []string{"192.168.0.1"}) {
		t.Fatalf("resolvers after teardown = %v, want the user's original list", f.svc["Wi-Fi"].dns)
	}
	if len(f.env) != 0 {
		t.Fatalf("the leftover environment survived teardown: %v", f.env)
	}
	if _, err := os.Stat(pacPath); !os.IsNotExist(err) {
		t.Fatalf("the leftover PAC file survived teardown: %v", err)
	}
	if pending, _ := j.Pending(ctx); len(pending) != 0 {
		t.Fatalf("journal not drained: %+v", pending)
	}
}

// TestAdoptionStillAppliesToRoutes: the veto must not weaken the guarantee it
// exists alongside. A route that is already present is still adopted, because a
// route we did not create belongs to somebody else.
func TestAdoptionStillAppliesToRoutes(t *testing.T) {
	f := newFakeSystem()
	f.ifaces["utun4"] = &fakeIface{index: 22, mtu: 1500, up: true}
	f.routes = append(f.routes, RouteEntry{Dst: netip.MustParsePrefix("0.0.0.0/1"), Iface: "utun4", Index: 22})
	m, _ := newTestManager(t, f)
	if err := m.Do(context.Background(), NewRoute(f, netip.MustParsePrefix("0.0.0.0/1"), netip.Addr{}, "utun4")); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if rec := m.Applied(); len(rec) != 1 || !rec[0].Adopted {
		t.Fatalf("record = %+v, want Adopted", rec)
	}
}
