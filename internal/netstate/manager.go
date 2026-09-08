package netstate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Env is everything an Op needs to touch the world. Passing it per call rather
// than storing it on the Op keeps Ops values that can be reconstructed from a
// journal record by a process that never built the original.
type Env struct {
	Runner Runner
	RIB    RIBReader
	Facts  *Facts
	Logf   func(string, ...any)
	DryRun bool

	// Sys is the operating system this run mutates. It is an interface so that
	// an Op's logic — which routes to install, what to capture before
	// overwriting, when adoption is allowed — is testable without a machine to
	// mutate, and identical on every platform.
	//
	// It is an addition, not a replacement: Runner and RIB stay, because the
	// platform default is built from them and because an Op's verifier still
	// reads the RIB directly.
	Sys Port

	// SelfIface names the utun this run owns, once it has one. Our own capture
	// routes are the same 0.0.0.0/1 + 128.0.0.0/1 pair a WireGuard-style VPN
	// installs, so classifyVPN has to be told which tunnel is ours.
	SelfIface string

	// PriorResidue says that a previous dpb run died without cleaning up, so a
	// loopback proxy/resolver setting we cannot match exactly is more likely to
	// be our dead listener than the user's own configuration. It is the ONLY
	// thing that lets an Op discard a captured loopback value it does not
	// recognise; without it, a user's dnscrypt-proxy or local web proxy is
	// captured and restored untouched. Set it from PriorResidue().
	PriorResidue bool
}

func (e Env) runner() Runner {
	if e.Runner == nil {
		return noRunner{}
	}
	return e.Runner
}

func (e Env) logf(format string, a ...any) {
	if e.Logf != nil {
		e.Logf(format, a...)
	}
}

// sys returns the configured Port, or the platform's default built from this
// Env. The default exists so that an Env assembled the old way — with only a
// Runner and a RIB — keeps working; every existing caller and test does exactly
// that, which is why the whole suite passes this refactor unchanged.
func (e Env) sys() Port {
	if e.Sys != nil {
		return e.Sys
	}
	return newDefaultPort(e)
}

// noRunner makes a zero Env fail loudly instead of nil-panicking deep inside an
// Op, which is the difference between a diagnosable bug report and a stack
// trace from a user's laptop.
type noRunner struct{}

func (noRunner) Run(_ context.Context, name string, args ...string) Result {
	return Result{
		Argv: append([]string{name}, args...),
		Err:  errors.New("netstate: Env.Runner is nil"),
	}
}

// Op is one reversible mutation of macOS system state.
//
// Op's contract: Verify MUST read through a different subsystem than Apply wrote
// through. Routes are written by route(8) and verified against the AF_ROUTE RIB;
// proxy settings are written by networksetup and verified with `scutil --proxy`;
// DNS likewise with `scutil --dns`; interfaces with net.Interfaces().
//
// There is exactly one carved-out exception, and it is deliberate:
// launchEnvOp writes with `launchctl setenv` and verifies with
// `launchctl getenv`, matching docs/PLAN.md's mutated-state table row 2.
// launchd's own store is the only place a user-session environment variable
// lives — there is no second observer to consult, and inventing one (spawning a
// child to print its environment) would answer a different question. The real
// gap here is not the missing second subsystem: setenv only affects processes
// started after the call, so even a passing Verify says nothing about the
// already-running Electron apps the variable exists for. That caveat is
// documented on launchEnvOp rather than papered over.
//
// Revert must be idempotent and VerifyReverted must tolerate already-absent
// state, because the journal is deliberately over-approximate.
type Op interface {
	Kind() OpKind
	ID() string
	Describe() string
	Apply(ctx context.Context, e Env) error
	Verify(ctx context.Context, e Env) error
	Revert(ctx context.Context, e Env) error
	VerifyReverted(ctx context.Context, e Env) error
	Record() Record
}

// preparer is implemented by Ops that must capture the state they will later
// restore. Manager calls it before Record(), which is before the journal's
// fsync, so the revert payload is durable before the mutation is attempted.
//
// It is unexported on purpose: it is a Manager/Op protocol, not part of the
// contract other packages code against.
type preparer interface {
	prepare(ctx context.Context, e Env) error
}

// adoptChecker lets an Op veto adoption.
//
// Adoption asks "was this state already here?", and answers yes by never
// touching it again. That is right for a VPN's scoped default. It is wrong for
// a proxy, resolver or PAC file whose Verify can only pass by finding *our own*
// settings already in place — which means a previous run was SIGKILLed before it
// could clean up. Adopting that residue would make it permanent.
type adoptChecker interface {
	canAdopt() bool
}

func canAdopt(op Op) bool {
	if c, ok := op.(adoptChecker); ok {
		return c.canAdopt()
	}
	return true
}

// mutator is implemented by Ops that can say whether their Apply actually
// changed anything.
//
// rollback consults it before reverting, because Revert is written to undo OUR
// change and cannot tell our change from somebody else's state that looks the
// same. route(8) is the case that forced this: the kernel resolves RTM_DELETE
// by destination + netmask + explicit -ifscope, and the link gateway an
// `-interface` add supplies is not part of the lookup, so a delete issued after
// a failed add removes whatever currently owns that destination — a coexisting
// VPN's half-default, for instance.
type mutator interface{ mutated() bool }

// mutated defaults to true: an Op that does not implement the interface may
// have half-applied (proxyOp and dnsOp loop over services), and reverting a
// half-applied Op is the safe direction.
func mutated(op Op) bool {
	if m, ok := op.(mutator); ok {
		return m.mutated()
	}
	return true
}

type applied struct {
	op    Op
	rec   Record
	token Token
}

// Manager sequences Ops through Begin→Apply→Verify→Commit with automatic
// rollback, and undoes them in reverse on the way out.
type Manager struct {
	j Journal
	e Env

	// opMu serialises whole lifecycles. Do's adoption pre-check, Apply and Verify
	// are three reads and writes of the same system state, and interleaving two
	// of them would let one Op adopt the other's half-applied change.
	opMu sync.Mutex

	mu   sync.Mutex
	done []applied
}

// NewManager returns a Manager writing to j and acting through e.
func NewManager(j Journal, e Env) *Manager { return &Manager{j: j, e: e} }

// Do applies one Op. On any failure it rolls back and returns a specific error;
// on success the record is committed to the journal and queued for UndoAll.
func (m *Manager) Do(ctx context.Context, op Op) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()

	if m.e.DryRun {
		m.e.logf("netstate: dry-run, would apply: %s", op.Describe())
		return nil
	}

	if p, ok := op.(preparer); ok {
		if err := p.prepare(ctx, m.e); err != nil {
			return fmt.Errorf("netstate: prepare %s %s: %w", op.Kind(), op.ID(), err)
		}
	}

	// Adoption check: run the verifier BEFORE applying. If the state is already
	// present we did not create it, so reverting it later would break somebody
	// else's configuration — a VPN's scoped default, an admin-set PAC.
	adopted := canAdopt(op) && op.Verify(ctx, m.e) == nil

	rec := op.Record()
	rec.Kind, rec.ID = op.Kind(), op.ID()

	if adopted {
		rec.Adopted, rec.Applied, rec.Verified = true, true, true
		if rec.Note == "" {
			rec.Note = "state already present; adopted, revert is a no-op"
		}
		tok, err := m.j.Begin(ctx, rec)
		if err != nil {
			return fmt.Errorf("netstate: journal adopted %s %s: %w", op.Kind(), op.ID(), err)
		}
		rec.Seq = uint64(tok)
		if err := m.j.Commit(ctx, tok, rec); err != nil {
			return fmt.Errorf("netstate: commit adopted %s %s: %w", op.Kind(), op.ID(), err)
		}
		m.push(applied{op: op, rec: rec, token: tok})
		m.e.logf("netstate: adopted existing %s (%s)", op.Kind(), op.Describe())
		return nil
	}

	tok, err := m.j.Begin(ctx, rec)
	if err != nil {
		return fmt.Errorf("netstate: journal %s %s: %w", op.Kind(), op.ID(), err)
	}
	rec.Seq = uint64(tok)

	if err := op.Apply(ctx, m.e); err != nil {
		m.rollback(ctx, op, tok, "apply")
		return fmt.Errorf("netstate: apply %s (%s): %w", op.Kind(), op.Describe(), err)
	}
	if err := op.Verify(ctx, m.e); err != nil {
		m.rollback(ctx, op, tok, "verify")
		return fmt.Errorf("netstate: verify %s (%s): %w", op.Kind(), op.Describe(), err)
	}

	rec.Applied, rec.Verified = true, true
	if err := m.j.Commit(ctx, tok, rec); err != nil {
		// The change is live but undurable. Undo it now rather than leave state we
		// cannot promise to clean up after a crash.
		m.rollback(ctx, op, tok, "commit")
		return fmt.Errorf("netstate: commit %s %s: %w", op.Kind(), op.ID(), err)
	}
	m.push(applied{op: op, rec: rec, token: tok})
	m.e.logf("netstate: applied %s", op.Describe())
	return nil
}

func (m *Manager) push(a applied) {
	m.mu.Lock()
	m.done = append(m.done, a)
	m.mu.Unlock()
}

// rollback undoes a half-applied Op. The journal entry is closed only when the
// revert is independently confirmed; otherwise it stays pending so Replay (or
// the janitor, or the next login) finishes the job.
func (m *Manager) rollback(ctx context.Context, op Op, tok Token, at string) {
	// An Op whose Apply mutated nothing has nothing to undo, and undoing it
	// anyway would act on state somebody else owns. Close the entry instead:
	// there is no residue for Replay to find.
	if !mutated(op) {
		m.e.logf("netstate: rollback after %s failure: %s changed nothing, so nothing is reverted", at, op.ID())
		if err := m.j.Done(ctx, tok); err != nil {
			m.e.logf("netstate: rollback after %s failure: close journal entry %d: %v", at, tok, err)
		}
		return
	}
	if err := op.Revert(ctx, m.e); err != nil {
		m.e.logf("netstate: rollback after %s failure: revert %s: %v; left journalled for replay",
			at, op.ID(), err)
		return
	}
	if err := op.VerifyReverted(ctx, m.e); err != nil {
		m.e.logf("netstate: rollback after %s failure: %s still present: %v; left journalled for replay",
			at, op.ID(), err)
		return
	}
	if err := m.j.Done(ctx, tok); err != nil {
		m.e.logf("netstate: rollback after %s failure: close journal entry %d: %v", at, tok, err)
	}
}

// UndoAll reverts every applied Op in reverse order and returns every error it
// hit. It never stops early: one stuck Op must not strand the rest of the
// user's system in a modified state.
func (m *Manager) UndoAll(ctx context.Context) []error {
	m.opMu.Lock()
	defer m.opMu.Unlock()

	m.mu.Lock()
	todo := m.done
	m.done = nil
	m.mu.Unlock()

	var errs []error
	for i := len(todo) - 1; i >= 0; i-- {
		a := todo[i]
		if a.rec.Adopted {
			// Never revert what we did not create. Still close the journal entry —
			// leaving it pending would make a later Replay reconsider it.
			if err := m.j.Done(ctx, a.token); err != nil {
				errs = append(errs, fmt.Errorf("netstate: close adopted entry %s: %w", a.rec.ID, err))
			}
			continue
		}
		if err := a.op.Revert(ctx, m.e); err != nil {
			errs = append(errs, fmt.Errorf("netstate: revert %s (%s): %w", a.rec.Kind, a.op.Describe(), err))
			continue
		}
		if err := a.op.VerifyReverted(ctx, m.e); err != nil {
			errs = append(errs, fmt.Errorf("netstate: verify revert %s (%s): %w", a.rec.Kind, a.op.Describe(), err))
			continue
		}
		if err := m.j.Done(ctx, a.token); err != nil {
			errs = append(errs, fmt.Errorf("netstate: close entry %s: %w", a.rec.ID, err))
		}
	}
	return errs
}

// Applied returns the records for everything currently applied, oldest first.
func (m *Manager) Applied() []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Record, 0, len(m.done))
	for _, a := range m.done {
		out = append(out, a.rec)
	}
	return out
}

// ReplayReport is the outcome of a Replay pass.
type ReplayReport struct {
	Pending  []Record
	Reverted []Record
	Skipped  []Record
	Failed   []Record
}

// Clean reports whether replay left nothing outstanding.
func (r ReplayReport) Clean() bool { return len(r.Failed) == 0 }

// Replay undoes every pending journal record whose owning process is gone. It
// is what `dpb doctor --repair`, the janitor child and the login LaunchAgent all
// run.
//
// ownerAlive decides whether a record's owner is still running; pass
// OwnerAlive in production. Records owned by a live dpb are skipped, never
// reverted, so two concurrent runs cannot clobber each other.
func Replay(ctx context.Context, j Journal, e Env,
	ownerAlive func(pid int, started time.Time) bool) (ReplayReport, error) {

	pending, err := j.Pending(ctx)
	if err != nil {
		return ReplayReport{}, fmt.Errorf("netstate: read pending journal: %w", err)
	}
	rep := ReplayReport{Pending: pending}
	if ownerAlive == nil {
		ownerAlive = OwnerAlive
	}

	// Reverse order: the journal is a stack, and teardown ordering matters (a
	// route delete naming a closed interface fails).
	for i := len(pending) - 1; i >= 0; i-- {
		r := pending[i]
		switch {
		case ownerAlive(r.PID, r.StartedAt):
			e.logf("netstate: replay: %s %s is owned by live pid %d, leaving it alone", r.Kind, r.ID, r.PID)
			rep.Skipped = append(rep.Skipped, r)
			continue
		case r.Adopted:
			// Adopted state was never ours. Close the entry, change nothing.
			if err := j.Done(ctx, Token(r.Seq)); err != nil {
				rep.Failed = append(rep.Failed, r)
				e.logf("netstate: replay: close adopted entry %s: %v", r.ID, err)
				continue
			}
			rep.Skipped = append(rep.Skipped, r)
			continue
		}

		op, err := revive(r)
		if err != nil {
			rep.Failed = append(rep.Failed, r)
			e.logf("netstate: replay: %v", err)
			continue
		}
		if err := op.Revert(ctx, e); err != nil {
			rep.Failed = append(rep.Failed, r)
			e.logf("netstate: replay: revert %s %s: %v", r.Kind, r.ID, err)
			continue
		}
		if err := op.VerifyReverted(ctx, e); err != nil {
			rep.Failed = append(rep.Failed, r)
			e.logf("netstate: replay: %s %s still present after revert: %v", r.Kind, r.ID, err)
			continue
		}
		if err := j.Done(ctx, Token(r.Seq)); err != nil {
			rep.Failed = append(rep.Failed, r)
			e.logf("netstate: replay: close entry %s: %v", r.ID, err)
			continue
		}
		rep.Reverted = append(rep.Reverted, r)
	}
	return rep, nil
}

// revive rebuilds an Op from a journal record. Only the revert half has to
// work: the process that applied the change is dead, and all we owe the user is
// putting it back.
func revive(r Record) (Op, error) {
	f, ok := reviveByKind[r.Kind]
	if !ok {
		return nil, fmt.Errorf("netstate: cannot replay unknown op kind %q (id %s)", r.Kind, r.ID)
	}
	op, err := f(r)
	if err != nil {
		return nil, fmt.Errorf("netstate: cannot replay %s %s: %w", r.Kind, r.ID, err)
	}
	return op, nil
}

// reviveByKind is populated by each op file's init, so adding an Op without a
// replay path is a compile-time-visible omission rather than a silent one.
var reviveByKind = map[OpKind]func(Record) (Op, error){}
