package netstate

import (
	"context"
	"errors"
	"fmt"
)

// ReverifyReport is the outcome of one Reverify pass.
type ReverifyReport struct {
	// Checked is every applied record that was still in force, plus every
	// adopted one (which is not ours to check).
	Checked []Record
	// Missing is what the independent verifier could no longer see.
	Missing []Record
	// Restored is the subset of Missing that was successfully re-applied.
	Restored []Record
	// Failed is the subset of Missing that could not be re-applied, with the
	// reason in Note.
	Failed []Record
}

// OK reports whether everything this manager applied is still in force.
func (r ReverifyReport) OK() bool { return len(r.Failed) == 0 }

// Reverify re-checks every applied Op against the subsystem that can see it
// and re-applies the ones that have gone missing.
//
// macOS flushes interface routes on a link change, and a Wi-Fi association can
// rewrite the DNS servers underneath a process without telling it. A run that
// applied its state at start-up and never looked again is, after one walk from
// a desk to a meeting room, reporting settings it no longer has — which is the
// class of failure the whole verification contract exists to prevent. So this
// runs on every network change (internal/netwatch) and behind `dpb doctor`.
//
// Three properties it must have, each of which cost a defect somewhere:
//
//   - An ADOPTED record is never touched. Adopted means the state was already
//     there and we did not create it: a VPN's scoped default, an admin-set PAC.
//     Verifying it would be pointless and re-applying it would install
//     somebody else's configuration on their behalf. This is the same rule
//     that makes Revert a no-op for those records, and it is why re-applying
//     everything through Do — which is what `dpb coverage --fix` does — is the
//     wrong primitive here: Do's adoption pre-check would see OUR OWN setting
//     already in place, mark the new record Adopted, and quietly turn our own
//     teardown into a no-op.
//   - No new journal record is written. The revert data was journalled with an
//     fsync before the mutation was first attempted and it has not changed;
//     every Revert is idempotent and every VerifyReverted tolerates
//     already-absent state, so re-applying under the existing record is
//     exactly as recoverable as the first apply was.
//   - Order is bring-up order, the same order Do was called in, because a
//     route that names an interface cannot be restored before the interface.
//
// It returns an error only when something could not be restored. A missing
// setting that WAS restored is a success with a report to read.
func (m *Manager) Reverify(ctx context.Context) (ReverifyReport, error) {
	var rep ReverifyReport
	if m.e.DryRun {
		return rep, nil
	}

	// The same lock Do takes: an adoption pre-check racing a re-apply is how
	// one Op adopts another's half-applied change.
	m.opMu.Lock()
	defer m.opMu.Unlock()

	m.mu.Lock()
	done := append([]applied(nil), m.done...)
	m.mu.Unlock()

	var errs []error
	for _, a := range done {
		if a.rec.Adopted {
			rep.Checked = append(rep.Checked, a.rec)
			continue
		}
		verr := a.op.Verify(ctx, m.e)
		if verr == nil {
			rep.Checked = append(rep.Checked, a.rec)
			continue
		}
		m.e.logf("netstate: %s (%s) is no longer in force: %v", a.op.Kind(), a.op.Describe(), verr)
		rec := a.rec
		rec.Note = verr.Error()
		rep.Missing = append(rep.Missing, rec)

		if err := m.restore(ctx, a.op); err != nil {
			rec.Verified = false
			rec.Note = err.Error()
			rep.Failed = append(rep.Failed, rec)
			errs = append(errs, err)
			continue
		}
		m.e.logf("netstate: re-applied %s (%s)", a.op.Kind(), a.op.Describe())
		rep.Restored = append(rep.Restored, rec)
	}
	if len(errs) > 0 {
		return rep, fmt.Errorf("netstate: %d applied setting(s) could not be restored: %w",
			len(errs), errors.Join(errs...))
	}
	return rep, nil
}

// restore re-applies one Op and confirms it through the independent verifier.
//
// A failure here is NOT rolled back. The state is already gone — that is why
// we are here — so there is nothing to undo, and calling Revert on a failed
// re-apply would act on whatever now owns the setting. The journal entry stays
// as it was, so teardown and Replay still know what to put back.
func (m *Manager) restore(ctx context.Context, op Op) error {
	// prepare is idempotent — every implementation returns early once it has
	// run — so this cannot re-capture the revert data over the state we are
	// about to fix. It is called for the Op that was never prepared at all,
	// which cannot happen through Do but can through a hand-built Manager.
	if p, ok := op.(preparer); ok {
		if err := p.prepare(ctx, m.e); err != nil {
			return fmt.Errorf("netstate: prepare %s %s: %w", op.Kind(), op.ID(), err)
		}
	}
	if err := op.Apply(ctx, m.e); err != nil {
		return fmt.Errorf("netstate: re-apply %s (%s): %w", op.Kind(), op.Describe(), err)
	}
	if err := op.Verify(ctx, m.e); err != nil {
		return fmt.Errorf("netstate: re-apply %s (%s): verify: %w", op.Kind(), op.Describe(), err)
	}
	return nil
}
