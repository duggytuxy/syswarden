package journal

import (
	"errors"
	"net"
	"os"
	"time"

	contracts "syswarden-core/contracts/v5"
)

// CustodyPolicyRequest binds a live accepted peer and an independently trusted
// current wall-clock source. The source must be bounded and safe for concurrent
// requests; nil fails closed. It must never read time from a client request.
// This value does not authenticate human operators or approve recovery plans.
type CustodyPolicyRequest struct {
	Peer *net.UnixConn
	Now  func() time.Time
}

type policyGuard struct {
	lease     *policyLease
	request   CustodyPolicyRequest
	operation CustodyOperation
	admission CustodyAdmission
	last      time.Time
	err       error
}

func (g *policyGuard) check() error {
	if g.err != nil {
		return g.err
	}
	if g.request.Now == nil {
		g.err = ErrCustodyAdmission
		return g.err
	}
	if err := g.lease.refresh(); err != nil {
		g.err = err
		return err
	}
	now := g.request.Now().Round(0) // Compare wall time, not an optional monotonic field.
	if now.IsZero() || (!g.last.IsZero() && now.Before(g.last)) {
		g.err = ErrCustodyAdmission
		return g.err
	}
	current := g.lease.tip.snapshot
	admission, err := AdmitLocalCustody(g.request.Peer, current.Document, current.Signature, current.Trust, now, g.operation)
	if err == nil && !g.last.IsZero() && (admission.UID != g.admission.UID || admission.GID != g.admission.GID || admission.PID != g.admission.PID) {
		err = ErrCustodyAdmission
	}
	if err != nil {
		g.err = err
		return err
	}
	g.last, g.admission = now, admission
	return nil
}

type policyBoundCustody struct {
	guard   *policyGuard
	backend RestartCustody
}
type policyBoundLease struct {
	guard  *policyGuard
	lease  RestartLease
	closed bool
}

func (b policyBoundCustody) Acquire() (RestartLease, error) {
	if err := b.guard.check(); err != nil {
		return nil, err
	}
	if b.backend == nil {
		return nil, ErrCustodyState
	}
	raw, err := b.backend.Acquire()
	if raw == nil {
		return nil, errors.Join(ErrCustodyState, err)
	}
	l := &policyBoundLease{guard: b.guard, lease: raw}
	if err != nil {
		return nil, errors.Join(err, l.Close())
	}
	if _, err = l.State(); err != nil {
		return nil, errors.Join(err, l.Close())
	}
	return l, nil
}
func (l *policyBoundLease) before() error {
	if l.closed {
		return ErrClosed
	}
	return l.guard.check()
}
func (l *policyBoundLease) State() (RestartState, error) {
	if err := l.before(); err != nil {
		return RestartState{}, err
	}
	s, err := l.lease.State()
	if err == nil {
		actual, e1 := custodyEnrollment(CustodyEnrollment{Initial: s.Initial, Authority: s.Authority})
		expected, e2 := custodyEnrollment(l.guard.admission.Enrollment)
		if validateRestartState(s) != nil || e1 != nil || e2 != nil || !sameRestartState(actual, expected) {
			err = ErrCustodyState
		}
	}
	if err = errors.Join(err, l.guard.check()); err != nil {
		return RestartState{}, err
	}
	return s, nil
}
func (l *policyBoundLease) Prepare(intent CustodyIntent) error {
	if err := l.before(); err != nil {
		return err
	}
	if l.guard.operation != CustodyCommit {
		return ErrCustodyAdmission
	}
	err := l.lease.Prepare(intent)
	return errors.Join(err, l.guard.check())
}
func (l *policyBoundLease) Finish(intent CustodyIntent) error {
	if err := l.before(); err != nil {
		return err
	}
	if l.guard.operation != CustodyCommit && l.guard.operation != CustodyApplyRecovery {
		return ErrCustodyAdmission
	}
	err := l.lease.Finish(intent)
	return errors.Join(err, l.guard.check())
}
func (l *policyBoundLease) AuthorizeRecovery(plan string) error {
	if err := l.before(); err != nil {
		return err
	}
	if l.guard.operation != CustodyApplyRecovery {
		return ErrCustodyAdmission
	}
	err := l.lease.AuthorizeRecovery(plan)
	return errors.Join(err, l.guard.check())
}
func (l *policyBoundLease) Close() error {
	if l.closed {
		return nil
	}
	before := l.guard.check()
	err := l.lease.Close()
	l.closed = true
	if err = errors.Join(before, err, l.guard.check()); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	return nil
}

func withPolicyCustody[T any](policies *LocalCustodyPolicy, request CustodyPolicyRequest, backend RestartCustody, operation CustodyOperation, call func(RestartCustody) (T, error)) (result T, err error) {
	lease, err := policies.acquire()
	if err != nil {
		return result, err
	}
	guard := &policyGuard{lease: lease, request: request, operation: operation}
	defer func() {
		// Keep policy locked through coordinator closure and the final validity
		// check. Never release it early when expiry or a storage error occurs.
		err = errors.Join(err, guard.check(), lease.close())
		if err != nil {
			var zero T
			result = zero
		}
	}()
	if err = guard.check(); err != nil {
		return result, err
	}
	return call(policyBoundCustody{guard: guard, backend: backend})
}

// ResumePolicyCustody verifies one current retained head with per-call kernel
// admission and an exclusive policy lease lasting through all custody closure.
// Every policy administrator and operational writer must use these same locks.
// This does not install a service or isolate the directories from other UIDs.
func ResumePolicyCustody(policies *LocalCustodyPolicy, request CustodyPolicyRequest, backend RestartCustody, anchor *os.File) (contracts.JournalCheckpointAnchor, error) {
	return withPolicyCustody(policies, request, backend, CustodyResume, func(bound RestartCustody) (contracts.JournalCheckpointAnchor, error) {
		return ResumeCustodiedAnchor(bound, anchor)
	})
}

// CommitPolicyPublication admits only commit, then delegates the existing exact
// verified publication protocol. Time/peer/policy are checked around each custody
// step and before success. Expiry may follow a persisted write: an error retains
// pending or completed state, never rolls it back and never silently retries it.
func CommitPolicyPublication(policies *LocalCustodyPolicy, request CustodyPolicyRequest, backend RestartCustody, anchor, journal *os.File, name string, limits Limits) (contracts.JournalCheckpointAnchor, error) {
	return withPolicyCustody(policies, request, backend, CustodyCommit, func(bound RestartCustody) (contracts.JournalCheckpointAnchor, error) {
		return CommitCustodiedPublication(bound, anchor, journal, name, limits)
	})
}

// PlanPolicyRecovery requires its own inspection grant; it does not approve apply.
func PlanPolicyRecovery(policies *LocalCustodyPolicy, request CustodyPolicyRequest, backend RestartCustody, anchor, journal *os.File) (AnchorRecoveryPlan, error) {
	return withPolicyCustody(policies, request, backend, CustodyInspectRecovery, func(bound RestartCustody) (AnchorRecoveryPlan, error) {
		return PlanCustodiedRecovery(bound, anchor, journal)
	})
}

// ApplyPolicyRecovery also retains the separate current exact-plan approval and
// durable audit requirement of the backend. A local UID grant cannot replace it.
func ApplyPolicyRecovery(policies *LocalCustodyPolicy, request CustodyPolicyRequest, backend RestartCustody, anchor, journal *os.File, planSHA256 string) (contracts.JournalCheckpointAnchor, error) {
	return withPolicyCustody(policies, request, backend, CustodyApplyRecovery, func(bound RestartCustody) (contracts.JournalCheckpointAnchor, error) {
		return ApplyCustodiedRecovery(bound, anchor, journal, planSHA256)
	})
}
