package journal

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"math"
	"os"

	contracts "syswarden-core/contracts/v5"
)

var (
	ErrCustodyState   = errors.New("independent journal restart custody is invalid or changed")
	ErrCustodyPending = errors.New("journal restart custody has an unresolved commit intent")
)

// CustodyIntent binds one authenticated publication to one expected transition.
// It is private coordination state, not a public schema or a recovery approval.
// The zero value means there is no pending intent. All fields are value-owned.
type CustodyIntent struct {
	Before, After                                contracts.JournalCheckpointAnchor
	SegmentName, SegmentSHA256, CheckpointSHA256 string
	Limits                                       Limits
	KeyID, PublicKeySHA256                       string
	FirstSequence, LastSequence                  uint64
}

// RestartState must come from an independently provisioned trusted backend,
// never from the local journal, its continuity file or a caller's next anchor.
// State returns an owned key copy. Pending is either zero or one complete intent.
type RestartState struct {
	Initial, Head contracts.JournalCheckpointAnchor
	Authority     contracts.JournalCheckpointAuthority
	Pending       CustodyIntent
}

// RestartCustody grants authorized, exclusive, non-expiring local custody leases.
// Acquisition must be bounded/nonblocking and scoped by independent provisioning.
// No production backend, authentication endpoint or provisioning is supplied here.
type RestartCustody interface {
	Acquire() (RestartLease, error)
}

// RestartLease is a trusted backend contract, not a source of untrusted claims.
// It serializes all state changes AND key-policy changes for this scope until
// Close, across processes. It must never silently expire or share writer access.
// State reads authoritative durable state, not a cached acknowledgement.
// Prepare atomically compares Head to intent.Before, requires no Pending, and
// durably stores exactly intent before success. Finish requires exact Pending,
// atomically advances Head to intent.After and clears Pending before success.
// Both preserve Initial and current Authority. No reset, blind write or cancel
// is allowed. Errors may mean an operation persisted; callers never retry them.
// AuthorizeRecovery checks an independently recorded, principal/scope-bound
// approval of the exact digest under current policy and durably audits it. A
// digest alone must not grant authority. Close releases the lease on all paths.
// A backend must separately prove isolation, rollback protection, durability and
// bounded resource use before deployment. An in-memory implementation is NOT
// restart custody. Remote expiring leases/HA require a different fencing design.
type RestartLease interface {
	State() (RestartState, error)
	Prepare(CustodyIntent) error
	Finish(CustodyIntent) error
	AuthorizeRecovery(planSHA256 string) error
	Close() error
}

func sameRestartState(a, b RestartState) bool {
	ka, kb := a.Authority, b.Authority
	return a.Initial == b.Initial && a.Head == b.Head && a.Pending == b.Pending &&
		ka.JournalID == kb.JournalID && ka.Identity == kb.Identity && ka.KeyID == kb.KeyID &&
		ka.FirstSequence == kb.FirstSequence && ka.LastSequence == kb.LastSequence && bytes.Equal(ka.PublicKey, kb.PublicKey)
}

func validateRestartState(s RestartState) error {
	_, e1 := encodeAnchor(s.Initial)
	_, e2 := encodeAnchor(s.Head)
	k := s.Authority
	if e1 != nil || e2 != nil || s.Initial.Cursor.JournalID != s.Head.Cursor.JournalID ||
		s.Initial.Cursor.Identity != s.Head.Cursor.Identity || s.Head.NextSequence < s.Initial.NextSequence ||
		(s.Head.NextSequence == s.Initial.NextSequence && s.Head != s.Initial) ||
		k.JournalID != s.Head.Cursor.JournalID || k.Identity != s.Head.Cursor.Identity ||
		len(k.PublicKey) != ed25519.PublicKeySize || len(k.KeyID) == 0 || len(k.KeyID) > 128 ||
		k.FirstSequence == 0 || k.LastSequence < k.FirstSequence || k.LastSequence == math.MaxUint64 {
		return ErrCustodyState
	}
	if p := s.Pending; p != (CustodyIntent{}) {
		_, err := encodeAnchor(p.After)
		if err != nil || p.Before != s.Head || !anchorTransition(p.Before, p.After) ||
			validateOptions(p.SegmentName, p.Before.Cursor, p.Limits) != nil ||
			!validRecoveryApproval(p.SegmentSHA256) || !validRecoveryApproval(p.CheckpointSHA256) ||
			p.KeyID != k.KeyID || p.PublicKeySHA256 != recoveryDigest(k.PublicKey) ||
			p.FirstSequence != k.FirstSequence || p.LastSequence != k.LastSequence ||
			p.Before.NextSequence < k.FirstSequence || p.Before.NextSequence > k.LastSequence {
			return ErrCustodyState
		}
	}
	return nil
}

type custodySession struct {
	lease RestartLease
	state RestartState
}

func withCustody[T any](custody RestartCustody, call func(*custodySession) (T, error)) (result T, err error) {
	if custody == nil {
		return result, ErrCustodyState
	}
	lease, err := custody.Acquire()
	if lease == nil {
		return result, errors.Join(ErrCustodyState, err)
	}
	defer func() {
		closeErr := lease.Close()
		if closeErr != nil {
			err = errors.Join(ErrCommitUncertain, err, closeErr)
		}
		if err != nil {
			var zero T
			result = zero
		}
	}()
	if err != nil {
		return result, err
	}
	state, err := lease.State()
	if err != nil {
		return result, err
	}
	if err = validateRestartState(state); err != nil {
		return result, err
	}
	state.Authority.PublicKey = bytes.Clone(state.Authority.PublicKey)
	return call(&custodySession{lease: lease, state: state})
}

func (c *custodySession) requireState(expected RestartState) error {
	actual, err := c.lease.State()
	if err != nil || validateRestartState(actual) != nil || !sameRestartState(actual, expected) {
		return errors.Join(ErrCustodyState, err)
	}
	return nil
}

func (c *custodySession) finish(intent CustodyIntent) error {
	if err := c.requireState(c.state); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	if err := c.lease.Finish(intent); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	expected := c.state
	expected.Head, expected.Pending = intent.After, CustodyIntent{}
	if err := c.requireState(expected); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	return nil
}

func publicationIntent(s *Segment, context contracts.JournalCheckpointContext) (CustodyIntent, error) {
	pending, final := checkpointNames(s.name)
	if err := requireAbsent(s.directory, pending); err != nil {
		return CustodyIntent{}, err
	}
	bundle, err := readCheckpointArtifact(s.directory, final)
	if err != nil {
		return CustodyIntent{}, err
	}
	cp, sig, err := decodeCheckpointBundle(bundle)
	if err != nil {
		return CustodyIntent{}, err
	}
	snapshot, err := s.snapshot()
	if err != nil {
		return CustodyIntent{}, err
	}
	_, next, err := contracts.ReadAuthenticatedJournalSegment(snapshot.Data, cp, sig, context, s.limits.MaxBytes, s.limits.MaxFrames)
	if err != nil {
		return CustodyIntent{}, err
	}
	k := context.Authority
	return CustodyIntent{Before: context.Anchor, After: next, SegmentName: s.name,
		SegmentSHA256: recoveryDigest(snapshot.Data), CheckpointSHA256: recoveryDigest(bundle), Limits: s.limits,
		KeyID: k.KeyID, PublicKeySHA256: recoveryDigest(k.PublicKey), FirstSequence: k.FirstSequence, LastSequence: k.LastSequence}, nil
}

// ResumeCustodiedAnchor accepts only independent stable custody and an exactly
// matching local continuity file. Pending work blocks resume, even when the file
// still ends at the old head. It never discovers a new head from local storage.
func ResumeCustodiedAnchor(custody RestartCustody, anchorDirectory *os.File) (contracts.JournalCheckpointAnchor, error) {
	return withCustody(custody, func(c *custodySession) (contracts.JournalCheckpointAnchor, error) {
		if c.state.Pending != (CustodyIntent{}) {
			return contracts.JournalCheckpointAnchor{}, ErrCustodyPending
		}
		a, err := OpenAnchorStore(anchorDirectory, c.state.Initial, c.state.Head)
		if err != nil {
			return contracts.JournalCheckpointAnchor{}, err
		}
		head, err := a.Current()
		err = errors.Join(err, a.Close(), c.requireState(c.state))
		return head, err
	})
}

// CommitCustodiedPublication first persists an exact intent in independent
// custody, then commits verified local storage, closes it, and finally advances
// custody. Success requires final custody readback and lease closure. It never
// presents a cross-resource operation as atomic: every uncertain interval remains
// pending or independently completed, and receives no success acknowledgement.
func CommitCustodiedPublication(custody RestartCustody, anchorDirectory, journalDirectory *os.File, name string, limits Limits) (contracts.JournalCheckpointAnchor, error) {
	return withCustody(custody, func(c *custodySession) (contracts.JournalCheckpointAnchor, error) {
		return c.commit(anchorDirectory, journalDirectory, name, limits, OpenAnchorStore)
	})
}

type custodyAnchorOpener func(*os.File, contracts.JournalCheckpointAnchor, contracts.JournalCheckpointAnchor) (*AnchorStore, error)

func (c *custodySession) commit(anchorDirectory, journalDirectory *os.File, name string, limits Limits, open custodyAnchorOpener) (contracts.JournalCheckpointAnchor, error) {
	if c.state.Pending != (CustodyIntent{}) {
		return contracts.JournalCheckpointAnchor{}, ErrCustodyPending
	}
	a, err := open(anchorDirectory, c.state.Initial, c.state.Head)
	if err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	context := contracts.JournalCheckpointContext{Anchor: c.state.Head, Authority: c.state.Authority}
	s, err := OpenPublishedSegment(journalDirectory, name, context, limits)
	if err != nil {
		return contracts.JournalCheckpointAnchor{}, errors.Join(err, a.Close())
	}
	next, err := c.commitLocked(a, s, context)
	err = errors.Join(err, s.Close(), a.Close())
	if err != nil {
		if c.state.Pending != (CustodyIntent{}) {
			err = errors.Join(ErrCommitUncertain, err)
		}
		return contracts.JournalCheckpointAnchor{}, err
	}
	if err = c.finish(c.state.Pending); err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	return next, nil
}

func (c *custodySession) commitLocked(a *AnchorStore, s *Segment, context contracts.JournalCheckpointContext) (contracts.JournalCheckpointAnchor, error) {
	if a.state.count >= MaxAnchorRecords {
		return contracts.JournalCheckpointAnchor{}, ErrFull
	}
	intent, err := publicationIntent(s, context)
	if err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	if err = c.requireState(c.state); err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	if err = c.lease.Prepare(intent); err != nil {
		return contracts.JournalCheckpointAnchor{}, errors.Join(ErrCommitUncertain, err)
	}
	c.state.Pending = intent
	if err = c.requireState(c.state); err == nil {
		var current CustodyIntent
		current, err = publicationIntent(s, context)
		if err == nil && current != intent {
			err = ErrChanged
		}
	}
	var next contracts.JournalCheckpointAnchor
	if err == nil {
		next, err = s.synchronizePublication(context)
		if err == nil && next != intent.After {
			err = ErrChanged
		}
	}
	if err == nil {
		_, err = a.Current()
	}
	if err == nil {
		err = a.appendAnchor(intent.After)
	}
	if err != nil {
		return contracts.JournalCheckpointAnchor{}, errors.Join(ErrCommitUncertain, err)
	}
	return intent.After, nil
}

func (c *custodySession) openPending(anchorDirectory, journalDirectory *os.File) (*recoverySession, AnchorRecoveryPlan, error) {
	p := c.state.Pending
	if p == (CustodyIntent{}) {
		return nil, AnchorRecoveryPlan{}, ErrRecoveryIneligible
	}
	r, plan, err := openRecovery(anchorDirectory, journalDirectory, c.state.Initial, c.state.Head, p.SegmentName, c.state.Authority, p.Limits)
	if err != nil {
		return nil, AnchorRecoveryPlan{}, err
	}
	actual, err := publicationIntent(r.segment, contracts.JournalCheckpointContext{Anchor: c.state.Head, Authority: c.state.Authority})
	if err != nil || actual != p {
		return nil, AnchorRecoveryPlan{}, errors.Join(ErrCustodyState, err, r.close())
	}
	return r, plan, nil
}

// PlanCustodiedRecovery derives all trust and intent parameters from protected
// custody. Like PlanAnchorRecovery, it performs no explicit write or sync. A
// pending intent with no complete extra local record remains blocked separately.
func PlanCustodiedRecovery(custody RestartCustody, anchorDirectory, journalDirectory *os.File) (AnchorRecoveryPlan, error) {
	return withCustody(custody, func(c *custodySession) (AnchorRecoveryPlan, error) {
		r, plan, err := c.openPending(anchorDirectory, journalDirectory)
		if err != nil {
			return AnchorRecoveryPlan{}, err
		}
		return plan, errors.Join(r.close(), c.requireState(c.state))
	})
}

// ApplyCustodiedRecovery requires both exact-plan matching and the custodian's
// independent recovery authorization. It resynchronizes one complete pending
// local transition, closes local handles, then finishes protected custody. No
// returned plan or supplied hash authenticates a principal by itself.
func ApplyCustodiedRecovery(custody RestartCustody, anchorDirectory, journalDirectory *os.File, approvedSHA256 string) (contracts.JournalCheckpointAnchor, error) {
	if !validRecoveryApproval(approvedSHA256) {
		return contracts.JournalCheckpointAnchor{}, ErrRecoveryApproval
	}
	return withCustody(custody, func(c *custodySession) (contracts.JournalCheckpointAnchor, error) {
		r, plan, err := c.openPending(anchorDirectory, journalDirectory)
		if err != nil {
			return contracts.JournalCheckpointAnchor{}, err
		}
		if plan.SHA256 != approvedSHA256 {
			return contracts.JournalCheckpointAnchor{}, errors.Join(ErrRecoveryApproval, r.close())
		}
		if err = c.lease.AuthorizeRecovery(approvedSHA256); err == nil {
			err = c.requireState(c.state)
		}
		if err != nil {
			return contracts.JournalCheckpointAnchor{}, errors.Join(err, r.close())
		}
		next, err := r.apply(approvedSHA256, recoverySyncOps{publication: r.segment.synchronizePublication, anchor: r.anchor.file.Sync, directory: r.anchor.directory.Sync})
		if err != nil {
			return contracts.JournalCheckpointAnchor{}, err
		}
		if next != c.state.Pending.After {
			return contracts.JournalCheckpointAnchor{}, ErrCustodyState
		}
		if err = c.finish(c.state.Pending); err != nil {
			return contracts.JournalCheckpointAnchor{}, err
		}
		return next, nil
	})
}
