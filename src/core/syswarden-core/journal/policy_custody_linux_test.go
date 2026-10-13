package journal

import (
	"bytes"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

func policyRequest(t *testing.T, p CustodyAccessPolicy) CustodyPolicyRequest {
	t.Helper()
	peer, _ := custodySocketPair(t, unix.SOCK_STREAM)
	return CustodyPolicyRequest{Peer: peer, Now: func() time.Time { return policyNow(p) }}
}

func TestPolicyCustodyRealCommitResumeAndRevocation(t *testing.T) {
	for _, count := range []int{0, 2} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			p := peerTestPolicy(t, CustodyCommit, CustodyResume)
			policies, dir, _, root := policyFixture(t, p)
			r := policyRequest(t, p)
			f, _ := custodyFixture(t, count)
			b, custodyDir, _ := localCustodyFixture(t, nil)
			next, err := CommitPolicyPublication(policies, r, b, f.anchor, f.journal, testName, testLimits())
			if err != nil || next != f.next {
				t.Fatal("real protected commit", err)
			}
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			b, err = OpenLocalCustody(custodyDir, testEnrollment(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = b.Close() }()
			next, err = ResumePolicyCustody(policies, r, b, f.anchor)
			if err != nil || next != f.next {
				t.Fatal("real protected restart", err)
			}
			before := f.bytes(t)
			if _, err = policies.Disable(root.Trust); err != nil {
				t.Fatal(err)
			}
			next, err = ResumePolicyCustody(policies, r, b, f.anchor)
			requireNoCustodyResult(t, next, err)
			if err = policies.Close(); err != nil {
				t.Fatal(err)
			}
			policies, err = OpenLocalCustodyPolicy(dir, root.Trust)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = policies.Close() }()
			next, err = ResumePolicyCustody(policies, r, b, f.anchor)
			requireNoCustodyResult(t, next, err)
			p.Revision++
			disabled := policyCurrent(t, policies)
			if _, err = policies.Install(disabled.Trust, signedPolicySnapshot(t, p, true), policyNow(p)); err != nil {
				t.Fatal(err)
			}
			next, err = ResumePolicyCustody(policies, r, b, f.anchor)
			if err != nil || next != f.next {
				t.Fatal("explicit new revision did not resume", err)
			}
			requireSameRecoveryBytes(t, before, f.bytes(t))
		})
	}
}

func TestPolicyCustodyRecoveryRequiresIndependentAuditedApproval(t *testing.T) {
	for _, decision := range []string{"nil", "denied", "approved"} {
		t.Run(decision, func(t *testing.T) {
			p := peerTestPolicy(t, CustodyApplyRecovery, CustodyInspectRecovery)
			policies, _, _, _ := policyFixture(t, p)
			r := policyRequest(t, p)
			f := interruptedAnchor(t, 2, false, false)
			auth := &testRecoveryAuthorizer{decision: strings.Repeat("d", 64)}
			var configured CustodyRecoveryAuthorizer = auth
			if decision == "nil" {
				configured = nil
			} else if decision == "denied" {
				auth.err = ErrRecoveryApproval
			}
			b, _, path := localCustodyFixture(t, configured)
			s, err := OpenPublishedSegment(f.journal, testName, contracts.JournalCheckpointContext{Anchor: f.expected, Authority: f.authority}, testLimits())
			if err != nil {
				t.Fatal(err)
			}
			intent, err := publicationIntent(s, contracts.JournalCheckpointContext{Anchor: f.expected, Authority: f.authority})
			if err = errors.Join(err, s.Close()); err != nil {
				t.Fatal(err)
			}
			l := localLease(t, b)
			if err = errors.Join(l.Prepare(intent), l.Close()); err != nil {
				t.Fatal(err)
			}
			plan, err := PlanPolicyRecovery(policies, r, b, f.anchor, f.journal)
			if err != nil {
				t.Fatal(err)
			}
			before, ledger := f.bytes(t), readFile(t, filepath.Join(path, custodyFileName))
			next, err := ApplyPolicyRecovery(policies, r, b, f.anchor, f.journal, plan.SHA256)
			if decision == "approved" {
				if err != nil || next != f.next || auth.calls != 1 || auth.request.PlanSHA256 != plan.SHA256 {
					t.Fatal("independent approval", err)
				}
				stored := readFile(t, filepath.Join(path, custodyFileName))
				if !bytes.Contains(stored, []byte(auth.decision)) || !bytes.Contains(stored, []byte(plan.SHA256)) {
					t.Fatal("approval audit not retained")
				}
			} else {
				requireNoCustodyResult(t, next, err)
				if !bytes.Equal(ledger, readFile(t, filepath.Join(path, custodyFileName))) {
					t.Fatal("denied recovery wrote custody")
				}
			}
			requireSameRecoveryBytes(t, before, f.bytes(t))
		})
	}
}

func TestPolicyCustodyFixedOperationMatrix(t *testing.T) {
	ops := []CustodyOperation{CustodyApplyRecovery, CustodyCommit, CustodyInspectRecovery, CustodyResume}
	for _, grant := range ops {
		for _, requested := range ops {
			t.Run(string(grant)+"/"+string(requested), func(t *testing.T) {
				p := peerTestPolicy(t, grant)
				policies, _, _, _ := policyFixture(t, p)
				r := policyRequest(t, p)
				f, b := custodyFixture(t, 1)
				b.fault = "acquire"
				var err error
				switch requested {
				case CustodyApplyRecovery:
					_, err = ApplyPolicyRecovery(policies, r, b, f.anchor, f.journal, strings.Repeat("a", 64))
				case CustodyCommit:
					_, err = CommitPolicyPublication(policies, r, b, f.anchor, f.journal, testName, testLimits())
				case CustodyInspectRecovery:
					_, err = PlanPolicyRecovery(policies, r, b, f.anchor, f.journal)
				case CustodyResume:
					_, err = ResumePolicyCustody(policies, r, b, f.anchor)
				}
				if err == nil || (len(b.stages) != 0) != (grant == requested) {
					t.Fatal("wrong entry point admitted", err, b.stages)
				}
			})
		}
	}
}

func TestPolicyCustodyDeniesBeforeBackend(t *testing.T) {
	for _, kind := range []string{"nil-store", "nil-clock", "zero-clock", "expired", "future", "disabled", "wrong-uid", "closed-peer", "nil-peer"} {
		t.Run(kind, func(t *testing.T) {
			p := peerTestPolicy(t, CustodyCommit)
			if kind == "wrong-uid" {
				p.Grants[0].UID ^= 1
			}
			policies, _, _, root := policyFixture(t, p)
			r := policyRequest(t, p)
			switch kind {
			case "nil-store":
				policies = nil
			case "nil-clock":
				r.Now = nil
			case "zero-clock":
				r.Now = func() time.Time { return time.Time{} }
			case "expired":
				r.Now = func() time.Time { return time.Unix(p.NotAfter, 0) }
			case "future":
				r.Now = func() time.Time { return time.Unix(p.NotBefore-1, 0) }
			case "disabled":
				if _, err := policies.Disable(root.Trust); err != nil {
					t.Fatal(err)
				}
			case "closed-peer":
				if err := r.Peer.Close(); err != nil {
					t.Fatal(err)
				}
			case "nil-peer":
				r.Peer = nil
			}
			f, b := custodyFixture(t, 1)
			before := f.bytes(t)
			next, err := CommitPolicyPublication(policies, r, b, f.anchor, f.journal, testName, testLimits())
			requireNoCustodyResult(t, next, err)
			if len(b.stages) != 0 {
				t.Fatal("rejection reached custody")
			}
			requireSameRecoveryBytes(t, before, f.bytes(t))
		})
	}
}

func TestPolicyCustodyEnrollmentCannotBeSubstituted(t *testing.T) {
	for _, kind := range []string{"initial", "key", "range", "nil-backend"} {
		t.Run(kind, func(t *testing.T) {
			p := peerTestPolicy(t, CustodyCommit)
			policies, _, _, _ := policyFixture(t, p)
			f, b := custodyFixture(t, 1)
			var backend RestartCustody = b
			switch kind {
			case "initial":
				b.state.Initial.PreviousSHA256 = strings.Repeat("a", 64)
			case "key":
				b.state.Authority.PublicKey[0] ^= 1
			case "range":
				b.state.Authority.LastSequence++
			case "nil-backend":
				backend = nil
			}
			before := f.bytes(t)
			next, err := CommitPolicyPublication(policies, policyRequest(t, p), backend, f.anchor, f.journal, testName, testLimits())
			requireNoCustodyResult(t, next, err)
			if b.preparations != 0 || (backend != nil && b.closes != 1) {
				t.Fatal("mismatched enrollment wrote or leaked a lease")
			}
			requireSameRecoveryBytes(t, before, f.bytes(t))
		})
	}
}

func TestPolicyCustodyExpiryRetainsPendingAndCompletedState(t *testing.T) {
	for _, phase := range []string{"acquire", "state", "prepare-after", "finish-before", "finish-after", "close"} {
		t.Run(phase, func(t *testing.T) {
			p := peerTestPolicy(t, CustodyCommit, CustodyResume)
			policies, _, _, _ := policyFixture(t, p)
			r := policyRequest(t, p)
			now := policyNow(p)
			r.Now = func() time.Time { return now }
			f, b := custodyFixture(t, 1)
			before := f.bytes(t)
			b.hook = func(stage string) {
				if stage == phase {
					now = time.Unix(p.NotAfter, 0)
				}
			}
			next, err := CommitPolicyPublication(policies, r, b, f.anchor, f.journal, testName, testLimits())
			requireNoCustodyResult(t, next, err)
			if b.closes != 1 || b.preparations > 1 || b.finishes > 1 {
				t.Fatal("automatic retry or lease leak")
			}
			switch phase {
			case "acquire", "state":
				requireSameRecoveryBytes(t, before, f.bytes(t))
				if b.state.Pending != (CustodyIntent{}) || b.preparations != 0 {
					t.Fatal("early expiry prepared work")
				}
			case "prepare-after":
				requireSameRecoveryBytes(t, before, f.bytes(t))
				if b.state.Pending == (CustodyIntent{}) || b.finishes != 0 {
					t.Fatal("prepared state lost or progressed")
				}
			default:
				// Expiry inside a backend method cannot undo its durable effects.
				if b.state.Head != f.next || b.state.Pending != (CustodyIntent{}) {
					t.Fatal("completed durable state lost")
				}
			}
			// A valid new policy can resume only independently completed state.
			b.hook = nil
			current := policyCurrent(t, policies)
			p.Revision++
			p.NotAfter += 3600
			if _, err := policies.Install(current.Trust, signedPolicySnapshot(t, p, true), now); err != nil {
				t.Fatal(err)
			}
			next, err = ResumePolicyCustody(policies, r, b, f.anchor)
			if phase == "prepare-after" {
				requireNoCustodyResult(t, next, err)
			} else if err != nil || next != b.state.Head {
				t.Fatal("renewed policy resume", err)
			}
		})
	}
}

func TestPolicyCustodyLockSpansClosure(t *testing.T) {
	p := peerTestPolicy(t, CustodyCommit)
	policies, _, _, root := policyFixture(t, p)
	f, b := custodyFixture(t, 1)
	nextPolicy := p
	nextPolicy.Revision++
	update := signedPolicySnapshot(t, nextPolicy, true)
	b.hook = func(stage string) {
		if _, err := policies.Disable(root.Trust); !errors.Is(err, ErrLocked) {
			t.Fatal("disable interleaved at", stage, err)
		}
		if _, err := policies.Install(root.Trust, update, policyNow(p)); !errors.Is(err, ErrLocked) {
			t.Fatal("install interleaved at", stage, err)
		}
	}
	next, err := CommitPolicyPublication(policies, policyRequest(t, p), b, f.anchor, f.journal, testName, testLimits())
	if err != nil || next != f.next {
		t.Fatal(err)
	}
	if _, err := policies.Disable(root.Trust); err != nil {
		t.Fatal("closure did not release policy", err)
	}
}

func TestPolicyCustodyExpiryAfterLocalWriteRequiresReviewedRecovery(t *testing.T) {
	p := peerTestPolicy(t, CustodyApplyRecovery, CustodyCommit, CustodyInspectRecovery, CustodyResume)
	policies, _, _, _ := policyFixture(t, p)
	r := policyRequest(t, p)
	f, b := custodyFixture(t, 1)
	before := f.bytes(t)
	// Simulate a deadline crossed during local disk I/O. The next guard must
	// retain the completed local anchor and prepared intent without finishing.
	r.Now = func() time.Time {
		if !bytes.Equal(before[0], readFile(t, filepath.Join(f.anchorPath, anchorName))) {
			return time.Unix(p.NotAfter, 0)
		}
		return policyNow(p)
	}
	next, err := CommitPolicyPublication(policies, r, b, f.anchor, f.journal, testName, testLimits())
	requireNoCustodyResult(t, next, err)
	if b.finishes != 0 || b.closes != 1 || b.state.Head != f.expected || b.state.Pending.After != f.next {
		t.Fatal("expired local commit lost pending state or finished")
	}
	current := policyCurrent(t, policies)
	p.Revision++
	p.NotAfter += 3600
	if _, err := policies.Install(current.Trust, signedPolicySnapshot(t, p, true), policyNow(p)); err != nil {
		t.Fatal(err)
	}
	r.Now = func() time.Time { return policyNow(p) }
	next, err = ResumePolicyCustody(policies, r, b, f.anchor)
	requireNoCustodyResult(t, next, err)
	plan, err := PlanPolicyRecovery(policies, r, b, f.anchor, f.journal)
	if err != nil {
		t.Fatal(err)
	}
	next, err = ApplyPolicyRecovery(policies, r, b, f.anchor, f.journal, plan.SHA256)
	requireNoCustodyResult(t, next, err)
	b.approved = plan.SHA256
	retained := f.bytes(t)
	next, err = ApplyPolicyRecovery(policies, r, b, f.anchor, f.journal, plan.SHA256)
	if err != nil || next != f.next {
		t.Fatal("reviewed recovery", err)
	}
	requireSameRecoveryBytes(t, retained, f.bytes(t))
}

func TestPolicyCustodyMidOperationFailure(t *testing.T) {
	for _, kind := range []string{"clock-rollback", "closed-peer", "changed-policy", "factory-close", "backend-close"} {
		t.Run(kind, func(t *testing.T) {
			p := peerTestPolicy(t, CustodyCommit)
			policies, _, path, _ := policyFixture(t, p)
			r := policyRequest(t, p)
			now := policyNow(p)
			r.Now = func() time.Time { return now }
			f, b := custodyFixture(t, 1)
			b.hook = func(stage string) {
				if stage != "prepare-after" {
					return
				}
				switch kind {
				case "clock-rollback":
					now = now.Add(-time.Nanosecond)
				case "closed-peer":
					if err := r.Peer.Close(); err != nil {
						t.Fatal(err)
					}
				case "changed-policy":
					if err := chmodFixture(filepath.Join(path, policyFileName), 0640); err != nil {
						t.Fatal(err)
					}
				case "factory-close":
					if err := policies.Close(); err != nil {
						t.Fatal(err)
					}
				case "backend-close":
					b.fault = "close"
				}
			}
			next, err := CommitPolicyPublication(policies, r, b, f.anchor, f.journal, testName, testLimits())
			if kind == "factory-close" {
				if err != nil || next != f.next {
					t.Fatal("factory close invalidated owned lease", err)
				}
			} else {
				requireNoCustodyResult(t, next, err)
			}
			if b.closes != 1 {
				t.Fatal("backend lock leaked")
			}
			if kind != "factory-close" && kind != "backend-close" && (b.finishes != 0 || b.state.Pending == (CustodyIntent{})) {
				t.Fatal("failed guard progressed or lost intent")
			}
		})
	}
}
