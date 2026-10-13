package journal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

const (
	MaxPolicyApprovalSeconds = 300
	maxPolicyChangeBytes     = 2*MaxCustodyPolicyBytes + 8192
	policyChangeSchema       = "syswarden.custody-policy-change.v1"
	policyChangeDomain       = "syswarden/custody-policy-change/v1\x00"
)

var ErrPolicyApproval = errors.New("policy administration requires independent exact-plan authorization and audit")

// CustodyPolicyChange describes a proposal, never an authorization. Install
// carries exact signed next bytes. Disable requires an empty Next and derives
// the disabled state from protected current storage. Bootstrap/key migration
// are deliberately not operations of this interface.
type CustodyPolicyChange struct {
	Operation string
	Next      CustodyPolicySnapshot
}

func clonePolicyChange(c CustodyPolicyChange) (CustodyPolicyChange, error) {
	if c.Operation == "disable" && samePolicySnapshot(c.Next, CustodyPolicySnapshot{}) {
		return c, nil
	}
	if c.Operation != "install" || len(c.Next.Document) == 0 || len(c.Next.Document) > MaxCustodyPolicyBytes || len(c.Next.Signature) != ed25519.SignatureSize || len(c.Next.Trust.IssuerPublicKey) != ed25519.PublicKeySize {
		return CustodyPolicyChange{}, ErrPolicyState
	}
	c.Next = clonePolicySnapshot(c.Next)
	return c, nil
}

// CustodyPolicyChangePlan is private inspection output, not a bearer credential.
// Apply reconstructs it from actual protected bytes, resources and kernel peer.
type CustodyPolicyChangePlan struct {
	Document []byte
	SHA256   string
}

// PolicyAdministrationRequest owns its plan bytes. UID is observed by the kernel;
// PID/GID are diagnostic bindings, not roles or human identities. Mode is inspect
// or apply. A caller-provided plan or UID is never used to construct this value.
type PolicyAdministrationRequest struct {
	Mode     string
	Plan     CustodyPolicyChangePlan
	UID, GID uint32
	PID      int32
}

// PolicyAdministrationDecision must identify the independent durable decision
// audit and exact request. Its lifetime is at most five minutes. This struct is
// accepted only from the trusted authorizer callback, never from request bytes.
type PolicyAdministrationDecision struct {
	Mode, PlanSHA256, DecisionSHA256 string
	UID                              uint32
	NotBefore, NotAfter              int64
}

// PolicyAdministrationAuthorizer is independently provisioned trusted authority.
// It must authenticate the administrator, enforce current scope and mode-specific
// rights, independently validate exact apply approval, and durably audit its
// decision before returning. Nil/denial/unavailable audit fail closed. Operational
// policy grants do not authorize this callback or administration. It must be
// bounded, concurrency-safe, participate in authority revocation serialization,
// and never reenter policy storage while its lease is held. This package supplies
// no permissive default, human identity provider, administrative service or MFA.
type PolicyAdministrationAuthorizer interface {
	AuthorizePolicyAdministration(PolicyAdministrationRequest) (PolicyAdministrationDecision, error)
}

type policyChangeDocument struct {
	Schema                string           `json:"schema"`
	Operation             string           `json:"operation"`
	PolicyID              string           `json:"policy_id"`
	IssuerKeyID           string           `json:"issuer_key_id"`
	IssuerPublicKeySHA256 string           `json:"issuer_public_key_sha256"`
	RootRevision          string           `json:"root_revision"`
	RootSHA256            string           `json:"root_sha256"`
	RootEnabled           bool             `json:"root_enabled"`
	Initial               json.RawMessage  `json:"initial"`
	BeforeEnabled         bool             `json:"before_enabled"`
	BeforePolicy          json.RawMessage  `json:"before_policy"`
	BeforeSignature       string           `json:"before_signature"`
	AfterEnabled          bool             `json:"after_enabled"`
	AfterPolicy           json.RawMessage  `json:"after_policy"`
	AfterSignature        string           `json:"after_signature"`
	Records               string           `json:"records"`
	HistorySHA256         string           `json:"history_sha256"`
	Directory             recoveryResource `json:"directory"`
	File                  recoveryResource `json:"file"`
	UID                   string           `json:"actor_uid"`
	GID                   string           `json:"actor_gid"`
	PID                   string           `json:"actor_pid"`
}

func (l *policyLease) proposed(change CustodyPolicyChange, now time.Time) (CustodyPolicySnapshot, error) {
	var next CustodyPolicySnapshot
	switch change.Operation {
	case "install":
		next = clonePolicySnapshot(change.Next)
		trust := next.Trust
		trust.Enabled = true // A newly installed disabled policy still needs valid signed bytes.
		if _, err := VerifyCustodyAccessPolicy(next.Document, next.Signature, trust, now); err != nil {
			return next, err
		}
	case "disable":
		if !samePolicySnapshot(change.Next, CustodyPolicySnapshot{}) {
			return next, ErrPolicyState
		}
		next = clonePolicySnapshot(l.tip.snapshot)
		next.Trust.Enabled = false
	default:
		return next, ErrPolicyState
	}
	if !policyTransition(l.tip.snapshot, next, change.Operation) {
		return CustodyPolicySnapshot{}, ErrPolicyState
	}
	if l.tip.count >= MaxPolicyRecords || (l.tip.count == MaxPolicyRecords-1 && next.Trust.Enabled) {
		return CustodyPolicySnapshot{}, ErrFull
	}
	return next, nil
}

func (l *policyLease) changePlan(operation string, next CustodyPolicySnapshot, peer unix.Ucred) (CustodyPolicyChangePlan, error) {
	if err := l.refresh(); err != nil {
		return CustodyPolicyChangePlan{}, err
	}
	var dir unix.Stat_t
	if err := unix.Fstat(int(l.directory.Fd()), &dir); err != nil || !privateDirectory(dir) {
		return CustodyPolicyChangePlan{}, errors.Join(ErrUnsafeStorage, err)
	}
	initial, err := encodeAnchor(l.root.Initial)
	if err != nil {
		return CustodyPolicyChangePlan{}, err
	}
	before := l.tip.snapshot
	doc, err := json.Marshal(policyChangeDocument{
		Schema: policyChangeSchema, Operation: operation, PolicyID: l.root.PolicyID, IssuerKeyID: l.root.IssuerKeyID,
		IssuerPublicKeySHA256: recoveryDigest(l.root.IssuerPublicKey), RootRevision: strconv.FormatUint(l.root.Revision, 10), RootSHA256: l.root.PolicySHA256, RootEnabled: l.root.Enabled, Initial: initial,
		BeforeEnabled: before.Trust.Enabled, BeforePolicy: before.Document, BeforeSignature: hex.EncodeToString(before.Signature),
		AfterEnabled: next.Trust.Enabled, AfterPolicy: next.Document, AfterSignature: hex.EncodeToString(next.Signature),
		Records: strconv.Itoa(l.tip.count), HistorySHA256: hex.EncodeToString(l.tip.hash[:]),
		Directory: bindRecoveryResource(dir), File: bindRecoveryResource(l.stamp),
		UID: strconv.FormatUint(uint64(peer.Uid), 10), GID: strconv.FormatUint(uint64(peer.Gid), 10), PID: strconv.FormatInt(int64(peer.Pid), 10),
	})
	if err != nil || len(doc) > maxPolicyChangeBytes {
		return CustodyPolicyChangePlan{}, errors.Join(ErrPolicyState, err)
	}
	sum := sha256.Sum256(append([]byte(policyChangeDomain), doc...))
	return CustodyPolicyChangePlan{Document: doc, SHA256: hex.EncodeToString(sum[:])}, nil
}

type policyAdministrationGuard struct {
	lease     *policyLease
	request   CustodyPolicyRequest
	peer      unix.Ucred
	last      time.Time
	decision  *PolicyAdministrationDecision
	candidate *CustodyPolicySnapshot
	err       error
}

func (g *policyAdministrationGuard) check() error {
	if g.err != nil {
		return g.err
	}
	if g.request.Now == nil {
		g.err = ErrPolicyApproval
		return g.err
	}
	if err := g.lease.refresh(); err != nil {
		g.err = err
		return err
	}
	now := g.request.Now().Round(0)
	if now.IsZero() || now.Unix() <= 0 || now.Unix() > maxPolicyTime || (!g.last.IsZero() && now.Before(g.last)) {
		g.err = ErrPolicyApproval
		return g.err
	}
	peer, err := custodyPeer(g.request.Peer)
	if err != nil || (!g.last.IsZero() && peer != g.peer) {
		g.err = errors.Join(ErrPolicyApproval, err)
		return g.err
	}
	if g.decision != nil && (now.Unix() < g.decision.NotBefore || now.Unix() >= g.decision.NotAfter) {
		g.err = ErrPolicyApproval
		return g.err
	}
	if g.candidate != nil {
		trust := g.candidate.Trust
		trust.Enabled = true
		if _, err := VerifyCustodyAccessPolicy(g.candidate.Document, g.candidate.Signature, trust, now); err != nil {
			g.err = err
			return err
		}
	}
	g.peer, g.last = peer, now
	return nil
}

func (g *policyAdministrationGuard) authorize(authorizer PolicyAdministrationAuthorizer, mode string, plan CustodyPolicyChangePlan) (*policyChangeAudit, error) {
	if authorizer == nil {
		return nil, ErrPolicyApproval
	}
	request := PolicyAdministrationRequest{Mode: mode, Plan: CustodyPolicyChangePlan{Document: bytes.Clone(plan.Document), SHA256: plan.SHA256}, UID: g.peer.Uid, GID: g.peer.Gid, PID: g.peer.Pid}
	d, err := authorizer.AuthorizePolicyAdministration(request)
	a := &policyChangeAudit{PlanSHA256: d.PlanSHA256, DecisionSHA256: d.DecisionSHA256, UID: strconv.FormatUint(uint64(d.UID), 10), NotBefore: strconv.FormatInt(d.NotBefore, 10), NotAfter: strconv.FormatInt(d.NotAfter, 10)}
	if err != nil || d.Mode != mode || d.PlanSHA256 != plan.SHA256 || d.UID != g.peer.Uid || !validPolicyChangeAudit(a) {
		return nil, errors.Join(ErrPolicyApproval, err)
	}
	g.decision = &d
	if err = g.check(); err != nil {
		return nil, err
	}
	return a, nil
}

func withPolicyAdministration[T any](policies *LocalCustodyPolicy, request CustodyPolicyRequest, call func(*policyAdministrationGuard) (T, error)) (result T, err error) {
	l, err := policies.acquire()
	if err != nil {
		return result, err
	}
	g := &policyAdministrationGuard{lease: l, request: request}
	defer func() {
		err = errors.Join(err, g.check(), l.close())
		if err != nil {
			var zero T
			result = zero
		}
	}()
	if err = g.check(); err != nil {
		return result, err
	}
	return call(g)
}

// PlanCustodyPolicyChange authorizes private inspection through an independent
// authorizer. It writes no policy record and grants no apply permission. The
// plan binds full before/after signed bytes, history, resources and kernel peer.
func PlanCustodyPolicyChange(policies *LocalCustodyPolicy, request CustodyPolicyRequest, authorizer PolicyAdministrationAuthorizer, change CustodyPolicyChange) (CustodyPolicyChangePlan, error) {
	change, err := clonePolicyChange(change)
	if err != nil || authorizer == nil {
		return CustodyPolicyChangePlan{}, errors.Join(ErrPolicyApproval, err)
	}
	return withPolicyAdministration(policies, request, func(g *policyAdministrationGuard) (CustodyPolicyChangePlan, error) {
		next, err := g.lease.proposed(change, g.last)
		if err != nil {
			return CustodyPolicyChangePlan{}, err
		}
		if change.Operation == "install" {
			g.candidate = &next
		}
		plan, err := g.lease.changePlan(change.Operation, next, g.peer)
		if err != nil {
			return CustodyPolicyChangePlan{}, err
		}
		if _, err = g.authorize(authorizer, "inspect", plan); err != nil {
			return CustodyPolicyChangePlan{}, err
		}
		return plan, nil
	})
}

// ApplyCustodyPolicyChange reconstructs the exact plan and independently approves
// application. Its audit reference and policy transition share one durable frame.
// Expiry/error after a write retains uncertain bytes and returns no result. No
// automatic retries, rollback, bootstrap, issuer rotation or raw IPC are provided.
func ApplyCustodyPolicyChange(policies *LocalCustodyPolicy, request CustodyPolicyRequest, authorizer PolicyAdministrationAuthorizer, change CustodyPolicyChange, planSHA256 string) (CustodyPolicySnapshot, error) {
	change, err := clonePolicyChange(change)
	if err != nil || authorizer == nil {
		return CustodyPolicySnapshot{}, errors.Join(ErrPolicyApproval, err)
	}
	return withPolicyAdministration(policies, request, func(g *policyAdministrationGuard) (CustodyPolicySnapshot, error) {
		if !validRecoveryApproval(planSHA256) {
			return CustodyPolicySnapshot{}, ErrPolicyApproval
		}
		next, err := g.lease.proposed(change, g.last)
		if err != nil {
			return CustodyPolicySnapshot{}, err
		}
		if change.Operation == "install" {
			g.candidate = &next
		}
		plan, err := g.lease.changePlan(change.Operation, next, g.peer)
		if err != nil || plan.SHA256 != planSHA256 {
			return CustodyPolicySnapshot{}, errors.Join(ErrPolicyApproval, err)
		}
		audit, err := g.authorize(authorizer, "apply", plan)
		if err != nil {
			return CustodyPolicySnapshot{}, err
		}
		// Reconstruct after independent authorization; callbacks cannot replace
		// resources or alter the exact state which the reviewed digest described.
		next, err = g.lease.proposed(change, g.last)
		if err != nil {
			return CustodyPolicySnapshot{}, err
		}
		current, err := g.lease.changePlan(change.Operation, next, g.peer)
		if err != nil || current.SHA256 != planSHA256 {
			return CustodyPolicySnapshot{}, errors.Join(ErrPolicyApproval, err)
		}
		if err = g.check(); err != nil {
			return CustodyPolicySnapshot{}, err
		}
		if err = g.lease.appendWithApproval(next, change.Operation, audit); err != nil {
			return CustodyPolicySnapshot{}, err
		}
		return clonePolicySnapshot(g.lease.tip.snapshot), nil
	})
}
