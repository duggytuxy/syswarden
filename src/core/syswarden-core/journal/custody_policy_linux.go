package journal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"time"

	contracts "syswarden-core/contracts/v5"
)

const (
	CustodyPolicySchema    = "syswarden.custody-access-policy.v1"
	MaxCustodyPolicyBytes  = 16384
	MaxCustodyPolicyGrants = 32
	custodyPolicyDomain    = "syswarden/custody-access-policy/v1\x00"
	maxPolicyTime          = 253402300799 // Last Unix second representable in year 9999.
)

var (
	ErrCustodyPolicy    = errors.New("invalid custody access policy")
	ErrCustodyAdmission = errors.New("local custody request is not authorized by current policy")
)

// CustodyOperation grants admission to one high-level coordinator operation.
// None permits direct Prepare/Finish, bootstrap, key changes or journal repair.
type CustodyOperation string

const (
	CustodyResume          CustodyOperation = "resume"
	CustodyCommit          CustodyOperation = "commit"
	CustodyInspectRecovery CustodyOperation = "inspect-recovery"
	CustodyApplyRecovery   CustodyOperation = "apply-recovery"
)

// CustodyLocalGrant is an exact host UID allowlist entry. GIDs, PID values,
// usernames and root status never imply a grant. Operations must be sorted.
type CustodyLocalGrant struct {
	UID        uint32
	Operations []CustodyOperation
}

// CustodyAccessPolicy is an offline issuer statement, not current authority by
// itself. Enrollment and all host UID grants belong to one exact journal epoch.
// Grants must be sorted by numeric UID. Empty grants explicitly admit nobody.
type CustodyAccessPolicy struct {
	PolicyID            string
	Revision            uint64
	IssuerKeyID         string
	NotBefore, NotAfter int64
	Enrollment          CustodyEnrollment
	Grants              []CustodyLocalGrant
}

// CustodyPolicyTrust must be independently provisioned and protected from all
// requesters. Enabled, the exact current digest/revision and issuer key are
// current policy, not values accepted from a signed document or a peer. Initial
// pins this host's exact enrolled scope/root. Updating this context must serialize
// with all custody leases. This value does not implement a durable policy registry.
type CustodyPolicyTrust struct {
	Enabled         bool
	PolicyID        string
	Revision        uint64
	PolicySHA256    string
	IssuerKeyID     string
	IssuerPublicKey ed25519.PublicKey
	Initial         contracts.JournalCheckpointAnchor
}

type custodyGrantWire struct {
	UID        string             `json:"uid"`
	Operations []CustodyOperation `json:"operations"`
}
type custodyPolicyWire struct {
	Schema      string             `json:"schema"`
	PolicyID    string             `json:"policy_id"`
	Revision    string             `json:"revision"`
	IssuerKeyID string             `json:"issuer_key_id"`
	NotBefore   string             `json:"not_before"`
	NotAfter    string             `json:"not_after"`
	Initial     json.RawMessage    `json:"initial"`
	Authority   custodyKeyWire     `json:"authority"`
	Grants      []custodyGrantWire `json:"grants"`
}

func custodyPolicyID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '.' && c != '-' && c != '_' {
			return false
		}
	}
	return true
}
func custodyOperation(op CustodyOperation) bool {
	return op == CustodyResume || op == CustodyCommit || op == CustodyInspectRecovery || op == CustodyApplyRecovery
}

// EncodeCustodyAccessPolicy pins compact struct-order JSON, with exact decimal
// integers encoded as strings. It neither signs nor authorizes enrollment.
func EncodeCustodyAccessPolicy(p CustodyAccessPolicy) ([]byte, error) {
	s, err := custodyEnrollment(p.Enrollment)
	if err != nil || !custodyPolicyID(p.PolicyID) || !custodyPolicyID(p.IssuerKeyID) ||
		!custodyPolicyID(p.Enrollment.Authority.KeyID) || p.Revision == 0 || p.Revision == math.MaxUint64 ||
		p.NotBefore <= 0 || p.NotAfter <= p.NotBefore || p.NotAfter > maxPolicyTime || len(p.Grants) > MaxCustodyPolicyGrants {
		return nil, ErrCustodyPolicy
	}
	state, err := custodyWire(s)
	if err != nil {
		return nil, ErrCustodyPolicy
	}
	w := custodyPolicyWire{Schema: CustodyPolicySchema, PolicyID: p.PolicyID, Revision: strconv.FormatUint(p.Revision, 10), IssuerKeyID: p.IssuerKeyID,
		NotBefore: strconv.FormatInt(p.NotBefore, 10), NotAfter: strconv.FormatInt(p.NotAfter, 10), Initial: state.Initial, Authority: state.Authority,
		Grants: make([]custodyGrantWire, 0, len(p.Grants))}
	for i, g := range p.Grants {
		if g.UID == math.MaxUint32 || (i > 0 && p.Grants[i-1].UID >= g.UID) || len(g.Operations) == 0 || len(g.Operations) > 4 {
			return nil, ErrCustodyPolicy
		}
		for j, op := range g.Operations {
			if !custodyOperation(op) || (j > 0 && g.Operations[j-1] >= op) {
				return nil, ErrCustodyPolicy
			}
		}
		w.Grants = append(w.Grants, custodyGrantWire{UID: strconv.FormatUint(uint64(g.UID), 10), Operations: g.Operations})
	}
	data, err := json.Marshal(w)
	if err != nil || len(data) > MaxCustodyPolicyBytes {
		return nil, ErrCustodyPolicy
	}
	return data, nil
}

// DecodeCustodyAccessPolicy validates canonical bounded shape only. Unknown,
// duplicate, omitted, null and alternate numeric spellings cannot normalize into
// an accepted policy. Authentication and current-policy checks are separate.
func DecodeCustodyAccessPolicy(data []byte) (CustodyAccessPolicy, error) {
	var w custodyPolicyWire
	if len(data) == 0 || len(data) > MaxCustodyPolicyBytes || json.Unmarshal(data, &w) != nil || w.Schema != CustodyPolicySchema || len(w.Grants) > MaxCustodyPolicyGrants {
		return CustodyAccessPolicy{}, ErrCustodyPolicy
	}
	s, err := custodyStateFromWire(custodyStateWire{Initial: w.Initial, Head: w.Initial, Authority: w.Authority})
	if err != nil {
		return CustodyAccessPolicy{}, ErrCustodyPolicy
	}
	revision, e1 := custodyUint(w.Revision, math.MaxUint64-1)
	before, e2 := custodyUint(w.NotBefore, maxPolicyTime)
	after, e3 := custodyUint(w.NotAfter, maxPolicyTime)
	if errors.Join(e1, e2, e3) != nil || before > maxPolicyTime || after > maxPolicyTime {
		return CustodyAccessPolicy{}, ErrCustodyPolicy
	}
	p := CustodyAccessPolicy{PolicyID: w.PolicyID, Revision: revision, IssuerKeyID: w.IssuerKeyID, NotBefore: int64(before), NotAfter: int64(after),
		Enrollment: CustodyEnrollment{Initial: s.Initial, Authority: s.Authority}, Grants: make([]CustodyLocalGrant, 0, len(w.Grants))}
	for _, g := range w.Grants {
		uid, err := strconv.ParseUint(g.UID, 10, 32)
		if err != nil || uid >= math.MaxUint32 || strconv.FormatUint(uid, 10) != g.UID {
			return CustodyAccessPolicy{}, ErrCustodyPolicy
		}
		p.Grants = append(p.Grants, CustodyLocalGrant{UID: uint32(uid), Operations: g.Operations})
	}
	canonical, err := EncodeCustodyAccessPolicy(p)
	if err != nil || !bytes.Equal(canonical, data) {
		return CustodyAccessPolicy{}, ErrCustodyPolicy
	}
	return p, nil
}

// CustodyAccessPolicySigningMessage returns owned domain-separated signing bytes.
// The issuer key must be independently managed and distinct from checkpoint keys.
// This helper does not hold private keys or implement signing/provisioning.
func CustodyAccessPolicySigningMessage(p CustodyAccessPolicy) ([]byte, error) {
	data, err := EncodeCustodyAccessPolicy(p)
	if err != nil {
		return nil, err
	}
	return append([]byte(custodyPolicyDomain), data...), nil
}

// VerifyCustodyAccessPolicy verifies a statement against independently current
// trust and trusted wall time. Validity is [NotBefore, NotAfter), with no grace.
// Zero time is rejected. Clock rollback and stale trust cannot be detected here;
// callers must establish their provenance/freshness and serialize policy updates.
// The returned owned statement is not a reusable authorization capability.
func VerifyCustodyAccessPolicy(data, signature []byte, trust CustodyPolicyTrust, now time.Time) (CustodyAccessPolicy, error) {
	p, err := DecodeCustodyAccessPolicy(data)
	if err != nil {
		return CustodyAccessPolicy{}, err
	}
	if !trust.Enabled || now.IsZero() || !custodyPolicyID(trust.IssuerKeyID) || len(trust.IssuerPublicKey) != ed25519.PublicKeySize ||
		!validRecoveryApproval(trust.PolicySHA256) || recoveryDigest(data) != trust.PolicySHA256 || p.PolicyID != trust.PolicyID ||
		p.Revision != trust.Revision || p.IssuerKeyID != trust.IssuerKeyID || p.Enrollment.Initial != trust.Initial ||
		now.Before(time.Unix(p.NotBefore, 0)) || !now.Before(time.Unix(p.NotAfter, 0)) ||
		bytes.Equal(trust.IssuerPublicKey, p.Enrollment.Authority.PublicKey) || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(trust.IssuerPublicKey, append([]byte(custodyPolicyDomain), data...), signature) {
		return CustodyAccessPolicy{}, ErrCustodyAdmission
	}
	return p, nil
}
