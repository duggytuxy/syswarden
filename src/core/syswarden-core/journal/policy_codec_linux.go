package journal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"time"
)

const (
	MaxPolicyRecords   = 256
	maxPolicyRecord    = MaxCustodyPolicyBytes + 512
	maxPolicyFile      = MaxPolicyRecords * (4 + maxPolicyRecord + sha256.Size)
	policyFileName     = "custody-policy-v1.swp"
	policyRecordSchema = "syswarden.custody-policy-record.v1"
	policyRecordDomain = "syswarden/custody-policy-record/v1\x00"
)

var ErrPolicyState = errors.New("protected custody policy is invalid or changed")

// CustodyPolicySnapshot owns the protected current pin and exact signed bytes.
// It is administrative state, not an admission, update approval or bearer token.
type CustodyPolicySnapshot struct {
	Trust               CustodyPolicyTrust
	Document, Signature []byte
}

type policyRecord struct {
	Schema    string          `json:"schema"`
	Sequence  string          `json:"sequence"`
	Operation string          `json:"operation"`
	Enabled   bool            `json:"enabled"`
	Policy    json.RawMessage `json:"policy"`
	Signature string          `json:"signature"`
}
type policyTip struct {
	snapshot     CustodyPolicySnapshot
	hash         [sha256.Size]byte
	count, bytes int
}

func clonePolicyTrust(t CustodyPolicyTrust) CustodyPolicyTrust {
	t.IssuerPublicKey = bytes.Clone(t.IssuerPublicKey)
	return t
}
func clonePolicySnapshot(s CustodyPolicySnapshot) CustodyPolicySnapshot {
	return CustodyPolicySnapshot{Trust: clonePolicyTrust(s.Trust), Document: bytes.Clone(s.Document), Signature: bytes.Clone(s.Signature)}
}
func samePolicyTrust(a, b CustodyPolicyTrust) bool {
	return a.Enabled == b.Enabled && a.PolicyID == b.PolicyID && a.Revision == b.Revision && a.PolicySHA256 == b.PolicySHA256 &&
		a.IssuerKeyID == b.IssuerKeyID && bytes.Equal(a.IssuerPublicKey, b.IssuerPublicKey) && a.Initial == b.Initial
}
func samePolicySnapshot(a, b CustodyPolicySnapshot) bool {
	return samePolicyTrust(a.Trust, b.Trust) && bytes.Equal(a.Document, b.Document) && bytes.Equal(a.Signature, b.Signature)
}
func samePolicyTip(a, b policyTip) bool {
	return a.hash == b.hash && a.count == b.count && a.bytes == b.bytes && samePolicySnapshot(a.snapshot, b.snapshot)
}
func validPolicyRoot(t CustodyPolicyTrust) bool {
	_, err := encodeAnchor(t.Initial)
	return err == nil && custodyPolicyID(t.PolicyID) && custodyPolicyID(t.IssuerKeyID) && len(t.IssuerPublicKey) == ed25519.PublicKeySize &&
		t.Revision > 0 && t.Revision < math.MaxUint64 && validRecoveryApproval(t.PolicySHA256)
}

// Historical records retain their signatures even after expiry/disable. Only
// admission enforces current validity; history must remain readable to revoke it.
func authenticatePolicySnapshot(s CustodyPolicySnapshot) (CustodyAccessPolicy, error) {
	p, err := DecodeCustodyAccessPolicy(s.Document)
	if err != nil {
		return CustodyAccessPolicy{}, err
	}
	t := s.Trust
	t.Enabled = true
	return VerifyCustodyAccessPolicy(s.Document, s.Signature, t, time.Unix(p.NotBefore, 0))
}
func policyTransition(before, after CustodyPolicySnapshot, operation string) bool {
	if operation == "disable" {
		expected := before
		expected.Trust.Enabled = false
		return before.Trust.Enabled && samePolicySnapshot(expected, after)
	}
	if operation != "install" || before.Trust.Revision >= math.MaxUint64-1 || after.Trust.Revision != before.Trust.Revision+1 {
		return false
	}
	a, b := before.Trust, after.Trust
	if a.PolicyID != b.PolicyID || a.Initial != b.Initial || a.IssuerKeyID != b.IssuerKeyID || !bytes.Equal(a.IssuerPublicKey, b.IssuerPublicKey) {
		return false
	}
	p1, e1 := DecodeCustodyAccessPolicy(before.Document)
	p2, e2 := DecodeCustodyAccessPolicy(after.Document)
	if e1 != nil || e2 != nil {
		return false
	}
	s1, e1 := custodyEnrollment(p1.Enrollment)
	s2, e2 := custodyEnrollment(p2.Enrollment)
	return e1 == nil && e2 == nil && sameRestartState(s1, s2)
}
func encodePolicyRecord(s CustodyPolicySnapshot, n int, op string) ([]byte, error) {
	if n < 1 || n > MaxPolicyRecords || (n == MaxPolicyRecords && s.Trust.Enabled) || (op != "bootstrap" && op != "install" && op != "disable") {
		return nil, ErrPolicyState
	}
	if _, err := authenticatePolicySnapshot(s); err != nil {
		return nil, err
	}
	data, err := json.Marshal(policyRecord{Schema: policyRecordSchema, Sequence: strconv.Itoa(n), Operation: op, Enabled: s.Trust.Enabled, Policy: s.Document, Signature: hex.EncodeToString(s.Signature)})
	if err != nil || len(data) > maxPolicyRecord {
		return nil, ErrPolicyState
	}
	return data, nil
}
func policyHash(previous [sha256.Size]byte, doc []byte) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(policyRecordDomain))
	_, _ = h.Write(previous[:])
	_, _ = h.Write(doc)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}
func policyFrame(s CustodyPolicySnapshot, n int, op string, previous [sha256.Size]byte) ([]byte, error) {
	doc, err := encodePolicyRecord(s, n, op)
	if err != nil {
		return nil, err
	}
	size := len(doc)
	if size > maxPolicyRecord {
		return nil, ErrPolicyState
	}
	frame := make([]byte, 4+size+sha256.Size)
	binary.BigEndian.PutUint32(frame[:4], uint32(size))
	copy(frame[4:], doc)
	sum := policyHash(previous, doc)
	copy(frame[4+size:], sum[:])
	return frame, nil
}
func decodePolicyRecord(doc []byte, root CustodyPolicyTrust) (CustodyPolicySnapshot, policyRecord, error) {
	var w policyRecord
	if len(doc) == 0 || len(doc) > maxPolicyRecord || json.Unmarshal(doc, &w) != nil || w.Schema != policyRecordSchema {
		return CustodyPolicySnapshot{}, w, ErrPolicyState
	}
	n, err := custodyUint(w.Sequence, MaxPolicyRecords)
	if err != nil || n > MaxPolicyRecords || len(w.Signature) != ed25519.SignatureSize*2 {
		return CustodyPolicySnapshot{}, w, ErrPolicyState
	}
	sig, err := hex.DecodeString(w.Signature)
	if err != nil || hex.EncodeToString(sig) != w.Signature {
		return CustodyPolicySnapshot{}, w, ErrPolicyState
	}
	p, err := DecodeCustodyAccessPolicy(w.Policy)
	if err != nil {
		return CustodyPolicySnapshot{}, w, ErrPolicyState
	}
	trust := clonePolicyTrust(root)
	trust.Enabled = w.Enabled
	trust.Revision = p.Revision
	trust.PolicySHA256 = recoveryDigest(w.Policy)
	s := CustodyPolicySnapshot{Trust: trust, Document: w.Policy, Signature: sig}
	canonical, err := encodePolicyRecord(s, int(n), w.Operation)
	if err != nil || !bytes.Equal(canonical, doc) {
		return CustodyPolicySnapshot{}, w, ErrPolicyState
	}
	return s, w, nil
}
func scanPolicies(data []byte, root CustodyPolicyTrust) (policyTip, error) {
	if len(data) == 0 || len(data) > maxPolicyFile || !validPolicyRoot(root) {
		return policyTip{}, ErrPolicyState
	}
	var tip policyTip
	for offset := 0; offset < len(data); {
		if tip.count >= MaxPolicyRecords || len(data)-offset < 4 {
			return policyTip{}, ErrPolicyState
		}
		size := binary.BigEndian.Uint32(data[offset : offset+4])
		if size == 0 || size > maxPolicyRecord || len(data)-offset-4 < int(size)+sha256.Size {
			return policyTip{}, ErrPolicyState
		}
		end := offset + 4 + int(size)
		doc := data[offset+4 : end]
		s, w, err := decodePolicyRecord(doc, root)
		if err != nil || w.Sequence != strconv.Itoa(tip.count+1) {
			return policyTip{}, ErrPolicyState
		}
		if tip.count == 0 {
			if w.Operation != "bootstrap" || !samePolicyTrust(s.Trust, root) {
				return policyTip{}, ErrPolicyState
			}
		} else if !policyTransition(tip.snapshot, s, w.Operation) {
			return policyTip{}, ErrPolicyState
		}
		sum := policyHash(tip.hash, doc)
		if !bytes.Equal(sum[:], data[end:end+sha256.Size]) {
			return policyTip{}, ErrPolicyState
		}
		tip.snapshot, tip.hash = s, sum
		tip.count++
		offset = end + sha256.Size
	}
	tip.bytes = len(data)
	return tip, nil
}
