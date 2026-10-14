package journal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
)

const (
	AuthorityRequestSchema    = "syswarden.local-authority-request.v1"
	AuthorityResponseSchema   = "syswarden.local-authority-response.v1"
	MaxAuthorityRequestBytes  = MaxCustodyPolicyBytes + 2048
	MaxAuthorityResponseBytes = 65536
)

var ErrAuthorityRequest = errors.New("invalid bounded local authority request")

// The request vocabulary deliberately cannot express a path, key, current trust
// pin, UID, clock, storage budget or authorizer. These belong to trusted startup.
type authorityRequest struct {
	Schema     string           `json:"schema"`
	ID         string           `json:"id"`
	Operation  string           `json:"operation"`
	Segment    string           `json:"segment,omitempty"`
	PlanSHA256 string           `json:"plan_sha256,omitempty"`
	Change     *authorityChange `json:"change,omitempty"`
}
type authorityChange struct {
	Operation string          `json:"operation"`
	Enabled   *bool           `json:"enabled,omitempty"`
	Policy    json.RawMessage `json:"policy,omitempty"`
	Signature string          `json:"signature,omitempty"`
}
type authorityPolicyResult struct {
	Enabled  bool   `json:"enabled"`
	Revision string `json:"revision"`
	SHA256   string `json:"sha256"`
}
type authorityResponse struct {
	Schema     string                 `json:"schema"`
	ID         string                 `json:"id"`
	Operation  string                 `json:"operation"`
	Anchor     json.RawMessage        `json:"anchor,omitempty"`
	Plan       json.RawMessage        `json:"plan,omitempty"`
	PlanSHA256 string                 `json:"plan_sha256,omitempty"`
	Policy     *authorityPolicyResult `json:"policy,omitempty"`
}

func validAuthorityChange(c *authorityChange) bool {
	if c == nil {
		return false
	}
	if c.Operation == "disable" {
		return c.Enabled == nil && len(c.Policy) == 0 && c.Signature == ""
	}
	if c.Operation != "install" || c.Enabled == nil || len(c.Policy) == 0 || len(c.Policy) > MaxCustodyPolicyBytes || len(c.Signature) != ed25519.SignatureSize*2 {
		return false
	}
	sig, err := hex.DecodeString(c.Signature)
	if err != nil || hex.EncodeToString(sig) != c.Signature {
		return false
	}
	_, err = DecodeCustodyAccessPolicy(c.Policy)
	return err == nil
}

func decodeAuthorityRequest(data []byte) (authorityRequest, error) {
	if len(data) == 0 || len(data) > MaxAuthorityRequestBytes {
		return authorityRequest{}, ErrAuthorityRequest
	}
	data = bytes.Clone(data)
	var r authorityRequest
	if json.Unmarshal(data, &r) != nil || r.Schema != AuthorityRequestSchema || !custodyPolicyID(r.ID) {
		return authorityRequest{}, ErrAuthorityRequest
	}
	valid := false
	switch r.Operation {
	case "resume", "inspect-recovery":
		valid = r.Segment == "" && r.PlanSHA256 == "" && r.Change == nil
	case "commit":
		valid = validName(r.Segment) && r.PlanSHA256 == "" && r.Change == nil
	case "apply-recovery":
		valid = r.Segment == "" && validRecoveryApproval(r.PlanSHA256) && r.Change == nil
	case "inspect-policy":
		valid = r.Segment == "" && r.PlanSHA256 == "" && validAuthorityChange(r.Change)
	case "apply-policy":
		valid = r.Segment == "" && validRecoveryApproval(r.PlanSHA256) && validAuthorityChange(r.Change)
	}
	canonical, err := json.Marshal(r)
	if !valid || err != nil || !bytes.Equal(canonical, data) {
		return authorityRequest{}, ErrAuthorityRequest
	}
	return r, nil
}

func authorityChangeProposal(c *authorityChange, root CustodyPolicyTrust) (CustodyPolicyChange, error) {
	if !validAuthorityChange(c) {
		return CustodyPolicyChange{}, ErrAuthorityRequest
	}
	if c.Operation == "disable" {
		return CustodyPolicyChange{Operation: "disable"}, nil
	}
	p, err := DecodeCustodyAccessPolicy(c.Policy)
	if err != nil {
		return CustodyPolicyChange{}, err
	}
	sig, err := hex.DecodeString(c.Signature)
	if err != nil {
		return CustodyPolicyChange{}, err
	}
	trust := clonePolicyTrust(root)
	trust.Enabled = *c.Enabled
	trust.Revision = p.Revision
	trust.PolicySHA256 = recoveryDigest(c.Policy)
	// Candidate revision and digest describe the proposal; issuer/root/scope
	// remain pinned to startup. The reviewed coordinator checks current history.
	return CustodyPolicyChange{Operation: "install", Next: CustodyPolicySnapshot{Trust: trust, Document: bytes.Clone(c.Policy), Signature: sig}}, nil
}

func authorityPolicySummary(s CustodyPolicySnapshot) *authorityPolicyResult {
	return &authorityPolicyResult{Enabled: s.Trust.Enabled, Revision: strconv.FormatUint(s.Trust.Revision, 10), SHA256: s.Trust.PolicySHA256}
}
