package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
)

var ErrAuthorityResponse = errors.New("invalid bounded local authority response")

func encodeClientRequest(r authorityRequest) ([]byte, error) { return json.Marshal(r) }

// A reply is a bounded result from the pinned local service, not independent
// approval or remote cryptographic evidence. Inspection plans stay opaque: shape,
// vocabulary and domain digest are checked, not every plan's authorization facts.
func validateAuthorityReply(data []byte, request authorityRequest) error {
	if len(data) == 0 || len(data) > MaxAuthorityResponseBytes {
		return ErrAuthorityResponse
	}
	var r authorityResponse
	if json.Unmarshal(data, &r) != nil || r.Schema != AuthorityResponseSchema || r.ID != request.ID || r.Operation != request.Operation {
		return ErrAuthorityResponse
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(data, canonical) {
		return ErrAuthorityResponse
	}
	switch request.Operation {
	case "resume", "commit", "apply-recovery":
		if len(r.Anchor) == 0 || len(r.Plan) != 0 || r.PlanSHA256 != "" || r.Policy != nil {
			return ErrAuthorityResponse
		}
		if _, err = decodeAnchor(r.Anchor); err != nil {
			return ErrAuthorityResponse
		}
	case "inspect-recovery", "inspect-policy":
		if len(r.Anchor) != 0 || r.Policy != nil || !validRecoveryApproval(r.PlanSHA256) || len(r.Plan) == 0 {
			return ErrAuthorityResponse
		}
		domain := anchorRecoveryDomain
		if request.Operation == "inspect-recovery" {
			var plan recoveryDocument
			if len(r.Plan) > maxRecoveryPlanBytes || json.Unmarshal(r.Plan, &plan) != nil || plan.Schema != anchorRecoverySchema || plan.Operation != "resynchronize-complete-anchor" {
				return ErrAuthorityResponse
			}
			canonical, err = json.Marshal(plan)
		} else {
			domain = policyChangeDomain
			var plan policyChangeDocument
			if request.Change == nil || len(r.Plan) > maxPolicyChangeBytes || json.Unmarshal(r.Plan, &plan) != nil || plan.Schema != policyChangeSchema || plan.Operation != request.Change.Operation {
				return ErrAuthorityResponse
			}
			canonical, err = json.Marshal(plan)
		}
		if err != nil || !bytes.Equal(canonical, r.Plan) || recoveryDigest(append([]byte(domain), r.Plan...)) != r.PlanSHA256 {
			return ErrAuthorityResponse
		}
	case "apply-policy":
		if len(r.Anchor) != 0 || len(r.Plan) != 0 || r.PlanSHA256 != "" || r.Policy == nil || request.Change == nil || !validRecoveryApproval(r.Policy.SHA256) {
			return ErrAuthorityResponse
		}
		revision, parseErr := strconv.ParseUint(r.Policy.Revision, 10, 64)
		if parseErr != nil || revision == 0 || strconv.FormatUint(revision, 10) != r.Policy.Revision {
			return ErrAuthorityResponse
		}
		if request.Change.Operation == "disable" {
			if r.Policy.Enabled {
				return ErrAuthorityResponse
			}
		} else {
			policy, decodeErr := DecodeCustodyAccessPolicy(request.Change.Policy)
			if decodeErr != nil || request.Change.Enabled == nil || r.Policy.Enabled != *request.Change.Enabled || revision != policy.Revision || r.Policy.SHA256 != recoveryDigest(request.Change.Policy) {
				return ErrAuthorityResponse
			}
		}
	default:
		return ErrAuthorityResponse
	}
	return nil
}
