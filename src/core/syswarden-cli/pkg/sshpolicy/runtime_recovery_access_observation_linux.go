//go:build linux

package sshpolicy

import "encoding/json"

const (
	sshObservedRestoredAccessRequestDomain  = "syswarden-ssh-restoration-access-request-v2"
	sshObservedRestoredAccessIssuanceDomain = "syswarden-ssh-restoration-access-issuance-v2"
	sshObservedRestoredAccessEvidenceDomain = "syswarden-ssh-restoration-access-evidence-v2"
)

// The new purpose version binds a recorded post-request observation and its
// current runtime generation. Legacy request bytes remain canonical v1 and are
// never promoted into evidence that an earlier request actually returned.
type sshObservedRestoredAccessRequest struct {
	sshRestoredAccessRequest
	ReloadObservation      string `json:"reload_observation_sha256"`
	ReloadObservationImage string `json:"reload_observation_image_sha256"`
	RuntimeGeneration      string `json:"runtime_generation_sha256"`
}

func canonicalSSHRestoredAccessRequest(wire []byte, request sshRestoredAccessRequest) ([]byte, error) {
	switch {
	case request.Schema == 1 && request.Domain == sshRestoredAccessRequestDomain:
		return json.Marshal(request)
	case request.Schema == 2 && request.Domain == sshObservedRestoredAccessRequestDomain:
		var observed sshObservedRestoredAccessRequest
		if err := json.Unmarshal(wire, &observed); err != nil {
			return nil, ErrInventoryUnsafe
		}
		for _, value := range []string{observed.ReloadObservation, observed.ReloadObservationImage, observed.RuntimeGeneration} {
			if !lowerDigest.MatchString(value) {
				return nil, ErrInventoryUnsafe
			}
		}
		return json.Marshal(observed)
	default:
		return nil, ErrInventoryUnsafe
	}
}

func marshalSSHRestoredAccessRequest(request sshRestoredAccessRequest, summary RecoveryAssessment) ([]byte, error) {
	if !summary.ReloadObservationObserved {
		if summary.Schema != 1 || summary.ReloadObservationSHA256 != "" || summary.ReloadObservationImageSHA256 != "" || summary.RuntimeGenerationSHA256 != "" {
			return nil, ErrInventoryUnsafe
		}
		return json.Marshal(request)
	}
	if summary.Schema != 2 {
		return nil, ErrInventoryUnsafe
	}
	for _, value := range []string{summary.ReloadObservationSHA256, summary.ReloadObservationImageSHA256, summary.RuntimeGenerationSHA256} {
		if !lowerDigest.MatchString(value) {
			return nil, ErrInventoryUnsafe
		}
	}
	request.Schema, request.Domain = 2, sshObservedRestoredAccessRequestDomain
	return json.Marshal(sshObservedRestoredAccessRequest{request, summary.ReloadObservationSHA256,
		summary.ReloadObservationImageSHA256, summary.RuntimeGenerationSHA256})
}

func validSSHRestoredAccessRecordVersion(schema int, domain string, evidence bool) bool {
	legacy, observed := sshRestoredAccessIssuanceDomain, sshObservedRestoredAccessIssuanceDomain
	if evidence {
		legacy, observed = sshRestoredAccessEvidenceDomain, sshObservedRestoredAccessEvidenceDomain
	}
	return (schema == 1 && domain == legacy) || (schema == 2 && domain == observed)
}
