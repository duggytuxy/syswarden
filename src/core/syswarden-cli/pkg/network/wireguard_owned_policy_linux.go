//go:build linux

package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"syswarden-cli/pkg/wireguardstate"
)

const ownedWireGuardPolicyAssessmentSchema = "syswarden-owned-wireguard-policy-assessment-v1"

// OwnedWireGuardPolicyAssessment is read-only evidence, never an apply plan.
// Stable observations do not establish a service-start fence or a write lease.
type OwnedWireGuardPolicyAssessment struct {
	Schema           string                             `json:"schema"`
	ReadOnly         bool                               `json:"read_only"`
	State            string                             `json:"state"`
	Files            wireguardstate.OwnedPolicySnapshot `json:"files"`
	ServiceManager   string                             `json:"service_manager"`
	Service          LegacyWireGuardServiceEvidence     `json:"service"`
	InterfacePresent bool                               `json:"interface_present"`
	TablePresent     bool                               `json:"table_present"`
	TableHandle      uint64                             `json:"table_handle"`
	TableSHA256      string                             `json:"table_sha256"`
	SharedForward    wireGuardSharedForwardState        `json:"shared_forward"`
	Blockers         []string                           `json:"blockers"`
}

func (host legacyWireGuardRecoveryHost) observeOwnedPolicy() (OwnedWireGuardPolicyAssessment, error) {
	var result OwnedWireGuardPolicyAssessment
	if err := host.validate(); err != nil {
		return result, err
	}
	manager, err := host.managerState()
	if err != nil || manager != "ACTIVE" {
		return result, errors.Join(fmt.Errorf("owned WireGuard policy assessment requires an active service manager"), err)
	}
	if err := inspectLegacyWireGuardConflict(host.filesystemRoot, host.expectedUID, host.expectedGID); err != nil {
		return result, err
	}
	files, err := wireguardstate.InspectOwnedPolicy(host.filesystemRoot, host.expectedUID, host.expectedGID)
	if err != nil {
		return result, err
	}
	serviceManager := "systemd"
	var service LegacyWireGuardServiceEvidence
	var present bool
	blockers := []string{}
	if host.isAlpine() {
		// rc-service status executes an init script. Until a bounded provider
		// observer is available, do not invoke it or infer activity/enablement.
		serviceManager = "openrc"
		service = LegacyWireGuardServiceEvidence{Name: "wg-quick.wg-syswarden",
			LoadState: "unobserved", ActiveState: "unobserved", EnabledState: "unobserved"}
		present, err = host.inspectHistoricalInterface("wg-syswarden")
		blockers = append(blockers, "bounded OpenRC service observation is not available; no init status script was executed")
	} else {
		observedHost := host
		observedHost.isAlpine = func() bool { return false }
		_, service, present, err = observedHost.inspectHistoricalService("wg-syswarden")
	}
	if err != nil {
		return result, err
	}
	result = OwnedWireGuardPolicyAssessment{Schema: ownedWireGuardPolicyAssessmentSchema,
		ReadOnly: true, State: "scoped-v2", Files: files, ServiceManager: serviceManager,
		Service: service, InterfacePresent: present, Blockers: blockers}
	ctx, cancel := context.WithTimeout(context.Background(), wireGuardCommandTimeout)
	defer cancel()
	result.TablePresent, result.TableHandle, err = wireGuardReservedNFTTableIdentity(ctx, host.nftRunner)
	if err != nil {
		return result, err
	}
	if result.TablePresent {
		wire, err := host.nftRunner.Run(ctx, "-a", "-j", "list", "table", "inet", "syswarden_wg")
		if err != nil {
			return result, err
		}
		handle, err := validateExistingWireGuardNFTTable(wire, files.Source)
		if err != nil || handle != result.TableHandle {
			return result, errors.Join(fmt.Errorf("owned WireGuard runtime differs from its manifest policy"), err)
		}
		result.TableSHA256 = retirementDigest(wire)
	}
	result.SharedForward, err = inspectWireGuardSharedForward(ctx, host.nftRunner, files.Source.OwnershipToken, files.Source)
	if err != nil {
		return result, err
	}
	if !files.Source.SharedForward && len(result.SharedForward.Rules) != 0 {
		return result, fmt.Errorf("owned shared forwarding exists without a matching configuration hook")
	}
	if files.Source.PolicyVersion == 0 {
		result.State = "v1-transition-required"
		result.Blockers = append(result.Blockers, "production policy migration requires a durable service-start fence and runtime acceptance beyond the internal file transaction")
		if serviceManager == "systemd" {
			result.Blockers = append(result.Blockers, retirementServiceBlockers("owned wg-syswarden", service, present)...)
		} else if present {
			result.Blockers = append(result.Blockers, "owned wg-syswarden interface must be absent")
		}
		if result.TablePresent || len(result.SharedForward.Rules) != 0 {
			result.Blockers = append(result.Blockers, "owned v1 runtime requires separately reviewed retirement before publication")
		}
		if files.PredecessorReceipt != nil {
			result.Blockers = append(result.Blockers, "sealed predecessor must remain immutable and be bound to its exact successor during coordinated migration")
		}
	}
	return result, nil
}

func (host legacyWireGuardRecoveryHost) inspectOwnedPolicy() (OwnedWireGuardPolicyAssessment, error) {
	first, err := host.observeOwnedPolicy()
	if err != nil {
		return OwnedWireGuardPolicyAssessment{}, err
	}
	second, err := host.observeOwnedPolicy()
	if err != nil || !reflect.DeepEqual(first, second) {
		return OwnedWireGuardPolicyAssessment{}, errors.Join(fmt.Errorf("owned WireGuard policy changed during read-only assessment"), err)
	}
	return second, nil
}

func InspectOwnedWireGuardPolicy() (OwnedWireGuardPolicyAssessment, error) {
	return productionLegacyWireGuardRecoveryHost().inspectOwnedPolicy()
}

func RenderOwnedWireGuardPolicyAssessment(assessment OwnedWireGuardPolicyAssessment) ([]byte, error) {
	if assessment.Schema != ownedWireGuardPolicyAssessmentSchema || !assessment.ReadOnly ||
		(assessment.State != "scoped-v2" && assessment.State != "v1-transition-required") || assessment.Blockers == nil {
		return nil, fmt.Errorf("invalid read-only owned WireGuard policy assessment")
	}
	return json.MarshalIndent(assessment, "", "  ")
}
