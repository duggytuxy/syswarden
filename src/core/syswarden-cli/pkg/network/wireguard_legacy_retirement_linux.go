//go:build linux

package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
)

const (
	legacyWireGuardRetirementSchema  = "syswarden-legacy-wireguard-retirement-v1"
	legacyWireGuardConfigurationPath = "/etc/wireguard/wg0.conf"
	legacyWireGuardArchiveDirectory  = "/etc/wireguard/.syswarden-retired"
	legacyWireGuardArchivePath       = legacyWireGuardArchiveDirectory + "/wg0.conf"
)

// LegacyWireGuardRetirementPlan binds both generations without selecting one
// implicitly. Configuration bytes, including keys, are never part of the plan.
type LegacyWireGuardRetirementPlan struct {
	Schema                     string                                          `json:"schema"`
	State                      string                                          `json:"state"`
	Configuration              LegacyWireGuardFileEvidence                     `json:"historical_configuration"`
	LegacyGenerated            []LegacyWireGuardFileEvidence                   `json:"historical_generated_artifacts,omitempty"`
	Ownership                  LegacyWireGuardOwnershipEvidence                `json:"current_ownership"`
	ServiceManager             string                                          `json:"service_manager"`
	HistoricalService          LegacyWireGuardServiceEvidence                  `json:"historical_service"`
	CurrentService             LegacyWireGuardServiceEvidence                  `json:"current_service"`
	HistoricalInterfacePresent bool                                            `json:"historical_interface_present"`
	CurrentInterfacePresent    bool                                            `json:"current_interface_present"`
	TableAction                string                                          `json:"table_action"`
	TableHandle                uint64                                          `json:"table_handle"`
	TableSHA256                string                                          `json:"table_sha256"`
	ForwardChainHandle         uint64                                          `json:"shared_forward_chain_handle"`
	ForwardRules               map[string][]LegacyWireGuardForwardRuleEvidence `json:"shared_forward_rules"`
	ArchivePath                string                                          `json:"private_archive_path"`
	ArchiveDirectory           *legacyWireGuardDirectoryEvidence               `json:"archive_directory"`
	SafeToApply                bool                                            `json:"safe_to_apply"`
	Blockers                   []string                                        `json:"blockers"`
}

func retirementDigest(wire []byte) string {
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}

func historicalWG0Egress(configuration []byte) (string, error) {
	return historicalWireGuardEgress(configuration, "wg0")
}

func retirementServiceBlockers(label string, service LegacyWireGuardServiceEvidence, present bool) []string {
	blockers := []string{}
	if service.LoadState != "not-found" {
		if service.ActiveState != "inactive" {
			blockers = append(blockers, label+" service must be inactive")
		}
		if service.EnabledState != "disabled" {
			blockers = append(blockers, label+" service must be disabled")
		}
	}
	if present {
		blockers = append(blockers, label+" interface must be absent")
	}
	return blockers
}

// InspectLegacyWireGuardRetirement inspects the explicit wg0 retirement path.
// It works even when historical PostDown already removed the reserved NAT table.
func InspectLegacyWireGuardRetirement() (LegacyWireGuardRetirementPlan, error) {
	return productionLegacyWireGuardRecoveryHost().inspectRetirement()
}

func (host legacyWireGuardRecoveryHost) inspectRetirement() (LegacyWireGuardRetirementPlan, error) {
	var plan LegacyWireGuardRetirementPlan
	if err := host.validate(); err != nil {
		return plan, err
	}
	manager, err := host.managerState()
	if err != nil || manager != "ACTIVE" {
		return plan, errors.Join(fmt.Errorf("WireGuard retirement requires an active service manager"), err)
	}
	inventory, err := wireguardstate.Inspect(host.filesystemRoot)
	if err != nil {
		return plan, err
	}
	if inventory.Transaction {
		return plan, fmt.Errorf("resume the pending verified WireGuard ownership transaction before historical retirement")
	}
	var historicalGenerated *legacyWireGuardGeneratedState
	if !inventory.Empty() && !inventory.Manifest {
		generated, err := inspectLegacyWireGuardGeneratedState(host.filesystemRoot, host.expectedUID, host.expectedGID)
		if err != nil {
			return plan, fmt.Errorf("current WireGuard artifacts lack an ownership manifest and cannot be proved as exact historical generated state; preserve them for separate verified recovery: %w", err)
		}
		historicalGenerated = &generated
	}
	ownership, err := inspectLegacyWireGuardOwnership(host.filesystemRoot, host.expectedUID, host.expectedGID)
	if err != nil {
		return plan, err
	}
	archiveDirectory, err := host.inspectRetirementDirectory()
	if err != nil {
		return plan, err
	}
	original, originalErr := captureLegacyWireGuardConfiguration(host.filesystemRoot, legacyWireGuardConfigurationPath, host.expectedUID, host.expectedGID)
	archive, archiveErr := captureLegacyWireGuardConfiguration(host.filesystemRoot, legacyWireGuardArchivePath, host.expectedUID, host.expectedGID)
	if originalErr != nil && !errors.Is(originalErr, os.ErrNotExist) {
		return plan, originalErr
	}
	if archiveErr != nil && !errors.Is(archiveErr, os.ErrNotExist) {
		return plan, archiveErr
	}
	if originalErr == nil && archiveErr == nil {
		return plan, fmt.Errorf("historical wg0 and its private archive both exist; no archive will be overwritten")
	}
	state := "pending"
	configuration := original
	if originalErr != nil {
		if archiveErr != nil {
			return plan, fmt.Errorf("no historical wg0 configuration or verified private archive is present")
		}
		state, configuration = "retired", archive
	}
	egress, err := historicalWG0Egress(configuration.content)
	if err != nil {
		return plan, fmt.Errorf("refuse unproven historical wg0 retirement: %w", err)
	}
	if historicalGenerated != nil && historicalGenerated.input.ActiveIf != egress {
		return plan, fmt.Errorf("historical WireGuard generations disagree on the reserved table egress")
	}
	configuration.evidence.Source = "exact-historical-config"
	serviceManager, historicalService, historicalPresent, err := host.inspectHistoricalService("wg0")
	if err != nil {
		return plan, err
	}
	currentManager, currentService, currentPresent, err := host.inspectHistoricalService("wg-syswarden")
	if err != nil {
		return plan, err
	}
	if serviceManager != currentManager {
		return plan, fmt.Errorf("service manager changed during retirement inspection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), wireGuardCommandTimeout)
	defer cancel()
	present, handle, err := wireGuardReservedNFTTableIdentity(ctx, host.nftRunner)
	if err != nil {
		return plan, err
	}
	tableAction, tableDigest := "absent", ""
	if present {
		wire, err := host.nftRunner.Run(ctx, "-a", "-j", "list", "table", "inet", "syswarden_wg")
		if err != nil {
			return plan, fmt.Errorf("inspect reserved table before retirement: %w", err)
		}
		legacy, legacyErr := validateLegacyWireGuardNFTTable(wire, handle)
		if legacyErr == nil {
			if legacy.EgressInterface != egress || (ownership.modernIdentity != nil && ownership.modernIdentity.ActiveInterface != egress) {
				return plan, fmt.Errorf("historical table egress does not match the retained configuration evidence")
			}
			tableAction = "delete-exact-legacy"
		} else {
			if ownership.modernIdentity == nil {
				return plan, fmt.Errorf("reserved table has no proven historical or current ownership")
			}
			currentHandle, currentErr := validateExistingWireGuardNFTTable(wire, *ownership.modernIdentity)
			if currentErr != nil || currentHandle != handle {
				return plan, fmt.Errorf("reserved table does not match the exact historical topology or current manifest")
			}
			tableAction = "preserve-exact-current"
		}
		tableDigest = retirementDigest(wire)
	}
	var currentIdentities []wireguardstate.ServerConfigurationIdentity
	if ownership.modernIdentity != nil {
		currentIdentities = append(currentIdentities, *ownership.modernIdentity)
	}
	matches, chainHandle, err := host.inspectRetirementForwardRules(ctx, currentIdentities...)
	if err != nil {
		return plan, err
	}
	for _, iface := range []string{"wg0", "wg-syswarden"} {
		rules, err := selectLegacyWireGuardForwardRules(map[string][]LegacyWireGuardForwardRuleEvidence{iface: matches[iface]}, iface)
		if err != nil {
			return plan, err
		}
		matches[iface] = rules
	}
	if len(matches["wg-syswarden"]) != 0 && ownership.modernIdentity == nil && historicalGenerated == nil {
		return plan, fmt.Errorf("shared current WireGuard rules lack a verified current manifest")
	}
	if state == "retired" && (tableAction == "delete-exact-legacy" || len(matches["wg0"]) != 0 || len(matches["wg-syswarden"]) != 0) {
		return plan, fmt.Errorf("historical runtime state appeared after configuration retirement; retain archive for inspection")
	}
	blockers := retirementServiceBlockers("historical wg0", historicalService, historicalPresent)
	// Pending retirement may remove shared historical rules. Both generations
	// must be stopped explicitly, even when the current private NAT is preserved.
	if state == "pending" || ownership.modernIdentity == nil || tableAction != "preserve-exact-current" {
		blockers = append(blockers, retirementServiceBlockers("current wg-syswarden", currentService, currentPresent)...)
	}
	plan = LegacyWireGuardRetirementPlan{
		Schema: legacyWireGuardRetirementSchema, State: state,
		Configuration: configuration.evidence, Ownership: ownership.evidence,
		ServiceManager: serviceManager, HistoricalService: historicalService, CurrentService: currentService,
		HistoricalInterfacePresent: historicalPresent, CurrentInterfacePresent: currentPresent,
		TableAction: tableAction, TableHandle: handle, TableSHA256: tableDigest, ForwardChainHandle: chainHandle, ForwardRules: matches,
		ArchivePath: legacyWireGuardArchivePath, ArchiveDirectory: archiveDirectory,
		SafeToApply: len(blockers) == 0, Blockers: blockers,
	}
	if historicalGenerated != nil {
		plan.LegacyGenerated = historicalGenerated.evidence()
	}
	return plan, nil
}

func canonicalLegacyWireGuardRetirementPlan(plan LegacyWireGuardRetirementPlan) ([]byte, error) {
	if plan.Schema != legacyWireGuardRetirementSchema || (plan.State != "pending" && plan.State != "retired") ||
		plan.ArchivePath != legacyWireGuardArchivePath || plan.Blockers == nil || plan.ForwardRules == nil ||
		plan.SafeToApply != (len(plan.Blockers) == 0) {
		return nil, fmt.Errorf("historical WireGuard retirement plan is incomplete")
	}
	return json.Marshal(plan)
}

// LegacyWireGuardRetirementPlanSHA256 binds exactly the inspected retirement.
func LegacyWireGuardRetirementPlanSHA256(plan LegacyWireGuardRetirementPlan) (string, error) {
	wire, err := canonicalLegacyWireGuardRetirementPlan(plan)
	if err != nil {
		return "", err
	}
	return retirementDigest(wire), nil
}

// RenderLegacyWireGuardRetirementPlan does not include configuration contents.
func RenderLegacyWireGuardRetirementPlan(plan LegacyWireGuardRetirementPlan) ([]byte, error) {
	if _, err := canonicalLegacyWireGuardRetirementPlan(plan); err != nil {
		return nil, err
	}
	return json.MarshalIndent(plan, "", "  ")
}

func retirementBatch(plan LegacyWireGuardRetirementPlan) string {
	var script strings.Builder
	for _, iface := range []string{"wg0", "wg-syswarden"} {
		for _, rule := range plan.ForwardRules[iface] {
			fmt.Fprintf(&script, "delete rule inet filter forward handle %d\n", rule.Handle)
		}
	}
	if plan.TableAction == "delete-exact-legacy" {
		fmt.Fprintf(&script, "delete table inet handle %d\n", plan.TableHandle)
	}
	return script.String()
}

func (host legacyWireGuardRecoveryHost) applyRetirement(expectedDigest string) (result LegacyWireGuardRetirementPlan, resultErr error) {
	if !wireGuardOwnershipTokenName.MatchString(expectedDigest) {
		return result, fmt.Errorf("plan SHA-256 must be exactly 64 lowercase hexadecimal characters")
	}
	plan, err := host.inspectRetirement()
	if err != nil {
		return result, err
	}
	digest, err := LegacyWireGuardRetirementPlanSHA256(plan)
	if err != nil || digest != expectedDigest {
		return result, errors.Join(fmt.Errorf("WireGuard retirement plan digest mismatch"), err)
	}
	if !plan.SafeToApply {
		return result, fmt.Errorf("WireGuard retirement is blocked: %s", strings.Join(plan.Blockers, "; "))
	}
	release, err := host.guard()
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, release()) }()
	// Reattest twice under the shared activation guard. No caller-supplied plan
	// fields are accepted for mutation.
	for i := 0; i < 2; i++ {
		current, err := host.inspectRetirement()
		if err != nil || !reflect.DeepEqual(current, plan) {
			return result, errors.Join(fmt.Errorf("WireGuard retirement state changed before apply"), err)
		}
	}
	if plan.State == "retired" {
		return plan, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), wireGuardCommandTimeout)
	defer cancel()
	if script := retirementBatch(plan); script != "" {
		if _, err := host.nftBatch(ctx, script); err != nil {
			return result, fmt.Errorf("exact WireGuard retirement nft batch failed; configuration evidence retained: %w", err)
		}
	}
	// The active-path file is retained until the expected kernel change and all
	// ownership/service evidence are verified again. A retry may then review a
	// fresh plan with an already absent table after an interrupted cleanup.
	after, err := host.inspectRetirement()
	expected := plan
	expected.ForwardRules = map[string][]LegacyWireGuardForwardRuleEvidence{"wg0": {}, "wg-syswarden": {}}
	if expected.TableAction == "delete-exact-legacy" {
		expected.TableAction, expected.TableHandle, expected.TableSHA256 = "absent", 0, ""
	}
	if err != nil || !reflect.DeepEqual(after, expected) {
		return result, errors.Join(fmt.Errorf("WireGuard retirement postcheck failed; historical configuration retained"), err)
	}
	if err := host.archiveRetiredWireGuardConfiguration(plan); err != nil {
		return result, err
	}
	final, err := host.inspectRetirement()
	expected.State = "retired"
	expected.Configuration.Path = legacyWireGuardArchivePath
	// Creation of the private archive directory is the only additional expected
	// metadata change. The archive helper already verified its pinned identity.
	expected.ArchiveDirectory = final.ArchiveDirectory
	if err != nil || !reflect.DeepEqual(final, expected) || !final.SafeToApply {
		return result, errors.Join(fmt.Errorf("verify archived WireGuard retirement; preserve private archive and inspect state"), err)
	}
	return plan, nil
}

// ApplyLegacyWireGuardRetirement never stops a service. Operators first review
// the runtime blockers, confirm independent access, and stop the affected VPNs.
func ApplyLegacyWireGuardRetirement(expectedDigest string) (LegacyWireGuardRetirementPlan, error) {
	return productionLegacyWireGuardRecoveryHost().applyRetirement(expectedDigest)
}
