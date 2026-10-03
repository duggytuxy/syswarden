//go:build linux

package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
)

const legacyWireGuardMigrationSchema = "syswarden-legacy-wireguard-migration-plan-v1"

// LegacyWireGuardMigrationPlan authorizes only preservation of the existing
// generated VPN and replacement of its historical hooks with owned hooks.
type LegacyWireGuardMigrationPlan struct {
	Schema             string                                 `json:"schema"`
	State              string                                 `json:"state"`
	Files              wireguardstate.LegacyMigrationSnapshot `json:"files"`
	ServiceManager     string                                 `json:"service_manager"`
	Service            LegacyWireGuardServiceEvidence         `json:"service"`
	InterfacePresent   bool                                   `json:"interface_present"`
	TableAction        string                                 `json:"table_action"`
	TableHandle        uint64                                 `json:"table_handle"`
	TableSHA256        string                                 `json:"table_sha256"`
	SharedForward      wireGuardSharedForwardState            `json:"restored_shared_forwarding"`
	ForwardChainHandle uint64                                 `json:"shared_forward_chain_handle"`
	ForwardRules       []LegacyWireGuardForwardRuleEvidence   `json:"shared_forward_rules"`
	NFTPath            string                                 `json:"nft_executable"`
	TruePath           string                                 `json:"no_op_executable"`
	SafeToApply        bool                                   `json:"safe_to_apply"`
	Blockers           []string                               `json:"blockers"`
}

func redactedLegacyMigrationSnapshot(snapshot wireguardstate.LegacyMigrationSnapshot) wireguardstate.LegacyMigrationSnapshot {
	snapshot.OriginalContents = nil
	return snapshot
}

func generatedStateFromMigration(snapshot wireguardstate.LegacyMigrationSnapshot) (legacyWireGuardGeneratedState, error) {
	state := legacyWireGuardGeneratedState{}
	for _, artifact := range snapshot.OriginalArtifacts() {
		content, ok := snapshot.OriginalContents[artifact.Path]
		if !ok {
			return state, fmt.Errorf("legacy migration original inventory is incomplete")
		}
		state.files = append(state.files, legacyWireGuardConfiguration{content: content})
	}
	if len(state.files) != 3 {
		return state, fmt.Errorf("legacy migration original inventory is incomplete")
	}
	return validateLegacyWireGuardGeneratedState(state)
}

func (host legacyWireGuardRecoveryHost) inspectMigration() (LegacyWireGuardMigrationPlan, error) {
	var plan LegacyWireGuardMigrationPlan
	if err := host.validate(); err != nil {
		return plan, err
	}
	if host.migrationNFTPath == nil || host.migrationTruePath == nil || host.migrationToken == nil {
		return plan, fmt.Errorf("legacy migration dependencies are incomplete")
	}
	manager, err := host.managerState()
	if err != nil || manager != "ACTIVE" {
		return plan, errors.Join(fmt.Errorf("WireGuard migration requires an active service manager"), err)
	}
	if err := inspectLegacyWireGuardConflict(host.filesystemRoot, host.expectedUID, host.expectedGID); err != nil {
		return plan, fmt.Errorf("retire the historical wg0 namespace claim before current-generation migration: %w", err)
	}
	_, err = captureLegacyWireGuardConfiguration(host.filesystemRoot, wireGuardForwardingTransitionPath, host.expectedUID, host.expectedGID)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return plan, fmt.Errorf("refusing legacy migration while forwarding transition evidence exists or cannot be inspected")
	}
	snapshot, err := wireguardstate.InspectLegacyMigration(host.filesystemRoot, host.expectedUID, host.expectedGID)
	if err != nil {
		return plan, err
	}
	generated, err := generatedStateFromMigration(snapshot)
	if err != nil {
		return plan, err
	}
	serviceManager, service, present, err := host.inspectHistoricalService("wg-syswarden")
	if err != nil {
		return plan, err
	}
	nftPath, err := host.migrationNFTPath()
	if err != nil {
		return plan, err
	}
	truePath, err := host.migrationTruePath()
	if err != nil {
		return plan, err
	}
	state := "pending"
	if snapshot.Journal != nil {
		state = "in-progress"
	}
	if snapshot.Completed() {
		state = "complete"
	}
	var currentIdentities []wireguardstate.ServerConfigurationIdentity
	if snapshot.Completed() {
		manifest, err := wireguardstate.ReadAndVerify(host.filesystemRoot, host.expectedUID, host.expectedGID)
		if err != nil {
			return plan, err
		}
		server, err := wireguardstate.ReadVerifiedArtifact(host.filesystemRoot, manifest, wireguardstate.ServerConfigurationPath, host.expectedUID, host.expectedGID)
		if err != nil {
			return plan, err
		}
		identity, err := wireguardstate.ParseServerConfiguration(server)
		if err != nil || !identity.SharedForward {
			return plan, fmt.Errorf("completed migration lacks exact shared forwarding hooks")
		}
		currentIdentities = append(currentIdentities, identity)
	}
	plan = LegacyWireGuardMigrationPlan{Schema: legacyWireGuardMigrationSchema, State: state, Files: redactedLegacyMigrationSnapshot(snapshot),
		ServiceManager: serviceManager, Service: service, InterfacePresent: present,
		NFTPath: nftPath, TruePath: truePath, TableAction: "absent", ForwardRules: []LegacyWireGuardForwardRuleEvidence{}, Blockers: []string{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), wireGuardCommandTimeout)
	defer cancel()
	plan.SharedForward, err = inspectWireGuardSharedForward(ctx, host.nftRunner, snapshot.OwnershipToken())
	if err != nil {
		return plan, err
	}
	if plan.SharedForward.ChainHandle == 0 {
		return plan, fmt.Errorf("legacy migration requires the existing inet filter forward base chain; restore the reviewed operator policy first")
	}
	if !snapshot.Completed() && len(plan.SharedForward.Rules) != 0 {
		return plan, fmt.Errorf("owned shared forwarding appeared before migration completed")
	}
	tablePresent, handle, err := wireGuardReservedNFTTableIdentity(ctx, host.nftRunner)
	if err != nil {
		return plan, err
	}
	if tablePresent {
		wire, err := host.nftRunner.Run(ctx, "-a", "-j", "list", "table", "inet", "syswarden_wg")
		if err != nil {
			return plan, err
		}
		if snapshot.Completed() {
			manifest, err := wireguardstate.ReadAndVerify(host.filesystemRoot, host.expectedUID, host.expectedGID)
			if err != nil {
				return plan, err
			}
			server, err := wireguardstate.ReadVerifiedArtifact(host.filesystemRoot, manifest, wireguardstate.ServerConfigurationPath, host.expectedUID, host.expectedGID)
			if err != nil {
				return plan, err
			}
			identity, err := wireguardstate.ParseServerConfiguration(server)
			if err != nil {
				return plan, err
			}
			currentHandle, err := validateExistingWireGuardNFTTable(wire, identity)
			if err != nil || currentHandle != handle {
				return plan, fmt.Errorf("completed migration runtime no longer matches current ownership")
			}
			plan.TableAction = "preserve-exact-current"
		} else {
			legacy, err := validateLegacyWireGuardNFTTable(wire, handle)
			if err != nil || legacy.EgressInterface != generated.input.ActiveIf {
				return plan, fmt.Errorf("unmarked table does not match the exact historical migration configuration")
			}
			plan.TableAction = "delete-exact-legacy"
		}
		plan.TableHandle, plan.TableSHA256 = handle, retirementDigest(wire)
	}
	matches, chainHandle, err := host.inspectRetirementForwardRules(ctx, currentIdentities...)
	if err != nil {
		return plan, err
	}
	plan.ForwardRules, err = selectLegacyWireGuardForwardRules(matches, "wg-syswarden")
	if err != nil {
		return plan, err
	}
	plan.ForwardChainHandle = chainHandle
	if snapshot.Completed() {
		if len(plan.ForwardRules) != 0 {
			return plan, fmt.Errorf("historical shared rules reappeared after migration; preserve evidence")
		}
	} else {
		plan.Blockers = retirementServiceBlockers("historical wg-syswarden", service, present)
	}
	plan.SafeToApply = len(plan.Blockers) == 0
	return plan, nil
}

func canonicalLegacyWireGuardMigrationPlan(plan LegacyWireGuardMigrationPlan) ([]byte, error) {
	if plan.Schema != legacyWireGuardMigrationSchema ||
		(plan.State != "pending" && plan.State != "in-progress" && plan.State != "complete") ||
		plan.Blockers == nil || plan.ForwardRules == nil || plan.SafeToApply != (len(plan.Blockers) == 0) {
		return nil, fmt.Errorf("historical WireGuard migration plan is incomplete")
	}
	return json.Marshal(plan)
}

func LegacyWireGuardMigrationPlanSHA256(plan LegacyWireGuardMigrationPlan) (string, error) {
	wire, err := canonicalLegacyWireGuardMigrationPlan(plan)
	if err != nil {
		return "", err
	}
	return retirementDigest(wire), nil
}

func RenderLegacyWireGuardMigrationPlan(plan LegacyWireGuardMigrationPlan) ([]byte, error) {
	if _, err := canonicalLegacyWireGuardMigrationPlan(plan); err != nil {
		return nil, err
	}
	return json.MarshalIndent(plan, "", "  ")
}

func (host legacyWireGuardRecoveryHost) applyMigration(digest string) (result LegacyWireGuardMigrationPlan, resultErr error) {
	if !wireGuardOwnershipTokenName.MatchString(digest) {
		return result, fmt.Errorf("plan SHA-256 must be exactly 64 lowercase hexadecimal characters")
	}
	plan, err := host.inspectMigration()
	if err != nil {
		return result, err
	}
	actualDigest, err := LegacyWireGuardMigrationPlanSHA256(plan)
	if err != nil || digest != actualDigest {
		return result, errors.Join(fmt.Errorf("WireGuard migration plan digest mismatch"), err)
	}
	if !plan.SafeToApply {
		return result, fmt.Errorf("WireGuard migration is blocked: %s", strings.Join(plan.Blockers, "; "))
	}
	release, err := host.guard()
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, release()) }()
	for range 2 {
		current, err := host.inspectMigration()
		if err != nil || !reflect.DeepEqual(current, plan) {
			return result, errors.Join(fmt.Errorf("WireGuard migration state changed before apply"), err)
		}
	}
	if plan.State == "complete" {
		return plan, nil
	}
	cleanup := LegacyWireGuardRetirementPlan{TableAction: plan.TableAction, TableHandle: plan.TableHandle,
		ForwardRules: map[string][]LegacyWireGuardForwardRuleEvidence{"wg0": {}, "wg-syswarden": plan.ForwardRules},
	}
	ctx, cancel := context.WithTimeout(context.Background(), wireGuardCommandTimeout)
	defer cancel()
	if script := retirementBatch(cleanup); script != "" {
		if _, err := host.nftBatch(ctx, script); err != nil {
			return result, fmt.Errorf("exact legacy migration runtime cleanup failed; configuration retained: %w", err)
		}
	}
	after, err := host.inspectMigration()
	expected := plan
	expected.TableAction, expected.TableHandle, expected.TableSHA256 = "absent", 0, ""
	expected.ForwardRules = []LegacyWireGuardForwardRuleEvidence{}
	if err != nil || !reflect.DeepEqual(after, expected) {
		return result, errors.Join(fmt.Errorf("legacy migration runtime postcheck failed; configuration retained"), err)
	}
	snapshot, err := wireguardstate.InspectLegacyMigration(host.filesystemRoot, host.expectedUID, host.expectedGID)
	if err != nil || !reflect.DeepEqual(redactedLegacyMigrationSnapshot(snapshot), after.Files) {
		return result, errors.Join(fmt.Errorf("legacy migration source changed before rendering"), err)
	}
	generated, err := generatedStateFromMigration(snapshot)
	if err != nil {
		return result, err
	}
	input := generated.input
	input.SharedForward = true
	input.NFTPath, input.TruePath = plan.NFTPath, plan.TruePath
	input.OwnershipToken = after.Files.OwnershipToken()
	if input.OwnershipToken == "" {
		input.OwnershipToken, err = host.migrationToken()
		if err != nil {
			return result, err
		}
	}
	server, client, err := renderWireGuardConfigurations(input)
	if err != nil {
		return result, err
	}
	if !bytes.Equal([]byte(client), snapshot.OriginalContents[wireguardstate.ClientConfigurationPath]) {
		return result, fmt.Errorf("legacy migration would change the existing client; refusing")
	}
	if after.Files.Journal == nil {
		if err := wireguardstate.BeginLegacyMigration(host.filesystemRoot, snapshot, []byte(server), host.expectedUID, host.expectedGID); err != nil {
			return result, err
		}
	}
	// The pending journal blocks all normal installation and removal paths. Only
	// this explicit migration can continue it, with the original private backups.
	current, err := host.inspectMigration()
	if err != nil || !current.SafeToApply || current.TableAction != "absent" || len(current.ForwardRules) != 0 {
		return result, errors.Join(fmt.Errorf("legacy migration state changed at configuration publication boundary"), err)
	}
	snapshot, err = wireguardstate.InspectLegacyMigration(host.filesystemRoot, host.expectedUID, host.expectedGID)
	if err != nil || !reflect.DeepEqual(redactedLegacyMigrationSnapshot(snapshot), current.Files) {
		return result, errors.Join(fmt.Errorf("legacy migration source changed before publication"), err)
	}
	if err := wireguardstate.ContinueLegacyMigration(host.filesystemRoot, snapshot, []byte(server), host.expectedUID, host.expectedGID); err != nil {
		return result, err
	}
	final, err := host.inspectMigration()
	if err != nil || final.State != "complete" || !final.SafeToApply ||
		final.Service != plan.Service || final.InterfacePresent || final.TableAction != "absent" || len(final.ForwardRules) != 0 {
		return result, errors.Join(fmt.Errorf("legacy migration final verification failed"), err)
	}
	return plan, nil
}

func InspectLegacyWireGuardMigration() (LegacyWireGuardMigrationPlan, error) {
	return productionLegacyWireGuardRecoveryHost().inspectMigration()
}

func ApplyLegacyWireGuardMigration(digest string) (LegacyWireGuardMigrationPlan, error) {
	return productionLegacyWireGuardRecoveryHost().applyMigration(digest)
}
