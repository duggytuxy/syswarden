//go:build linux

package wireguardstate

import (
	"errors"
	"fmt"
	"reflect"
)

const ForwardingTransitionPath = "/etc/wireguard/.syswarden-forwarding-transition-v1.json"

// OwnedPolicySnapshot binds an assessment to the complete existing ownership
// envelope, including an owned OpenRC link. It contains no configuration bytes.
// Neither this snapshot nor its digest authorizes a replacement transaction.
type OwnedPolicySnapshot struct {
	Manifest           Manifest                    `json:"manifest"`
	ManifestArtifact   Artifact                    `json:"manifest_artifact"`
	Source             ServerConfigurationIdentity `json:"source"`
	Target             ServerConfigurationIdentity `json:"target"`
	TargetServerSHA256 string                      `json:"target_server_sha256"`
	PredecessorReceipt *Artifact                   `json:"predecessor_receipt,omitempty"`
}

// InspectOwnedPolicy validates complete ownership and derives only the exact
// scoped successor. Interrupted ownership/legacy migrations and altered sealed
// predecessors are refused. Original receipts and private backups stay intact.
func InspectOwnedPolicy(root string, uid, gid uint32) (OwnedPolicySnapshot, error) {
	var result OwnedPolicySnapshot
	inventory, err := Inspect(root)
	if err != nil {
		return result, err
	}
	if inventory.Transaction || !inventory.Manifest {
		return result, fmt.Errorf("owned WireGuard policy requires a complete manifest without a pending transaction")
	}
	if pending, err := inventoryLogicalExists(root, ForwardingTransitionPath); err != nil || pending {
		return result, errors.Join(fmt.Errorf("owned WireGuard forwarding transition is pending or cannot be inspected"), err)
	}
	manifest, record, err := readManifestWithRecord(root, uid, gid)
	if err != nil {
		return result, err
	}
	if err := VerifyManifest(root, manifest, uid, gid); err != nil {
		return result, err
	}
	server, err := ReadVerifiedArtifact(root, manifest, ServerConfigurationPath, uid, gid)
	if err != nil {
		return result, err
	}
	source, err := ParseServerConfiguration(server)
	if err != nil {
		return result, err
	}
	targetBytes, err := ScopedServerConfiguration(server)
	if err != nil {
		return result, err
	}
	target, err := ParseServerConfiguration(targetBytes)
	if err != nil {
		return result, err
	}
	receipt, _, err := captureMigrationOptional(root, LegacyMigrationReceiptPath, uid, gid)
	if err != nil {
		return result, err
	}
	if receipt != nil {
		previous, err := InspectLegacyMigration(root, uid, gid)
		if err != nil || !previous.Completed() || !reflect.DeepEqual(previous.Receipt, receipt) {
			return result, errors.Join(fmt.Errorf("owned policy predecessor evidence is incomplete or changed"), err)
		}
	}
	again, againRecord, err := readManifestWithRecord(root, uid, gid)
	if err != nil || !sameArtifact(againRecord, record) || !reflect.DeepEqual(again, manifest) {
		return result, errors.Join(fmt.Errorf("owned WireGuard manifest changed during assessment"), err)
	}
	if err := VerifyManifest(root, manifest, uid, gid); err != nil {
		return result, err
	}
	againReceipt, _, err := captureMigrationOptional(root, LegacyMigrationReceiptPath, uid, gid)
	if err != nil || !reflect.DeepEqual(receipt, againReceipt) {
		return result, errors.Join(fmt.Errorf("owned WireGuard predecessor changed during assessment"), err)
	}
	againInventory, err := Inspect(root)
	if err != nil || !reflect.DeepEqual(inventory, againInventory) {
		return result, errors.Join(fmt.Errorf("owned WireGuard transaction inventory changed during assessment"), err)
	}
	if pending, err := inventoryLogicalExists(root, ForwardingTransitionPath); err != nil || pending {
		return result, errors.Join(fmt.Errorf("owned WireGuard forwarding transition appeared during assessment"), err)
	}
	result = OwnedPolicySnapshot{Manifest: manifest, ManifestArtifact: record,
		Source: source, Target: target, TargetServerSHA256: plannedArtifact(ServerConfigurationPath, targetBytes, uid, gid).SHA256,
		PredecessorReceipt: receipt}
	return result, nil
}
