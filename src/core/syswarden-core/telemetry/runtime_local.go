package telemetry

import (
	"fmt"

	"syswarden-core/firewall"
)

func collectLocalRuntimeEnforcementView(manager FirewallManager) (runtimeEnforcementView, error) {
	view := unavailableRuntimeEnforcementView()
	reporter, available := manager.(firewall.RuntimeLifecycleStateReporter)
	if !available {
		return view, nil
	}
	snapshot, err := reporter.RuntimeLifecycleStateSnapshot(maximumRuntimeEnforcementClaims)
	if err != nil {
		return view, fmt.Errorf("read local native runtime history: %w", err)
	}
	if err := firewall.ValidateRuntimeLifecycleSnapshot(snapshot); err != nil {
		return view, err
	}
	view.scope = "local-native-runtime-snapshot"
	view.linked, view.complete, view.truncated = true, !snapshot.Truncated, snapshot.Truncated
	view.modelSHA256, view.capturedAt = snapshot.ModelSHA256, snapshot.CapturedAt
	view.active, view.expired, view.deleted, view.tombstoned = snapshot.Active, snapshot.Expired, snapshot.Deleted, snapshot.Tombstoned
	view.localSnapshot = &snapshot
	for _, claim := range snapshot.Claims {
		view.byIP[claim.Entry] = claim.State
	}
	return view, nil
}

func validateGRCLocalRuntimeLifecycle(lifecycle GRCKPILifecycle) error {
	snapshot := lifecycle.RuntimeLocalSnapshot
	if !lifecycle.RuntimeStateLinked || snapshot == nil || lifecycle.RuntimeClusterID != "" || lifecycle.RuntimeEpoch != 0 ||
		lifecycle.RuntimeNodeID != "" || lifecycle.RuntimeRole != "" || lifecycle.RuntimeCoordination != "" ||
		lifecycle.RuntimeCheckpointSHA256 != "" || lifecycle.RuntimePeerCheckpointSHA256 != "" || lifecycle.RuntimeCheckpointAt != "" {
		return fmt.Errorf("local runtime lifecycle evidence has an invalid or mixed authority")
	}
	if err := firewall.ValidateRuntimeLifecycleSnapshot(*snapshot); err != nil {
		return err
	}
	if lifecycle.RuntimeSnapshotComplete == snapshot.Truncated || lifecycle.RuntimeSnapshotTruncated != snapshot.Truncated ||
		lifecycle.RuntimeModelSHA256 != snapshot.ModelSHA256 || lifecycle.RuntimeCapturedAt != snapshot.CapturedAt ||
		lifecycle.ActiveClaims != snapshot.Active || lifecycle.ExpiredClaims != snapshot.Expired ||
		lifecycle.DeletedClaims != snapshot.Deleted || lifecycle.TombstonedClaims != snapshot.Tombstoned {
		return fmt.Errorf("local runtime lifecycle projection disagrees with its native snapshot")
	}
	return nil
}

func completeGRCRuntimeLifecycle(lifecycle GRCKPILifecycle) bool {
	if !lifecycle.RuntimeStateLinked || !lifecycle.RuntimeSnapshotComplete || lifecycle.RuntimeSnapshotTruncated {
		return false
	}
	if lifecycle.Scope == "local-native-runtime-snapshot" {
		return lifecycle.RuntimeLocalSnapshot != nil
	}
	return lifecycle.Scope == "ha-v2-runtime-snapshot" && lifecycle.RuntimeCoordination == "healthy" &&
		lifecycle.RuntimePeerCheckpointSHA256 == lifecycle.RuntimeCheckpointSHA256
}
