package telemetry

import (
	"errors"
	"testing"
	"time"

	"syswarden-core/firewall"
)

type runtimeEnforcementReporterFixture struct {
	snapshot firewall.HAReplicationSnapshot
	err      error
}

func (fixture runtimeEnforcementReporterFixture) Ban(string) error { return nil }

func (fixture runtimeEnforcementReporterFixture) HAReplicationStateSnapshot(limit int) (firewall.HAReplicationSnapshot, error) {
	if limit != maximumRuntimeEnforcementClaims {
		return firewall.HAReplicationSnapshot{}, errors.New("unexpected snapshot limit")
	}
	return fixture.snapshot, fixture.err
}

type runtimeEnforcementLegacyFixture struct{}

func (runtimeEnforcementLegacyFixture) Ban(string) error { return nil }

func validRuntimeEnforcementSnapshot() firewall.HAReplicationSnapshot {
	return firewall.HAReplicationSnapshot{
		SchemaVersion:        1,
		ClusterID:            "cluster-a",
		Epoch:                7,
		NodeID:               "node-a",
		Role:                 "writer",
		Coordination:         "healthy",
		ModelSHA256:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CheckpointSHA256:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PeerCheckpointSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		CheckpointAt:         "2026-09-03T12:00:00Z",
		CapturedAt:           "2026-09-03T12:00:00Z",
		Active:               2,
		Expired:              1,
		Deleted:              1,
		Tombstoned:           1,
		Claims: []firewall.HAReplicationClaimSnapshot{
			{Owner: "node-a", Source: "waap", IP: "8.8.8.8", State: "active", ExpiresAt: "2026-09-03T13:00:00Z"},
			{Owner: "node-b", Source: "cli", IP: "1.1.1.1", State: "active"},
			{Owner: "node-a", Source: "waap", IP: "9.9.9.9", State: "expired", ExpiresAt: "2026-09-03T11:00:00Z"},
			{Owner: "node-a", Source: "cli", IP: "4.2.2.2", State: "deleted", TombstoneUntil: "2026-09-10T12:00:00Z"},
			{Owner: "node-b", Source: "waap", IP: "8.8.8.8", State: "tombstoned", TombstoneUntil: "2026-09-10T12:00:00Z"},
		},
	}
}

func TestRuntimeEnforcementViewLinksExactHAV2Snapshot_SW_GRC_010(t *testing.T) {
	previousNow := runtimeEnforcementNow
	runtimeEnforcementNow = func() time.Time { return time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { runtimeEnforcementNow = previousNow })
	view, err := collectRuntimeEnforcementView(runtimeEnforcementReporterFixture{snapshot: validRuntimeEnforcementSnapshot()})
	if err != nil {
		t.Fatal(err)
	}
	if !view.linked || !view.complete || view.truncated || view.scope != "ha-v2-runtime-snapshot" ||
		view.clusterID != "cluster-a" || view.epoch != 7 || view.nodeID != "node-a" || view.role != "writer" || view.coordination != "healthy" ||
		view.modelSHA256 != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ||
		view.checkpointSHA256 != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ||
		view.peerCheckpointSHA256 != view.checkpointSHA256 || view.checkpointAt != "2026-09-03T12:00:00Z" ||
		view.capturedAt != "2026-09-03T12:00:00Z" ||
		view.active != 2 || view.expired != 1 || view.deleted != 1 || view.tombstoned != 1 {
		t.Fatalf("unexpected runtime view: %#v", view)
	}
	if view.byIP["8.8.8.8"] != "active" || view.byIP["9.9.9.9"] != "expired" ||
		view.byIP["4.2.2.2"] != "deleted" || view.byIP["1.1.1.1"] != "active" {
		t.Fatalf("unexpected address state projection: %#v", view.byIP)
	}
}

func TestRuntimeEnforcementViewDoesNotOverclaimLegacyManager_SW_GRC_011(t *testing.T) {
	view, err := collectRuntimeEnforcementView(runtimeEnforcementLegacyFixture{})
	if err != nil {
		t.Fatal(err)
	}
	if view.linked || view.complete || view.scope != "not-reported" || len(view.byIP) != 0 {
		t.Fatalf("legacy manager was overclaimed: %#v", view)
	}
}

func TestRuntimeEnforcementSnapshotRejectsAmbiguity_SW_GRC_012(t *testing.T) {
	previousNow := runtimeEnforcementNow
	runtimeEnforcementNow = func() time.Time { return time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { runtimeEnforcementNow = previousNow })
	base := validRuntimeEnforcementSnapshot()
	tests := map[string]func(*firewall.HAReplicationSnapshot){
		"schema":       func(value *firewall.HAReplicationSnapshot) { value.SchemaVersion = 2 },
		"epoch":        func(value *firewall.HAReplicationSnapshot) { value.Epoch = 0 },
		"identity":     func(value *firewall.HAReplicationSnapshot) { value.NodeID = "UPPER" },
		"role":         func(value *firewall.HAReplicationSnapshot) { value.Role = "active" },
		"coordination": func(value *firewall.HAReplicationSnapshot) { value.Coordination = "unknown" },
		"digest":       func(value *firewall.HAReplicationSnapshot) { value.ModelSHA256 = "short" },
		"checkpoint":   func(value *firewall.HAReplicationSnapshot) { value.CheckpointSHA256 = "short" },
		"peer mismatch": func(value *firewall.HAReplicationSnapshot) {
			value.PeerCheckpointSHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		},
		"checkpoint time": func(value *firewall.HAReplicationSnapshot) { value.CheckpointAt = "2026-09-03T14:00:00+02:00" },
		"calendar date":   func(value *firewall.HAReplicationSnapshot) { value.CheckpointAt = "2026-02-30T12:00:00Z" },
		"captured":        func(value *firewall.HAReplicationSnapshot) { value.CapturedAt = "2026-09-03T14:00:00+02:00" },
		"future capture":  func(value *firewall.HAReplicationSnapshot) { value.CapturedAt = "2026-09-03T12:05:01Z" },
		"stale healthy checkpoint": func(value *firewall.HAReplicationSnapshot) {
			value.CheckpointAt = "2026-09-03T11:54:59Z"
		},
		"future checkpoint": func(value *firewall.HAReplicationSnapshot) {
			value.Coordination = "degraded"
			value.CheckpointAt = "2026-09-03T12:05:00.000000001Z"
		},
		"counter": func(value *firewall.HAReplicationSnapshot) { value.Active++ },
		"duplicate": func(value *firewall.HAReplicationSnapshot) {
			value.Claims[1] = value.Claims[0]
			value.Active = 2
		},
		"address": func(value *firewall.HAReplicationSnapshot) { value.Claims[0].IP = "::ffff:8.8.8.8" },
		"state":   func(value *firewall.HAReplicationSnapshot) { value.Claims[0].State = "removed" },
		"timestamp": func(value *firewall.HAReplicationSnapshot) {
			value.Claims[0].ExpiresAt = "2026-09-03T15:00:00+02:00"
		},
		"truncation": func(value *firewall.HAReplicationSnapshot) {
			value.Truncated = true
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Claims = append([]firewall.HAReplicationClaimSnapshot(nil), base.Claims...)
			mutate(&candidate)
			if err := validateRuntimeEnforcementSnapshot(candidate); err == nil {
				t.Fatal("ambiguous runtime snapshot was accepted")
			}
		})
	}
}

func TestRuntimeEnforcementReporterFailureRemainsUnlinked_SW_GRC_013(t *testing.T) {
	injected := errors.New("injected snapshot failure")
	view, err := collectRuntimeEnforcementView(runtimeEnforcementReporterFixture{err: injected})
	if !errors.Is(err, injected) || view.linked || view.scope != "ha-v2-runtime-snapshot" {
		t.Fatalf("unexpected reporter failure: view=%#v err=%v", view, err)
	}
}

func TestRuntimeEnforcementResolutionPreservesActiveOwnershipAndLatestLifecycle_SW_GRC_014(t *testing.T) {
	previousNow := runtimeEnforcementNow
	runtimeEnforcementNow = func() time.Time { return time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { runtimeEnforcementNow = previousNow })
	view, err := collectRuntimeEnforcementView(runtimeEnforcementReporterFixture{snapshot: validRuntimeEnforcementSnapshot()})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := make(map[string]runtimeLifecycleObservation)
	observeRuntimeLifecycleEvent(TelemetryEvent{
		Action: "DELETED", IP: "8.8.8.8", Timestamp: "2026-09-03T12:00:00Z",
	}, lifecycle)
	observeRuntimeLifecycleEvent(TelemetryEvent{
		Action: "EXPIRED", IP: "208.67.222.222", Timestamp: "2026-09-03T12:00:00Z",
	}, lifecycle)
	observeRuntimeLifecycleEvent(TelemetryEvent{
		Action: "TOMBSTONE", IP: "208.67.222.222", Timestamp: "2026-09-03T12:00:01Z",
	}, lifecycle)
	observeRuntimeLifecycleEvent(TelemetryEvent{
		Action: "DELETED", IP: "208.67.222.222", Timestamp: "2026-09-03T11:59:59Z",
	}, lifecycle)
	persistent := testPersistentEnforcementView(t, "4.2.2.2")

	tests := map[string]string{
		"8.8.8.8":        "active",
		"4.2.2.2":        "active",
		"9.9.9.9":        "expired",
		"208.67.222.222": "tombstoned",
		"1.0.0.1":        "absent",
	}
	for ip, expected := range tests {
		if actual := resolveRuntimeEnforcementState(ip, view, persistent, lifecycle); actual != expected {
			t.Fatalf("state for %s = %q, want %q", ip, actual, expected)
		}
	}
	if !lifecycle["208.67.222.222"].observedAt.Equal(time.Date(2026, 9, 3, 12, 0, 1, 0, time.UTC)) {
		t.Fatal("latest lifecycle observation was not retained")
	}
	if actual := resolveRuntimeEnforcementState("1.0.0.1", unavailableRuntimeEnforcementView(), persistentEnforcementView{}, nil); actual != "unknown" {
		t.Fatalf("unlinked state = %q", actual)
	}
}
