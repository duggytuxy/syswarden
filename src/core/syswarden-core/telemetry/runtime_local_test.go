package telemetry

import (
	"errors"
	"strings"
	"testing"

	"syswarden-core/firewall"
)

type localRuntimeReporterFixture struct {
	snapshot firewall.RuntimeLifecycleSnapshot
	err      error
}

func (localRuntimeReporterFixture) Ban(string) error { return nil }
func (fixture localRuntimeReporterFixture) RuntimeLifecycleStateSnapshot(limit int) (firewall.RuntimeLifecycleSnapshot, error) {
	if limit != 1024 {
		return firewall.RuntimeLifecycleSnapshot{}, errors.New("unexpected local snapshot bound")
	}
	return fixture.snapshot, fixture.err
}

func localRuntimeSnapshotFixture() firewall.RuntimeLifecycleSnapshot {
	return firewall.RuntimeLifecycleSnapshot{SchemaVersion: 1, Identity: strings.Repeat("a", 64), Sequence: 4,
		ModelSHA256: strings.Repeat("b", 64), UpdatedAt: "2026-09-10T12:02:00Z", CapturedAt: "2026-09-10T12:02:00Z",
		Active: 1, Tombstoned: 1, Claims: []firewall.RuntimeLifecycleClaimSnapshot{
			{Entry: "192.0.2.10", Generation: 1, State: "active", Cause: "verified-ban", CreatedAt: "2026-09-10T12:00:00Z", TransitionAt: "2026-09-10T12:00:00Z"},
			{Entry: "192.0.2.11", Generation: 1, State: "tombstoned", Cause: "native-expiry", CreatedAt: "2026-09-10T12:00:00Z", TransitionAt: "2026-09-10T12:01:00Z", ExpiresAt: "2026-09-10T12:01:00Z", ConfirmedAt: "2026-09-10T12:02:00Z"},
		}}
}

func TestGRCLocalRuntimeHistoryDoesNotInventPhysicalHits(t *testing.T) {
	view, err := collectRuntimeEnforcementView(localRuntimeReporterFixture{snapshot: localRuntimeSnapshotFixture()})
	if err != nil {
		t.Fatal(err)
	}
	metric := testGRCMetric("192.0.2.10", 5)
	document := buildGRCKPIDocumentWithRuntime([]attackerMetric{metric}, testGRCCatalog(), completeGRCEvidence(5), grcKPILifecycleCounts{}, view, view.byIP)
	wire, err := marshalGRCKPIDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	if document.Status != "complete" || len(document.Records) != 1 || document.Records[0].PhysicalHits != 5 ||
		len(document.Lifecycle.RuntimeLocalSnapshot.Claims) != 2 || document.Lifecycle.RuntimeLocalSnapshot.Claims[1].State != "tombstoned" {
		t.Fatalf("administrative history altered real-hit evidence: %s", wire)
	}
	if strings.Contains(string(wire), "runtime_cluster_id") || strings.Contains(string(wire), "runtime_peer_checkpoint_sha256") {
		t.Fatal("local history fabricated HA authority")
	}
	decoded, err := decodeGRCKPIDocument(wire)
	if err != nil || len(decoded.Lifecycle.RuntimeLocalSnapshot.Claims) != 2 {
		t.Fatalf("local GRC round trip lost history: %v", err)
	}
}

func TestGRCLocalRuntimeRequiresConsistentNativeEvidence(t *testing.T) {
	view, err := collectRuntimeEnforcementView(localRuntimeReporterFixture{snapshot: localRuntimeSnapshotFixture()})
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"mixed-ha-authority", "counter-mismatch", "scope-mismatch", "missing-native-snapshot", "early-confirmation"} {
		t.Run(fault, func(t *testing.T) {
			local := *view.localSnapshot
			local.Claims = append([]firewall.RuntimeLifecycleClaimSnapshot{}, local.Claims...)
			copyView := view
			copyView.localSnapshot = &local
			document := buildGRCKPIDocumentWithRuntime(nil, testGRCCatalog(), completeGRCEvidence(0), grcKPILifecycleCounts{}, copyView, nil)
			switch fault {
			case "mixed-ha-authority":
				document.Lifecycle.RuntimeClusterID = "invented-cluster"
			case "counter-mismatch":
				document.Lifecycle.ActiveClaims++
			case "scope-mismatch":
				document.Lifecycle.Scope = "ha-v2-runtime-snapshot"
			case "missing-native-snapshot":
				document.Lifecycle.RuntimeLocalSnapshot = nil
			case "early-confirmation":
				local.Claims[1].ConfirmedAt = "2026-09-10T12:01:01Z"
			}
			if _, err := marshalGRCKPIDocument(document); err == nil {
				t.Fatal("invalid local evidence was published")
			}
		})
	}
	failed, err := collectRuntimeEnforcementView(localRuntimeReporterFixture{err: errors.New("unverified kernel state")})
	if err == nil || failed.linked || failed.complete {
		t.Fatal("failed native read remained linked and complete")
	}
}

func TestLocalRuntimePrefixEnforcementOverridesPointTombstone(t *testing.T) {
	snapshot := localRuntimeSnapshotFixture()
	snapshot.Claims[0].Entry = "192.0.2.0/24"
	view, err := collectRuntimeEnforcementView(localRuntimeReporterFixture{snapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.200"} {
		if state := resolveRuntimeEnforcementState(entry, view, persistentEnforcementView{}, nil); state != "active" {
			t.Fatalf("prefix enforcement was lost for %s: %s", entry, state)
		}
	}
}
