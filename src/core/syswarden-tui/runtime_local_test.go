package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func tuiLocalRuntimeEvidenceFixture() grcKPIEvidenceEnvelope {
	snapshot := &tuiRuntimeLifecycleSnapshot{SchemaVersion: 1, Identity: strings.Repeat("a", 64), Sequence: 4,
		ModelSHA256: strings.Repeat("b", 64), UpdatedAt: "2026-09-10T12:02:00Z", CapturedAt: "2026-09-10T12:02:00Z",
		Active: 1, Tombstoned: 1, Claims: []tuiRuntimeLifecycleClaimSnapshot{
			{Entry: "192.0.2.10", Generation: 1, State: "active", Cause: "verified-ban", CreatedAt: "2026-09-10T12:00:00Z", TransitionAt: "2026-09-10T12:00:00Z"},
			{Entry: "192.0.2.11", Generation: 1, State: "tombstoned", Cause: "native-expiry", CreatedAt: "2026-09-10T12:00:00Z", TransitionAt: "2026-09-10T12:01:00Z", ExpiresAt: "2026-09-10T12:01:00Z", ConfirmedAt: "2026-09-10T12:02:00Z"},
		}}
	return grcKPIEvidenceEnvelope{SchemaVersion: 1, Status: "complete",
		Window:  tuiGRCKPIWindow{Scope: "retained-telemetry-journal", Complete: true},
		Catalog: tuiGRCKPICatalog{Version: "2026.09", SHA256: strings.Repeat("c", 64), RiskModelVersion: "sw-risk-v1"},
		Lifecycle: tuiGRCKPILifecycle{Scope: "local-native-runtime-snapshot", RuntimeStateLinked: true, RuntimeSnapshotComplete: true,
			RuntimeModelSHA256: snapshot.ModelSHA256, RuntimeCapturedAt: snapshot.CapturedAt, ActiveClaims: 1, TombstonedClaims: 1, RuntimeLocalSnapshot: snapshot},
		Records: []tuiGRCKPIRecord{}}
}

func TestTUILocalRuntimeHistoryRetainsAdministrativeClaimsWithoutHits(t *testing.T) {
	envelope := tuiLocalRuntimeEvidenceFixture()
	wire, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeTUIGRCKPIEvidence(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Records) != 0 || !grcKPIEvidenceComplete(wire) || grcKPIEvidenceSummary(wire) != "complete/native-runtime" {
		t.Fatal("native history was treated as attack events or HA evidence")
	}
	lines, err := runtimeLifecycleHistoryLines(wire)
	if err != nil {
		t.Fatal(err)
	}
	display := strings.Join(lines, "\n")
	for _, expected := range []string{"192.0.2.10 | state=active", "192.0.2.11 | state=tombstoned", "cause=native-expiry", "absence-confirmed=2026-09-10T12:02:00Z"} {
		if !strings.Contains(display, expected) {
			t.Fatalf("retained history missing %q: %s", expected, display)
		}
	}
	if strings.Contains(display, "hits=") {
		t.Fatal("administrative runtime history invented physical hits")
	}
}

func TestTUILocalRuntimeHistoryRejectsMixedAndPrematureEvidence(t *testing.T) {
	for _, fault := range []string{"mixed-authority", "counter", "early-confirmation", "missing-snapshot", "unknown-nested-field", "duplicate-nested-field"} {
		t.Run(fault, func(t *testing.T) {
			envelope := tuiLocalRuntimeEvidenceFixture()
			switch fault {
			case "mixed-authority":
				envelope.Lifecycle.RuntimeClusterID = "invented-cluster"
			case "counter":
				envelope.Lifecycle.ActiveClaims++
			case "early-confirmation":
				envelope.Lifecycle.RuntimeLocalSnapshot.Claims[1].ConfirmedAt = "2026-09-10T12:01:01Z"
			case "missing-snapshot":
				envelope.Lifecycle.RuntimeLocalSnapshot = nil
			}
			wire, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "unknown-nested-field" {
				wire = []byte(strings.Replace(string(wire), `"identity":`, `"unexpected":true,"identity":`, 1))
			}
			if fault == "duplicate-nested-field" {
				wire = []byte(strings.Replace(string(wire), `"identity":`, `"sequence":4,"identity":`, 1))
			}
			if _, err := runtimeLifecycleHistoryLines(wire); err == nil {
				t.Fatal("invalid native evidence was rendered as authoritative history")
			}
		})
	}
}
