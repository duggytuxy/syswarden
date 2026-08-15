package telemetry

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHATelemetryExposesPerPeerDesynchronization_SW_HA_002(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	snapshot := haSyncStatusSnapshot{
		UpdatedAt: now.Add(-time.Minute).Format(time.RFC3339),
		Peers: []HAPeerTelemetry{
			{
				Peer:           "192.0.2.10",
				State:          "desynced",
				Desynced:       true,
				LocalIPs:       12,
				RemoteIPs:      11,
				MissingOnPeer:  1,
				MissingLocally: 0,
				Attempts:       3,
				LastAttempt:    now.Add(-time.Minute).Format(time.RFC3339),
			},
			{
				Peer:        "192.0.2.11",
				State:       "synced",
				InSync:      true,
				LocalIPs:    12,
				RemoteIPs:   12,
				Attempts:    1,
				LastAttempt: now.Add(-time.Minute).Format(time.RFC3339),
			},
		},
	}
	path := filepath.Join(t.TempDir(), "sync-status.json")
	wire, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}

	telemetry := loadHATelemetry(path, []string{"192.0.2.11", "192.0.2.10"}, now)
	if telemetry.Status != "desynced" || telemetry.Stale || len(telemetry.Peers) != 2 {
		t.Fatalf("HA telemetry = %#v", telemetry)
	}
	if telemetry.Peers[0].Peer != "192.0.2.10" || telemetry.Peers[0].MissingOnPeer != 1 || telemetry.Peers[0].InSync || !telemetry.Peers[0].Desynced {
		t.Fatalf("desynchronized peer telemetry = %#v", telemetry.Peers[0])
	}
	if telemetry.Peers[1].Peer != "192.0.2.11" || !telemetry.Peers[1].InSync {
		t.Fatalf("synchronized peer telemetry = %#v", telemetry.Peers[1])
	}
}

func TestHATelemetryReportsMissingAndStaleProducerState_SW_HA_002(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	missing := loadHATelemetry(filepath.Join(t.TempDir(), "missing"), []string{"192.0.2.20"}, now)
	if missing.Status != "unknown" || len(missing.Peers) != 1 || missing.Peers[0].State != "unknown" {
		t.Fatalf("missing producer telemetry = %#v", missing)
	}

	path := filepath.Join(t.TempDir(), "sync-status.json")
	snapshot := haSyncStatusSnapshot{
		UpdatedAt: now.Add(-defaultHASyncTelemetryMaxAge - time.Second).Format(time.RFC3339),
		Peers: []HAPeerTelemetry{{
			Peer:        "192.0.2.20",
			State:       "synced",
			InSync:      true,
			LastAttempt: now.Add(-defaultHASyncTelemetryMaxAge - time.Second).Format(time.RFC3339),
		}},
	}
	wire, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	stale := loadHATelemetry(path, []string{"192.0.2.20"}, now)
	if stale.Status != "stale" || !stale.Stale {
		t.Fatalf("stale HA telemetry = %#v", stale)
	}
}

func TestDashboardDataWithoutHAKeepsLegacyWireShape_SW_HA_002(t *testing.T) {
	wire, err := json.Marshal(DashboardData{})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["ha"]; exists {
		t.Fatalf("disabled HA unexpectedly changed the legacy dashboard shape: %s", wire)
	}
}

func TestHATelemetryCIDROnlyIsInboundOnlyAndNeverAFalsePeerFailure_SW_HA_002(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	telemetry := loadHATelemetry(filepath.Join(t.TempDir(), "missing"), []string{"10.20.30.0/29"}, now)
	if telemetry.Status != "inbound-only" || len(telemetry.Peers) != 0 {
		t.Fatalf("CIDR-only HA telemetry = %#v", telemetry)
	}
	mixed := normalizedHAPeerNames([]string{"10.20.30.0/29", "192.0.2.10", "2001:db8::10"})
	if len(mixed) != 2 || mixed[0] != "192.0.2.10" || mixed[1] != "2001:db8::10" {
		t.Fatalf("dialable telemetry peers = %v", mixed)
	}
}

func TestHATelemetryStatusReaderRejectsSymlinkAndWrongMode_SW_HA_003(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte(`{"updated_at":"2026-08-14T12:00:00Z","peers":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "status.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readHASyncStatus(symlink); err == nil {
		t.Fatal("HA telemetry accepted a symbolic-link status file")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	targetHandle, err := root.Open(filepath.Base(target))
	if err != nil {
		t.Fatal(err)
	}
	if err := targetHandle.Chmod(0644); err != nil {
		_ = targetHandle.Close()
		t.Fatal(err)
	}
	if err := targetHandle.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readHASyncStatus(target); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("HA telemetry accepted wrong-mode status file: %v", err)
	}
}
