package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestListCommandPreservesHistoricalOutputAndAddsHAProvenance_SW_HA_004(t *testing.T) {
	directory := t.TempDir()
	ledger := filepath.Join(directory, "bans.json")
	wire := `{"version":1,"bans":[{"ip":"198.51.100.44","source":"bunkerweb","reason":"partner detection","peer_scope":"10.20.30.0/29","origin_peer_ip":"10.20.30.2","expires_at":"2026-08-14T13:00:00Z","created_at":"2026-08-14T12:00:00Z","updated_at":"2026-08-14T12:00:00Z","state":"active"}]}`
	if err := os.WriteFile(ledger, []byte(wire), 0600); err != nil {
		t.Fatal(err)
	}
	previousHistorical, previousLedger, previousNow := listHistoricalIPs, listHALedgerFile, listNow
	historicalCalls := 0
	listHistoricalIPs = func() { historicalCalls++ }
	listHALedgerFile = ledger
	listNow = func() time.Time { return time.Date(2026, 8, 14, 12, 10, 0, 0, time.UTC) }
	t.Cleanup(func() {
		listHistoricalIPs, listHALedgerFile, listNow = previousHistorical, previousLedger, previousNow
	})
	var output bytes.Buffer
	listCmd.SetOut(&output)
	if err := listCmd.RunE(listCmd, nil); err != nil {
		t.Fatal(err)
	}
	if historicalCalls != 1 {
		t.Fatalf("historical list renderer calls = %d", historicalCalls)
	}
	for _, field := range []string{"[ HA Temporary Bans ]", "198.51.100.44", "claimed_source=bunkerweb", "observed_origin=10.20.30.2", "peer_scope=10.20.30.0/29", "reason=partner detection", "expires_at=2026-08-14T13:00:00Z"} {
		if !strings.Contains(output.String(), field) {
			t.Fatalf("list output missing %q: %s", field, output.String())
		}
	}
}

func TestListCommandReportsCorruptHALedgerAfterHistoricalOutput_SW_HA_004(t *testing.T) {
	directory := t.TempDir()
	ledger := filepath.Join(directory, "bans.json")
	if err := os.WriteFile(ledger, []byte(`{"version":1,"bans":[],"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	previousHistorical, previousLedger, previousNow := listHistoricalIPs, listHALedgerFile, listNow
	historicalCalls := 0
	listHistoricalIPs = func() { historicalCalls++ }
	listHALedgerFile = ledger
	listNow = time.Now
	t.Cleanup(func() {
		listHistoricalIPs, listHALedgerFile, listNow = previousHistorical, previousLedger, previousNow
	})
	if err := listCmd.RunE(listCmd, nil); err == nil || !strings.Contains(err.Error(), "read HA temporary-ban ledger") {
		t.Fatalf("corrupt HA ledger error = %v", err)
	}
	if historicalCalls != 1 {
		t.Fatalf("historical list output was skipped on HA error: %d", historicalCalls)
	}
}
