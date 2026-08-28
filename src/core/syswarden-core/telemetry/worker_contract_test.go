package telemetry

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func readKPIJournalWindow(t *testing.T, window *kpiJournalWindow) []byte {
	t.Helper()
	var wire []byte
	for _, reader := range window.readers {
		part, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		wire = append(wire, part...)
	}
	return wire
}

func TestKPIJournalSnapshotIsBoundedAndRecordAligned_SW_KPI_001(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "waf.json")
	wire := []byte("discard-me\nkeep-one\nkeep-two\n")
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}

	readSnapshot := func(limit int64) ([]byte, kpiJournalSnapshot, error) {
		file, reader, snapshot, err := openKPIJournalSnapshot(path, limit)
		if err != nil {
			return nil, snapshot, err
		}
		defer file.Close()
		content, err := io.ReadAll(reader)
		return content, snapshot, err
	}

	full, snapshot, err := readSnapshot(int64(len(wire)))
	if err != nil {
		t.Fatal(err)
	}
	if string(full) != string(wire) || !snapshot.complete || snapshot.totalBytes != int64(len(wire)) ||
		snapshot.scannedBytes != int64(len(wire)) {
		t.Fatalf("full snapshot = %q, %#v", full, snapshot)
	}

	wantTail := []byte("keep-one\nkeep-two\n")
	partialLimit := int64(len("rd-me\nkeep-one\nkeep-two\n"))
	tail, snapshot, err := readSnapshot(partialLimit)
	if err != nil {
		t.Fatal(err)
	}
	if string(tail) != string(wantTail) || snapshot.complete || snapshot.totalBytes != int64(len(wire)) ||
		snapshot.scannedBytes != int64(len(wantTail)) {
		t.Fatalf("aligned partial snapshot = %q, %#v", tail, snapshot)
	}

	boundaryTail, snapshot, err := readSnapshot(int64(len(wantTail)))
	if err != nil {
		t.Fatal(err)
	}
	if string(boundaryTail) != string(wantTail) || snapshot.complete || snapshot.scannedBytes != int64(len(wantTail)) {
		t.Fatalf("boundary snapshot = %q, %#v", boundaryTail, snapshot)
	}
}

func TestKPIJournalSnapshotRefusesInvalidLimit_SW_KPI_001(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "waf.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if file, reader, snapshot, err := openKPIJournalSnapshot(path, 0); err == nil || file != nil || reader != nil || snapshot != (kpiJournalSnapshot{}) {
		t.Fatalf("invalid limit result = file:%v reader:%v snapshot:%#v err:%v", file, reader, snapshot, err)
	}
}

func TestKPIJournalSnapshotCannotClaimEarlyEOFComplete_SW_KPI_001(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "waf.json")
	wire := []byte("{\"record\":\"retained\"}\n")
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	file, reader, snapshot, err := openKPIJournalSnapshot(path, int64(len(wire)))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatal(err)
	}
	if !snapshot.complete || snapshot.scannedBytes != int64(len(wire)) {
		t.Fatalf("pre-read snapshot = %#v", snapshot)
	}
	if reader.consumed == snapshot.scannedBytes {
		t.Fatalf("early EOF could be reported complete: consumed=%d snapshot=%#v", reader.consumed, snapshot)
	}
	state := kpiEvidenceState{
		catalogAvailable:    true,
		journalScanComplete: snapshot.complete && reader.consumed == snapshot.scannedBytes,
		journalBytesTotal:   snapshot.totalBytes,
		journalBytesScanned: reader.consumed,
	}
	if state.quality() != kpiEvidenceQualityDegraded {
		t.Fatalf("early EOF evidence quality = %q, state=%#v", state.quality(), state)
	}
}

func TestKPIJournalWindowSpansRotatedAndActiveGenerations_SW_KPI_001(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	activePath := filepath.Join(directory, "waf.json")
	previous := []byte("old-one\nold-two\n")
	active := []byte("new-one\n")
	if err := os.WriteFile(activePath+".1", previous, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(activePath, active, 0600); err != nil {
		t.Fatal(err)
	}

	fullWindow, err := openKPIJournalWindow(activePath, int64(len(previous)+len(active)))
	if err != nil {
		t.Fatal(err)
	}
	full := readKPIJournalWindow(t, fullWindow)
	if !fullWindow.snapshot.complete || !fullWindow.stable() ||
		fullWindow.consumedBytes() != fullWindow.snapshot.scannedBytes ||
		string(full) != string(append(append([]byte(nil), previous...), active...)) {
		_ = fullWindow.Close()
		t.Fatalf("full multi-generation snapshot = %q, %#v", full, fullWindow.snapshot)
	}
	if err := fullWindow.Close(); err != nil {
		t.Fatal(err)
	}

	wantTail := []byte("old-two\nnew-one\n")
	tailWindow, err := openKPIJournalWindow(activePath, int64(len(wantTail)))
	if err != nil {
		t.Fatal(err)
	}
	tail := readKPIJournalWindow(t, tailWindow)
	if tailWindow.snapshot.complete || !tailWindow.stable() || string(tail) != string(wantTail) ||
		tailWindow.snapshot.totalBytes != int64(len(previous)+len(active)) ||
		tailWindow.consumedBytes() != tailWindow.snapshot.scannedBytes {
		_ = tailWindow.Close()
		t.Fatalf("bounded multi-generation tail = %q, %#v", tail, tailWindow.snapshot)
	}
	if err := tailWindow.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestKPIJournalWindowIsolatesPartialGenerationRecord_SW_KPI_001(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	activePath := filepath.Join(directory, "waf.json")
	if err := os.WriteFile(activePath+".1", []byte(`{"old":true`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(activePath, []byte("{\"new\":true}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	window, err := openKPIJournalWindow(activePath, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer window.Close()
	decodeErrors := 0
	newRecords := 0
	for _, reader := range window.readers {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			var record map[string]bool
			if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
				decodeErrors++
				continue
			}
			if record["new"] {
				newRecords++
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
	}
	if decodeErrors != 1 || newRecords != 1 || window.consumedBytes() != window.snapshot.scannedBytes {
		t.Fatalf("generation boundary result = decode_errors:%d new_records:%d consumed:%d snapshot:%#v",
			decodeErrors, newRecords, window.consumedBytes(), window.snapshot)
	}
}

func TestKPIJournalWindowDetectsConcurrentRotation_SW_KPI_001(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	activePath := filepath.Join(directory, "waf.json")
	if err := os.WriteFile(activePath, []byte("before\n"), 0600); err != nil {
		t.Fatal(err)
	}
	window, err := openKPIJournalWindow(activePath, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer window.Close()
	if err := os.Rename(activePath, activePath+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(activePath, []byte("after\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if window.stable() {
		t.Fatal("concurrent journal rotation retained a false stable snapshot")
	}
}

func TestDashboardDataProducerContract_SW_QA_001(t *testing.T) {
	t.Parallel()
	fixturePath := filepath.Join("..", "..", "..", "..", "testdata", "contracts", "dashboard-data-v4.02.8.json")
	fixture, err := os.ReadFile(fixturePath) // #nosec G304 -- fixturePath is a fixed repository test path
	if err != nil {
		t.Fatalf("read shared dashboard fixture: %v", err)
	}

	var decoded DashboardData
	if err := json.Unmarshal(fixture, &decoded); err != nil {
		t.Fatalf("producer schema no longer decodes the shared fixture: %v", err)
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("producer schema no longer encodes: %v", err)
	}

	var want, got any
	if err := json.Unmarshal(fixture, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("producer JSON contract diverged:\ngot=%s\nwant=%s", encoded, fixture)
	}
}

func TestDashboardDataVersionToleranceContract_SW_QA_001(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fixture string
		release string
	}{
		{fixture: "dashboard-data-v4.02.7.json", release: "v4.02.7"},
		{fixture: "dashboard-data-v4.02.8.json", release: "v4.02.8"},
		{fixture: "dashboard-data-forward-extension.json", release: "v4.03.0"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.fixture, func(t *testing.T) {
			t.Parallel()
			fixturePath := filepath.Join("..", "..", "..", "..", "testdata", "contracts", test.fixture)
			fixture, err := os.ReadFile(fixturePath) // #nosec G304 -- fixturePath is a fixed repository test path
			if err != nil {
				t.Fatal(err)
			}
			var decoded DashboardData
			if err := json.Unmarshal(fixture, &decoded); err != nil {
				t.Fatalf("compatible dashboard fixture was rejected: %v", err)
			}
			if decoded.GithubRelease != test.release {
				t.Fatalf("release = %q, want %q", decoded.GithubRelease, test.release)
			}
		})
	}
}

func TestWAFEventNDJSONConsumerContract_SW_QA_001(t *testing.T) {
	t.Parallel()
	fixturePath := filepath.Join("..", "..", "..", "..", "testdata", "contracts", "waf-events-v4.02.8.ndjson")
	fixture, err := os.Open(fixturePath) // #nosec G304 -- fixturePath is a fixed repository test path
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()

	wantActions := []string{"BANNED", "ALLOWED", "DETECTED", "SHADOW-ALERT", "SIMULATED-BAN", "COMPLIANCE-DRIFT"}
	var gotActions []string
	scanner := bufio.NewScanner(fixture)
	for scanner.Scan() {
		var event TelemetryEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("WAF event no longer decodes: %v", err)
		}
		if event.Timestamp == "" || event.IP == "" || event.Jail == "" || event.Payload == "" {
			t.Fatalf("required WAF event field missing after decode: %#v", event)
		}
		gotActions = append(gotActions, event.Action)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(gotActions, ",") != strings.Join(wantActions, ",") {
		t.Fatalf("actions = %v, want %v", gotActions, wantActions)
	}
}
