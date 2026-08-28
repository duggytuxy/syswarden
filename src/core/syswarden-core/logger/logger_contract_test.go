package logger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func readLoggerTestFile(t *testing.T, path string) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	wire, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestPersistentBlocklistWriterIsAtomicCanonicalAndFailClosed_SW_HA_003(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "syswarden_blacklist.ipv4")
	for _, entry := range []string{"198.51.100.9", "198.51.100.7", "198.51.100.9", "203.0.113.9/24"} {
		if err := UpdatePersistentBlocklist(path, entry, true); err != nil {
			t.Fatal(err)
		}
	}
	wire := readLoggerTestFile(t, path)
	if string(wire) != "198.51.100.7\n198.51.100.9\n203.0.113.0/24\n" {
		t.Fatalf("canonical deduplicated blocklist = %q", wire)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("published blocklist info=%v err=%v", info, err)
	}
	if err := UpdatePersistentBlocklist(path, "198.51.100.9", false); err != nil {
		t.Fatal(err)
	}
	wire = readLoggerTestFile(t, path)
	if string(wire) != "198.51.100.7\n203.0.113.0/24\n" {
		t.Fatalf("atomic removal = %q", wire)
	}

	const workers = 64
	var wait sync.WaitGroup
	for index := 1; index <= workers; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := UpdatePersistentBlocklist(path, "192.0.2."+strconv.Itoa(index), true); err != nil {
				t.Errorf("concurrent persistence: %v", err)
			}
		}()
	}
	wait.Wait()
	wire = readLoggerTestFile(t, path)
	if got := len(strings.Fields(string(wire))); got != workers+2 {
		t.Fatalf("concurrent atomic writer retained %d entries, want %d", got, workers+2)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "operator-target")
	if err := os.WriteFile(target, []byte("operator data\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := UpdatePersistentBlocklist(path, "198.51.100.100", true); err == nil {
		t.Fatal("persistent blocklist writer accepted a symlink destination")
	}
	targetWire := readLoggerTestFile(t, target)
	if !reflect.DeepEqual(targetWire, []byte("operator data\n")) {
		t.Fatalf("symlink target changed: %q", targetWire)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	insecureRoot, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer insecureRoot.Close()
	insecureFile, err := insecureRoot.OpenFile(filepath.Base(path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insecureFile.Write([]byte("198.51.100.11\n")); err != nil {
		_ = insecureFile.Close()
		t.Fatal(err)
	}
	if err := insecureFile.Chmod(0644); err != nil {
		_ = insecureFile.Close()
		t.Fatal(err)
	}
	if err := insecureFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := UpdatePersistentBlocklist(path, "198.51.100.12", true); err == nil {
		t.Fatal("persistent blocklist writer accepted an insecure destination mode")
	}
	if wire := readLoggerTestFile(t, path); string(wire) != "198.51.100.11\n" {
		t.Fatalf("insecure destination changed despite rejection: %q", wire)
	}

	realParent := t.TempDir()
	realChild := filepath.Join(realParent, "real-child")
	if err := os.Mkdir(realChild, 0700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(directory, "linked-ancestor")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	if err := UpdatePersistentBlocklist(filepath.Join(linkedParent, "real-child", "syswarden_blacklist.ipv4"), "198.51.100.12", true); err == nil {
		t.Fatal("persistent blocklist writer accepted a symbolic-link ancestor")
	}
	if _, err := os.Lstat(filepath.Join(realChild, "syswarden_blacklist.ipv4")); !os.IsNotExist(err) {
		t.Fatalf("symbolic-link ancestor target was mutated: %v", err)
	}
	if err := UpdatePersistentBlocklist(directory+"/./syswarden_blacklist.ipv4", "198.51.100.12", true); err == nil {
		t.Fatal("persistent blocklist writer accepted a non-canonical path")
	}
}

func TestLocalCheckTelemetryPreservesStructuredCompatibility_SW_DOC_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waf.json")
	l := NewLogger(path)
	l.LogComplianceDrift("selected local check observed a deviation")
	l.LogComplianceOK("selected local checks found no deviation")
	l.Close()

	content, err := os.ReadFile(path) // #nosec G304 -- path is a test-owned temporary file
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("telemetry event count = %d, want 2", len(lines))
	}
	for index, wantAction := range []string{"COMPLIANCE-DRIFT", "COMPLIANCE-OK"} {
		var event TelemetryEvent
		if err := json.Unmarshal([]byte(lines[index]), &event); err != nil {
			t.Fatal(err)
		}
		if event.Action != wantAction || event.Jail != "NIS2-AUDIT" {
			t.Fatalf("structured compatibility changed: %#v", event)
		}
		for _, forbidden := range []string{"NIS2", "ISO27001", "compliant"} {
			if strings.Contains(strings.ToLower(event.Payload), strings.ToLower(forbidden)) {
				t.Fatalf("payload retains unsupported claim %q: %s", forbidden, event.Payload)
			}
		}
	}
}

func TestWAFEventNDJSONProducerSchemaContract_SW_QA_001(t *testing.T) {
	t.Parallel()
	fixturePath := filepath.Join("..", "..", "..", "..", "testdata", "contracts", "waf-events-v4.02.8.ndjson")
	fixture, err := os.Open(fixturePath) // #nosec G304 -- fixturePath is a fixed repository test path
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()

	var actions []string
	scanner := bufio.NewScanner(fixture)
	for scanner.Scan() {
		var event TelemetryEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("logger event schema rejected fixture: %v", err)
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		for _, required := range []string{"action", "timestamp", "ip", "jail", "payload"} {
			if _, ok := fields[required]; !ok {
				t.Fatalf("producer omitted required field %q from %s", required, encoded)
			}
		}
		actions = append(actions, event.Action)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(actions, ",") != "BANNED,ALLOWED,DETECTED,SHADOW-ALERT,SIMULATED-BAN,COMPLIANCE-DRIFT" {
		t.Fatalf("producer actions = %v", actions)
	}
}

func TestRuleTelemetryPersistsEffectivePolicyAttestation_SW_KPI_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waf.json")
	logger := NewLogger(path)
	logger.LogDetectedWithRule("192.0.2.60", "mitre-t1190-exploit-public", "payload\nwith newline", RuleContext{
		RuleID:                  "mitre-t1190-exploit-public",
		RiskCategory:            "exploit",
		RuleAction:              "detect",
		EffectiveThreshold:      1,
		EffectiveWindowSeconds:  0,
		SignatureCatalogVersion: "sw-signatures-v1",
		SignatureCatalogSHA256:  strings.Repeat("a", 64),
		RiskModelVersion:        "sw-risk-v1",
		MetricEligible:          true,
		ObservationModel:        "collector-content-window-v1",
	})
	logger.Close()

	content, err := os.ReadFile(path) // #nosec G304 -- test-owned path
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("physical NDJSON line count = %d, want 1", len(lines))
	}
	var event TelemetryEvent
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatalf("decode attested event: %v", err)
	}
	if event.RuleID != "mitre-t1190-exploit-public" || event.RiskCategory != "exploit" || event.RuleAction != "detect" ||
		event.EffectiveThreshold != 1 || event.EffectiveWindowSeconds == nil || *event.EffectiveWindowSeconds != 0 ||
		event.SignatureCatalogVersion != "sw-signatures-v1" || event.RiskModelVersion != "sw-risk-v1" ||
		event.MetricEligible == nil || !*event.MetricEligible {
		t.Fatalf("rule attestation changed: %#v", event)
	}
	if event.RuleAttestationStatus != "attested" {
		t.Fatalf("rule attestation status = %q", event.RuleAttestationStatus)
	}
	if event.Payload != "payload\nwith newline" {
		t.Fatalf("payload changed: %q", event.Payload)
	}
}

func TestLegacyLoggerMethodsOmitUnattestedRuleMetadata_SW_KPI_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waf.json")
	logger := NewLogger(path)
	logger.LogDetected("192.0.2.61", "legacy-jail", "payload")
	logger.Close()

	content, err := os.ReadFile(path) // #nosec G304 -- test-owned path
	if err != nil {
		t.Fatal(err)
	}
	var event TelemetryEvent
	if err := json.Unmarshal(content, &event); err != nil {
		t.Fatal(err)
	}
	if event.RuleID != "" || event.RiskCategory != "" || event.MetricEligible != nil {
		t.Fatalf("legacy event falsely claims attested policy: %#v", event)
	}
}

func TestRuleTelemetryUsesDetectionTimeAndRejectsIncoherentContext_SW_KPI_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waf.json")
	logger := NewLogger(path)
	observedAt := time.Date(2026, 8, 28, 12, 34, 56, 123456789, time.UTC)
	context := RuleContext{
		RuleID:                  "ssh-auth",
		RiskCategory:            "brute_force",
		RuleAction:              "track",
		EffectiveThreshold:      5,
		EffectiveWindowSeconds:  60,
		SignatureCatalogVersion: "sw-signatures-v1",
		SignatureCatalogSHA256:  strings.Repeat("b", 64),
		RiskModelVersion:        "sw-risk-v1",
		MetricEligible:          true,
		ObservedAt:              observedAt,
		ObservationModel:        "collector-content-window-v1",
	}
	logger.LogShadowAlertWithRule("192.0.2.62", "ssh-auth", "attempt", context)
	context.RuleID = "different-jail"
	logger.LogShadowAlertWithRule("192.0.2.62", "ssh-auth", "mismatch", context)
	context.RuleID = "ssh-auth"
	context.RuleAction = "detect"
	context.EffectiveThreshold = 1
	context.EffectiveWindowSeconds = 0
	logger.writeTelemetry(newTelemetryEvent("BANNED", "192.0.2.62", "ssh-auth", "invalid-transition", 10, &context))
	logger.Close()

	file, err := os.Open(path) // #nosec G304 -- test-owned path
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var events []TelemetryEvent
	for scanner.Scan() {
		var event TelemetryEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0].Timestamp != observedAt.Format(time.RFC3339Nano) || events[0].RuleID != "ssh-auth" {
		t.Fatalf("attested detection time = %#v", events)
	}
	if events[1].RuleID != "" || events[1].MetricEligible != nil || events[1].EffectiveWindowSeconds != nil || events[1].RuleAttestationStatus != "invalid" {
		t.Fatalf("incoherent rule context was attested: %#v", events[1])
	}
	if events[1].Timestamp == observedAt.Format(time.RFC3339Nano) || events[2].RuleID != "" || events[2].MetricEligible != nil || events[2].RuleAttestationStatus != "invalid" {
		t.Fatalf("invalid context influenced evidence: %#v", events)
	}
}

func TestKernelPacketDropDispositionIsAttestedAndBounded_SW_KPI_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waf.json")
	eventLogger := NewLogger(path)
	context := RuleContext{
		RuleID:                  "L2-ARP-FLOOD",
		RiskCategory:            "denial_of_service",
		RuleAction:              "detect",
		EffectiveThreshold:      1,
		SignatureCatalogVersion: "sw-kernel-signals-v1",
		SignatureCatalogSHA256:  strings.Repeat("c", 64),
		RiskModelVersion:        "sw-risk-v1",
		MetricEligible:          true,
		ObservationModel:        "kernel-log-observation-v1",
		ObservationDisposition:  "kernel-packet-dropped",
	}
	eventLogger.LogDetectedWithRule("192.0.2.70", "L2-ARP-FLOOD", "kernel packet", context)
	context.RuleID = "different-jail"
	eventLogger.LogDetectedWithRule("192.0.2.70", "L2-ARP-FLOOD", "invalid disposition", context)
	eventLogger.Close()

	file, err := os.Open(path) // #nosec G304 -- test-owned path
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var events []TelemetryEvent
	for scanner.Scan() {
		var event TelemetryEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].RuleAttestationStatus != "attested" ||
		events[0].ObservationDisposition != "kernel-packet-dropped" {
		t.Fatalf("kernel packet disposition = %#v", events)
	}
	if events[1].RuleAttestationStatus != "invalid" || events[1].ObservationDisposition != "" {
		t.Fatalf("invalid disposition was attested: %#v", events[1])
	}
}

func TestRiskAttributionPersistsWithoutChangingEnforcementPolicy_SW_KPI_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waf.json")
	eventLogger := NewLogger(path)
	eventLogger.LogShadowAlertWithRule("192.0.2.72", "generic-auth", "combined signature", RuleContext{
		RuleID:                        "generic-auth",
		RiskCategory:                  "brute_force",
		RuleAction:                    "track",
		EffectiveThreshold:            5,
		EffectiveWindowSeconds:        60,
		RiskAttributionRuleID:         "owasp-a03-xss",
		RiskAttributionCategory:       "exploit",
		RiskAttributionAction:         "detect",
		RiskAttributionThreshold:      1,
		RiskAttributionWindowSeconds:  0,
		RiskAttributionMetricEligible: true,
		SignatureCatalogVersion:       "sw-signatures-v1",
		SignatureCatalogSHA256:        strings.Repeat("d", 64),
		RiskModelVersion:              "sw-risk-v1",
		MetricEligible:                true,
		ObservationModel:              "collector-content-window-v1",
	})
	eventLogger.Close()

	content := readLoggerTestFile(t, path)
	var event TelemetryEvent
	if err := json.Unmarshal(content, &event); err != nil {
		t.Fatal(err)
	}
	if event.RuleAttestationStatus != "attested" || event.RuleID != "generic-auth" || event.RuleAction != "track" ||
		event.RiskAttributionRuleID != "owasp-a03-xss" || event.RiskAttributionCategory != "exploit" ||
		event.RiskAttributionAction != "detect" || event.RiskAttributionWindowSeconds == nil ||
		*event.RiskAttributionWindowSeconds != 0 || event.RiskAttributionMetricEligible == nil ||
		!*event.RiskAttributionMetricEligible {
		t.Fatalf("risk attribution changed enforcement evidence: %#v", event)
	}
}

func TestLoggerCloseWaitsForOwnedAsyncWorkAndRejectsLateWork_SW_KPI_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "waf.json")
	eventLogger := NewLogger(path)
	started := make(chan struct{})
	release := make(chan struct{})
	eventLogger.runAsync(func() {
		close(started)
		<-release
	})
	<-started

	closed := make(chan struct{})
	go func() {
		eventLogger.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("logger closed before owned async work completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("logger close did not join owned async work")
	}

	late := false
	eventLogger.runAsync(func() { late = true })
	if late {
		t.Fatal("logger accepted async work after close")
	}
	eventLogger.writeTelemetry(newTelemetryEvent("DETECTED", "192.0.2.71", "late", "late", 0, nil))
	eventLogger.Close()
	if content := readLoggerTestFile(t, path); len(content) != 0 {
		t.Fatalf("logger wrote after close: %q", content)
	}
}
