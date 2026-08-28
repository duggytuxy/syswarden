package network

import (
	"bufio"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"syswarden-core/engine"
	corelogger "syswarden-core/logger"
)

func TestUDSAndDirectCollectorsEvaluateEachPhysicalAttemptOnce_SW_KPI_001(t *testing.T) {
	directory := t.TempDir()
	signaturesPath := filepath.Join(directory, "signatures.json")
	signatures := `{
  "catalog_version":"sw-test-signatures-v1",
  "risk_model_version":"sw-risk-v1",
  "risk_categories":{
    "exploit":["dummy-exploit"],
    "brute_force":["ssh-auth"],
    "reconnaissance":["dummy-recon"],
    "denial_of_service":["dummy-dos"],
    "abuse":["dummy-abuse"]
  },
  "rules":[
    {"id":"ssh-auth","type":"regex","pattern":"^<HOST> failed login attempt=[0-9]+$","service":"sshd","action":"track","threshold":3,"window":60},
    {"id":"dummy-exploit","type":"aho-corasick","patterns":["never-exploit"],"service":"http","action":"ban"},
    {"id":"dummy-recon","type":"aho-corasick","patterns":["never-recon"],"service":"http","action":"ban"},
    {"id":"dummy-dos","type":"aho-corasick","patterns":["never-dos"],"service":"http","action":"ban"},
    {"id":"dummy-abuse","type":"aho-corasick","patterns":["never-abuse"],"service":"http","action":"ban"}
  ]
}`
	if err := os.WriteFile(signaturesPath, []byte(signatures), 0600); err != nil {
		t.Fatal(err)
	}
	detector, err := engine.NewEngine(signaturesPath, 5, 60)
	if err != nil {
		t.Fatal(err)
	}
	telemetryPath := filepath.Join(directory, "waf.json")
	eventLogger := corelogger.NewLogger(telemetryPath)
	manager := &recordingWAAPFirewall{}

	direct := &WAAPEngine{
		config: WAAPConfig{Mode: "audit"},
		fw:     manager, logger: eventLogger, engine: detector,
		localInterfaceAddresses: func() ([]netip.Addr, error) { return nil, nil },
		protectedHAPeers:        func() ([]netip.Prefix, error) { return nil, nil },
		isWhitelisted:           func(string) (bool, error) { return false, nil },
	}
	uds := NewUDSServer(context.Background(), filepath.Join(directory, "core.sock"), detector, manager, eventLogger)
	uds.localInterfaceAddresses = func() ([]netip.Addr, error) { return nil, nil }
	uds.protectedHAPeers = func() ([]netip.Prefix, error) { return nil, nil }
	uds.isWhitelisted = func(string) (bool, error) { return false, nil }
	uds.enforcementMode = func() string { return "audit" }
	uds.isInternalLogLine = func(string) bool { return false }

	for attempt := 1; attempt <= 3; attempt++ {
		line := "8.8.8.70 failed login attempt=" + string(rune('0'+attempt))
		direct.processLogLine(line)
		uds.processLogLine(line + "\n")
	}
	eventLogger.Close()

	file, err := os.Open(telemetryPath) // #nosec G304 -- test-owned path
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var actions []string
	var payloads []string
	var events []corelogger.TelemetryEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event corelogger.TelemetryEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, event.Action)
		payloads = append(payloads, event.Payload)
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 3 || actions[0] != "SHADOW-ALERT" || actions[1] != "SHADOW-ALERT" || actions[2] != "SIMULATED-BAN" {
		t.Fatalf("deduplicated physical attempts produced actions %v", actions)
	}
	for index, payload := range payloads {
		if payload != "8.8.8.70 failed login attempt="+string(rune('1'+index)) {
			t.Fatalf("normalized payload %d = %q", index, payload)
		}
	}
	for index, event := range events {
		if event.RuleID != "ssh-auth" || event.RiskCategory != "brute_force" || event.EffectiveThreshold != 3 ||
			event.EffectiveWindowSeconds == nil || *event.EffectiveWindowSeconds != 60 ||
			event.ObservationModel != engine.IngressCorrelationModel {
			t.Fatalf("attested correlated event %d = %#v", index, event)
		}
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.banned) != 0 {
		t.Fatalf("audit-mode threshold mutated firewall: %v", manager.banned)
	}
}
