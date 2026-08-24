//go:build linux

package network

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"syswarden-core/engine"
	corelogger "syswarden-core/logger"
)

type recordingWAAPFirewall struct {
	mu     sync.Mutex
	banned []string
}

func (manager *recordingWAAPFirewall) Ban(ip string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.banned = append(manager.banned, ip)
	return nil
}

func (*recordingWAAPFirewall) Unban(string) error { return nil }
func (*recordingWAAPFirewall) Name() string       { return "recursion-regression" }

func TestWAAPRejectsMarkedOutputWithoutStoppingExternalIngestion_SW2_H2(t *testing.T) {
	directory := t.TempDir()
	signaturesPath := filepath.Join(directory, "signatures.json")
	signatures := `{"rules":[` +
		`{"id":"external-regression","type":"regex","pattern":"attack from <HOST>","service":"test","action":"detect"},` +
		`{"id":"internal-regression","type":"regex","pattern":"ip=<HOST>","service":"test","action":"detect"}` +
		`]}`
	if err := os.WriteFile(signaturesPath, []byte(signatures), 0o600); err != nil {
		t.Fatal(err)
	}
	detectionEngine, err := engine.NewEngine(signaturesPath, 1, 60)
	if err != nil {
		t.Fatal(err)
	}
	telemetryPath := filepath.Join(directory, "waf.json")
	eventLogger := corelogger.NewLogger(telemetryPath)
	manager := &recordingWAAPFirewall{}
	waap := &WAAPEngine{
		config: WAAPConfig{Mode: "enforcing"},
		fw:     manager,
		logger: eventLogger,
		engine: detectionEngine,
	}

	attackerMarkerLine := "198.51.100.42 attack from 198.51.100.42 request=" + corelogger.InternalLogMarker
	if corelogger.IsInternalLogLine(attackerMarkerLine) {
		t.Fatal("an attacker-controlled marker was trusted before WAAP ingestion")
	}
	waap.processLogLine(attackerMarkerLine)
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()
	var processLog bytes.Buffer
	log.SetOutput(&processLog)
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("")
	(&corelogger.Logger{}).LogSimulatedBan("203.0.113.77", "internal-regression", "attack from 203.0.113.77")
	log.SetOutput(previousWriter)
	log.SetFlags(previousFlags)
	log.SetPrefix(previousPrefix)
	productLine := strings.TrimSpace(processLog.String())
	if !corelogger.IsInternalLogLine(productLine) {
		t.Fatalf("authenticated product record was not recognized before WAAP ingestion: %q", productLine)
	}
	if detectionEngine.Scan(productLine) == nil {
		t.Fatal("recursion fixture does not exercise a rematchable product record")
	}
	waap.processLogLine(productLine)
	waap.processLogLine("192.0.2.88 attack from 192.0.2.88")
	eventLogger.Close()

	file, err := os.Open(telemetryPath) // #nosec G304 -- test-owned path
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var events []corelogger.TelemetryEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event corelogger.TelemetryEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].IP != "198.51.100.42" || events[1].IP != "192.0.2.88" {
		t.Fatalf("WAAP telemetry after marked replay = %#v", events)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.banned) != 0 {
		t.Fatalf("detect-only recursion regression unexpectedly banned addresses: %v", manager.banned)
	}
}
