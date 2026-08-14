package logger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
