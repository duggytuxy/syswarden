package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "signatures.json")
	config := `{
  "rules": [
    {
      "id": "ssh-auth",
      "type": "regex",
      "pattern": "Failed password .* from <HOST>",
      "service": "sshd",
      "action": "track",
      "threshold": 3,
      "window": 60
    },
    {
      "id": "encoded-probe",
      "type": "aho-corasick",
      "patterns": ["../etc/passwd", "sqlmap"],
      "service": "http",
      "action": "ban"
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(configPath, 5, 60)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return engine
}

func TestNewEngineRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	if _, err := NewEngine(filepath.Join(t.TempDir(), "missing.json"), 5, 60); err == nil {
		t.Fatal("NewEngine() succeeded with a missing signature file")
	}

	invalidJSON := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(invalidJSON, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEngine(invalidJSON, 5, 60); err == nil {
		t.Fatal("NewEngine() succeeded with invalid JSON")
	}

	invalidRegex := filepath.Join(t.TempDir(), "invalid-regex.json")
	if err := os.WriteFile(
		invalidRegex,
		[]byte(`{"rules":[{"id":"bad","type":"regex","pattern":"(","service":"test"}]}`),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEngine(invalidRegex, 5, 60); err == nil {
		t.Fatal("NewEngine() succeeded with an invalid regular expression")
	}
}

func TestEngineScanCompatibility(t *testing.T) {
	engine := newTestEngine(t)
	if got := engine.RuleCount(); got != 3 {
		t.Fatalf("RuleCount() = %d, want 3 compiled patterns", got)
	}

	tests := []struct {
		name      string
		line      string
		wantRule  string
		wantMatch bool
	}{
		{
			name:      "regex with valid IPv4",
			line:      "Failed password for root from 192.0.2.44 port 22",
			wantRule:  "ssh-auth",
			wantMatch: true,
		},
		{
			name:      "regex rejects invalid host",
			line:      "Failed password for root from 999.0.2.44 port 22",
			wantMatch: false,
		},
		{
			name:      "raw Aho-Corasick",
			line:      "scanner user-agent sqlmap",
			wantRule:  "encoded-probe",
			wantMatch: true,
		},
		{
			name:      "URL-decoded Aho-Corasick",
			line:      "GET /..%2Fetc%2Fpasswd HTTP/1.1",
			wantRule:  "encoded-probe",
			wantMatch: true,
		},
		{name: "no match", line: "GET /health HTTP/1.1", wantMatch: false},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			match := engine.Scan(test.line)
			if (match != nil) != test.wantMatch {
				t.Fatalf("Scan(%q) match = %#v, wantMatch %t", test.line, match, test.wantMatch)
			}
			if match != nil && match.RuleID != test.wantRule {
				t.Fatalf("Scan(%q) rule = %q, want %q", test.line, match.RuleID, test.wantRule)
			}
		})
	}
}

func TestEvaluateThresholdCompatibility(t *testing.T) {
	engine := newTestEngine(t)
	if engine.EvaluateThreshold("192.0.2.1", "ssh-auth", 3, 60) {
		t.Fatal("first event reached threshold")
	}
	if engine.EvaluateThreshold("192.0.2.1", "ssh-auth", 3, 60) {
		t.Fatal("second event reached threshold")
	}
	if !engine.EvaluateThreshold("192.0.2.1", "ssh-auth", 3, 60) {
		t.Fatal("third event did not reach threshold")
	}
	if engine.EvaluateThreshold("192.0.2.1", "ssh-auth", 3, 60) {
		t.Fatal("tracker was not reset after threshold")
	}
	if !engine.EvaluateThreshold("192.0.2.2", "instant", 1, 60) {
		t.Fatal("threshold 1 did not trigger immediately")
	}
}

func TestExtractIPCompatibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
		want string
	}{
		{name: "Nginx IPv4", line: "192.0.2.55 - - [date] GET /", want: "192.0.2.55"},
		{name: "JSON IPv4", line: `{"remote_ip":"198.51.100.8","status":403}`, want: "198.51.100.8"},
		{name: "JSON IPv6", line: `{"client_ip":"2001:db8::8","status":403}`, want: "2001:db8::8"},
		{name: "loopback ignored", line: "127.0.0.1 - - GET /", want: ""},
		{name: "invalid IPv4 ignored", line: "999.0.2.1 - - GET /", want: ""},
		{name: "no address", line: "application started", want: ""},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := ExtractIP(test.line); got != test.want {
				t.Fatalf("ExtractIP(%q) = %q, want %q", test.line, got, test.want)
			}
		})
	}
}

func TestDetectionPipelineContract_SW_WAAP_001(t *testing.T) {
	engine := newTestEngine(t)
	line := "192.0.2.44 Failed password for root from 192.0.2.44 port 22"
	match := engine.Scan(line)
	if match == nil {
		t.Fatal("realistic SSH log did not match")
	}
	if match.RuleID != "ssh-auth" || match.Service != "sshd" || match.Action != "track" || match.Threshold != 3 || match.Window != 60 {
		t.Fatalf("match contract changed: %#v", match)
	}
	ip := ExtractIP(line)
	if ip != "192.0.2.44" {
		t.Fatalf("ExtractIP() = %q, want 192.0.2.44", ip)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		triggered := engine.EvaluateThreshold(ip, match.RuleID, match.Threshold, match.Window)
		if triggered != (attempt == 3) {
			t.Fatalf("attempt %d triggered=%t", attempt, triggered)
		}
	}
	if engine.EvaluateThreshold("198.51.100.9", match.RuleID, match.Threshold, match.Window) {
		t.Fatal("threshold state leaked between source IPs")
	}
	if engine.EvaluateThreshold(ip, "different-rule", match.Threshold, match.Window) {
		t.Fatal("threshold state leaked between rules")
	}

	// Distinct keys exercise concurrent access under go test -race without
	// hiding the non-atomic same-key behavior tracked by SW-WAAP-001.
	var group sync.WaitGroup
	for index := 0; index < 32; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			engine.EvaluateThreshold(
				fmt.Sprintf("203.0.113.%d", index+1),
				"concurrent-rule",
				2,
				60,
			)
		}(index)
	}
	group.Wait()
}
