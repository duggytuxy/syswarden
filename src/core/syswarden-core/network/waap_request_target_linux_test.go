//go:build linux

package network

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"syswarden-core/engine"
	corelogger "syswarden-core/logger"
)

func newWAAPRequestTargetTestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	directory := t.TempDir()
	signaturesPath := filepath.Join(directory, "signatures.json")
	signatures := `{
  "rules": [
    {
      "id": "waap-scoped-sqli",
      "type": "aho-corasick",
      "patterns": ["UNION SELECT"],
      "service": "http",
      "match_scope": "request-target",
      "action": "ban"
    },
    {
      "id": "waap-scoped-lfi",
      "type": "aho-corasick",
      "patterns": ["/../etc/passwd"],
      "service": "http",
      "match_scope": "request-target",
      "action": "ban"
    }
  ]
}`
	if err := os.WriteFile(signaturesPath, []byte(signatures), 0o600); err != nil {
		t.Fatal(err)
	}
	detector, err := engine.NewEngine(signaturesPath, 1, 60)
	if err != nil {
		t.Fatal(err)
	}
	return detector
}

func newWAAPRequestTargetTestBoundary(
	detector *engine.Engine,
	manager *recordingWAAPFirewall,
	eventLogger *corelogger.Logger,
	mode string,
) *WAAPEngine {
	return &WAAPEngine{
		config:                  WAAPConfig{Mode: mode},
		fw:                      manager,
		logger:                  eventLogger,
		engine:                  detector,
		localInterfaceAddresses: func() ([]netip.Addr, error) { return nil, nil },
		protectedHAPeers:        func() ([]netip.Prefix, error) { return nil, nil },
		isWhitelisted:           func(string) (bool, error) { return false, nil },
	}
}

func recordedWAAPRequestTargetBans(manager *recordingWAAPFirewall) []string {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return append([]string(nil), manager.banned...)
}

func assertWAAPRequestTargetNoEnforcementOrTelemetry(t *testing.T, line string) {
	t.Helper()
	detector := newWAAPRequestTargetTestEngine(t)

	auditManager := &recordingWAAPFirewall{}
	telemetryPath := filepath.Join(t.TempDir(), "waap.json")
	eventLogger := corelogger.NewLogger(telemetryPath)
	audit := newWAAPRequestTargetTestBoundary(detector, auditManager, eventLogger, "audit")
	audit.processLogLine(line)
	eventLogger.Close()
	if bans := recordedWAAPRequestTargetBans(auditManager); len(bans) != 0 {
		t.Fatalf("audit request-target fixture mutated firewall: %v", bans)
	}
	telemetry, err := os.ReadFile(telemetryPath) // #nosec G304 -- test-owned path
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(telemetry)) != "" {
		t.Fatalf("request-target fixture emitted unexpected WAAP telemetry: %s", telemetry)
	}

	enforcingManager := &recordingWAAPFirewall{}
	enforcing := newWAAPRequestTargetTestBoundary(detector, enforcingManager, nil, "enforcing")
	enforcing.processLogLine(line)
	if bans := recordedWAAPRequestTargetBans(enforcingManager); len(bans) != 0 {
		t.Fatalf("request-target fixture caused firewall ban: %v", bans)
	}
}

func TestWAAPRequestTargetScopeIgnoresCombinedAndJSONHeaders_SW_WAAP_002(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{
			name: "combined SQLi in Referer only",
			line: `8.8.8.8 - - [31/Aug/2026:08:15:00 +0200] "GET /safe HTTP/1.1" 200 123 "https://attacker.invalid/?q=UNION%20SELECT" "Mozilla/5.0"`,
		},
		{
			name: "combined LFI in User-Agent only",
			line: `8.8.4.4 - - [31/Aug/2026:08:15:01 +0200] "GET /safe HTTP/1.1" 200 123 "https://example.invalid/" "scanner /../etc/passwd"`,
		},
		{
			name: "JSON SQLi in Referer only",
			line: `{"client_ip":"1.1.1.1","path":"/safe","referer":"https://attacker.invalid/?q=UNION%20SELECT","user_agent":"Mozilla/5.0"}`,
		},
		{
			name: "JSON LFI in User-Agent only",
			line: `{"client_ip":"9.9.9.9","path":"/safe","referer":"https://example.invalid/","user_agent":"scanner /../etc/passwd"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertWAAPRequestTargetNoEnforcementOrTelemetry(t, test.line)
		})
	}
}

func TestWAAPRequestTargetScopeEnforcesCombinedAndJSONTargets_SW_WAAP_002(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		wantIP string
	}{
		{
			name:   "combined LFI target",
			line:   `8.8.8.8 - - [31/Aug/2026:08:16:00 +0200] "GET /../etc/passwd HTTP/1.1" 404 0 "-" "Mozilla/5.0"`,
			wantIP: "8.8.8.8",
		},
		{
			name:   "JSON encoded SQLi target",
			line:   `{"client_ip":"1.1.1.1","path":"/search?q=UNION%20SELECT","referer":"-","user_agent":"Mozilla/5.0"}`,
			wantIP: "1.1.1.1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := &recordingWAAPFirewall{}
			waap := newWAAPRequestTargetTestBoundary(
				newWAAPRequestTargetTestEngine(t),
				manager,
				nil,
				"enforcing",
			)
			waap.processLogLine(test.line)
			if bans := recordedWAAPRequestTargetBans(manager); strings.Join(bans, ",") != test.wantIP {
				t.Fatalf("request-target firewall bans = %v, want %s", bans, test.wantIP)
			}
		})
	}
}

func TestWAAPRequestTargetScopeRejectsMissingOrAmbiguousTargets_SW_WAAP_002(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{
			name: "combined missing request line",
			line: `8.8.8.8 - - [31/Aug/2026:08:17:00 +0200] "-" 400 0 "https://attacker.invalid/?q=UNION%20SELECT" "scanner /../etc/passwd"`,
		},
		{
			name: "JSON missing target",
			line: `{"client_ip":"1.1.1.1","referer":"https://attacker.invalid/?q=UNION%20SELECT","user_agent":"scanner /../etc/passwd"}`,
		},
		{
			name: "JSON conflicting target fields",
			line: `{"client_ip":"9.9.9.9","path":"/safe","request_uri":"/../etc/passwd","referer":"-","user_agent":"Mozilla/5.0"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertWAAPRequestTargetNoEnforcementOrTelemetry(t, test.line)
		})
	}
}
