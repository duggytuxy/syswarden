package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestDashboardDataSchemaCompatibility(t *testing.T) {
	t.Parallel()

	fixturePath := filepath.Join("..", "..", "..", "testdata", "contracts", "dashboard-data-v4.02.8.json")
	fixture, err := os.ReadFile(fixturePath) // #nosec G304 -- fixturePath is a fixed repository test path
	if err != nil {
		t.Fatalf("read shared dashboard fixture: %v", err)
	}

	var decoded DashboardData
	if err := json.Unmarshal(fixture, &decoded); err != nil {
		t.Fatalf("DashboardData fixture no longer decodes: %v", err)
	}
	if decoded.ProfileName != "production" || decoded.System.Hostname != "node-a" {
		t.Fatalf("decoded identity changed: profile=%q host=%q", decoded.ProfileName, decoded.System.Hostname)
	}
	if decoded.WAF.ActiveSignatures != 78 || len(decoded.WAF.BannedIPs) != 1 {
		t.Fatalf("decoded WAF schema changed: signatures=%d bans=%d", decoded.WAF.ActiveSignatures, len(decoded.WAF.BannedIPs))
	}
	if decoded.WAF.Sparkline24h[23] != 4 {
		t.Fatalf("sparkline final bucket = %d, want 4", decoded.WAF.Sparkline24h[23])
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal(fixture, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("consumer JSON contract diverged:\ngot=%s\nwant=%s", encoded, fixture)
	}
}

func TestDashboardDataBackwardAndForwardDecodeContract_SW_QA_001(t *testing.T) {
	t.Parallel()
	tests := []struct {
		fixture string
		release string
		host    string
	}{
		{fixture: "dashboard-data-v4.02.7.json", release: "v4.02.7", host: "node-n-minus-one"},
		{fixture: "dashboard-data-v4.02.8.json", release: "v4.02.8", host: "node-a"},
		{fixture: "dashboard-data-forward-extension.json", release: "v4.03.0", host: "node-forward"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.fixture, func(t *testing.T) {
			t.Parallel()
			fixturePath := filepath.Join("..", "..", "..", "testdata", "contracts", test.fixture)
			fixture, err := os.ReadFile(fixturePath) // #nosec G304 -- fixturePath is a fixed repository test path
			if err != nil {
				t.Fatal(err)
			}
			var decoded DashboardData
			if err := json.Unmarshal(fixture, &decoded); err != nil {
				t.Fatalf("compatible dashboard fixture was rejected: %v", err)
			}
			if decoded.GithubRelease != test.release || decoded.System.Hostname != test.host {
				t.Fatalf("decoded identity = %q/%q", decoded.GithubRelease, decoded.System.Hostname)
			}
		})
	}
}

func TestTUIHAEndpointAndLegacyAuthenticationContract_SW_HA_001(t *testing.T) {
	t.Parallel()
	if haPeerPort != "62026" {
		t.Fatalf("default HA peer port = %q, want 62026", haPeerPort)
	}
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve TUI source path")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "main.go")) // #nosec G304 -- fixed sibling source file
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, endpoint := range []string{"/ha/status", "/ha/telemetry"} {
		if !strings.Contains(text, endpoint) {
			t.Fatalf("TUI HA endpoint %s is missing", endpoint)
		}
	}
	// The v4.02.8 TUI does not attach an HA bearer token. This is a deliberate
	// mixed-version baseline assertion to replace when SW-HA-001 is implemented.
	if strings.Contains(text, `Header.Set("Authorization"`) {
		t.Fatal("TUI HA authorization behavior changed; replace the legacy assertion with authenticated protocol tests")
	}
}

func TestBuildProgressBarCompatibility(t *testing.T) {
	t.Parallel()

	if got := buildProgressBar(0, 0, "RAM", "green"); got != "[gray][RAM 0%][-]" {
		t.Fatalf("zero progress bar = %q", got)
	}
	if got := buildProgressBar(50, 100, "RAM", "green"); !strings.Contains(got, "RAM 50.0%") {
		t.Fatalf("half progress bar = %q", got)
	}
	if got := buildProgressBar(90, 100, "RAM", "green"); !strings.HasPrefix(got, "[red]") {
		t.Fatalf("high utilization did not use red: %q", got)
	}
	if got := buildProgressBar(200, 100, "RAM", "green"); !strings.Contains(got, "100.0%") {
		t.Fatalf("over-capacity progress bar was not capped: %q", got)
	}
}

func TestBuildProgressBarNegativeInputBaseline_SW_RES_001(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("negative progress input no longer exhibits the tracked panic; update the SW-RES-001 contract when fixed")
		}
	}()
	_ = buildProgressBar(-1, 10, "RAM", "green")
}

func TestPayloadTranslationsCompatibility(t *testing.T) {
	t.Parallel()

	const timestamp = "2026-08-13 08:00:00"
	allowed := TranslateAllowedPayload(
		"sshd",
		"Accepted publickey for alice from 192.0.2.10 port 22 ssh2: ED25519 SHA256:test",
		"192.0.2.10",
		timestamp,
	)
	if !strings.Contains(allowed, "user 'alice' via public key") || !strings.Contains(allowed, "ED25519 SHA256:test") {
		t.Fatalf("allowed SSH translation = %q", allowed)
	}

	attack := TranslatePayload(
		"ssh-auth",
		"Failed password from 198.51.100.9 port 2222",
		"198.51.100.9",
		timestamp,
	)
	if !strings.Contains(attack, "SSH brute-force on port 2222") {
		t.Fatalf("SSH attack translation = %q", attack)
	}

	web := TranslatePayload(
		"sqli",
		"GET /search?q=attack HTTP/1.1",
		"198.51.100.9",
		timestamp,
	)
	if !strings.Contains(web, "Web exploit (SQLI) on URI '/search?q=attack'") {
		t.Fatalf("web attack translation = %q", web)
	}
}
