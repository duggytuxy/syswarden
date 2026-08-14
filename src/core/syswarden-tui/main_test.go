package main

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestHAHTTPClientFailsClosedAndVerifiesTrustedTLS13Peer(t *testing.T) {
	t.Parallel()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)

	untrustedClient, err := newHAHTTPClient(filepath.Join(t.TempDir(), "missing-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrustedClient.Get(server.URL); err == nil {
		t.Fatal("HA client accepted an untrusted self-signed peer certificate")
	}

	invalidBundle := filepath.Join(t.TempDir(), "invalid-ha-ca.pem")
	if err := os.WriteFile(invalidBundle, []byte("not a certificate\n"), 0600); err != nil {
		t.Fatal(err)
	}
	invalidClient, invalidErr := newHAHTTPClient(invalidBundle)
	if invalidErr == nil {
		t.Fatal("HA client accepted an invalid configured CA bundle")
	}
	if _, err := invalidClient.Get(server.URL); err == nil {
		t.Fatal("HA client with an invalid CA bundle did not fail closed")
	}

	caBundle := filepath.Join(t.TempDir(), "ha-ca.pem")
	if err := os.WriteFile(caBundle, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	}), 0600); err != nil {
		t.Fatal(err)
	}
	trustedClient, err := newHAHTTPClient(caBundle)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := trustedClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("HA client has no explicit TLS configuration")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("HA client minimum TLS version = %x", transport.TLSClientConfig.MinVersion)
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("HA client disabled peer certificate verification")
	}
	response, err := trustedClient.Get(server.URL)
	if err != nil {
		t.Fatalf("HA client rejected an explicitly trusted TLS peer: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("trusted HA response status = %d", response.StatusCode)
	}
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("trusted HA response TLS state = %#v, want TLS 1.3", response.TLS)
	}
}

func TestHAPeerURLSupportsIPv4DNSAndIPv6(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		peer string
		want string
	}{
		{peer: "192.0.2.10", want: "https://192.0.2.10:62026/ha/status"},
		{peer: "node.example", want: "https://node.example:62026/ha/status"},
		{peer: "2001:db8::10", want: "https://[2001:db8::10]:62026/ha/status"},
		{peer: "[2001:db8::10]", want: "https://[2001:db8::10]:62026/ha/status"},
	} {
		if got := haPeerURL(test.peer, "/ha/status"); got != test.want {
			t.Fatalf("haPeerURL(%q) = %q, want %q", test.peer, got, test.want)
		}
	}
}

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
