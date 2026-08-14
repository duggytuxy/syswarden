package network

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/viper"
)

const haServerHelperEnvironment = "SYSWARDEN_HA_SERVER_HELPER"

type noOpFirewallManager struct{}

func (noOpFirewallManager) Ban(string) error   { return nil }
func (noOpFirewallManager) Unban(string) error { return nil }
func (noOpFirewallManager) Name() string       { return "test" }

func TestHAServerAuthenticationAndMixedVersionContract_SW_HA_001(t *testing.T) {
	tokenServer := startHAServerProcess(t, "127.0.0.1", "shared-secret")

	response := requestHAServer(t, tokenServer, http.MethodGet, "/ha/sync", "", "")
	assertHAResponse(t, response, http.StatusUnauthorized, "Unauthorized")
	response = requestHAServer(t, tokenServer, http.MethodGet, "/ha/sync", "Bearer wrong", "")
	assertHAResponse(t, response, http.StatusUnauthorized, "Unauthorized")
	response = requestHAServer(t, tokenServer, http.MethodGet, "/ha/sync", "Bearer shared-secret", "")
	assertHAResponse(t, response, http.StatusOK, `{"ips":null}`)
	response = requestHAServer(t, tokenServer, http.MethodPost, "/ha/sync", "Bearer shared-secret", "{")
	assertHAResponse(t, response, http.StatusBadRequest, "Invalid JSON")
	response = requestHAServer(t, tokenServer, http.MethodPatch, "/ha/sync", "Bearer shared-secret", "")
	assertHAResponse(t, response, http.StatusMethodNotAllowed, "Method Not Allowed")

	// v4.02.8 authenticates /ha/sync with the token but /ha/status only by
	// source IP. Preserve this visible mixed-version behavior until SW-HA-001.
	response = requestHAServer(t, tokenServer, http.MethodGet, "/ha/status", "", "")
	if response.status != http.StatusOK {
		t.Fatalf("legacy status route without token = %d, body=%s", response.status, response.body)
	}
	var status map[string]string
	if err := json.Unmarshal([]byte(response.body), &status); err != nil {
		t.Fatal(err)
	}
	if status["version"] != "v4.02.8" || status["status"] != "online" {
		t.Fatalf("status payload = %#v", status)
	}

	legacyServer := startHAServerProcess(t, "127.0.0.1", "")
	response = requestHAServer(t, legacyServer, http.MethodGet, "/ha/sync", "", "")
	assertHAResponse(t, response, http.StatusOK, `{"ips":null}`)
	response = requestHAServer(t, legacyServer, http.MethodGet, "/ha/sync", "Bearer newer-node-token", "")
	assertHAResponse(t, response, http.StatusOK, `{"ips":null}`)

	disallowedServer := startHAServerProcess(t, "192.0.2.200", "shared-secret")
	response = requestHAServer(t, disallowedServer, http.MethodGet, "/ha/sync", "Bearer shared-secret", "")
	assertHAResponse(t, response, http.StatusForbidden, "Forbidden: IP not in cluster")
}

func TestHAServerHelperProcess(t *testing.T) {
	if os.Getenv(haServerHelperEnvironment) != "1" {
		return
	}
	viper.Reset()
	viper.Set("integrations.ha.enabled", true)
	viper.Set("integrations.ha.peer_ips", []string{os.Getenv("SYSWARDEN_HA_TEST_PEER")})
	viper.Set("integrations.ha.peer_port", os.Getenv("SYSWARDEN_HA_TEST_PORT"))
	viper.Set("integrations.ha.token", os.Getenv("SYSWARDEN_HA_TEST_TOKEN"))
	StartHAServer(noOpFirewallManager{})
	select {}
}

type haTestServer struct {
	address string
}

type haResponse struct {
	status int
	body   string
}

func startHAServerProcess(t *testing.T, peer, token string) haTestServer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			requireOrSkipHAServerLoopback(t, err)
		}
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	toolDir := t.TempDir()
	fakeCLI := filepath.Join(toolDir, "syswarden")
	if err := os.WriteFile(fakeCLI, []byte("#!/bin/sh\nprintf 'SYSWARDEN v4.02.8 CLI\\n'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fakeCLI, 0700); err != nil { // #nosec G302 -- the owner-only fake CLI must be executable by the isolated HA helper
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestHAServerHelperProcess$") // #nosec G204 G702 -- os.Args[0] is the fixed current test binary and the argument is static
	command.Env = append(
		os.Environ(),
		haServerHelperEnvironment+"=1",
		"SYSWARDEN_HA_TEST_PEER="+peer,
		"SYSWARDEN_HA_TEST_PORT="+stringPort(port),
		"SYSWARDEN_HA_TEST_TOKEN="+token,
		"PATH="+toolDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
	})
	server := haTestServer{address: "127.0.0.1:" + stringPort(port)}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		client := haHTTPClient()
		request, _ := http.NewRequest(http.MethodGet, "https://"+server.address+"/ha/sync", nil)
		if response, err := client.Do(request); err == nil {
			_ = response.Body.Close()
			return server
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("HA server helper did not become ready")
	return haTestServer{}
}

func requireOrSkipHAServerLoopback(t *testing.T, err error) {
	t.Helper()
	if os.Getenv("CI") != "" || os.Getenv("ACT") == "true" || os.Getenv("SYSWARDEN_REQUIRE_LOOPBACK_TESTS") == "1" {
		t.Fatalf("HA server loopback contract is mandatory in CI/Act but sockets are unavailable: %v", err)
	}
	t.Skipf("HA server contract requires loopback sockets unavailable in this sandbox: %v", err)
}

func requestHAServer(t *testing.T, server haTestServer, method, path, authorization, body string) haResponse {
	t.Helper()
	request, err := http.NewRequest(method, "https://"+server.address+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response, err := haHTTPClient().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return haResponse{status: response.StatusCode, body: strings.TrimSpace(string(content))}
}

func haHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- isolated self-signed test server
			MinVersion:         tls.VersionTLS13,
		}},
	}
}

func assertHAResponse(t *testing.T, got haResponse, wantStatus int, wantBody string) {
	t.Helper()
	if got.status != wantStatus || got.body != wantBody {
		t.Fatalf("response = (%d, %q), want (%d, %q)", got.status, got.body, wantStatus, wantBody)
	}
}

func stringPort(port int) string {
	return fmt.Sprintf("%d", port)
}
