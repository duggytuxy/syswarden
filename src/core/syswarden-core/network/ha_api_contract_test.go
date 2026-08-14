package network

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
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
	if tlsDirectory := os.Getenv("SYSWARDEN_HA_TEST_TLS_DIR"); tlsDirectory != "" {
		haTLSDir = filepath.Clean(tlsDirectory)
	}
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
		"SYSWARDEN_HA_TEST_TLS_DIR="+filepath.Join(t.TempDir(), "ha-tls"),
		"PATH="+toolDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	command.Env = append(command.Env, "SYSWARDEN_HA_TEST_TOKEN="+token)
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
	if response.TLS == nil {
		t.Fatal("HA server response has no TLS connection state")
	}
	if response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HA server negotiated TLS version %#x, want TLS 1.3", response.TLS.Version)
	}
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

func TestHABlacklistRoutingDoesNotTreatPeerInputAsAPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ip   string
		want haBlacklistFamily
	}{
		{ip: "192.0.2.10", want: haBlacklistIPv4},
		{ip: "2001:db8::10", want: haBlacklistIPv6},
		{ip: "../../tmp/escape", want: haBlacklistIPv4},
		{ip: "2001:db8::10/../../tmp/escape", want: haBlacklistIPv6},
	}
	for _, test := range tests {
		test := test
		t.Run(test.ip, func(t *testing.T) {
			t.Parallel()
			if got := blacklistFamilyForIP(test.ip); got != test.want {
				t.Fatalf("blacklistFamilyForIP(%q) = %d, want %d", test.ip, got, test.want)
			}
		})
	}
}

func TestHATLSIdentityPublicationIsAtomicOnPrivateKeyFailure(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "ha-tls")
	certPEM, keyPEM, err := generateSelfSignedCertPEM()
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	writeFailure := errors.New("injected private-key write failure")
	err = persistNewHATLSIdentity(directory, certPEM, keyPEM, func(path string, content []byte) error {
		writes++
		if filepath.Base(path) == haTLSPrivateKeyName {
			return writeFailure
		}
		return writePrivateTLSFile(path, content)
	})
	if !errors.Is(err, writeFailure) {
		t.Fatalf("persistNewHATLSIdentity error = %v, want %v", err, writeFailure)
	}
	if writes != 2 {
		t.Fatalf("identity writer calls = %d, want 2", writes)
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatalf("failed publication left a visible HA TLS identity: %v", err)
	}
	staging, err := filepath.Glob(filepath.Join(filepath.Dir(directory), ".ha-tls.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(staging) != 0 {
		t.Fatalf("failed publication left staging directories: %v", staging)
	}
}

func TestHATLSIdentityRejectsSymbolicLinkDirectories(t *testing.T) {
	t.Parallel()

	realDirectory := t.TempDir()
	symlinkDirectory := filepath.Join(t.TempDir(), "ha-tls")
	if err := os.Symlink(realDirectory, symlinkDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateHATLSCertificate(symlinkDirectory); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("loadOrCreateHATLSCertificate symlink error = %v", err)
	}

	realParent := t.TempDir()
	symlinkParent := filepath.Join(t.TempDir(), "ha-parent")
	if err := os.Symlink(realParent, symlinkParent); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateHATLSCertificate(filepath.Join(symlinkParent, "ha-tls")); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("loadOrCreateHATLSCertificate parent symlink error = %v", err)
	}
}

func TestHATLSIdentityIsPersistentPrivateAndVerifiable(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "ha-tls")
	first, err := loadOrCreateHATLSCertificate(directory)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateHATLSCertificate(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Certificate) == 0 || len(second.Certificate) == 0 {
		t.Fatal("persistent HA TLS identity has no leaf certificate")
	}
	if !bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("HA TLS certificate changed after reloading persisted identity")
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0700 {
		t.Fatalf("HA TLS identity directory mode = %s", directoryInfo.Mode())
	}

	for _, name := range []string{haTLSCertificateName, haTLSPrivateKeyName} {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("HA TLS file %s mode = %s", name, info.Mode())
		}
	}

	leaf, err := x509.ParseCertificate(first.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:     "localhost",
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("persisted HA TLS identity is not verifiable for localhost: %v", err)
	}
}

func TestHATLSIdentityRejectsCertificatesOutsideTheirValidityWindow(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM, err := generateSelfSignedCertPEM()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := validateHATLSCertificate(&certificate, leaf.NotBefore.Add(-time.Second)); err == nil || !strings.Contains(err.Error(), "not valid before") {
		t.Fatalf("future HA certificate validation error = %v", err)
	}
	if err := validateHATLSCertificate(&certificate, leaf.NotAfter); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired HA certificate validation error = %v", err)
	}
	if err := validateHATLSCertificate(&certificate, time.Now()); err != nil {
		t.Fatalf("current HA certificate rejected: %v", err)
	}
	if certificate.Leaf == nil {
		t.Fatal("validated HA certificate did not retain its parsed leaf")
	}

	withoutSAN := *leaf
	withoutSAN.DNSNames = nil
	withoutSAN.IPAddresses = nil
	if err := validateHATLSLeaf(&withoutSAN, time.Now()); err == nil || !strings.Contains(err.Error(), "subject alternative name") {
		t.Fatalf("SAN-less HA certificate validation error = %v", err)
	}

	withUnhandledCriticalExtension := *leaf
	withUnhandledCriticalExtension.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
	if err := validateHATLSLeaf(&withUnhandledCriticalExtension, time.Now()); err == nil || !strings.Contains(err.Error(), "unhandled critical extensions") {
		t.Fatalf("critical-extension HA certificate validation error = %v", err)
	}
}

func stringPort(port int) string {
	return fmt.Sprintf("%d", port)
}
