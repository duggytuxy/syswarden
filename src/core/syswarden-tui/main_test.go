package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func checkedTUITestIdentity(t *testing.T, name string, value int) uint32 {
	t.Helper()
	wide := int64(value)
	if wide < 0 || wide > math.MaxUint32 {
		t.Fatalf("effective %s is outside uint32: %d", name, value)
		return 0
	}
	return uint32(wide)
}

func tuiTestIdentity(t *testing.T) (uint32, uint32) {
	t.Helper()
	return checkedTUITestIdentity(t, "UID", os.Geteuid()), checkedTUITestIdentity(t, "GID", os.Getegid())
}

func newStrictTUIHATestCertificatePEM(t *testing.T, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestTUIRemovalTombstoneStartupGuard_SW2_FWBACKEND_001(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "removal-in-progress-v1")
	uid, gid := tuiTestIdentity(t)
	present, err := inspectTUIRemovalTombstone(path, uid, gid)
	if err != nil || present {
		t.Fatalf("missing tombstone result = present %t, error %v", present, err)
	}
	if err := os.WriteFile(path, []byte(tuiRemovalTombstoneRecord), 0600); err != nil {
		t.Fatal(err)
	}
	present, err = inspectTUIRemovalTombstone(path, uid, gid)
	if err != nil || !present {
		t.Fatalf("valid tombstone result = present %t, error %v", present, err)
	}
	if err := os.WriteFile(path, []byte("SYSWARDEN_REMOVAL_V1\nstate=modified\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if present, err = inspectTUIRemovalTombstone(path, uid, gid); err == nil || !present {
		t.Fatalf("modified tombstone result = present %t, error %v", present, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte(tuiRemovalTombstoneRecord), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if present, err = inspectTUIRemovalTombstone(path, uid, gid); err == nil || !present {
		t.Fatalf("symlink tombstone result = present %t, error %v", present, err)
	}
}

func TestTUIRemovalTombstoneRejectsUnsafeParentBeforeMissingFile_SW2_FWBACKEND_001(t *testing.T) {
	uid, gid := tuiTestIdentity(t)

	unsafeParent := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(unsafeParent, 0700); err != nil {
		t.Fatal(err)
	}
	unsafeParentFD, err := unix.Open(
		unsafeParent,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Fchmod(unsafeParentFD, 0700); err != nil {
			t.Errorf("restore unsafe parent mode: %v", err)
		}
		if err := unix.Close(unsafeParentFD); err != nil {
			t.Errorf("close unsafe parent: %v", err)
		}
	})
	if err := unix.Fchmod(unsafeParentFD, 0720); err != nil {
		t.Fatal(err)
	}
	unsafePath := filepath.Join(unsafeParent, "removal-in-progress-v1")
	if present, err := inspectTUIRemovalTombstone(unsafePath, uid, gid); err == nil || !present {
		t.Fatalf("unsafe parent result = present %t, error %v", present, err)
	}

	root := t.TempDir()
	realParent := filepath.Join(root, "real-state")
	linkedParent := filepath.Join(root, "linked-state")
	if err := os.Mkdir(realParent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	linkedPath := filepath.Join(linkedParent, "removal-in-progress-v1")
	if present, err := inspectTUIRemovalTombstone(linkedPath, uid, gid); err == nil || !present {
		t.Fatalf("symlink parent result = present %t, error %v", present, err)
	}
}

func TestTUIRemovalGuardRunsBeforeTerminalAndStateAccess_SW2_FWBACKEND_001(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	content := string(source)
	guard := strings.Index(content, "inspectTUIRemovalTombstone(tuiRemovalTombstonePath")
	terminal := strings.Index(content, "term.IsTerminal")
	if guard < 0 || terminal < 0 || guard > terminal {
		t.Fatalf("TUI removal guard is not the first startup boundary: guard=%d terminal=%d", guard, terminal)
	}
}

func newTUIHALoopbackServerCertificate(t *testing.T, serial int64) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestStrictTUIHACABundleParserConsumesAllBytes_SW_HA_001(t *testing.T) {
	certificateA := newStrictTUIHATestCertificatePEM(t, 1)
	certificateB := newStrictTUIHATestCertificatePEM(t, 2)
	decoded, _ := pem.Decode(certificateA)
	if decoded == nil {
		t.Fatal("test certificate did not decode")
	}
	validMulti := append(append([]byte("\n\t"), certificateA...), certificateB...)
	if err := addStrictHATrustCertificates(x509.NewCertPool(), validMulti); err != nil {
		t.Fatalf("valid multi-certificate bundle: %v", err)
	}
	invalid := map[string][]byte{
		"empty":              nil,
		"junk prefix":        append([]byte("junk\n"), certificateA...),
		"junk suffix":        append(append([]byte(nil), certificateA...), []byte("junk")...),
		"junk between":       bytes.Join([][]byte{certificateA, []byte("junk\n"), certificateB}, nil),
		"non certificate":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: decoded.Bytes}),
		"certificate header": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: decoded.Bytes}),
		"invalid DER":        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")}),
		"malformed PEM":      []byte("-----BEGIN CERTIFICATE-----\nAAAA\n"),
	}
	for name, wire := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := addStrictHATrustCertificates(x509.NewCertPool(), wire); err == nil {
				t.Fatal("strict TUI CA parser accepted invalid bundle")
			}
		})
	}
}

func TestHAHTTPClientFailsClosedAndVerifiesTrustedTLS13Peer(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("TLS loopback unavailable: %v", err)
	}
	_ = listener.Close()

	trustedCertificate := newTUIHALoopbackServerCertificate(t, 201)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{trustedCertificate}}
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
	if invalidErr == nil || invalidClient != nil {
		t.Fatal("HA client accepted an invalid configured CA bundle")
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

	untrustedCertificate := newTUIHALoopbackServerCertificate(t, 202)
	otherServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	otherServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{untrustedCertificate}}
	otherServer.StartTLS()
	t.Cleanup(otherServer.Close)
	if _, err := trustedClient.Get(otherServer.URL); err == nil {
		t.Fatal("explicit HA CA bundle was not used as an exclusive trust pool")
	}
	_, trustedPort, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trustedClient.Get("https://localhost:" + trustedPort); err == nil {
		t.Fatal("HA client accepted a certificate with the wrong SAN")
	}

	legacyProbeCertificate := newTUIHALoopbackServerCertificate(t, 203)
	offeredVersions := make(chan []uint16, 1)
	legacyProbeServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	legacyProbeServer.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{legacyProbeCertificate},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			offeredVersions <- append([]uint16(nil), hello.SupportedVersions...)
			return nil, errors.New("TLS version probe complete")
		},
	}
	legacyProbeServer.StartTLS()
	t.Cleanup(legacyProbeServer.Close)
	legacyProbeBundle := filepath.Join(t.TempDir(), "legacy-probe-ca.pem")
	if err := os.WriteFile(legacyProbeBundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: legacyProbeServer.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	tls13Client, err := newHAHTTPClient(legacyProbeBundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls13Client.Get(legacyProbeServer.URL); err == nil {
		t.Fatal("HA TLS version probe unexpectedly completed a request")
	}
	select {
	case versions := <-offeredVersions:
		hasTLS13 := false
		for _, version := range versions {
			if version == tls.VersionTLS13 {
				hasTLS13 = true
			}
			if version <= tls.VersionTLS12 {
				t.Fatalf("HA client offered legacy TLS version %#x: %v", version, versions)
			}
		}
		if !hasTLS13 {
			t.Fatalf("HA client did not offer TLS 1.3: %v", versions)
		}
	case <-time.After(time.Second):
		t.Fatal("HA TLS version probe did not observe a ClientHello")
	}

	symlinkBundle := filepath.Join(t.TempDir(), "ha-ca-link.pem")
	if err := os.Symlink(caBundle, symlinkBundle); err != nil {
		t.Fatal(err)
	}
	if _, err := newHAHTTPClient(symlinkBundle); err == nil {
		t.Fatal("HA client accepted a symbolic-link CA bundle")
	}
}

type tuiRoundTripperFunc func(*http.Request) (*http.Response, error)

func (roundTrip tuiRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestHAPeerURLSupportsOnlyExactIPv4AndIPv6(t *testing.T) {
	for _, test := range []struct {
		peer string
		want string
	}{
		{peer: "192.0.2.10", want: "https://192.0.2.10:62026/ha/status"},
		{peer: "2001:db8::10", want: "https://[2001:db8::10]:62026/ha/status"},
		{peer: "[2001:db8::10]", want: "https://[2001:db8::10]:62026/ha/status"},
	} {
		got, err := haPeerURL(test.peer, "/ha/status")
		if err != nil {
			t.Fatalf("haPeerURL(%q): %v", test.peer, err)
		}
		if got != test.want {
			t.Fatalf("haPeerURL(%q) = %q, want %q", test.peer, got, test.want)
		}
	}
	for _, peer := range []string{"node.example", "10.0.0.0/29", "::ffff:192.0.2.10", "fe80::1%eth0"} {
		if _, err := haPeerURL(peer, "/ha/status"); err == nil {
			t.Fatalf("haPeerURL accepted non-dialable peer %q", peer)
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

func TestTUIHAStatusAndTelemetryRequireBearer_SW_HA_001(t *testing.T) {
	if haPeerPort != "62026" {
		t.Fatalf("default HA peer port = %q, want 62026", haPeerPort)
	}
	requests := 0
	testClient := &http.Client{Transport: tuiRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Authorization") != "Bearer shared-secret" {
			t.Errorf("missing TUI bearer on %s", request.URL.Path)
		}
		if request.URL.Path != "/ha/status" && request.URL.Path != "/ha/telemetry" {
			t.Errorf("unexpected TUI HA path %q", request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
	})}

	haRuntimeConfigMu.Lock()
	previousClient, previousCAErr := httpClient, haCAErr
	previousToken, previousConfigErr := haBearerToken, haRuntimeConfigErr
	httpClient, haCAErr = testClient, nil
	haBearerToken, haRuntimeConfigErr = "shared-secret", nil
	haRuntimeConfigMu.Unlock()
	t.Cleanup(func() {
		haRuntimeConfigMu.Lock()
		httpClient, haCAErr = previousClient, previousCAErr
		haBearerToken, haRuntimeConfigErr = previousToken, previousConfigErr
		haRuntimeConfigMu.Unlock()
	})
	for _, endpoint := range []string{"/ha/status", "/ha/telemetry"} {
		response, err := haGet("https://192.0.2.10:62026" + endpoint)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
	}
	if requests != 2 {
		t.Fatalf("authenticated TUI requests = %d, want 2", requests)
	}

	haRuntimeConfigMu.Lock()
	haBearerToken = " bad-token "
	haRuntimeConfigMu.Unlock()
	if _, err := haGet("https://192.0.2.10:62026/ha/status"); err == nil || strings.Contains(err.Error(), "bad-token") ||
		!strings.Contains(err.Error(), "integrations.ha.token") || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("invalid token did not fail closed without disclosure: %v", err)
	}
	if requests != 2 {
		t.Fatal("TUI issued an HTTP request before validating the bearer token")
	}
	haRuntimeConfigMu.Lock()
	haBearerToken = "shared-secret"
	httpClient = &http.Client{Transport: tuiRoundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxTUIHAResponseBytes+1))), Header: make(http.Header)}, nil
	})}
	haRuntimeConfigMu.Unlock()
	if _, err := haGet("https://192.0.2.10:62026/ha/status"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized TUI HA response error = %v", err)
	}
}

func TestTUIHAModularConfigAndInboundOnlyCIDR_SW_HA_001(t *testing.T) {
	root := t.TempDir()
	modular := filepath.Join(root, "config")
	modules := filepath.Join(modular, "modules")
	if err := os.MkdirAll(modules, 0700); err != nil {
		t.Fatal(err)
	}
	master := "[integrations.ha]\nenabled = true\npeer_ips = [\"10.20.30.0/29\", \"2001:db8::10\"]\npeer_port = \"62026\"\ntoken = \"old-token\"\n"
	if err := os.WriteFile(filepath.Join(modular, "config.toml"), []byte(master), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modules, "10-port.toml"), []byte("[integrations.ha]\npeer_port = \"62443\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modules, "20-token.toml"), []byte("[integrations.ha]\ntoken = \"shared-secret\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadTUIHAConfig(modular, filepath.Join(root, "legacy.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || cfg.PeerPort != "62443" || cfg.Token != "shared-secret" {
		t.Fatalf("merged modular HA config = %#v", cfg)
	}
	if got := dialableTUIHAPeers(cfg.PeerIPs); !reflect.DeepEqual(got, []string{"2001:db8::10"}) {
		t.Fatalf("dialable modular peers = %v", got)
	}
}

func TestTUIHALegacyFallbackIsFailClosed_SW_HA_001(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "legacy.conf")
	wire := "SYSWARDEN_HA_ENABLED=y\nSYSWARDEN_HA_PEER_IP=192.0.2.10,10.20.30.0/29\nSYSWARDEN_HA_PEER_PORT=62026\nSYSWARDEN_HA_TOKEN=shared-secret\n"
	if err := os.WriteFile(legacy, []byte(wire), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadTUIHAConfig(filepath.Join(root, "missing-modular"), legacy)
	if err != nil {
		t.Fatal(err)
	}
	if got := dialableTUIHAPeers(cfg.PeerIPs); !reflect.DeepEqual(got, []string{"192.0.2.10"}) {
		t.Fatalf("legacy dialable peers = %v", got)
	}

	modular := filepath.Join(root, "config")
	if err := os.Mkdir(modular, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modular, "config.toml"), []byte("[integrations.ha]\nenabled=true\npeer_ips=[\"192.0.2.10\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTUIHAConfig(modular, legacy); err == nil || !strings.Contains(err.Error(), "integrations.ha.token") ||
		!strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("modular HA config without token did not provide a safe upgrade action: %v", err)
	}
	modularRoot, err := os.OpenRoot(modular)
	if err != nil {
		t.Fatal(err)
	}
	defer modularRoot.Close()
	configHandle, err := modularRoot.Open("config.toml")
	if err != nil {
		t.Fatal(err)
	}
	if err := configHandle.Chmod(0666); err != nil {
		_ = configHandle.Close()
		t.Fatal(err)
	}
	if err := configHandle.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTUIHAConfig(modular, legacy); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("TUI accepted a group/world-writable modular config containing HA credentials: %v", err)
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

func TestDashboardSnapshotTitleIsOperationalAndNeutral_SW_DOC_001(t *testing.T) {
	lower := strings.ToLower(dashboardSnapshotTitle)
	if !strings.Contains(lower, "local dashboard") {
		t.Fatalf("dashboard snapshot title = %q", dashboardSnapshotTitle)
	}
	for _, forbidden := range []string{"enterprise", "compliant", "certified"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("dashboard snapshot title contains unsupported claim %q", forbidden)
		}
	}
}

func TestEmptyRegistryMessageDoesNotClaimSecurity_SW_DOC_001(t *testing.T) {
	if emptyRegistryMessage != "Registry is empty. No active entries." {
		t.Fatalf("empty registry message = %q", emptyRegistryMessage)
	}
	for _, forbidden := range []string{"secure", "safe", "compliant", "certified"} {
		if strings.Contains(strings.ToLower(emptyRegistryMessage), forbidden) {
			t.Fatalf("empty registry message contains unsupported claim %q", forbidden)
		}
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
