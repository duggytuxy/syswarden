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
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"syswarden-core/firewall"
	corelogger "syswarden-core/logger"
	"testing"
	"time"

	"github.com/spf13/viper"
)

const haServerHelperEnvironment = "SYSWARDEN_HA_SERVER_HELPER"

type noOpFirewallManager struct{}

func (noOpFirewallManager) Ban(string) error          { return nil }
func (noOpFirewallManager) Unban(string) error        { return nil }
func (noOpFirewallManager) BanPermanent(string) error { return nil }
func (noOpFirewallManager) Name() string              { return "test" }
func (noOpFirewallManager) BanExpiryMode() firewall.BanExpiryMode {
	return firewall.BanExpiryExternal
}

type recordingHAFirewallManager struct {
	mu        sync.Mutex
	banned    []string
	permanent []string
	unbanned  []string
	banErr    error
	unbanErr  error
}

type recordedHATTLBan struct {
	IP  string
	TTL time.Duration
}

type recordingHANativeFirewallManager struct {
	recordingHAFirewallManager
	ttlBans []recordedHATTLBan
}

type legacyOnlyHAFirewallManager struct {
	banned []string
}

func (manager *legacyOnlyHAFirewallManager) Ban(ip string) error {
	manager.banned = append(manager.banned, ip)
	return nil
}
func (*legacyOnlyHAFirewallManager) Unban(string) error { return nil }
func (*legacyOnlyHAFirewallManager) Name() string       { return "legacy-only" }
func (*legacyOnlyHAFirewallManager) BanExpiryMode() firewall.BanExpiryMode {
	return firewall.BanExpiryExternal
}

func (manager *recordingHANativeFirewallManager) BanWithTTL(ip string, ttl time.Duration) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.ttlBans = append(manager.ttlBans, recordedHATTLBan{IP: ip, TTL: ttl})
	return manager.banErr
}

func (manager *recordingHANativeFirewallManager) ReconcileBanTTL(ip string, ttl time.Duration) error {
	return manager.BanWithTTL(ip, ttl)
}

func (*recordingHANativeFirewallManager) BanExpiryMode() firewall.BanExpiryMode {
	return firewall.BanExpiryNative
}

type haAPITestFixture struct {
	api       *haAPI
	handler   http.Handler
	directory string
	ipv4      string
	ipv6      string
	telemetry string
	ledger    string
}

func newHAAPITestFixture(t *testing.T, manager firewall.Manager, peers []string) haAPITestFixture {
	return newHAAPITestFixtureWithBunkerWeb(t, manager, peers, true)
}

func newHAAPITestFixtureWithBunkerWeb(t *testing.T, manager firewall.Manager, peers []string, enabled bool) haAPITestFixture {
	t.Helper()
	directory := t.TempDir()
	fixture := haAPITestFixture{
		directory: directory,
		ipv4:      filepath.Join(directory, "blacklist.ipv4"),
		ipv6:      filepath.Join(directory, "blacklist.ipv6"),
		telemetry: filepath.Join(directory, "data.json"),
		ledger:    filepath.Join(directory, "bans.json"),
	}
	if err := os.WriteFile(fixture.telemetry, []byte(`{"ok":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	api, err := newHAAPI(HAConfig{
		Enabled: "y", Token: "shared-secret", PeerIPs: peers, Port: "62026", BunkerWebEnabled: enabled,
	}, manager,
		"v4.02.8", fixture.ipv4, fixture.ipv6, fixture.telemetry, fixture.ledger)
	if err != nil {
		t.Fatal(err)
	}
	api.localInterfaceAddresses = func() ([]netip.Addr, error) { return nil, nil }
	api.isWhitelisted = func(string) (bool, error) { return false, nil }
	fixture.api = api
	fixture.handler = api.handler()
	return fixture
}

func TestHABunkerWebExtensionsRequireExplicitGate_SW_HA_004(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	if cfg := loadHAConfig(); cfg.BunkerWebEnabled {
		t.Fatal("BunkerWeb integration did not default to disabled")
	}
	viper.Set("integrations.bunkerweb.enabled", true)
	if cfg := loadHAConfig(); !cfg.BunkerWebEnabled {
		t.Fatal("BunkerWeb integration enable flag was not loaded")
	}

	manager := &recordingHAFirewallManager{}
	disabled := newHAAPITestFixtureWithBunkerWeb(t, manager, []string{"9.9.9.10"}, false)
	status := requestDirectHAPath(t, disabled.handler, http.MethodGet, "/ha/status", "Bearer shared-secret", "", "9.9.9.10:43123")
	if status.Code != http.StatusOK {
		t.Fatalf("disabled-gate legacy status = %d, %q", status.Code, status.Body.String())
	}
	var statusPayload struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(status.Body.Bytes(), &statusPayload); err != nil {
		t.Fatal(err)
	}
	for _, capability := range statusPayload.Capabilities {
		if capability == "sync_ttl" || capability == "sync_provenance" {
			t.Fatalf("disabled BunkerWeb capability advertised: %v", statusPayload.Capabilities)
		}
	}
	for _, request := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/ha/sync?details=true", ""},
		{http.MethodPost, "/ha/sync", `{"ip":"8.8.4.90","ttl":60,"reason":"gated","source":"bunkerweb"}`},
		{http.MethodPost, "/ha/sync", `{"bans":[{"ip":"8.8.4.90","ttl":60,"reason":"gated","source":"bunkerweb"}]}`},
		{http.MethodDelete, "/ha/sync", `{"ip":"8.8.4.90","source":"bunkerweb"}`},
	} {
		response := requestDirectHAPath(t, disabled.handler, request.method, request.path, "Bearer shared-secret", request.body, "9.9.9.10:43123")
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "integrations.bunkerweb.enabled") {
			t.Fatalf("disabled BunkerWeb %s %s = %d, %q", request.method, request.path, response.Code, response.Body.String())
		}
	}
	manager.mu.Lock()
	if len(manager.banned) != 0 || len(manager.unbanned) != 0 {
		t.Fatalf("disabled BunkerWeb extension mutated firewall: %v/%v", manager.banned, manager.unbanned)
	}
	manager.mu.Unlock()

	// Legacy authenticated HA remains available while the partner extension is
	// disabled, including the historic body and GET response shape.
	response := requestDirectHAHandler(t, disabled.handler, http.MethodPost, "Bearer shared-secret", `{"ips":["8.8.4.91"]}`)
	if response.Code != http.StatusOK {
		t.Fatalf("disabled-gate legacy POST = %d, %q", response.Code, response.Body.String())
	}
	response = requestDirectHAHandler(t, disabled.handler, http.MethodGet, "Bearer shared-secret", "")
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"ips":["8.8.4.91"]}` {
		t.Fatalf("disabled-gate legacy GET = %d, %q", response.Code, response.Body.String())
	}

	enabledManager := &recordingHAFirewallManager{}
	enabled := newHAAPITestFixtureWithBunkerWeb(t, enabledManager, []string{"9.9.9.10"}, true)
	response = requestDirectHAHandler(t, enabled.handler, http.MethodPost, "Bearer shared-secret",
		`{"ip":"8.8.4.92","ttl":60,"reason":"explicitly enabled","source":"bunkerweb"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("enabled BunkerWeb temporary POST = %d, %q", response.Code, response.Body.String())
	}
	status = requestDirectHAPath(t, enabled.handler, http.MethodGet, "/ha/status", "Bearer shared-secret", "", "9.9.9.10:43123")
	if !strings.Contains(status.Body.String(), `"sync_ttl"`) || !strings.Contains(status.Body.String(), `"sync_provenance"`) {
		t.Fatalf("enabled BunkerWeb capabilities = %q", status.Body.String())
	}
}

func (manager *recordingHAFirewallManager) Ban(ip string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.banned = append(manager.banned, ip)
	return manager.banErr
}

func (manager *recordingHAFirewallManager) BanPermanent(ip string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.permanent = append(manager.permanent, ip)
	manager.banned = append(manager.banned, ip)
	return manager.banErr
}

func (manager *recordingHAFirewallManager) Unban(ip string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.unbanned = append(manager.unbanned, ip)
	return manager.unbanErr
}

func (*recordingHAFirewallManager) Name() string { return "recording" }
func (*recordingHAFirewallManager) BanExpiryMode() firewall.BanExpiryMode {
	return firewall.BanExpiryExternal
}

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

	response = requestHAServer(t, tokenServer, http.MethodGet, "/ha/status", "", "")
	assertHAResponse(t, response, http.StatusUnauthorized, "Unauthorized")
	response = requestHAServer(t, tokenServer, http.MethodGet, "/ha/telemetry", "", "")
	assertHAResponse(t, response, http.StatusUnauthorized, "Unauthorized")
	response = requestHAServer(t, tokenServer, http.MethodGet, "/ha/status", "Bearer shared-secret", "")
	if response.status != http.StatusOK {
		t.Fatalf("authenticated status route = %d, body=%s", response.status, response.body)
	}
	var status map[string]any
	if err := json.Unmarshal([]byte(response.body), &status); err != nil {
		t.Fatal(err)
	}
	if status["version"] != "v4.02.8" || status["status"] != "online" || status["api_version"] != "2" {
		t.Fatalf("status payload = %#v", status)
	}
	capabilities, ok := status["capabilities"].([]any)
	wantCapabilities := []any{"auth_all_routes", "native_sync_fence_v1", "peer_cidr", "sync_ttl", "sync_provenance", "tls_verified_client"}
	if !ok || !reflect.DeepEqual(capabilities, wantCapabilities) {
		t.Fatalf("status capabilities = %#v", status["capabilities"])
	}
	for _, invalidToken := range []string{"", " shared-secret", "shared-secret "} {
		if _, err := newHAAPI(HAConfig{Token: invalidToken, PeerIPs: []string{"127.0.0.1"}}, noOpFirewallManager{}, "test", "/tmp/v4", "/tmp/v6", "/tmp/data", "/tmp/ledger"); err == nil {
			t.Fatalf("newHAAPI accepted token %q", invalidToken)
		}
	}

	disallowedServer := startHAServerProcess(t, "9.9.9.200", "shared-secret")
	response = requestHAServer(t, disallowedServer, http.MethodGet, "/ha/sync", "Bearer shared-secret", "")
	assertHAResponse(t, response, http.StatusForbidden, "Forbidden")
}

func TestHAV4028ClientMustUpgradeAuthWhileLegacySyncWireRemains_SW_HA_001(t *testing.T) {
	manager := &recordingHAFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})

	// v4.02.8 TUI-style status and telemetry requests carried no bearer. They
	// are intentionally rejected after hardening; the server must never fall
	// back to IP-only authentication or reveal token details.
	for _, path := range []string{"/ha/status", "/ha/telemetry"} {
		response := requestDirectHAPath(t, fixture.handler, http.MethodGet, path, "", "", "9.9.9.10:43123")
		if response.Code != http.StatusUnauthorized || strings.TrimSpace(response.Body.String()) != "Unauthorized" {
			t.Fatalf("legacy unauthenticated %s = %d, %q", path, response.Code, response.Body.String())
		}
	}

	// The historic sync body remains a supported mixed-version wire contract
	// once the old client is configured to send the mandatory bearer.
	response := requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret", `{"ips":["8.8.4.88"]}`)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated legacy sync POST = %d, %q", response.Code, response.Body.String())
	}
	response = requestDirectHAHandler(t, fixture.handler, http.MethodGet, "Bearer shared-secret", "")
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"ips":["8.8.4.88"]}` {
		t.Fatalf("authenticated legacy sync GET = %d, %q", response.Code, response.Body.String())
	}
	response = requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret", `{"ips":["8.8.4.88"]}`)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated legacy sync DELETE = %d, %q", response.Code, response.Body.String())
	}
}

func TestHAAllRoutesAuthenticateAfterCIDRAllowlist_SW_HA_001(t *testing.T) {
	manager := &recordingHAFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"10.20.30.6", "10.20.30.0/29"})
	for _, path := range []string{"/ha/sync", "/ha/status", "/ha/telemetry"} {
		for _, authorization := range []string{"", "Basic shared-secret", "Bearer wrong"} {
			response := requestDirectHAPath(t, fixture.handler, http.MethodGet, path, authorization, "", "10.20.30.2:43123")
			if response.Code != http.StatusUnauthorized || strings.TrimSpace(response.Body.String()) != "Unauthorized" {
				t.Fatalf("%s auth %q = %d, %q", path, authorization, response.Code, response.Body.String())
			}
		}
		response := requestDirectHAPath(t, fixture.handler, http.MethodGet, path, "Bearer shared-secret", "", "10.20.30.3:43123")
		if response.Code != http.StatusOK {
			t.Fatalf("CIDR-authorized %s = %d, %q", path, response.Code, response.Body.String())
		}
	}
	for _, remote := range []string{"10.20.30.8:43123", "[::ffff:10.20.30.2]:43123"} {
		response := requestDirectHAPath(t, fixture.handler, http.MethodGet, "/ha/status", "Bearer shared-secret", "", remote)
		if response.Code != http.StatusForbidden || strings.TrimSpace(response.Body.String()) != "Forbidden" {
			t.Fatalf("disallowed remote %q = %d, %q", remote, response.Code, response.Body.String())
		}
	}
	if _, err := newHAAPI(HAConfig{Token: "shared-secret", PeerIPs: []string{"10.20.30.1/29"}}, manager,
		"test", fixture.ipv4, fixture.ipv6, fixture.telemetry, fixture.ledger); err == nil {
		t.Fatal("HA API accepted a CIDR with host bits outside its mask")
	}
	for _, peer := range []string{"0.0.0.0/0", "::/0", "8.8.0.0/23", "2606:4700::/63"} {
		if _, err := newHAAPI(HAConfig{Token: "shared-secret", PeerIPs: []string{peer}}, manager,
			"test", fixture.ipv4, fixture.ipv6, fixture.telemetry, fixture.ledger); err == nil {
			t.Fatalf("HA API accepted an overbroad peer prefix %q", peer)
		}
	}
	for _, peer := range []string{"8.8.8.0/24", "2606:4700:4700::/64"} {
		if _, err := canonicalHAPeerPrefix(peer); err != nil {
			t.Fatalf("canonicalHAPeerPrefix(%q) rejected a bounded public CIDR: %v", peer, err)
		}
	}
	for _, peers := range [][]string{
		{"10.20.30.0/24", "10.20.30.0/29", "10.20.30.2"},
		{"10.20.30.2", "10.20.30.0/29", "10.20.30.0/24"},
	} {
		orderFixture := newHAAPITestFixture(t, &recordingHAFirewallManager{}, peers)
		orderFixture.api.now = func() time.Time { return time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC) }
		response := requestDirectHAPath(t, orderFixture.handler, http.MethodPost, "/ha/sync", "Bearer shared-secret",
			`{"ip":"8.8.4.7","ttl":60,"reason":"scope order","source":"claimed-source"}`, "10.20.30.2:43123")
		if response.Code != http.StatusOK {
			t.Fatalf("overlapping-scope POST = %d, %q", response.Code, response.Body.String())
		}
		ledger, err := orderFixture.api.readHALedger()
		if err != nil || len(ledger.Bans) != 1 || ledger.Bans[0].PeerScope != "10.20.30.2/32" {
			t.Fatalf("longest-prefix scope for %v = %#v, err=%v", peers, ledger.Bans, err)
		}
	}
}

func TestHAMutationValidationRejectsEntireRequestBeforeMutation_SW_HA_003(t *testing.T) {
	tooMany := make([]string, maxHAIPsPerRequest+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("192.0.%d.%d", (index/254)%254, index%254+1)
	}
	tooManyWire, err := json.Marshal(HASyncPayload{IPs: tooMany})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{name: "malformed", body: `{`, wantStatus: http.StatusBadRequest},
		{name: "unknown field", body: `{"ips":["9.9.9.1"],"future":true}`, wantStatus: http.StatusBadRequest},
		{name: "trailing value", body: `{"ips":["9.9.9.1"]}{}`, wantStatus: http.StatusBadRequest},
		{name: "invalid after valid", body: `{"ips":["9.9.9.1","../../escape"]}`, wantStatus: http.StatusBadRequest},
		{name: "too many IPs", body: string(tooManyWire), wantStatus: http.StatusRequestEntityTooLarge},
		{name: "too many bytes", body: `{"ips":[],"padding":"` + strings.Repeat("x", maxHARequestBytes) + `"}`, wantStatus: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			manager := &recordingHAFirewallManager{}
			handler, ipv4, ipv6 := directHAHandler(t, manager)
			response := requestDirectHAHandler(t, handler, http.MethodPost, "Bearer shared-secret", test.body)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, body=%q, want %d", response.Code, response.Body.String(), test.wantStatus)
			}
			manager.mu.Lock()
			if len(manager.banned) != 0 || len(manager.unbanned) != 0 {
				t.Fatalf("rejected payload mutated firewall: bans=%v unbans=%v", manager.banned, manager.unbanned)
			}
			manager.mu.Unlock()
			for _, path := range []string{ipv4, ipv6} {
				content, err := readHARootedFile(path)
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				if len(content) != 0 {
					t.Fatalf("rejected payload mutated %s: %q", path, content)
				}
			}
		})
	}
}

func TestHAMaxBytesReaderRejectsStreamingBodyBeforeMutation_SW_HA_003(t *testing.T) {
	manager := &recordingHAFirewallManager{}
	handler, ipv4, _ := directHAHandler(t, manager)
	body := `{"ips":[],"padding":"` + strings.Repeat("x", maxHARequestBytes) + `"}`
	request := httptest.NewRequest(http.MethodPost, "https://node.example/ha/sync", strings.NewReader(body))
	request.ContentLength = -1 // Exercise MaxBytesReader rather than the Content-Length fast path.
	request.RemoteAddr = "9.9.9.10:43123"
	request.Header.Set("Authorization", "Bearer shared-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("streaming oversized body = %d, %q", response.Code, response.Body.String())
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.banned) != 0 || len(manager.unbanned) != 0 {
		t.Fatalf("oversized streaming payload mutated firewall: bans=%v unbans=%v", manager.banned, manager.unbanned)
	}
	if _, err := readHARootedFile(ipv4); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversized streaming payload mutated blocklist: %v", err)
	}
}

func TestHAMutationsAreIdempotentAndCanonical_SW_HA_002(t *testing.T) {
	manager := &recordingHAFirewallManager{}
	handler, ipv4, ipv6 := directHAHandler(t, manager)
	rejected := requestDirectHAHandler(t, handler, http.MethodPost, "Bearer shared-secret", `{"ips":["8.8.8.0/24"]}`)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("CIDR mutation = %d, %q; want rejection", rejected.Code, rejected.Body.String())
	}
	manager.mu.Lock()
	if len(manager.banned) != 0 {
		t.Fatalf("CIDR rejection mutated firewall: %v", manager.banned)
	}
	manager.mu.Unlock()

	postBody := `{"ips":["9.9.9.44","9.9.9.44","2606:4700:4700:0000::44"]}`
	for attempt := 0; attempt < 2; attempt++ {
		response := requestDirectHAHandler(t, handler, http.MethodPost, "Bearer shared-secret", postBody)
		if response.Code != http.StatusOK {
			t.Fatalf("POST attempt %d = %d, %q", attempt+1, response.Code, response.Body.String())
		}
	}
	manager.mu.Lock()
	wantBans := "2606:4700:4700::44,9.9.9.44,2606:4700:4700::44,9.9.9.44"
	if strings.Join(manager.banned, ",") != wantBans {
		t.Fatalf("idempotent bans = %v", manager.banned)
	}
	manager.mu.Unlock()
	assertFileText(t, ipv4, "9.9.9.44\n")
	assertFileText(t, ipv6, "2606:4700:4700::44\n")

	deleteBody := `{"ips":["2606:4700:4700::44","9.9.9.44","9.9.9.44"]}`
	for attempt := 0; attempt < 2; attempt++ {
		response := requestDirectHAHandler(t, handler, http.MethodDelete, "Bearer shared-secret", deleteBody)
		if response.Code != http.StatusOK {
			t.Fatalf("DELETE attempt %d = %d, %q", attempt+1, response.Code, response.Body.String())
		}
	}
	manager.mu.Lock()
	wantUnbans := "2606:4700:4700::44,9.9.9.44,2606:4700:4700::44,9.9.9.44"
	if strings.Join(manager.unbanned, ",") != wantUnbans {
		t.Fatalf("idempotent unbans = %v", manager.unbanned)
	}
	manager.mu.Unlock()
	assertFileText(t, ipv4, "")
	assertFileText(t, ipv6, "")
}

func TestHAProtectedBanRejectedButExistingBanCanBeRemoved_SW_SEC_M6(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		local       []netip.Addr
		whitelisted bool
	}{
		{name: "local interface", target: "9.9.9.9", local: []netip.Addr{netip.MustParseAddr("9.9.9.9")}},
		{name: "HA peer", target: "9.9.9.10"},
		{name: "whitelist", target: "1.1.1.1", whitelisted: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			manager := &recordingHAFirewallManager{}
			fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
			fixture.api.localInterfaceAddresses = func() ([]netip.Addr, error) { return test.local, nil }
			fixture.api.isWhitelisted = func(address string) (bool, error) {
				return test.whitelisted && address == test.target, nil
			}
			writeHATestRootedFile(t, fixture.ipv4, []byte(test.target+"\n"))

			post := requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret",
				fmt.Sprintf(`{"ips":[%q]}`, test.target))
			if post.Code != http.StatusBadRequest {
				t.Fatalf("protected POST = %d, %q", post.Code, post.Body.String())
			}
			manager.mu.Lock()
			if len(manager.banned) != 0 {
				t.Fatalf("protected POST mutated firewall: %v", manager.banned)
			}
			manager.mu.Unlock()

			remove := requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret",
				fmt.Sprintf(`{"ips":[%q]}`, test.target))
			if remove.Code != http.StatusOK {
				t.Fatalf("protected DELETE = %d, %q", remove.Code, remove.Body.String())
			}
			manager.mu.Lock()
			if strings.Join(manager.unbanned, ",") != test.target {
				t.Fatalf("protected DELETE unbans = %v", manager.unbanned)
			}
			manager.mu.Unlock()
			assertFileText(t, fixture.ipv4, "")
		})
	}
}

func TestHALegacyUnsafePrefixCanOnlyBeRemoved_SW_SEC_M6(t *testing.T) {
	manager := &recordingHAFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	writeHATestRootedFile(t, fixture.ipv4, []byte("0.0.0.0/0\n"))

	get := requestDirectHAHandler(t, fixture.handler, http.MethodGet, "Bearer shared-secret", "")
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"0.0.0.0/0"`) {
		t.Fatalf("legacy prefix GET = %d, %q", get.Code, get.Body.String())
	}

	post := requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret", `{"ips":["0.0.0.0/0"]}`)
	if post.Code != http.StatusBadRequest {
		t.Fatalf("legacy prefix POST = %d, %q; want rejection", post.Code, post.Body.String())
	}

	remove := requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret", `{"ips":["0.0.0.0/0"]}`)
	if remove.Code != http.StatusOK {
		t.Fatalf("legacy prefix DELETE = %d, %q", remove.Code, remove.Body.String())
	}
	manager.mu.Lock()
	if strings.Join(manager.unbanned, ",") != "0.0.0.0/0" {
		t.Fatalf("legacy prefix DELETE unbans = %v", manager.unbanned)
	}
	if len(manager.banned) != 0 {
		t.Fatalf("legacy prefix recovery applied a ban: %v", manager.banned)
	}
	manager.mu.Unlock()
	assertFileText(t, fixture.ipv4, "")
}

func TestHALegacyPrefixWithHostBitsCanOnlyBeRemoved_SW_SEC_M6(t *testing.T) {
	manager := &recordingHAFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	writeHATestRootedFile(t, fixture.ipv4, []byte("8.8.8.129/24\n"))

	get := requestDirectHAHandler(t, fixture.handler, http.MethodGet, "Bearer shared-secret", "")
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"8.8.8.0/24"`) {
		t.Fatalf("legacy host-bit prefix GET = %d, %q", get.Code, get.Body.String())
	}

	post := requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret", `{"ips":["8.8.8.129/24"]}`)
	if post.Code != http.StatusBadRequest {
		t.Fatalf("legacy host-bit prefix POST = %d, %q; want rejection", post.Code, post.Body.String())
	}

	remove := requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret", `{"ips":["8.8.8.129/24"]}`)
	if remove.Code != http.StatusOK {
		t.Fatalf("legacy host-bit prefix DELETE = %d, %q", remove.Code, remove.Body.String())
	}
	manager.mu.Lock()
	if strings.Join(manager.unbanned, ",") != "8.8.8.0/24" {
		t.Fatalf("legacy host-bit prefix DELETE unbans = %v", manager.unbanned)
	}
	if len(manager.banned) != 0 {
		t.Fatalf("legacy host-bit prefix recovery applied a ban: %v", manager.banned)
	}
	manager.mu.Unlock()
	assertFileText(t, fixture.ipv4, "")
}

func TestHAMissingRequiredWhitelistFailsClosedBeforeMutation_SW_SEC_M6(t *testing.T) {
	manager := &recordingHAFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	fixture.api.isWhitelisted = func(string) (bool, error) {
		return false, errors.New("required whitelist source is missing")
	}
	response := requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret", `{"ips":["8.8.8.8"]}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("POST with unavailable whitelist = %d, %q", response.Code, response.Body.String())
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.banned) != 0 || len(manager.unbanned) != 0 {
		t.Fatalf("unavailable whitelist mutated firewall: bans=%v unbans=%v", manager.banned, manager.unbanned)
	}
	if _, err := readHARootedFile(fixture.ipv4); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unavailable whitelist mutated persistent blocklist: %v", err)
	}
}

func TestHAMutationDoesNotClaimSuccessWhenFirewallRejects_SW_HA_002(t *testing.T) {
	manager := &recordingHAFirewallManager{banErr: errors.New("injected ban failure")}
	handler, ipv4, _ := directHAHandler(t, manager)
	writeHATestRootedFile(t, ipv4, []byte("9.9.9.70\n"))
	response := requestDirectHAHandler(t, handler, http.MethodPost, "Bearer shared-secret", `{"ips":["9.9.9.70"]}`)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "Firewall mutation failed") {
		t.Fatalf("failed ban response = %d, %q", response.Code, response.Body.String())
	}
	manager.mu.Lock()
	if strings.Join(manager.banned, ",") != "9.9.9.70" {
		t.Fatalf("preexisting file bypassed kernel ban verification: %v", manager.banned)
	}
	manager.mu.Unlock()
	assertFileText(t, ipv4, "9.9.9.70\n")

	manager = &recordingHAFirewallManager{unbanErr: errors.New("injected unban failure")}
	handler, ipv4, _ = directHAHandler(t, manager)
	response = requestDirectHAHandler(t, handler, http.MethodDelete, "Bearer shared-secret", `{"ips":["9.9.9.70"]}`)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "Firewall reconciliation failed") {
		t.Fatalf("failed unban response = %d, %q", response.Code, response.Body.String())
	}
	manager.mu.Lock()
	if strings.Join(manager.unbanned, ",") != "9.9.9.70" {
		t.Fatalf("absent file bypassed kernel unban verification: %v", manager.unbanned)
	}
	manager.mu.Unlock()
	if _, err := readHARootedFile(ipv4); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed firewall unban created a blocklist: %v", err)
	}
}

func TestHALegacyPermanentBanFallsBackForMixedVersionManager_SW_HA_002(t *testing.T) {
	manager := &legacyOnlyHAFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	response := requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret", `{"ips":["8.8.4.80"]}`)
	if response.Code != http.StatusOK {
		t.Fatalf("mixed-version legacy POST = %d, %q", response.Code, response.Body.String())
	}
	if strings.Join(manager.banned, ",") != "8.8.4.80" {
		t.Fatalf("mixed-version Ban fallback = %v", manager.banned)
	}
	assertFileText(t, fixture.ipv4, "8.8.4.80\n")
}

func TestHATemporaryBanLedgerCollisionRenewalAndProvenance_SW_HA_004(t *testing.T) {
	manager := &recordingHANativeFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"10.20.30.6", "10.20.30.0/29"})
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	fixture.api.now = func() time.Time { return base }
	post := func(body, remote string) {
		response := requestDirectHAPath(t, fixture.handler, http.MethodPost, "/ha/sync", "Bearer shared-secret", body, remote)
		if response.Code != http.StatusOK {
			t.Fatalf("temporary POST = %d, %q", response.Code, response.Body.String())
		}
	}
	post(`{"ip":"8.8.4.44","ttl":120,"reason":"first producer","source":"producer-a"}`, "10.20.30.2:43123")
	post(`{"ip":"8.8.4.44","ttl":30,"reason":"second producer","source":"producer-b"}`, "10.20.30.3:43123")
	base = base.Add(10 * time.Second)
	post(`{"ip":"8.8.4.44","ttl":60,"reason":"renewed without shortening","source":"producer-a"}`, "10.20.30.4:43123")

	ledger, err := fixture.api.readHALedger()
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger.Bans) != 2 {
		t.Fatalf("temporary ledger records = %#v", ledger.Bans)
	}
	for _, record := range ledger.Bans {
		if record.PeerScope != "10.20.30.0/29" || record.State != haBanActive {
			t.Fatalf("temporary record scope/state = %#v", record)
		}
		if record.Source == "producer-a" {
			if record.OriginPeerIP != "10.20.30.4" || record.ExpiresAt != "2026-08-14T12:02:00Z" || record.Reason != "renewed without shortening" {
				t.Fatalf("renewed producer record = %#v", record)
			}
		}
	}
	manager.mu.Lock()
	if len(manager.ttlBans) != 3 || manager.ttlBans[1].TTL != 120*time.Second || manager.ttlBans[2].TTL != 110*time.Second {
		t.Fatalf("kernel TTL aggregation = %#v", manager.ttlBans)
	}
	manager.mu.Unlock()

	legacy := requestDirectHAPath(t, fixture.handler, http.MethodGet, "/ha/sync", "Bearer shared-secret", "", "10.20.30.5:43123")
	if strings.TrimSpace(legacy.Body.String()) != `{"ips":["8.8.4.44"]}` {
		t.Fatalf("legacy GET exposed provenance or changed shape: %q", legacy.Body.String())
	}
	details := requestDirectHAPath(t, fixture.handler, http.MethodGet, "/ha/sync?details=true&limit=1", "Bearer shared-secret", "", "10.20.30.5:43123")
	if details.Code != http.StatusOK {
		t.Fatalf("details GET = %d, %q", details.Code, details.Body.String())
	}
	var firstPage HASyncPayload
	if err := json.Unmarshal(details.Body.Bytes(), &firstPage); err != nil {
		t.Fatal(err)
	}
	if len(firstPage.Bans) != 1 || firstPage.NextCursor == "" || firstPage.Bans[0].PeerScope != "10.20.30.0/29" || firstPage.Bans[0].OriginPeerIP == "" {
		t.Fatalf("first provenance page = %s", details.Body.String())
	}
	secondPage := requestDirectHAPath(t, fixture.handler, http.MethodGet,
		"/ha/sync?details=true&limit=1&cursor="+firstPage.NextCursor, "Bearer shared-secret", "", "10.20.30.2:43123")
	var secondPayload HASyncPayload
	if err := json.Unmarshal(secondPage.Body.Bytes(), &secondPayload); err != nil || len(secondPayload.Bans) != 1 || secondPayload.NextCursor != "" {
		t.Fatalf("second provenance page = %s, err=%v", secondPage.Body.String(), err)
	}

	response := requestDirectHAPath(t, fixture.handler, http.MethodDelete, "/ha/sync", "Bearer shared-secret",
		`{"ip":"8.8.4.44","source":"producer-b"}`, "10.20.30.6:43123")
	if response.Code != http.StatusOK {
		t.Fatalf("different-scope temporary DELETE = %d, %q", response.Code, response.Body.String())
	}
	ledger, err = fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != 2 {
		t.Fatalf("different-scope DELETE crossed ownership boundary: %#v, err=%v", ledger.Bans, err)
	}
	response = requestDirectHAPath(t, fixture.handler, http.MethodDelete, "/ha/sync", "Bearer shared-secret",
		`{"ip":"8.8.4.44","source":"producer-b"}`, "10.20.30.5:43123")
	if response.Code != http.StatusOK {
		t.Fatalf("scoped temporary DELETE = %d, %q", response.Code, response.Body.String())
	}
	ledger, err = fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != 1 || ledger.Bans[0].Source != "producer-a" {
		t.Fatalf("scoped DELETE ledger = %#v, err=%v", ledger.Bans, err)
	}
	manager.mu.Lock()
	if len(manager.unbanned) != 0 || len(manager.ttlBans) != 4 || manager.ttlBans[len(manager.ttlBans)-1].TTL != 110*time.Second {
		t.Fatalf("owned delete created an absence or wrong final TTL: ttl=%v unbans=%v", manager.ttlBans, manager.unbanned)
	}
	manager.mu.Unlock()
	response = requestDirectHAPath(t, fixture.handler, http.MethodDelete, "/ha/sync", "Bearer shared-secret", `{"ip":"8.8.4.44"}`, "10.20.30.2:43123")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unowned temporary DELETE = %d, %q", response.Code, response.Body.String())
	}
}

func TestHATemporaryDeleteMutatesOnlyOwnedLedgerClaims_SW_HA_004(t *testing.T) {
	const ip = "8.8.4.45"
	noFirewall := newHAAPITestFixture(t, nil, []string{"9.9.9.10"})
	response := requestDirectHAHandler(t, noFirewall.handler, http.MethodDelete, "Bearer shared-secret",
		`{"ip":"8.8.4.45","source":"unknown"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("unknown DELETE without firewall = %d, %q", response.Code, response.Body.String())
	}
	if _, err := os.Lstat(noFirewall.ledger); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unknown DELETE without firewall created a ledger: %v", err)
	}

	manager := &recordingHAFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"10.20.30.6", "10.20.30.0/29"})
	fixture.api.now = func() time.Time { return time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC) }

	response = requestDirectHAPath(t, fixture.handler, http.MethodDelete, "/ha/sync", "Bearer shared-secret",
		`{"ip":"8.8.4.45","source":"unknown"}`, "10.20.30.5:43123")
	if response.Code != http.StatusOK {
		t.Fatalf("unknown empty-ledger DELETE = %d, %q", response.Code, response.Body.String())
	}
	if _, err := os.Lstat(fixture.ledger); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unknown empty-ledger DELETE created a ledger: %v", err)
	}
	manager.mu.Lock()
	if len(manager.banned) != 0 || len(manager.unbanned) != 0 {
		manager.mu.Unlock()
		t.Fatalf("unknown empty-ledger DELETE mutated firewall: bans=%v unbans=%v", manager.banned, manager.unbanned)
	}
	manager.mu.Unlock()

	response = requestDirectHAPath(t, fixture.handler, http.MethodPost, "/ha/sync", "Bearer shared-secret",
		`{"ip":"8.8.4.45","ttl":120,"reason":"owned claim","source":"producer-a"}`, "10.20.30.5:43123")
	if response.Code != http.StatusOK {
		t.Fatalf("owned POST = %d, %q", response.Code, response.Body.String())
	}
	ledgerBefore, err := os.ReadFile(fixture.ledger)
	if err != nil {
		t.Fatal(err)
	}
	identityBefore, err := os.Lstat(fixture.ledger)
	if err != nil {
		t.Fatal(err)
	}

	for _, request := range []struct {
		label  string
		body   string
		remote string
	}{
		{"unknown source", `{"ip":"8.8.4.45","source":"producer-b"}`, "10.20.30.4:43123"},
		{"wrong peer scope", `{"ip":"8.8.4.45","source":"producer-a"}`, "10.20.30.6:43123"},
		{"unknown IP batch member", `{"bans":[{"ip":"8.8.4.46","source":"producer-a"}]}`, "10.20.30.3:43123"},
	} {
		response = requestDirectHAPath(t, fixture.handler, http.MethodDelete, "/ha/sync", "Bearer shared-secret",
			request.body, request.remote)
		if response.Code != http.StatusOK {
			t.Fatalf("%s DELETE = %d, %q", request.label, response.Code, response.Body.String())
		}
		ledgerAfter, err := os.ReadFile(fixture.ledger)
		if err != nil {
			t.Fatal(err)
		}
		identityAfter, err := os.Lstat(fixture.ledger)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ledgerAfter, ledgerBefore) || !os.SameFile(identityBefore, identityAfter) {
			t.Fatalf("%s DELETE republished or changed the ledger", request.label)
		}
	}
	manager.mu.Lock()
	if !reflect.DeepEqual(manager.banned, []string{ip}) || len(manager.unbanned) != 0 {
		manager.mu.Unlock()
		t.Fatalf("unowned DELETE mutated firewall: bans=%v unbans=%v", manager.banned, manager.unbanned)
	}
	manager.mu.Unlock()

	response = requestDirectHAPath(t, fixture.handler, http.MethodDelete, "/ha/sync", "Bearer shared-secret",
		`{"ip":"8.8.4.45","source":"producer-a"}`, "10.20.30.3:43123")
	if response.Code != http.StatusOK {
		t.Fatalf("owned DELETE = %d, %q", response.Code, response.Body.String())
	}
	ledger, err := fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != 0 {
		t.Fatalf("owned DELETE ledger = %#v, err=%v", ledger.Bans, err)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !reflect.DeepEqual(manager.unbanned, []string{ip}) {
		t.Fatalf("owned DELETE firewall calls = %v", manager.unbanned)
	}
}

func TestHATemporaryDeletePendingClaimRetryConverges_SW_HA_004(t *testing.T) {
	const ip = "8.8.4.47"
	manager := &recordingHAFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	fixture.api.now = func() time.Time { return time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC) }
	response := requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret",
		`{"ip":"8.8.4.47","ttl":120,"reason":"retry claim","source":"producer-a"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("temporary POST = %d, %q", response.Code, response.Body.String())
	}
	manager.mu.Lock()
	manager.unbanErr = errors.New("injected temporary delete failure")
	manager.mu.Unlock()
	response = requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret",
		`{"ip":"8.8.4.47","source":"producer-a"}`)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("failed temporary DELETE = %d, %q", response.Code, response.Body.String())
	}
	ledger, err := fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != 1 || ledger.Bans[0].State != haBanPendingDelete {
		t.Fatalf("failed temporary DELETE ledger = %#v, err=%v", ledger.Bans, err)
	}
	manager.mu.Lock()
	manager.unbanErr = nil
	manager.mu.Unlock()
	response = requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret",
		`{"ip":"8.8.4.47","source":"producer-a"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("temporary DELETE retry = %d, %q", response.Code, response.Body.String())
	}
	ledger, err = fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != 0 {
		t.Fatalf("temporary DELETE retry ledger = %#v, err=%v", ledger.Bans, err)
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !reflect.DeepEqual(manager.unbanned, []string{ip, ip}) {
		t.Fatalf("temporary DELETE retry firewall calls = %v", manager.unbanned)
	}
}

func TestHATemporaryAndPermanentDeleteSemantics_SW_HA_004(t *testing.T) {
	manager := &recordingHAFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	fixture.api.now = func() time.Time { return time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC) }
	for _, request := range []struct {
		method string
		body   string
	}{
		{http.MethodPost, `{"ips":["8.8.4.50"]}`},
		{http.MethodPost, `{"ip":"8.8.4.50","ttl":300,"reason":"temporary overlap","source":"bunkerweb"}`},
		{http.MethodDelete, `{"ip":"8.8.4.50","source":"bunkerweb"}`},
	} {
		response := requestDirectHAHandler(t, fixture.handler, request.method, "Bearer shared-secret", request.body)
		if response.Code != http.StatusOK {
			t.Fatalf("overlap mutation %s = %d, %q", request.method, response.Code, response.Body.String())
		}
	}
	assertFileText(t, fixture.ipv4, "8.8.4.50\n")
	ledger, err := fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != 0 {
		t.Fatalf("temporary delete removed wrong state: %#v, %v", ledger.Bans, err)
	}
	manager.mu.Lock()
	if len(manager.unbanned) != 0 {
		t.Fatalf("temporary delete created an absence while a static ban remained: %v", manager.unbanned)
	}
	manager.mu.Unlock()

	response := requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret",
		`{"ip":"8.8.4.50","ttl":300,"reason":"temporary overlap","source":"bunkerweb"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("re-add temporary = %d, %q", response.Code, response.Body.String())
	}
	response = requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret", `{"ips":["8.8.4.50"]}`)
	if response.Code != http.StatusOK {
		t.Fatalf("legacy static DELETE = %d, %q", response.Code, response.Body.String())
	}
	assertFileText(t, fixture.ipv4, "")
	ledger, err = fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != 1 || ledger.Bans[0].State != haBanActive {
		t.Fatalf("legacy DELETE erased temporary ownership: %#v, %v", ledger.Bans, err)
	}
}

func addHAActiveTemporaryRecord(t *testing.T, fixture haAPITestFixture, ip, source string, now time.Time, ttl time.Duration) {
	t.Helper()
	if err := fixture.api.mutateHALedger(func(ledger *haBanLedger) error {
		ledger.Bans = append(ledger.Bans, haBanLedgerRecord{
			IP: ip, Source: source, Reason: "legacy delete reconciliation", PeerScope: "9.9.9.10/32",
			OriginPeerIP: "9.9.9.10", CreatedAt: now.Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339),
			ExpiresAt: now.Add(ttl).Format(time.RFC3339), State: haBanActive,
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHALegacyDeletePersistFirstReconciliationMatrix_SW_HA_002(t *testing.T) {
	const ip = "8.8.4.77"
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

	t.Run("no remaining desired state uses Unban", func(t *testing.T) {
		manager := &recordingHAFirewallManager{}
		fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
		fixture.api.now = func() time.Time { return now }
		if err := fixture.api.setStoredIP(ip, true); err != nil {
			t.Fatal(err)
		}
		response := requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret", `{"ips":["8.8.4.77"]}`)
		if response.Code != http.StatusOK {
			t.Fatalf("legacy DELETE = %d, %q", response.Code, response.Body.String())
		}
		present, err := fixture.api.storedIPPresent(ip)
		if err != nil || present {
			t.Fatalf("static persistence after DELETE = %v, err=%v", present, err)
		}
		manager.mu.Lock()
		defer manager.mu.Unlock()
		if !reflect.DeepEqual(manager.unbanned, []string{ip}) || len(manager.banned) != 0 {
			t.Fatalf("no-remaining reconciliation: bans=%v unbans=%v", manager.banned, manager.unbanned)
		}
	})

	t.Run("external temporary state uses idempotent Ban without Unban", func(t *testing.T) {
		manager := &recordingHAFirewallManager{}
		fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
		fixture.api.now = func() time.Time { return now }
		if err := fixture.api.setStoredIP(ip, true); err != nil {
			t.Fatal(err)
		}
		addHAActiveTemporaryRecord(t, fixture, ip, "external", now, 2*time.Minute)
		response := requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret", `{"ips":["8.8.4.77"]}`)
		if response.Code != http.StatusOK {
			t.Fatalf("external legacy DELETE = %d, %q", response.Code, response.Body.String())
		}
		manager.mu.Lock()
		defer manager.mu.Unlock()
		if !reflect.DeepEqual(manager.banned, []string{ip}) || len(manager.unbanned) != 0 || len(manager.permanent) != 0 {
			t.Fatalf("external reconciliation: bans=%v permanent=%v unbans=%v", manager.banned, manager.permanent, manager.unbanned)
		}
	})

	t.Run("native temporary state uses exact ReconcileBanTTL without Unban", func(t *testing.T) {
		manager := &recordingHANativeFirewallManager{}
		fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
		fixture.api.now = func() time.Time { return now }
		if err := fixture.api.setStoredIP(ip, true); err != nil {
			t.Fatal(err)
		}
		addHAActiveTemporaryRecord(t, fixture, ip, "native", now, 2*time.Minute)
		response := requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret", `{"ips":["8.8.4.77"]}`)
		if response.Code != http.StatusOK {
			t.Fatalf("native legacy DELETE = %d, %q", response.Code, response.Body.String())
		}
		manager.mu.Lock()
		defer manager.mu.Unlock()
		if len(manager.unbanned) != 0 || len(manager.ttlBans) != 1 || manager.ttlBans[0] != (recordedHATTLBan{IP: ip, TTL: 2 * time.Minute}) {
			t.Fatalf("native reconciliation: ttl=%v unbans=%v", manager.ttlBans, manager.unbanned)
		}
	})

	t.Run("remaining static state uses BanPermanent", func(t *testing.T) {
		manager := &recordingHAFirewallManager{}
		fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
		if err := fixture.api.setStoredIP(ip, true); err != nil {
			t.Fatal(err)
		}
		desired, err := fixture.api.reconcileDesiredHABanAfterRemoval(ip, now)
		if err != nil || !desired {
			t.Fatalf("static desired state = %v, err=%v", desired, err)
		}
		manager.mu.Lock()
		defer manager.mu.Unlock()
		if !reflect.DeepEqual(manager.permanent, []string{ip}) || len(manager.unbanned) != 0 {
			t.Fatalf("static reconciliation: permanent=%v unbans=%v", manager.permanent, manager.unbanned)
		}
	})

	t.Run("corrupt ledger fails after durable removal and retry converges", func(t *testing.T) {
		manager := &recordingHAFirewallManager{}
		fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
		fixture.api.now = func() time.Time { return now }
		if err := fixture.api.setStoredIP(ip, true); err != nil {
			t.Fatal(err)
		}
		writeHATestRootedFile(t, fixture.ledger, []byte(`{"version":1,"version":1,"bans":[]}`))
		response := requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret", `{"ips":["8.8.4.77"]}`)
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("corrupt-ledger DELETE = %d, %q", response.Code, response.Body.String())
		}
		present, err := fixture.api.storedIPPresent(ip)
		if err != nil || present {
			t.Fatalf("corrupt-ledger durable removal = %v, err=%v", present, err)
		}
		manager.mu.Lock()
		if len(manager.banned) != 0 || len(manager.unbanned) != 0 {
			manager.mu.Unlock()
			t.Fatalf("corrupt ledger mutated firewall: bans=%v unbans=%v", manager.banned, manager.unbanned)
		}
		manager.mu.Unlock()
		writeHATestRootedFile(t, fixture.ledger, []byte(`{"version":1,"bans":[]}`))
		response = requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret", `{"ips":["8.8.4.77"]}`)
		if response.Code != http.StatusOK {
			t.Fatalf("repaired-ledger retry = %d, %q", response.Code, response.Body.String())
		}
		manager.mu.Lock()
		defer manager.mu.Unlock()
		if !reflect.DeepEqual(manager.unbanned, []string{ip}) {
			t.Fatalf("repaired-ledger retry calls = %v", manager.unbanned)
		}
	})

	t.Run("firewall failure leaves removal idempotent for retry", func(t *testing.T) {
		manager := &recordingHAFirewallManager{unbanErr: errors.New("injected unban failure")}
		fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
		fixture.api.now = func() time.Time { return now }
		if err := fixture.api.setStoredIP(ip, true); err != nil {
			t.Fatal(err)
		}
		response := requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret", `{"ips":["8.8.4.77"]}`)
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("failed firewall DELETE = %d, %q", response.Code, response.Body.String())
		}
		present, err := fixture.api.storedIPPresent(ip)
		if err != nil || present {
			t.Fatalf("failed-firewall durable removal = %v, err=%v", present, err)
		}
		manager.mu.Lock()
		manager.unbanErr = nil
		manager.mu.Unlock()
		response = requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret", `{"ips":["8.8.4.77"]}`)
		if response.Code != http.StatusOK {
			t.Fatalf("firewall retry = %d, %q", response.Code, response.Body.String())
		}
		manager.mu.Lock()
		defer manager.mu.Unlock()
		if !reflect.DeepEqual(manager.unbanned, []string{ip, ip}) {
			t.Fatalf("firewall retry was not idempotent: %v", manager.unbanned)
		}
	})

	t.Run("native reconciliation failure retries without an Unban window", func(t *testing.T) {
		manager := &recordingHANativeFirewallManager{}
		fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
		fixture.api.now = func() time.Time { return now }
		if err := fixture.api.setStoredIP(ip, true); err != nil {
			t.Fatal(err)
		}
		addHAActiveTemporaryRecord(t, fixture, ip, "native", now, 2*time.Minute)
		manager.mu.Lock()
		manager.banErr = errors.New("injected reconcile failure")
		manager.mu.Unlock()
		response := requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret", `{"ips":["8.8.4.77"]}`)
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("failed native reconciliation = %d, %q", response.Code, response.Body.String())
		}
		present, err := fixture.api.storedIPPresent(ip)
		if err != nil || present {
			t.Fatalf("failed native reconciliation durable removal = %v, err=%v", present, err)
		}
		manager.mu.Lock()
		manager.banErr = nil
		manager.mu.Unlock()
		response = requestDirectHAHandler(t, fixture.handler, http.MethodDelete, "Bearer shared-secret", `{"ips":["8.8.4.77"]}`)
		if response.Code != http.StatusOK {
			t.Fatalf("native reconciliation retry = %d, %q", response.Code, response.Body.String())
		}
		manager.mu.Lock()
		defer manager.mu.Unlock()
		wantTTL := recordedHATTLBan{IP: ip, TTL: 2 * time.Minute}
		if len(manager.unbanned) != 0 || !reflect.DeepEqual(manager.ttlBans, []recordedHATTLBan{wantTTL, wantTTL}) {
			t.Fatalf("native retry introduced an absence or wrong TTL: unbans=%v ttl=%v", manager.unbanned, manager.ttlBans)
		}
	})
}

func TestHATemporaryBatchLimitsWorstCaseAndAtomicValidation_SW_HA_004(t *testing.T) {
	type postBan struct {
		IP     string `json:"ip"`
		TTL    int64  `json:"ttl"`
		Reason string `json:"reason"`
		Source string `json:"source"`
	}
	makeBans := func(count int) []postBan {
		bans := make([]postBan, count)
		for index := range bans {
			bans[index] = postBan{
				IP: fmt.Sprintf("8.0.%d.%d", index/250, index%250+1), TTL: 3600,
				Reason: strings.Repeat("r", maxHAReasonBytes), Source: "bunkerweb",
			}
		}
		return bans
	}
	marshalBatch := func(t *testing.T, bans any) string {
		t.Helper()
		wire, err := json.Marshal(map[string]any{"bans": bans})
		if err != nil {
			t.Fatal(err)
		}
		return string(wire)
	}

	manager := &recordingHAFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	fixture.api.now = func() time.Time { return time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC) }
	worstCase := marshalBatch(t, makeBans(maxHABansPerRequest))
	if len(worstCase) > maxHARequestBytes {
		t.Fatalf("documented 500-ban worst case is larger than request bound: %d > %d", len(worstCase), maxHARequestBytes)
	}
	response := requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret", worstCase)
	if response.Code != http.StatusOK {
		t.Fatalf("500-ban batch = %d, %q", response.Code, response.Body.String())
	}
	manager.mu.Lock()
	if len(manager.banned) != maxHABansPerRequest {
		t.Fatalf("500-ban manager calls = %d", len(manager.banned))
	}
	manager.mu.Unlock()
	ledger, err := fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != maxHABansPerRequest {
		t.Fatalf("500-ban ledger count = %d, err=%v", len(ledger.Bans), err)
	}

	manager = &recordingHAFirewallManager{}
	fixture = newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	response = requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret", marshalBatch(t, makeBans(maxHABansPerRequest+1)))
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("501-ban batch = %d, %q", response.Code, response.Body.String())
	}
	manager.mu.Lock()
	if len(manager.banned) != 0 {
		t.Fatalf("501-ban rejection mutated firewall: %v", manager.banned)
	}
	manager.mu.Unlock()

	invalid := []map[string]any{
		{"ip": "8.8.4.1", "ttl": 60, "reason": "valid first", "source": "bunkerweb"},
		{"ip": "8.8.4.2", "ttl": 0, "reason": "invalid second", "source": "bunkerweb"},
	}
	response = requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret", marshalBatch(t, invalid))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid batch item = %d, %q", response.Code, response.Body.String())
	}
	manager.mu.Lock()
	if len(manager.banned) != 0 {
		t.Fatalf("invalid item after valid item mutated firewall: %v", manager.banned)
	}
	manager.mu.Unlock()

	duplicate := postBan{IP: "8.8.4.8", TTL: 60, Reason: "duplicate", Source: "bunkerweb"}
	response = requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret", marshalBatch(t, []postBan{duplicate, duplicate}))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("identical duplicate batch = %d, %q", response.Code, response.Body.String())
	}
	manager.mu.Lock()
	if len(manager.banned) != 0 {
		t.Fatalf("identical duplicate manager calls = %v", manager.banned)
	}
	manager.mu.Unlock()
	conflict := duplicate
	conflict.TTL = 120
	response = requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret", marshalBatch(t, []postBan{duplicate, conflict}))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("conflicting duplicate batch = %d, %q", response.Code, response.Body.String())
	}
	manager.mu.Lock()
	if len(manager.banned) != 0 {
		t.Fatalf("conflicting duplicate mutated firewall: %v", manager.banned)
	}
	manager.mu.Unlock()
}

func TestHATemporaryWireUnionBoundsAndOwnedDeleteBatch_SW_HA_004(t *testing.T) {
	invalidBodies := []struct {
		method string
		body   string
	}{
		{http.MethodPost, `{"ips":["8.8.4.1"],"ip":"8.8.4.1","ttl":60,"reason":"mixed","source":"bunkerweb"}`},
		{http.MethodPost, `{"ip":"8.8.4.1","ttl":0,"reason":"bad ttl","source":"bunkerweb"}`},
		{http.MethodPost, `{"ip":"8.8.4.1","ttl":2592001,"reason":"bad ttl","source":"bunkerweb"}`},
		{http.MethodPost, `{"ip":"8.8.4.1","ttl":1.5,"reason":"bad ttl","source":"bunkerweb"}`},
		{http.MethodPost, `{"ip":"8.8.4.1","ttl":60,"reason":"","source":"bunkerweb"}`},
		{http.MethodPost, `{"ip":"8.8.4.1","ttl":60,"reason":"line\nbreak","source":"bunkerweb"}`},
		{http.MethodPost, `{"ip":"8.8.4.1","ttl":60,"reason":"valid","source":"bad source"}`},
		{http.MethodPost, `{"ip":"8.8.4.1","ttl":60,"reason":"valid","source":"` + strings.Repeat("s", maxHASourceBytes+1) + `"}`},
		{http.MethodPost, `{"ip":"8.8.4.1","ttl":60,"reason":"` + strings.Repeat("r", maxHAReasonBytes+1) + `","source":"bunkerweb"}`},
		{http.MethodPost, `{"ip":"8.8.4.1","ttl":60,"reason":"valid","source":"bunkerweb","origin_peer_ip":"10.20.30.2"}`},
		{http.MethodPost, `{"bans":[]}`},
		{http.MethodDelete, `{"ip":"8.8.4.1"}`},
		{http.MethodDelete, `{"ip":"8.8.4.1","source":"bunkerweb","reason":"forbidden"}`},
		{http.MethodDelete, `{"ip":"8.8.4.1","source":"bunkerweb","ttl":60}`},
	}
	for index, invalid := range invalidBodies {
		manager := &recordingHAFirewallManager{}
		fixture := newHAAPITestFixture(t, manager, []string{"10.20.30.0/29"})
		response := requestDirectHAPath(t, fixture.handler, invalid.method, "/ha/sync", "Bearer shared-secret", invalid.body, "10.20.30.2:43123")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid union %d = %d, %q", index, response.Code, response.Body.String())
		}
		manager.mu.Lock()
		if len(manager.banned) != 0 || len(manager.unbanned) != 0 {
			t.Fatalf("invalid union %d mutated firewall: %v/%v", index, manager.banned, manager.unbanned)
		}
		manager.mu.Unlock()
	}

	manager := &recordingHAFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"10.20.30.0/29"})
	fixture.api.now = func() time.Time { return time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC) }
	post := `{"bans":[{"ip":"8.8.4.20","ttl":60,"reason":"source a","source":"producer-a"},{"ip":"8.8.4.20","ttl":120,"reason":"source b","source":"producer-b"}]}`
	response := requestDirectHAPath(t, fixture.handler, http.MethodPost, "/ha/sync", "Bearer shared-secret", post, "10.20.30.2:43123")
	if response.Code != http.StatusOK {
		t.Fatalf("owned POST batch = %d, %q", response.Code, response.Body.String())
	}
	response = requestDirectHAPath(t, fixture.handler, http.MethodDelete, "/ha/sync", "Bearer shared-secret",
		`{"bans":[{"ip":"8.8.4.20","source":"producer-a"}]}`, "10.20.30.3:43123")
	if response.Code != http.StatusOK {
		t.Fatalf("owned DELETE batch = %d, %q", response.Code, response.Body.String())
	}
	ledger, err := fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != 1 || ledger.Bans[0].Source != "producer-b" {
		t.Fatalf("owned DELETE retained records = %#v, err=%v", ledger.Bans, err)
	}
	tooManyDeletes := make([]map[string]string, maxHABansPerRequest+1)
	for index := range tooManyDeletes {
		tooManyDeletes[index] = map[string]string{"ip": "8.8.4.20", "source": "producer-b"}
	}
	wire, err := json.Marshal(map[string]any{"bans": tooManyDeletes})
	if err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	beforeUnbans := len(manager.unbanned)
	manager.mu.Unlock()
	response = requestDirectHAPath(t, fixture.handler, http.MethodDelete, "/ha/sync", "Bearer shared-secret", string(wire), "10.20.30.4:43123")
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("501 DELETE batch = %d, %q", response.Code, response.Body.String())
	}
	manager.mu.Lock()
	if len(manager.unbanned) != beforeUnbans {
		t.Fatalf("501 DELETE batch mutated firewall: %v", manager.unbanned)
	}
	manager.mu.Unlock()
}

func TestHALedgerRejectsCorruptionSymlinkOversizeAndQuotaWithoutMutation_SW_HA_004(t *testing.T) {
	manager := &recordingHAFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	fixture.api.now = func() time.Time { return time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC) }
	assertNoFirewallMutation := func(label string) {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		if len(manager.banned) != 0 || len(manager.unbanned) != 0 {
			t.Fatalf("%s mutated firewall: bans=%v unbans=%v", label, manager.banned, manager.unbanned)
		}
	}

	if err := os.WriteFile(fixture.ledger, []byte(`{"version":1,"bans":[],"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	response := requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret",
		`{"ip":"8.8.4.1","ttl":60,"reason":"corrupt ledger","source":"bunkerweb"}`)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("corrupt ledger POST = %d, %q", response.Code, response.Body.String())
	}
	assertNoFirewallMutation("corrupt ledger")

	if err := os.Remove(fixture.ledger); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(fixture.directory, "ledger-target.json")
	if err := os.WriteFile(target, []byte(`{"version":1,"bans":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, fixture.ledger); err != nil {
		t.Fatal(err)
	}
	response = requestDirectHAHandler(t, fixture.handler, http.MethodGet, "Bearer shared-secret", "")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("symlink ledger GET = %d, %q", response.Code, response.Body.String())
	}
	assertNoFirewallMutation("symlink ledger")

	if err := os.Remove(fixture.ledger); err != nil {
		t.Fatal(err)
	}
	oversized, err := os.OpenFile(fixture.ledger, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := oversized.Truncate(maxHALedgerBytes + 1); err != nil {
		_ = oversized.Close()
		t.Fatal(err)
	}
	if err := oversized.Close(); err != nil {
		t.Fatal(err)
	}
	response = requestDirectHAHandler(t, fixture.handler, http.MethodGet, "Bearer shared-secret", "")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("oversized ledger GET = %d, %q", response.Code, response.Body.String())
	}
	assertNoFirewallMutation("oversized ledger")

	if err := os.Remove(fixture.ledger); err != nil {
		t.Fatal(err)
	}
	ledger := haBanLedger{Version: haLedgerVersion, Bans: make([]haBanLedgerRecord, maxHALedgerRecords)}
	for index := range ledger.Bans {
		ledger.Bans[index] = haBanLedgerRecord{
			IP:     fmt.Sprintf("10.%d.%d.%d", (index>>16)&255, (index>>8)&255, index&255),
			Source: "quota", Reason: "quota record", PeerScope: "9.9.9.10/32", OriginPeerIP: "9.9.9.10",
			CreatedAt: "2026-08-14T12:00:00Z", UpdatedAt: "2026-08-14T12:00:00Z",
			ExpiresAt: "2026-09-01T12:00:00Z", State: haBanActive,
		}
	}
	wire, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) > maxHALedgerBytes {
		t.Fatalf("valid quota ledger exceeds byte bound: %d", len(wire))
	}
	if err := os.WriteFile(fixture.ledger, wire, 0600); err != nil {
		t.Fatal(err)
	}
	response = requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret",
		`{"ip":"1.1.1.9","ttl":60,"reason":"over quota","source":"bunkerweb"}`)
	if response.Code != http.StatusInsufficientStorage {
		t.Fatalf("full ledger POST = %d, %q", response.Code, response.Body.String())
	}
	assertNoFirewallMutation("full ledger")
}

func TestHATemporaryPendingRecoveryExpiryAndRestart_SW_HA_004(t *testing.T) {
	manager := &recordingHAFirewallManager{banErr: errors.New("injected initial failure")}
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	fixture.api.now = func() time.Time { return base }
	response := requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret",
		`{"ip":"8.8.4.90","ttl":60,"reason":"recover after crash","source":"bunkerweb"}`)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("failed temporary apply = %d, %q", response.Code, response.Body.String())
	}
	ledger, err := fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != 1 || ledger.Bans[0].State != haBanPendingApply {
		t.Fatalf("pending recovery ledger = %#v, err=%v", ledger.Bans, err)
	}

	manager.mu.Lock()
	manager.banErr = nil
	manager.mu.Unlock()
	restarted, err := newHAAPI(fixture.api.cfg, manager, "v4.02.8", fixture.ipv4, fixture.ipv6, fixture.telemetry, fixture.ledger)
	if err != nil {
		t.Fatal(err)
	}
	restarted.localInterfaceAddresses = func() ([]netip.Addr, error) { return nil, nil }
	restarted.isWhitelisted = func(string) (bool, error) { return false, nil }
	if err := restarted.reconcileHABans(base, maxHALedgerRecords); err != nil {
		t.Fatalf("pending apply recovery: %v", err)
	}
	ledger, err = restarted.readHALedger()
	if err != nil || len(ledger.Bans) != 1 || ledger.Bans[0].State != haBanActive {
		t.Fatalf("recovered ledger = %#v, err=%v", ledger.Bans, err)
	}
	if err := restarted.reconcileHABans(base.Add(61*time.Second), maxHALedgerRecords); err != nil {
		t.Fatalf("expiry reconciliation: %v", err)
	}
	ledger, err = restarted.readHALedger()
	if err != nil || len(ledger.Bans) != 0 {
		t.Fatalf("expired ledger = %#v, err=%v", ledger.Bans, err)
	}
	manager.mu.Lock()
	if len(manager.banned) < 2 || len(manager.unbanned) != 1 || manager.unbanned[0] != "8.8.4.90" {
		t.Fatalf("restart/expiry manager calls: bans=%v unbans=%v", manager.banned, manager.unbanned)
	}
	manager.mu.Unlock()
}

func TestHAInitialLedgerReconciliationFailsClosed_SW_HA_004(t *testing.T) {
	recordWithDuplicateSource := `{"ip":"8.8.4.9","source":"producer-a","source":"producer-b","reason":"duplicate schema","peer_scope":"9.9.9.10/32","origin_peer_ip":"9.9.9.10","expires_at":"2026-08-14T13:00:00Z","created_at":"2026-08-14T12:00:00Z","updated_at":"2026-08-14T12:00:00Z","state":"active"}`
	for name, wire := range map[string]string{
		"unknown root field":     `{"version":1,"bans":[],"unexpected":true}`,
		"duplicate root field":   `{"version":1,"version":1,"bans":[]}`,
		"duplicate record field": `{"version":1,"bans":[` + recordWithDuplicateSource + `]}`,
	} {
		t.Run(name, func(t *testing.T) {
			manager := &recordingHAFirewallManager{}
			fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
			if err := os.WriteFile(fixture.ledger, []byte(wire), 0600); err != nil {
				t.Fatal(err)
			}
			if err := prepareHAServerAPI(fixture.api); err == nil {
				t.Fatal("server preparation accepted a corrupt HA ledger")
			}
			manager.mu.Lock()
			defer manager.mu.Unlock()
			if len(manager.banned) != 0 || len(manager.unbanned) != 0 {
				t.Fatalf("corrupt initial ledger mutated firewall: %v/%v", manager.banned, manager.unbanned)
			}
		})
	}
}

func TestHABlocklistPublicationFlockSymlinkAndMode_SW_HA_003(t *testing.T) {
	manager := &recordingHAFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	second, err := newHAAPI(fixture.api.cfg, manager, "v4.02.8", fixture.ipv4, fixture.ipv6, fixture.telemetry, fixture.ledger)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for index := 1; index <= 64; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			api := fixture.api
			if index%2 == 0 {
				api = second
			}
			if err := api.setStoredIP(fmt.Sprintf("8.8.4.%d", index), true); err != nil {
				t.Errorf("concurrent blocklist append: %v", err)
			}
		}()
	}
	wait.Wait()
	content, err := readHARootedFile(fixture.ipv4)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Fields(string(content))); got != 64 {
		t.Fatalf("flock publication lost updates: %d entries", got)
	}
	info, err := os.Lstat(fixture.ipv4)
	if err != nil || info.Mode().Perm() != 0600 || !info.Mode().IsRegular() {
		t.Fatalf("published blocklist mode = %v, err=%v", info, err)
	}

	if err := os.Remove(fixture.ipv4); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(fixture.directory, "operator-target")
	if err := os.WriteFile(target, []byte("operator data\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, fixture.ipv4); err != nil {
		t.Fatal(err)
	}
	response := requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret", `{"ips":["1.1.1.10"]}`)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("symlink blocklist POST = %d, %q", response.Code, response.Body.String())
	}
	targetRoot, err := os.OpenRoot(fixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer targetRoot.Close()
	targetWire, err := targetRoot.ReadFile(filepath.Base(target))
	if err != nil || string(targetWire) != "operator data\n" {
		t.Fatalf("symlink target changed: %q, %v", targetWire, err)
	}
}

func TestHAReplaceAndWAAPPersistenceShareAtomicDirectoryLock_SW_HA_003(t *testing.T) {
	fixture := newHAAPITestFixture(t, &recordingHAFirewallManager{}, []string{"9.9.9.10"})
	for index := 1; index <= 32; index++ {
		if err := fixture.api.setStoredIP(fmt.Sprintf("8.8.4.%d", index), true); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 1; index <= 32; index++ {
		index := index
		wait.Add(3)
		go func() {
			defer wait.Done()
			<-start
			if err := fixture.api.setStoredIP(fmt.Sprintf("8.8.4.%d", index), false); err != nil {
				t.Errorf("HA atomic removal: %v", err)
			}
		}()
		go func() {
			defer wait.Done()
			<-start
			if err := fixture.api.setStoredIP(fmt.Sprintf("8.8.4.%d", index+32), true); err != nil {
				t.Errorf("HA atomic replacement: %v", err)
			}
		}()
		go func() {
			defer wait.Done()
			<-start
			// This is the exact synchronous primitive used by logger.LogBan for
			// WAAP/WAF persistence, targeting the test-owned IPv4 blocklist.
			if err := corelogger.UpdatePersistentBlocklist(fixture.ipv4, fmt.Sprintf("1.1.1.%d", index), true); err != nil {
				t.Errorf("WAAP atomic persistence: %v", err)
			}
		}()
	}
	close(start)
	wait.Wait()
	content, err := readHARootedFile(fixture.ipv4)
	if err != nil {
		t.Fatal(err)
	}
	entries := strings.Fields(string(content))
	if len(entries) != 64 {
		t.Fatalf("HA/WAAP concurrent RMW retained %d entries, want 64", len(entries))
	}
	set := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		set[entry] = struct{}{}
	}
	for index := 1; index <= 32; index++ {
		if _, present := set[fmt.Sprintf("8.8.4.%d", index)]; present {
			t.Fatalf("HA removal was lost for index %d", index)
		}
		for _, expected := range []string{fmt.Sprintf("8.8.4.%d", index+32), fmt.Sprintf("1.1.1.%d", index)} {
			if _, present := set[expected]; !present {
				t.Fatalf("concurrent HA/WAAP update lost %s", expected)
			}
		}
	}
}

func TestHATelemetryResponseIsBounded_SW_HA_003(t *testing.T) {
	fixture := newHAAPITestFixture(t, &recordingHAFirewallManager{}, []string{"9.9.9.10"})
	telemetry, err := os.OpenFile(fixture.telemetry, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := telemetry.Truncate(maxHATelemetryBytes + 1); err != nil {
		_ = telemetry.Close()
		t.Fatal(err)
	}
	if err := telemetry.Close(); err != nil {
		t.Fatal(err)
	}
	response := requestDirectHAPath(t, fixture.handler, http.MethodGet, "/ha/telemetry", "Bearer shared-secret", "", "9.9.9.10:43123")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("oversized telemetry = %d, %q", response.Code, response.Body.String())
	}
}

func TestHAServerHasBoundedConnectionTimeouts_SW_HA_003(t *testing.T) {
	server := newHAServer(":62026", http.NewServeMux(), tls.Certificate{})
	if server.ReadTimeout != haReadTimeout || server.ReadHeaderTimeout != haReadHeaderTimeout || server.WriteTimeout != haWriteTimeout || server.IdleTimeout != haIdleTimeout {
		t.Fatalf("HA timeout contract = read:%s header:%s write:%s idle:%s", server.ReadTimeout, server.ReadHeaderTimeout, server.WriteTimeout, server.IdleTimeout)
	}
	if server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 {
		t.Fatal("HA server contains an unbounded connection timeout")
	}
	if server.TLSConfig == nil || server.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("HA server TLS 1.3 contract changed")
	}
}

type bunkerWebSchedulerHarness struct {
	t       *testing.T
	client  *http.Client
	baseURL string
	token   string
}

func newBunkerWebSchedulerHarness(t *testing.T, server *httptest.Server, roots *x509.CertPool, sourceIP, token string) *bunkerWebSchedulerHarness {
	t.Helper()
	localAddress := net.ParseIP(sourceIP)
	if localAddress == nil {
		t.Fatalf("invalid scheduler source IP %q", sourceIP)
	}
	dialer := &net.Dialer{
		Timeout:   2 * time.Second,
		LocalAddr: &net.TCPAddr{IP: localAddress},
	}
	transport := &http.Transport{
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots,
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &bunkerWebSchedulerHarness{
		t: t, client: &http.Client{Timeout: bunkerWebSchedulerTestHTTPTimeout, Transport: transport}, baseURL: server.URL, token: token,
	}
}

func (scheduler *bunkerWebSchedulerHarness) request(method, path string, body any) (int, []byte) {
	scheduler.t.Helper()
	var reader io.Reader
	if body != nil {
		wire, err := json.Marshal(body)
		if err != nil {
			scheduler.t.Fatal(err)
		}
		reader = bytes.NewReader(wire)
	}
	request, err := http.NewRequest(method, scheduler.baseURL+path, reader)
	if err != nil {
		scheduler.t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+scheduler.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := scheduler.client.Do(request)
	if err != nil {
		scheduler.t.Fatal(err)
	}
	defer response.Body.Close()
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 {
		scheduler.t.Fatalf("scheduler connection did not negotiate verified TLS 1.3")
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, maxHAResponseTestBytes))
	if err != nil {
		scheduler.t.Fatal(err)
	}
	return response.StatusCode, wire
}

const (
	maxHAResponseTestBytes            = 2 * 1024 * 1024
	bunkerWebSchedulerTestHTTPTimeout = 2 * time.Minute
)

// This is the SysWarden side of the BunkerWeb scheduler contract: a real
// verified TLS client is recreated with a new container IP inside the same
// configured peer CIDR, while logical ownership remains bound to that scope.
func TestBunkerWebSchedulerEndToEndContract_SW_HA_004(t *testing.T) {
	manager := &recordingHANativeFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"127.0.0.0/24"})
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	fixture.api.now = func() time.Time { return now }

	certificatePEM, privateKeyPEM, err := generateSelfSignedCertPEM()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			requireOrSkipHAServerLoopback(t, err)
		}
		t.Fatal(err)
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{
		Handler: fixture.handler, ReadHeaderTimeout: time.Second,
	}}
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("failed to install the scheduler's out-of-band HA trust bundle")
	}

	schedulerA := newBunkerWebSchedulerHarness(t, server, roots, "127.0.0.2", "shared-secret")
	wrongToken := newBunkerWebSchedulerHarness(t, server, roots, "127.0.0.2", "wrong-secret")
	statusCode, wire := wrongToken.request(http.MethodGet, "/ha/status", nil)
	if statusCode != http.StatusUnauthorized || strings.TrimSpace(string(wire)) != "Unauthorized" {
		t.Fatalf("scheduler bad bearer = %d, %q", statusCode, wire)
	}
	statusCode, wire = schedulerA.request(http.MethodGet, "/ha/status", nil)
	if statusCode != http.StatusOK {
		t.Fatalf("scheduler capabilities = %d, %q", statusCode, wire)
	}
	var status struct {
		APIVersion   string   `json:"api_version"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(wire, &status); err != nil {
		t.Fatal(err)
	}
	wantCapabilities := map[string]bool{
		"auth_all_routes": false, "peer_cidr": false, "sync_ttl": false,
		"sync_provenance": false, "tls_verified_client": false,
	}
	for _, capability := range status.Capabilities {
		if _, expected := wantCapabilities[capability]; expected {
			wantCapabilities[capability] = true
		}
	}
	for capability, present := range wantCapabilities {
		if !present {
			t.Fatalf("api_version=%q lacks capability %q: %v", status.APIVersion, capability, status.Capabilities)
		}
	}
	if status.APIVersion != "2" {
		t.Fatalf("scheduler api_version = %q", status.APIVersion)
	}
	statusCode, wire = schedulerA.request(http.MethodGet, "/ha/telemetry", nil)
	if statusCode != http.StatusOK || strings.TrimSpace(string(wire)) != `{"ok":true}` {
		t.Fatalf("authenticated scheduler telemetry = %d, %q", statusCode, wire)
	}

	type schedulerBan struct {
		IP     string `json:"ip"`
		TTL    int    `json:"ttl"`
		Reason string `json:"reason"`
		Source string `json:"source"`
	}
	bans := make([]schedulerBan, 0, maxHABansPerRequest)
	for index := 0; index < maxHABansPerRequest-1; index++ {
		bans = append(bans, schedulerBan{
			IP: fmt.Sprintf("45.200.%d.%d", index/250, index%250+1), TTL: 300,
			Reason: "scheduler detection", Source: "bunkerweb-a",
		})
	}
	// A distinct claimed source may own the same address inside the same trust
	// scope; it must not collide with or be deleted by bunkerweb-a.
	bans = append(bans, schedulerBan{
		IP: "45.200.0.1", TTL: 120, Reason: "second producer", Source: "bunkerweb-b",
	})
	statusCode, wire = schedulerA.request(http.MethodPost, "/ha/sync", map[string]any{"bans": bans})
	if statusCode != http.StatusOK {
		t.Fatalf("scheduler 500-ban POST = %d, %q", statusCode, wire)
	}

	statusCode, legacyWire := schedulerA.request(http.MethodGet, "/ha/sync", nil)
	if statusCode != http.StatusOK || bytes.Contains(legacyWire, []byte(`"bans"`)) {
		t.Fatalf("scheduler legacy GET shape = %d, %q", statusCode, legacyWire)
	}
	var legacy HASyncPayload
	if err := json.Unmarshal(legacyWire, &legacy); err != nil || len(legacy.IPs) != maxHABansPerRequest-1 {
		t.Fatalf("scheduler legacy union count = %d, err=%v", len(legacy.IPs), err)
	}
	statusCode, detailsWire := schedulerA.request(http.MethodGet, "/ha/sync?details=true&limit=500", nil)
	var details HASyncPayload
	if statusCode != http.StatusOK {
		t.Fatalf("scheduler provenance GET = %d, %q", statusCode, detailsWire)
	}
	if err := json.Unmarshal(detailsWire, &details); err != nil || len(details.Bans) != maxHABansPerRequest || details.NextCursor != "" {
		t.Fatalf("scheduler provenance page = %d records, cursor=%q, err=%v", len(details.Bans), details.NextCursor, err)
	}

	// Simulate a container restart: the scheduler's observed source address
	// changes, but its configured /24 peer scope and claimed source are stable.
	now = now.Add(10 * time.Second)
	schedulerB := newBunkerWebSchedulerHarness(t, server, roots, "127.0.0.3", "shared-secret")
	statusCode, wire = schedulerB.request(http.MethodPost, "/ha/sync", schedulerBan{
		IP: "45.200.0.1", TTL: 600, Reason: "renewed after container restart", Source: "bunkerweb-a",
	})
	if statusCode != http.StatusOK {
		t.Fatalf("scheduler renewal from changed IP = %d, %q", statusCode, wire)
	}
	ledger, err := fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != maxHABansPerRequest {
		t.Fatalf("scheduler renewal ledger = %d records, err=%v", len(ledger.Bans), err)
	}
	var renewed, secondSource *haBanLedgerRecord
	for index := range ledger.Bans {
		record := &ledger.Bans[index]
		if record.IP != "45.200.0.1" {
			continue
		}
		switch record.Source {
		case "bunkerweb-a":
			renewed = record
		case "bunkerweb-b":
			secondSource = record
		}
	}
	if renewed == nil || secondSource == nil || renewed.PeerScope != "127.0.0.0/24" ||
		renewed.OriginPeerIP != "127.0.0.3" || secondSource.OriginPeerIP != "127.0.0.2" ||
		renewed.ExpiresAt != "2026-08-14T12:10:10Z" {
		t.Fatalf("scheduler dynamic-CIDR provenance = renewed:%#v second:%#v", renewed, secondSource)
	}

	statusCode, wire = schedulerB.request(http.MethodDelete, "/ha/sync", map[string]string{
		"ip": "45.200.0.1", "source": "bunkerweb-a",
	})
	if statusCode != http.StatusOK {
		t.Fatalf("scheduler owned DELETE = %d, %q", statusCode, wire)
	}
	ledger, err = fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != maxHABansPerRequest-1 {
		t.Fatalf("scheduler owned DELETE ledger = %d records, err=%v", len(ledger.Bans), err)
	}
	for _, record := range ledger.Bans {
		if record.IP == "45.200.0.1" && record.Source == "bunkerweb-a" {
			t.Fatal("owned DELETE retained the deleted scheduler tuple")
		}
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.unbanned) != 0 || len(manager.ttlBans) == 0 || manager.ttlBans[len(manager.ttlBans)-1].TTL != 110*time.Second {
		t.Fatalf("scheduler source delete exposed address or retained wrong TTL: unbans=%v ttl=%v", manager.unbanned, manager.ttlBans)
	}
}

func startTrustedHATestServer(t *testing.T, handler http.Handler) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	certificatePEM, privateKeyPEM, err := generateSelfSignedCertPEM()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			requireOrSkipHAServerLoopback(t, err)
		}
		t.Fatal(err)
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{
		Handler: handler, ReadHeaderTimeout: time.Second,
	}}
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return server, roots
}

func TestTwoNodeLegacyHADurableBidirectionalSyncWithWAAP_BunkerGateMatrix_SW_HA_002(t *testing.T) {
	for _, bunkerWebEnabled := range []bool{false, true} {
		label := "disabled"
		if bunkerWebEnabled {
			label = "enabled"
		}
		t.Run(label, func(t *testing.T) {
			managerA := &recordingHAFirewallManager{}
			managerB := &recordingHAFirewallManager{}
			nodeA := newHAAPITestFixtureWithBunkerWeb(t, managerA, []string{"127.0.0.1"}, bunkerWebEnabled)
			nodeB := newHAAPITestFixtureWithBunkerWeb(t, managerB, []string{"127.0.0.1"}, bunkerWebEnabled)
			serverA, rootsA := startTrustedHATestServer(t, nodeA.handler)
			serverB, rootsB := startTrustedHATestServer(t, nodeB.handler)
			clientToA := newBunkerWebSchedulerHarness(t, serverA, rootsA, "127.0.0.1", "shared-secret")
			clientToB := newBunkerWebSchedulerHarness(t, serverB, rootsB, "127.0.0.1", "shared-secret")

			nodeAEntries := []string{"8.8.4.10", "8.8.4.11", "1.1.1.77"}
			nodeBEntries := []string{"2606:4700:4700::10", "2606:4700:4700::11"}
			for _, entry := range nodeAEntries[:2] {
				if err := nodeA.api.setStoredIP(entry, true); err != nil {
					t.Fatal(err)
				}
			}
			// Use the exact synchronous persistence primitive called by logger.LogBan;
			// the resulting WAAP entry must survive both HA directions.
			if err := corelogger.UpdatePersistentBlocklist(nodeA.ipv4, nodeAEntries[2], true); err != nil {
				t.Fatal(err)
			}
			for _, entry := range nodeBEntries {
				if err := nodeB.api.setStoredIP(entry, true); err != nil {
					t.Fatal(err)
				}
			}

			for label, client := range map[string]*bunkerWebSchedulerHarness{"A": clientToA, "B": clientToB} {
				statusCode, wire := client.request(http.MethodGet, "/ha/status", nil)
				hasTTL := bytes.Contains(wire, []byte(`"sync_ttl"`))
				hasProvenance := bytes.Contains(wire, []byte(`"sync_provenance"`))
				if statusCode != http.StatusOK || hasTTL != bunkerWebEnabled || hasProvenance != bunkerWebEnabled {
					t.Fatalf("node %s bunkerweb=%t capabilities = %d, %s", label, bunkerWebEnabled, statusCode, wire)
				}
			}
			statusCode, wire := clientToB.request(http.MethodPost, "/ha/sync", map[string]any{"ips": nodeAEntries})
			if statusCode != http.StatusOK {
				t.Fatalf("A -> B durable sync = %d, %q", statusCode, wire)
			}
			statusCode, wire = clientToA.request(http.MethodPost, "/ha/sync", map[string]any{"ips": nodeBEntries})
			if statusCode != http.StatusOK {
				t.Fatalf("B -> A durable sync = %d, %q", statusCode, wire)
			}
			wantUnion := append(append([]string(nil), nodeAEntries...), nodeBEntries...)
			sort.Strings(wantUnion)
			for label, node := range map[string]haAPITestFixture{"A": nodeA, "B": nodeB} {
				got, err := node.api.readStoredIPs()
				if err != nil || !reflect.DeepEqual(got, wantUnion) {
					t.Fatalf("node %s durable union = %v, err=%v, want=%v", label, got, err, wantUnion)
				}
			}

			for _, entry := range nodeAEntries {
				if err := nodeA.api.setStoredIP(entry, false); err != nil {
					t.Fatal(err)
				}
			}
			statusCode, wire = clientToB.request(http.MethodDelete, "/ha/sync", map[string]any{"ips": nodeAEntries})
			if statusCode != http.StatusOK {
				t.Fatalf("A -> B durable removal = %d, %q", statusCode, wire)
			}
			for _, entry := range nodeBEntries {
				if err := nodeB.api.setStoredIP(entry, false); err != nil {
					t.Fatal(err)
				}
			}
			statusCode, wire = clientToA.request(http.MethodDelete, "/ha/sync", map[string]any{"ips": nodeBEntries})
			if statusCode != http.StatusOK {
				t.Fatalf("B -> A durable removal = %d, %q", statusCode, wire)
			}
			for label, node := range map[string]haAPITestFixture{"A": nodeA, "B": nodeB} {
				got, err := node.api.readStoredIPs()
				if err != nil || len(got) != 0 {
					t.Fatalf("node %s final durable state = %v, err=%v", label, got, err)
				}
			}
			managerA.mu.Lock()
			if len(managerA.unbanned) != len(nodeBEntries) {
				managerA.mu.Unlock()
				t.Fatalf("node A removal calls = %v", managerA.unbanned)
			}
			managerA.mu.Unlock()
			managerB.mu.Lock()
			defer managerB.mu.Unlock()
			if len(managerB.unbanned) != len(nodeAEntries) || !slices.Contains(managerB.unbanned, "1.1.1.77") {
				t.Fatalf("node B removal calls lack WAAP entry: %v", managerB.unbanned)
			}
		})
	}
}

func TestBunkerWebElevenScenarioQualificationOwnershipMatrix_SW_HA_004(t *testing.T) {
	const (
		localPass       = "PASS"
		localNotApplied = "not-applicable"
		external        = "external-partner/not executed here"
	)
	type qualification struct {
		ID                 int    `json:"id"`
		Scenario           string `json:"scenario"`
		SysWardenStatus    string `json:"syswarden_status"`
		SysWardenEvidence  string `json:"syswarden_evidence,omitempty"`
		BunkerWebStatus    string `json:"bunkerweb_status"`
		RequiredPartnerRun string `json:"required_partner_run"`
	}
	qualifications := []qualification{
		{1, "real Layer 7 attacker is banned and pushed", localPass, "TestBunkerWebSchedulerEndToEndContract_SW_HA_004", external, "real BunkerWeb detection, scheduler request, and kernel drop"},
		{2, "temporary ban is removed after expiry", localPass, "TestHATemporaryPendingRecoveryExpiryAndRestart_SW_HA_004", external, "partner expiry and withdrawal cycle"},
		{3, "operator-owned entries survive plugin cycles", localPass, "TestHATemporaryBanLedgerCollisionRenewalAndProvenance_SW_HA_004", external, "multiple real scheduler cycles against an operator entry"},
		{4, "audit mode emits no mutations", localNotApplied, "", external, "BunkerWeb audit-mode job and request-log assertion"},
		{5, "downloaded blocklist causes a Layer 7 refusal", localPass, "TestBunkerWebSchedulerEndToEndContract_SW_HA_004 validates bounded authenticated reads", external, "BunkerWeb cache load and HTTP/preread decision"},
		{6, "whitelist takes priority over blocklist", localNotApplied, "", external, "BunkerWeb Lua decision order"},
		{7, "peer outage remains fail-open with last-known-good cache", localNotApplied, "", external, "BunkerWeb outage and recovery stack"},
		{8, "SysWarden state appears in the BunkerWeb UI", localPass, "TestBunkerWebSchedulerEndToEndContract_SW_HA_004 validates authenticated status and telemetry", external, "BunkerWeb scheduler cache and UI rendering"},
		{9, "optional real-time push meets its latency target", localNotApplied, "", external, "BunkerWeb real-time path and timing assertion"},
		{10, "TLS works in CA, fingerprint, and explicit-unsafe modes", localPass, "TestBunkerWebSchedulerEndToEndContract_SW_HA_004 validates verified TLS 1.3 CA mode only", external, "BunkerWeb CA, fingerprint, and explicitly unsafe client modes"},
		{11, "push-only cycles do not reload Nginx", localNotApplied, "", external, "BunkerWeb scheduler and process-state assertion"},
	}
	if len(qualifications) != 11 {
		t.Fatalf("qualification scenario count = %d, want 11", len(qualifications))
	}
	for index, item := range qualifications {
		if item.ID != index+1 || item.Scenario == "" || item.RequiredPartnerRun == "" {
			t.Fatalf("invalid qualification row %d: %#v", index, item)
		}
		if item.BunkerWebStatus != external {
			t.Fatalf("scenario %d falsely claims partner execution: %q", item.ID, item.BunkerWebStatus)
		}
		switch item.SysWardenStatus {
		case localPass:
			if item.SysWardenEvidence == "" {
				t.Fatalf("scenario %d marks local PASS without evidence", item.ID)
			}
		case localNotApplied:
			if item.SysWardenEvidence != "" {
				t.Fatalf("scenario %d has evidence despite not-applicable status", item.ID)
			}
		default:
			t.Fatalf("scenario %d has invalid local classification %q", item.ID, item.SysWardenStatus)
		}
	}
	wire, err := json.Marshal(qualifications)
	if err != nil {
		t.Fatal(err)
	}
	var decoded []qualification
	if err := json.Unmarshal(wire, &decoded); err != nil || !reflect.DeepEqual(decoded, qualifications) {
		t.Fatalf("qualification matrix is not stable machine-readable JSON: decoded=%#v err=%v", decoded, err)
	}
	t.Logf("BUNKERWEB_QUALIFICATION_JSON=%s", wire)
}

func directHAHandler(t *testing.T, manager *recordingHAFirewallManager) (http.Handler, string, string) {
	t.Helper()
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	return fixture.handler, fixture.ipv4, fixture.ipv6
}

func requestDirectHAHandler(t *testing.T, handler http.Handler, method, authorization, body string) *httptest.ResponseRecorder {
	t.Helper()
	return requestDirectHAPath(t, handler, method, "/ha/sync", authorization, body, "9.9.9.10:43123")
}

func requestDirectHAPath(t *testing.T, handler http.Handler, method, path, authorization, body, remoteAddress string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "https://node.example"+path, strings.NewReader(body))
	request.RemoteAddr = remoteAddress
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertFileText(t *testing.T, path, want string) {
	t.Helper()
	content, err := readHARootedFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != want {
		t.Fatalf("%s = %q, want %q", path, content, want)
	}
}

func writeHATestRootedFile(t *testing.T, path string, content []byte) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile(filepath.Base(path), content, 0600); err != nil {
		t.Fatal(err)
	}
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
	viper.Set("integrations.bunkerweb.enabled", true)
	if tlsDirectory := os.Getenv("SYSWARDEN_HA_TEST_TLS_DIR"); tlsDirectory != "" {
		haTLSDir = filepath.Clean(tlsDirectory)
	}
	if dataDirectory := os.Getenv("SYSWARDEN_HA_TEST_DATA_DIR"); dataDirectory != "" {
		dataDirectory = filepath.Clean(dataDirectory)
		if err := os.MkdirAll(dataDirectory, 0700); err != nil {
			panic(err)
		}
		haRuntimeBlacklistIPv4 = filepath.Join(dataDirectory, "blacklist.ipv4")
		haRuntimeBlacklistIPv6 = filepath.Join(dataDirectory, "blacklist.ipv6")
		haRuntimeTelemetryFile = filepath.Join(dataDirectory, "telemetry.json")
		haRuntimeBanLedgerFile = filepath.Join(dataDirectory, "bans.json")
		if err := os.WriteFile(haRuntimeTelemetryFile, []byte("{}"), 0600); err != nil {
			panic(err)
		}
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
		"SYSWARDEN_HA_TEST_DATA_DIR="+t.TempDir(),
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
