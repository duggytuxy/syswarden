package network

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func hasHACapability(capabilities []string, expected string) bool {
	for _, capability := range capabilities {
		if capability == expected {
			return true
		}
	}
	return false
}

func TestHAV2BunkerWebSchedulerAuthorizationIsSeparateFromPeerIdentity(t *testing.T) {
	directory := t.TempDir()
	telemetry := filepath.Join(directory, "data.json")
	if err := os.WriteFile(telemetry, []byte(`{"ok":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	api, err := newHAAPI(HAConfig{
		Enabled: "y", Token: "shared-secret", PeerIPs: []string{"9.9.9.10"}, Port: "62026",
		BunkerWebEnabled: true, BunkerWebSchedulerIPs: []string{"9.9.9.20"}, V2Enabled: true,
	}, noOpFirewallManager{}, "v4.10.0", filepath.Join(directory, "blacklist.ipv4"),
		filepath.Join(directory, "blacklist.ipv6"), telemetry, filepath.Join(directory, "bans.json"))
	if err != nil {
		t.Fatal(err)
	}
	api.localInterfaceAddresses = func() ([]netip.Addr, error) { return nil, nil }
	api.isWhitelisted = func(string) (bool, error) { return false, nil }

	for _, path := range []string{"/ha/status", "/ha/telemetry", "/ha/sync"} {
		response := requestDirectHAPath(t, api.handler(), http.MethodGet, path, "Bearer shared-secret", "", "9.9.9.20:43123")
		if response.Code != http.StatusOK {
			t.Fatalf("scheduler GET %s = %d, %q", path, response.Code, response.Body.String())
		}
	}
	peerMutation := requestDirectHAPath(t, api.handler(), http.MethodPost, "/ha/sync", "Bearer shared-secret",
		`{"ip":"8.8.8.40","ttl":300,"reason":"scheduler event","source":"bunkerweb"}`, "9.9.9.10:43123")
	if peerMutation.Code != http.StatusForbidden {
		t.Fatalf("HA peer used scheduler mutation authority: %d, %q", peerMutation.Code, peerMutation.Body.String())
	}
	schedulerStaticMutation := requestDirectHAPath(t, api.handler(), http.MethodPost, "/ha/sync", "Bearer shared-secret",
		`{"ips":["8.8.8.41"]}`, "9.9.9.20:43123")
	if schedulerStaticMutation.Code != http.StatusForbidden {
		t.Fatalf("scheduler used HA static mutation authority: %d, %q", schedulerStaticMutation.Code, schedulerStaticMutation.Body.String())
	}
	unknown := requestDirectHAPath(t, api.handler(), http.MethodGet, "/ha/status", "Bearer shared-secret", "", "9.9.9.30:43123")
	if unknown.Code != http.StatusForbidden {
		t.Fatalf("unknown API client = %d, %q", unknown.Code, unknown.Body.String())
	}
}

func TestHAV2BunkerWebRequiresExplicitSchedulerAllowlist(t *testing.T) {
	directory := t.TempDir()
	_, err := newHAAPI(HAConfig{
		Enabled: "y", Token: "shared-secret", PeerIPs: []string{"9.9.9.10"}, Port: "62026",
		BunkerWebEnabled: true, V2Enabled: true,
	}, noOpFirewallManager{}, "v4.10.0", filepath.Join(directory, "blacklist.ipv4"),
		filepath.Join(directory, "blacklist.ipv6"), filepath.Join(directory, "data.json"), filepath.Join(directory, "bans.json"))
	if err == nil {
		t.Fatal("HA v2 reused its static peer identity as the BunkerWeb scheduler allowlist")
	}
}

func TestLoadHAConfigReadsBunkerWebSchedulerAllowlist(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("integrations.bunkerweb.enabled", true)
	viper.Set("integrations.bunkerweb.scheduler_ips", []string{"192.0.2.40", "2001:db8:40::/64"})
	cfg := loadHAConfig()
	if !cfg.BunkerWebEnabled || len(cfg.BunkerWebSchedulerIPs) != 2 || cfg.BunkerWebSchedulerIPs[0] != "192.0.2.40" {
		t.Fatalf("BunkerWeb scheduler configuration was not loaded: %#v", cfg)
	}
}

func TestHAV2RetainedBunkerWebScopesRequireExactCurrentAuthorization(t *testing.T) {
	ledger := haBanLedger{Version: haLedgerVersion, Bans: []haBanLedgerRecord{{
		IP: "8.8.8.44", Source: "bunkerweb", PeerScope: "10.20.30.0/24", OriginPeerIP: "10.20.30.5",
	}}}
	tests := []struct {
		name       string
		schedulers []netip.Prefix
		wantError  bool
	}{
		{name: "identical", schedulers: []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24")}},
		{name: "removed", wantError: true},
		{name: "narrowed", schedulers: []netip.Prefix{netip.MustParsePrefix("10.20.30.5/32")}, wantError: true},
		{name: "shadowed", schedulers: []netip.Prefix{netip.MustParsePrefix("10.20.30.5/32"), netip.MustParsePrefix("10.20.30.0/24")}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := &haAPI{bunkerWebSchedulers: test.schedulers}
			err := api.attestRetainedBunkerWebSchedulerScopes(ledger)
			if (err != nil) != test.wantError {
				t.Fatalf("retained scheduler scope attestation error=%v, wantError=%t", err, test.wantError)
			}
		})
	}
}

type haBunkerWebStatusProbe struct {
	Status       string             `json:"status"`
	Capabilities []string           `json:"capabilities"`
	Replication  *haRuntimeV2Status `json:"replication_v2"`
}

func readHABunkerWebStatus(t *testing.T, api *haAPI) haBunkerWebStatusProbe {
	t.Helper()
	response := requestDirectHAPath(t, api.handler(), http.MethodGet, "/ha/status", "Bearer "+api.cfg.Token, "", "9.9.9.10:43123")
	if response.Code != http.StatusOK {
		t.Fatalf("HA status = %d, %q", response.Code, response.Body.String())
	}
	var status haBunkerWebStatusProbe
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestHAV2StatusAdvertisesBunkerWebMutationsOnlyOnHealthyWriter(t *testing.T) {
	tests := []struct {
		name         string
		role         haRuntimeV2Role
		prepare      func(*haRuntimeV2Adapter, *haReplicationCoordinator, time.Time)
		wantStatus   string
		wantMutation bool
	}{
		{
			name: "healthy writer", role: haRuntimeV2Writer, wantStatus: "online", wantMutation: true,
			prepare: func(adapter *haRuntimeV2Adapter, _ *haReplicationCoordinator, now time.Time) {
				attestHARuntimeV2Peer(adapter, now)
			},
		},
		{
			name: "healthy standby", role: haRuntimeV2Standby, wantStatus: "online",
			prepare: func(adapter *haRuntimeV2Adapter, _ *haReplicationCoordinator, now time.Time) {
				attestHARuntimeV2Peer(adapter, now)
			},
		},
		{name: "degraded writer", role: haRuntimeV2Writer, wantStatus: "degraded"},
		{
			name: "fenced writer", role: haRuntimeV2Writer, wantStatus: "fenced",
			prepare: func(_ *haRuntimeV2Adapter, coordinator *haReplicationCoordinator, _ time.Time) {
				coordinator.fence("test fence")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api, adapter, coordinator := testHARuntimeV2API(t, test.role)
			if test.prepare != nil {
				test.prepare(adapter, coordinator, api.now())
			}
			status := readHABunkerWebStatus(t, api)
			if status.Status != test.wantStatus {
				t.Fatalf("top-level status = %q, want %q", status.Status, test.wantStatus)
			}
			if status.Replication == nil || status.Replication.Role != test.role {
				t.Fatalf("replication status = %#v", status.Replication)
			}
			for _, capability := range []string{"sync_ttl", "sync_provenance"} {
				if got := hasHACapability(status.Capabilities, capability); got != test.wantMutation {
					t.Fatalf("capability %s present=%t, want %t: %v", capability, got, test.wantMutation, status.Capabilities)
				}
			}
		})
	}
}

func TestHAV2StandbySyncIncludesReplicatedClaimsWithExplicitOpaqueProvenance(t *testing.T) {
	api, _, coordinator := testHARuntimeV2API(t, haRuntimeV2Standby)
	source := haV2BunkerWebClaimSource("bunkerweb", "10.20.30.0/24")
	operation := testHAReplicationOperation(t, "node-a", 1, "8.8.8.42", source, "upsert")
	if _, err := coordinator.model.apply(operation); err != nil {
		t.Fatal(err)
	}
	ips, bans, err := api.readHASyncSnapshot(api.now())
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != operation.IP {
		t.Fatalf("standby effective sync IPs = %v", ips)
	}
	if len(bans) != 1 || bans[0].IP != operation.IP || bans[0].Source != source || bans[0].ExpiresAt != operation.ExpiresAt ||
		bans[0].Provenance != "opaque_v2" || bans[0].HAOwner != "node-a" || bans[0].Reason != "" || bans[0].PeerScope != "" || bans[0].OriginPeerIP != "" {
		t.Fatalf("standby opaque provenance = %#v", bans)
	}
}

func TestHAV2WriterSyncKeepsCompleteBunkerWebProvenance(t *testing.T) {
	api, adapter, coordinator := testHARuntimeV2API(t, haRuntimeV2Writer)
	store := testHAV2TransactionStore(t)
	initializeHAV2TransactionStoreForModel(t, store, coordinator.model)
	manager := newHAV2RecoverableFirewall()
	if err := adapter.configureTransactions(context.Background(), manager, store, api.now); err != nil {
		t.Fatal(err)
	}
	replicated, err := newHAV2ReplicatedManager(manager, adapter)
	if err != nil {
		t.Fatal(err)
	}
	api.fwManager = replicated
	attestHARuntimeV2Peer(adapter, api.now())
	response := requestDirectHAPath(t, api.handler(), http.MethodPost, "/ha/sync", "Bearer "+api.cfg.Token,
		`{"ip":"8.8.8.43","ttl":300,"reason":"BunkerWeb detection","source":"bunkerweb"}`, "9.9.9.10:43123")
	if response.Code != http.StatusOK {
		t.Fatalf("writer BunkerWeb mutation = %d, %q", response.Code, response.Body.String())
	}
	ips, bans, err := api.readHASyncSnapshot(api.now())
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "8.8.8.43" || len(bans) != 1 {
		t.Fatalf("writer sync snapshot IPs=%v bans=%#v", ips, bans)
	}
	ban := bans[0]
	if ban.Source != "bunkerweb" || ban.Reason != "BunkerWeb detection" || ban.PeerScope != "9.9.9.10/32" ||
		ban.OriginPeerIP != "9.9.9.10" || ban.Provenance != "complete" || ban.HAOwner != "" {
		t.Fatalf("writer complete provenance = %#v", ban)
	}
}
