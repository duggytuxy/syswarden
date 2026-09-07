package network

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"syswarden-core/firewall"
)

type bunkerWebCompatibilitySnapshot struct {
	SchemaVersion          string            `json:"schema_version"`
	RetrievedAt            string            `json:"retrieved_at"`
	Repository             string            `json:"repository"`
	Ref                    string            `json:"ref"`
	Commit                 string            `json:"commit"`
	CommitVerified         bool              `json:"commit_verified"`
	PluginVersion          string            `json:"plugin_version"`
	Blobs                  map[string]string `json:"blobs"`
	APIVersion             string            `json:"api_version"`
	StatusPath             string            `json:"status_path"`
	SyncPath               string            `json:"sync_path"`
	Authentication         string            `json:"authentication"`
	RequiredCapabilities   []string          `json:"required_capabilities"`
	HAV2RoleAwareRouting   bool              `json:"ha_v2_role_aware_mutation_routing"`
	HAV2RequiresManifest   bool              `json:"ha_v2_multi_peer_requires_complete_fence_manifest"`
	MaximumLegacyItems     int               `json:"maximum_legacy_items"`
	MaximumProvenanceItems int               `json:"maximum_provenance_items"`
	MinimumTTLSeconds      int64             `json:"minimum_ttl_seconds"`
	MaximumTTLSeconds      int64             `json:"maximum_ttl_seconds"`
	MaximumReasonBytes     int               `json:"maximum_reason_bytes"`
	MaximumSourceBytes     int               `json:"maximum_source_bytes"`
	TLSModes               []string          `json:"tls_modes"`
	MutationMethods        []string          `json:"mutation_methods"`
}

func loadBunkerWebCompatibilitySnapshot(t *testing.T) bunkerWebCompatibilitySnapshot {
	t.Helper()
	wire, err := os.ReadFile("testdata/bunkerweb-plugin-contract-v1.11.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var snapshot bunkerWebCompatibilitySnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("compatibility snapshot has trailing JSON: %v", err)
	}
	return snapshot
}

func TestBunkerWebPublicPluginSnapshotMatchesSysWardenAPIv2_SW_INT_002(t *testing.T) {
	snapshot := loadBunkerWebCompatibilitySnapshot(t)
	wantBlobs := map[string]string{
		"syswarden/jobs/syswarden-ban-push.py": "a5b0024d7ece77b5da91817f6699a5f3dfc6784e",
		"syswarden/jobs/syswarden_client.py":   "71e1895be5025b95423ac334cab889ebe3894af9",
		"syswarden/jobs/syswarden_helpers.py":  "8ce4f1bc48dcc0c3fffa1d3c550b542790edb612",
		"syswarden/plugin.json":                "434059b55dcd4d0c46ebf975920187943a83f63c",
	}
	if snapshot.SchemaVersion != "syswarden.bunkerweb-compatibility.v1" ||
		snapshot.Repository != "https://github.com/bunkerity/bunkerweb-plugins" ||
		snapshot.Ref != "dev" || snapshot.Commit != "90fe786729cf6912203196aac4d17517ab2fa3cb" ||
		!snapshot.CommitVerified || snapshot.PluginVersion != "1.11" || !reflect.DeepEqual(snapshot.Blobs, wantBlobs) {
		t.Fatalf("unexpected public plugin provenance: %#v", snapshot)
	}
	if _, err := time.Parse(time.RFC3339, snapshot.RetrievedAt); err != nil {
		t.Fatalf("invalid retrieval timestamp: %v", err)
	}
	if snapshot.APIVersion != "2" || snapshot.StatusPath != "/ha/status" || snapshot.SyncPath != "/ha/sync" ||
		snapshot.Authentication != "bearer" || snapshot.MaximumLegacyItems != maxHAIPsPerRequest ||
		snapshot.MaximumProvenanceItems != maxHABansPerRequest || snapshot.MinimumTTLSeconds != int64(firewall.MinimumBanTTL/time.Second) ||
		snapshot.MaximumTTLSeconds != int64(firewall.MaximumBanTTL/time.Second) || snapshot.MaximumReasonBytes != maxHAReasonBytes ||
		snapshot.MaximumSourceBytes != maxHASourceBytes {
		t.Fatalf("public plugin bounds differ from SysWarden API v2: %#v", snapshot)
	}
	if snapshot.HAV2RoleAwareRouting || !snapshot.HAV2RequiresManifest {
		t.Fatalf("public plugin HA v2 compatibility scope is overstated: %#v", snapshot)
	}
	sort.Strings(snapshot.RequiredCapabilities)
	if !reflect.DeepEqual(snapshot.RequiredCapabilities, []string{"sync_provenance", "sync_ttl"}) {
		t.Fatalf("required capabilities = %v", snapshot.RequiredCapabilities)
	}
	sort.Strings(snapshot.MutationMethods)
	if !reflect.DeepEqual(snapshot.MutationMethods, []string{http.MethodDelete, http.MethodPost}) {
		t.Fatalf("mutation methods = %v", snapshot.MutationMethods)
	}
	sort.Strings(snapshot.TLSModes)
	if !reflect.DeepEqual(snapshot.TLSModes, []string{"ca_bundle", "explicit_insecure", "sha256_fingerprint"}) {
		t.Fatalf("TLS modes = %v", snapshot.TLSModes)
	}
}

func TestBunkerWebProvenanceMutationsRemainRetryIdempotent_SW_INT_002(t *testing.T) {
	manager := &recordingHANativeFirewallManager{}
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	body := `{"bans":[{"ip":"8.8.4.40","ttl":300,"reason":"BunkerWeb ban","source":"bunkerweb-cluster-a"}]}`
	for attempt := 0; attempt < 2; attempt++ {
		response := requestDirectHAPath(t, fixture.handler, http.MethodPost, "/ha/sync", "Bearer shared-secret", body, "9.9.9.10:43123")
		if response.Code != http.StatusOK {
			t.Fatalf("POST retry %d = %d, %q", attempt, response.Code, response.Body.String())
		}
	}
	ledger, err := fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != 1 || ledger.Bans[0].Source != "bunkerweb-cluster-a" {
		t.Fatalf("retried POST changed ownership cardinality: bans=%#v err=%v", ledger.Bans, err)
	}
	deleteBody := `{"bans":[{"ip":"8.8.4.40","source":"bunkerweb-cluster-a"}]}`
	wantDeleted := []string{`{"status":"ok","deleted":1}`, `{"status":"ok","deleted":0}`}
	for attempt, want := range wantDeleted {
		response := requestDirectHAPath(t, fixture.handler, http.MethodDelete, "/ha/sync", "Bearer shared-secret", deleteBody, "9.9.9.10:43123")
		if response.Code != http.StatusOK || string(bytes.TrimSpace(response.Body.Bytes())) != want {
			t.Fatalf("DELETE retry %d = %d, %q, want %q", attempt, response.Code, response.Body.String(), want)
		}
	}
	ledger, err = fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != 0 {
		t.Fatalf("retried DELETE retained ownership: bans=%#v err=%v", ledger.Bans, err)
	}
}
