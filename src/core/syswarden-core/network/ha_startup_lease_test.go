package network

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func startupLeaseTestConfig(t *testing.T) HAConfig {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- owner-only temporary fixture
		t.Fatal(err)
	}
	pki := newHAV2TestPKI(t)
	cert, key, _ := pki.node(t, "node-a")
	_, _, pin := pki.node(t, "node-b")
	cfg := validHARuntimeV2ConfigForTest()
	cfg.PeerIPs = []string{"198.18.0.2"}
	cfg.V2SecretFile = writeHAV2TLSFixture(t, directory, "v2.secret", bytes.Repeat([]byte{0x41}, 32))
	cfg.TLSCertFile = writeHAV2TLSFixture(t, directory, "node-a.crt", cert)
	cfg.TLSKeyFile = writeHAV2TLSFixture(t, directory, "node-a.key", key)
	cfg.TLSCAFile = writeHAV2TLSFixture(t, directory, "ca.crt", pki.caPEM)
	cfg.PeerCertSHA256 = []string{pin}
	cfg.StateFile = filepath.Join(directory, "replication-v2.json")
	cfg.TransactionFile = filepath.Join(directory, "replication-v2.wal.json")
	return cfg
}

func configureStartupLeaseTest(t *testing.T, cfg HAConfig) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	values := map[string]any{
		"enabled": cfg.Enabled == "y", "token": cfg.Token, "peer_ips": cfg.PeerIPs, "peer_port": cfg.Port,
		"v2_enabled": cfg.V2Enabled, "cluster_id": cfg.ClusterID, "epoch": cfg.Epoch,
		"node_id": cfg.NodeID, "peer_id": cfg.PeerID, "role": cfg.Role,
		"v2_secret_file": cfg.V2SecretFile, "tls_cert_file": cfg.TLSCertFile,
		"tls_key_file": cfg.TLSKeyFile, "tls_ca_file": cfg.TLSCAFile,
		"peer_tls_name": cfg.PeerTLSName, "peer_cert_sha256": cfg.PeerCertSHA256,
		"state_file": cfg.StateFile, "transaction_file": cfg.TransactionFile,
		"heartbeat_interval_seconds": int(cfg.HeartbeatInterval / time.Second),
		"heartbeat_timeout_seconds":  int(cfg.HeartbeatTimeout / time.Second),
		"request_timeout_seconds":    int(cfg.RequestTimeout / time.Second),
	}
	for key, value := range values {
		viper.Set("integrations.ha."+key, value)
	}
	viper.Set("integrations.bunkerweb.enabled", cfg.BunkerWebEnabled)
	viper.Set("integrations.bunkerweb.scheduler_ips", cfg.BunkerWebSchedulerIPs)
	oldIPv4, oldIPv6 := haRuntimeBlacklistIPv4, haRuntimeBlacklistIPv6
	oldTelemetry, oldLedger, oldTLS := haRuntimeTelemetryFile, haRuntimeBanLedgerFile, haTLSDir
	t.Cleanup(func() {
		haRuntimeBlacklistIPv4, haRuntimeBlacklistIPv6 = oldIPv4, oldIPv6
		haRuntimeTelemetryFile, haRuntimeBanLedgerFile, haTLSDir = oldTelemetry, oldLedger, oldTLS
	})
	directory := filepath.Dir(cfg.StateFile)
	haRuntimeBlacklistIPv4 = filepath.Join(directory, "blacklist.ipv4")
	haRuntimeBlacklistIPv6 = filepath.Join(directory, "blacklist.ipv6")
	haRuntimeTelemetryFile = filepath.Join(directory, "telemetry.json")
	haRuntimeBanLedgerFile = filepath.Join(directory, "bans.json")
	haTLSDir = filepath.Join(directory, "legacy-tls")
	// A version query cannot invoke an installed product or any fixture process.
	t.Setenv("PATH", t.TempDir())
}

func assertStartupLeaseHeld(t *testing.T, cfg HAConfig) {
	t.Helper()
	other, err := reserveHARuntimeV2Lease(cfg)
	if other != nil {
		other.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "another HA v2 runtime holds the instance lock") {
		t.Fatalf("instance lease was not held: %v", err)
	}
}

func TestHAStartupLeaseRefusesBusyStartupBeforeSharedInitialization(t *testing.T) {
	cfg := startupLeaseTestConfig(t)
	configureStartupLeaseTest(t, cfg)
	controller := newHAFenceTombstoneTestController(t, filepath.Join(filepath.Dir(cfg.StateFile), "fence"))
	publishHAFenceTestTombstones(t, controller, []haFenceEpochEvent{testHAFenceEngagementEvent()})
	publishHAFenceTestState(t, controller, activeHAFenceTestState(8))
	lease, err := ReserveHAStartupLease()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	for _, path := range []string{cfg.StateFile, cfg.TransactionFile} {
		if err := os.WriteFile(path, []byte("retained temporary fixture bytes\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	paths := []string{filepath.Join(controller.directory, haFenceStateName), cfg.StateFile, cfg.TransactionFile}
	before := make(map[string][]byte, len(paths))
	for _, path := range paths {
		before[path], err = os.ReadFile(path) // #nosec G304 -- every path is a fixed fence, state or WAL fixture under this test's private temporary directory
		if err != nil {
			t.Fatal(err)
		}
	}
	manager := newHAV2RecoverableFirewall()
	if _, err := StartHAServerContext(context.Background(), manager); err == nil || !strings.Contains(err.Error(), "another HA v2 runtime holds the instance lock") {
		t.Fatalf("busy startup was not refused at reservation: %v", err)
	}
	for _, path := range paths {
		after, err := os.ReadFile(path) // #nosec G304 -- every path is the same private temporary fixture captured before the refused startup
		if err != nil || !bytes.Equal(before[path], after) {
			t.Fatalf("refused startup changed retained fixture %s: %v", path, err)
		}
	}
	if len(manager.mutations) != 0 {
		t.Fatal("refused startup reached firewall recovery")
	}
	assertStartupLeaseHeld(t, cfg)
}

func TestHAStartupLeaseBindsConfigurationAndTransfersOnlyOnce(t *testing.T) {
	cfg := startupLeaseTestConfig(t)
	cfg.BunkerWebSchedulerIPs = []string{"198.18.0.3"}
	lease, err := reserveHARuntimeV2Lease(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	originalStore, originalFile := lease.store, lease.store.instanceLock
	for name, change := range map[string]func(*HAConfig){
		"token":     func(other *HAConfig) { other.Token = "changed-fixture-token" },
		"port":      func(other *HAConfig) { other.Port = "62028" },
		"state":     func(other *HAConfig) { other.StateFile += ".other" },
		"role":      func(other *HAConfig) { other.Role = "standby" },
		"peer":      func(other *HAConfig) { other.PeerIPs = []string{"198.18.0.4"} },
		"pin":       func(other *HAConfig) { other.PeerCertSHA256 = []string{strings.Repeat("b", 64)} },
		"scheduler": func(other *HAConfig) { other.BunkerWebSchedulerIPs = nil },
	} {
		t.Run(name, func(t *testing.T) {
			other := cfg
			change(&other)
			if store, err := lease.take(other); err == nil || store != nil {
				t.Fatal("changed configuration consumed the reserved lease")
			}
			assertStartupLeaseHeld(t, cfg)
		})
	}
	store, err := lease.take(cfg)
	if err != nil || store != originalStore || store.instanceLock != originalFile {
		t.Fatalf("handoff did not preserve the exact store and lock file: %v", err)
	}
	defer store.releaseInstanceLock()
	lease.Close()
	if second, err := lease.take(cfg); err == nil || second != nil {
		t.Fatal("a consumed lease was reused")
	}
	assertStartupLeaseHeld(t, cfg)
}

func TestHAStartupLeaseCopiesSlicesAndRejectsClosedHandle(t *testing.T) {
	cfg := startupLeaseTestConfig(t)
	cfg.BunkerWebSchedulerIPs = []string{"198.18.0.3"}
	original := cfg
	original.PeerIPs = slices.Clone(cfg.PeerIPs)
	original.PeerCertSHA256 = slices.Clone(cfg.PeerCertSHA256)
	original.BunkerWebSchedulerIPs = slices.Clone(cfg.BunkerWebSchedulerIPs)
	lease, err := reserveHARuntimeV2Lease(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	cfg.PeerIPs[0] = "198.18.0.4"
	cfg.PeerCertSHA256[0] = strings.Repeat("b", 64)
	cfg.BunkerWebSchedulerIPs[0] = "198.18.0.5"
	if store, err := lease.take(cfg); err == nil || store != nil {
		t.Fatal("caller slice mutations changed the reservation binding")
	}
	store, err := lease.take(original)
	if err != nil {
		t.Fatalf("original configuration was not preserved: %v", err)
	}
	store.releaseInstanceLock()
	closed, err := reserveHARuntimeV2Lease(original)
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	successor, err := reserveHARuntimeV2Lease(original)
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Close()
	if store, err := closed.take(original); err == nil || store != nil {
		t.Fatal("closed lease was reused")
	}
	closed.Close()
	lease.Close()
	assertStartupLeaseHeld(t, original)
}

func TestHAStartupLeaseFailedPreparationReleasesConsumedLease(t *testing.T) {
	for _, stage := range []string{"api", "handoff", "secret", "identity", "recovery"} {
		t.Run(stage, func(t *testing.T) {
			cfg := startupLeaseTestConfig(t)
			if stage == "api" {
				cfg.BunkerWebEnabled = true
			}
			configureStartupLeaseTest(t, cfg)
			if stage != "api" && stage != "handoff" {
				controller := newHAFenceTombstoneTestController(t, filepath.Join(filepath.Dir(cfg.StateFile), "fence"))
				publishHAFenceTestTombstones(t, controller, []haFenceEpochEvent{testHAFenceEngagementEvent()})
				publishHAFenceTestState(t, controller, activeHAFenceTestState(8))
			}
			want := "scheduler"
			switch stage {
			case "handoff":
				want = "active drained"
			case "secret":
				want = "message secret"
				if err := os.Remove(cfg.V2SecretFile); err != nil {
					t.Fatal(err)
				}
			case "identity":
				want = "mutual TLS identity"
				writeHAV2TLSFixture(t, filepath.Dir(cfg.TLSCertFile), filepath.Base(cfg.TLSCertFile), []byte("invalid fixture certificate"))
			case "recovery":
				want = "head transaction"
				writeHAV2TLSFixture(t, filepath.Dir(cfg.StateFile), filepath.Base(cfg.StateFile)+".head.wal.json", []byte("invalid fixture journal"))
			}
			lease, err := ReserveHAStartupLease()
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if _, err := StartHAServerContextWithLease(ctx, newHAV2RecoverableFirewall(), lease); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("expected %s preparation failure: %v", stage, err)
			}
			successor, err := reserveHARuntimeV2Lease(cfg)
			if err != nil {
				t.Fatalf("failed %s preparation retained the lease: %v", stage, err)
			}
			defer successor.Close()
			lease.Close()
			assertStartupLeaseHeld(t, cfg)
		})
	}
}

func TestHAStartupLeaseRuntimeKeepsTransferredFileAcrossCancellation(t *testing.T) {
	cfg := startupLeaseTestConfig(t)
	lease, err := reserveHARuntimeV2Lease(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	file := lease.store.instanceLock
	store, err := lease.take(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.releaseInstanceLock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	components, err := prepareHARuntimeV2WithLease(ctx, cfg, newHAV2RecoverableFirewall(), time.Now, store)
	if err != nil {
		t.Fatal(err)
	}
	defer components.adapter.coordinator.close()
	if components.adapter.transactionStore != store || store.instanceLock != file {
		t.Fatal("runtime preparation replaced the reserved lease")
	}
	retainHAV2InstanceLease(store)
	t.Cleanup(func() {
		haV2RetainedLeases.Lock()
		defer haV2RetainedLeases.Unlock()
		haV2RetainedLeases.stores = slices.DeleteFunc(haV2RetainedLeases.stores, func(retained *haV2TransactionStore) bool {
			return retained == store
		})
	})
	lease.Close()
	cancel()
	assertStartupLeaseHeld(t, cfg)
}

func TestHAStartupLeaseLegacyAndRejectedConfigKeepOwnership(t *testing.T) {
	cfg := startupLeaseTestConfig(t)
	configureStartupLeaseTest(t, cfg)
	lease, err := ReserveHAStartupLease()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	viper.Set("integrations.ha.token", "different-fixture-token")
	if _, err := StartHAServerContextWithLease(context.Background(), noOpFirewallManager{}, lease); err == nil {
		t.Fatal("changed configuration accepted a reserved lease")
	}
	assertStartupLeaseHeld(t, cfg)
	viper.Set("integrations.ha.v2_enabled", false)
	if _, err := StartHAServerContextWithLease(context.Background(), noOpFirewallManager{}, lease); err == nil {
		t.Fatal("legacy startup accepted a v2 reservation")
	}
	assertStartupLeaseHeld(t, cfg)
	optional, err := ReserveHAStartupLease()
	if err != nil || optional != nil {
		t.Fatalf("legacy mode required a reservation: %v", err)
	}
	optional.Close()
	viper.Set("integrations.ha.enabled", false)
	if _, err := StartHAServerContextWithLease(context.Background(), noOpFirewallManager{}, nil); err != nil {
		t.Fatalf("disabled legacy mode did not preserve startup behavior: %v", err)
	}
}
