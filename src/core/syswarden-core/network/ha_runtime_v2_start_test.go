package network

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"syswarden-core/firewall"
)

func engageTestHAV2LegacyFence(t *testing.T, api *haAPI) {
	t.Helper()
	drainedAt := time.Date(2026, 9, 3, 7, 59, 0, 0, time.UTC).Format(time.RFC3339)
	condition := "sw-fence-v1-" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	err := api.fence.withLock(true, false, func(root *os.Root) error {
		return publishHAFenceState(root, haFenceDiskState{
			Version: haFenceVersion, State: haFenceStateActiveDrained, Epoch: "test-epoch", Generation: 2,
			MembershipSHA256: strings.Repeat("a", 64), LegacyWriterInventorySHA256: strings.Repeat("b", 64),
			Condition: condition, DrainedAt: &drainedAt,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

func validHARuntimeV2ConfigForTest() HAConfig {
	return HAConfig{ // #nosec G101 -- the bearer token is a non-secret test fixture for HA validation
		Enabled: "y", Token: "outer-bearer-token", PeerIPs: []string{"8.8.8.20"}, Port: "62026",
		V2Enabled: true, ClusterID: "cluster-a", Epoch: 1, NodeID: "node-a", PeerID: "node-b", Role: "writer",
		V2SecretFile: "/etc/syswarden/ha/v2.secret", TLSCertFile: "/etc/syswarden/ha/node-a.crt",
		TLSKeyFile: "/etc/syswarden/ha/node-a.key", TLSCAFile: "/etc/syswarden/ha/ca.crt",
		PeerTLSName: "node-b", PeerCertSHA256: []string{strings.Repeat("a", 64)},
		StateFile: "/var/lib/syswarden/ha/replication-v2.json", TransactionFile: "/var/lib/syswarden/ha/replication-v2.wal.json",
		HeartbeatInterval: 2 * time.Second, HeartbeatTimeout: 10 * time.Second, RequestTimeout: 5 * time.Second,
	}
}

func TestHARuntimeV2ConfigurationIsExactAndOptIn(t *testing.T) {
	base := validHARuntimeV2ConfigForTest()
	if err := validateHARuntimeV2Config(base); err != nil {
		t.Fatalf("valid HA v2 runtime configuration rejected: %v", err)
	}
	tests := map[string]func(*HAConfig){
		"not opted in":            func(cfg *HAConfig) { cfg.V2Enabled = false },
		"legacy disabled":         func(cfg *HAConfig) { cfg.Enabled = "n" },
		"zero epoch":              func(cfg *HAConfig) { cfg.Epoch = 0 },
		"same node identity":      func(cfg *HAConfig) { cfg.PeerID = cfg.NodeID },
		"non-static role":         func(cfg *HAConfig) { cfg.Role = "auto" },
		"CIDR peer":               func(cfg *HAConfig) { cfg.PeerIPs = []string{"8.8.8.0/24"} },
		"noncanonical peer":       func(cfg *HAConfig) { cfg.PeerIPs = []string{"2001:DB8::20"} },
		"multicast peer":          func(cfg *HAConfig) { cfg.PeerIPs = []string{"ff02::1"} },
		"loopback peer":           func(cfg *HAConfig) { cfg.PeerIPs = []string{"127.0.0.1"} },
		"TLS name mismatch":       func(cfg *HAConfig) { cfg.PeerTLSName = "node-c" },
		"duplicate fingerprint":   func(cfg *HAConfig) { cfg.PeerCertSHA256 = []string{strings.Repeat("a", 64), strings.Repeat("a", 64)} },
		"unbounded heartbeat":     func(cfg *HAConfig) { cfg.HeartbeatTimeout = 3 * time.Minute },
		"same persistence file":   func(cfg *HAConfig) { cfg.TransactionFile = cfg.StateFile },
		"anchor collision":        func(cfg *HAConfig) { cfg.TransactionFile = cfg.StateFile + ".anchor.json" },
		"head WAL collision":      func(cfg *HAConfig) { cfg.TransactionFile = cfg.StateFile + ".head.wal.json" },
		"instance lock collision": func(cfg *HAConfig) { cfg.TransactionFile = cfg.StateFile + ".instance.lock" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.PeerIPs = append([]string(nil), base.PeerIPs...)
			candidate.PeerCertSHA256 = append([]string(nil), base.PeerCertSHA256...)
			mutate(&candidate)
			if err := validateHARuntimeV2Config(candidate); err == nil {
				t.Fatal("unsafe HA v2 runtime configuration accepted")
			}
		})
	}
}

func TestPrepareHARuntimeV2FailsClosedWithoutRecoverableFirewall(t *testing.T) {
	components, err := prepareHARuntimeV2(context.Background(), validHARuntimeV2ConfigForTest(), noOpFirewallManager{}, time.Now)
	if err == nil || components != nil || !strings.Contains(err.Error(), "recoverable firewall transaction") {
		t.Fatalf("HA v2 started without recoverable firewall capability: components=%#v err=%v", components, err)
	}
}

func TestHAV2StartupRequiresDrainedLegacyFenceAndLedger(t *testing.T) {
	fixture := newHAAPITestFixture(t, noOpFirewallManager{}, []string{"9.9.9.10"})
	if err := attestHAV2LegacyHandoff(fixture.api); err == nil || !strings.Contains(err.Error(), "active drained") {
		t.Fatalf("inactive legacy fence accepted: %v", err)
	}
	engageTestHAV2LegacyFence(t, fixture.api)
	if err := attestHAV2LegacyHandoff(fixture.api); err != nil {
		t.Fatalf("empty drained handoff rejected: %v", err)
	}
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	_, err := fixture.api.stageHATemporaryBans(
		haPeerIdentity{IP: "9.9.9.10", Scope: "9.9.9.10/32"},
		[]haTemporaryBanRequest{{IP: "8.8.8.90", TTL: time.Hour, Reason: "handoff test", Source: "bunkerweb"}}, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := attestHAV2LegacyHandoff(fixture.api); err == nil || !strings.Contains(err.Error(), "ledger to be drained") {
		t.Fatalf("non-empty legacy ledger accepted: %v", err)
	}
}

func TestPrepareHARuntimeV2AttestsTLSBeforePendingWALRecovery(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- the owner-only HA fixture directory requires execute permission
		t.Fatal(err)
	}
	cfg := validHARuntimeV2ConfigForTest()
	cfg.V2SecretFile = writeHAV2TLSFixture(t, directory, "v2.secret", []byte("0123456789abcdef0123456789abcdef"))
	cfg.TLSCertFile = writeHAV2TLSFixture(t, directory, "node-a.crt", []byte("invalid certificate"))
	cfg.TLSKeyFile = writeHAV2TLSFixture(t, directory, "node-a.key", []byte("invalid key"))
	cfg.TLSCAFile = writeHAV2TLSFixture(t, directory, "ca.crt", []byte("invalid CA"))
	cfg.StateFile = filepath.Join(directory, "replication-v2.json")
	cfg.TransactionFile = filepath.Join(directory, "replication-v2.wal.json")
	store, err := newHAV2TransactionStore(cfg.StateFile, cfg.TransactionFile, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	model := testHAV2TransactionalModel(t, store, cfg.Epoch)
	candidate, _ := cloneHAReplicationModel(model)
	operation := testHAReplicationOperation(t, "node-a", 1, "8.8.8.96", "ssh", "upsert")
	if _, err := candidate.enqueue(operation); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	if err := store.prepare(testHAV2Journal(t, store, operation, candidate, now)); err != nil {
		t.Fatal(err)
	}
	manager := newHAV2RecoverableFirewall()
	components, err := prepareHARuntimeV2(context.Background(), cfg, manager, func() time.Time { return now })
	if err == nil || components != nil || !strings.Contains(err.Error(), "mutual TLS identity") {
		t.Fatalf("invalid TLS material did not fail before recovery: components=%#v err=%v", components, err)
	}
	manager.mu.Lock()
	mutations := len(manager.mutations)
	manager.mu.Unlock()
	if mutations != 0 {
		t.Fatalf("invalid TLS material allowed %d recovery mutations", mutations)
	}
	if _, _, present, err := readHAV2Transaction(store); err != nil || !present {
		t.Fatalf("invalid TLS attestation consumed pending WAL: present=%t err=%v", present, err)
	}
}

func TestPrepareHARuntimeV2BuildsAttestedTransactionalRuntime(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- the owner-only HA fixture directory requires execute permission
		t.Fatal(err)
	}
	pki := newHAV2TestPKI(t)
	certA, keyA, _ := pki.node(t, "node-a")
	_, _, pinB := pki.node(t, "node-b")
	cfg := validHARuntimeV2ConfigForTest()
	cfg.V2SecretFile = writeHAV2TLSFixture(t, directory, "v2.secret", []byte("0123456789abcdef0123456789abcdef"))
	cfg.TLSCertFile = writeHAV2TLSFixture(t, directory, "node-a.crt", certA)
	cfg.TLSKeyFile = writeHAV2TLSFixture(t, directory, "node-a.key", keyA)
	cfg.TLSCAFile = writeHAV2TLSFixture(t, directory, "ca.crt", pki.caPEM)
	cfg.PeerCertSHA256 = []string{pinB}
	cfg.StateFile = filepath.Join(directory, "replication-v2.json")
	cfg.TransactionFile = filepath.Join(directory, "replication-v2.wal.json")
	manager := newHAV2RecoverableFirewall()
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	components, err := prepareHARuntimeV2(ctx, cfg, manager, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer components.adapter.coordinator.close()
	if components.adapter.role != haRuntimeV2Writer || components.outbound == nil || components.identity == nil || components.manager == nil {
		t.Fatalf("incomplete HA v2 runtime: %#v", components)
	}
	if _, ok := components.manager.(firewall.HAReplicationStateReporter); !ok {
		t.Fatal("attested runtime did not expose the read-only replication snapshot")
	}
	persisted, err := loadHAReplicationModel(cfg.StateFile, os.Geteuid(), cfg.ClusterID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.localNodeID != cfg.NodeID || persisted.peerNodeID != cfg.PeerID || persisted.staticRole != cfg.Role {
		t.Fatalf("runtime identity was not persisted: %#v", persisted.persistentState())
	}
	if _, err := persisted.bindRuntimeIdentity(cfg.NodeID, cfg.PeerID, string(haRuntimeV2Standby)); err == nil {
		t.Fatal("static role changed without a new cluster epoch")
	}
}

func TestPrepareHARuntimeV2RecoversPendingHeadBeforeFirewallRecovery(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- the owner-only HA fixture directory requires execute permission
		t.Fatal(err)
	}
	pki := newHAV2TestPKI(t)
	certA, keyA, _ := pki.node(t, "node-a")
	_, _, pinB := pki.node(t, "node-b")
	cfg := validHARuntimeV2ConfigForTest()
	cfg.V2SecretFile = writeHAV2TLSFixture(t, directory, "v2.secret", []byte("0123456789abcdef0123456789abcdef"))
	cfg.TLSCertFile = writeHAV2TLSFixture(t, directory, "node-a.crt", certA)
	cfg.TLSKeyFile = writeHAV2TLSFixture(t, directory, "node-a.key", keyA)
	cfg.TLSCAFile = writeHAV2TLSFixture(t, directory, "ca.crt", pki.caPEM)
	cfg.PeerCertSHA256 = []string{pinB}
	cfg.StateFile = filepath.Join(directory, "replication-v2.json")
	cfg.TransactionFile = filepath.Join(directory, "replication-v2.wal.json")

	store, err := newHAV2TransactionStore(cfg.StateFile, cfg.TransactionFile, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	model := testHAV2TransactionalModel(t, store, cfg.Epoch)
	bindTestHAV2Writer(t, store, model)
	candidate, err := cloneHAReplicationModel(model)
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.setCoordination(haCoordinationDegraded, "pending durable head"); err != nil {
		t.Fatal(err)
	}
	preDigest, _ := model.persistentStateDigest()
	candidateDigest, _ := candidate.persistentStateDigest()
	if err := store.publishHeadJournal(haV2HeadJournal{
		Version: 1, ClusterID: cfg.ClusterID, Epoch: cfg.Epoch, GenesisID: candidate.genesisID,
		PreStateSHA256: preDigest, CandidateSHA256: candidateDigest, CandidateState: candidate.persistentState(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := saveHAReplicationModel(store.statePath, store.expectedOwnerUID, candidate); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	components, err := prepareHARuntimeV2(ctx, cfg, newHAV2RecoverableFirewall(), time.Now)
	if err != nil {
		t.Fatalf("valid pending head blocked HA v2 restart: %v", err)
	}
	defer components.adapter.coordinator.close()
	defer components.adapter.transactionStore.releaseInstanceLock()
	if _, _, pending, err := components.adapter.transactionStore.readHeadJournal(); err != nil || pending {
		t.Fatalf("pending head was not recovered before startup: pending=%t err=%v", pending, err)
	}
	persisted, err := loadHAReplicationModel(cfg.StateFile, os.Geteuid(), cfg.ClusterID)
	if err != nil || persisted.coordinationState != haCoordinationDegraded {
		t.Fatalf("pending head recovered the wrong durable state: state=%v err=%v", persisted, err)
	}
}
