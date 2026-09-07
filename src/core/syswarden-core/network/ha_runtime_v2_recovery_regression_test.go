package network

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type haV2LoopbackDoer struct {
	handler              http.Handler
	remote               string
	loseFirstReplication bool
	lost                 bool
}

func (doer *haV2LoopbackDoer) Do(request *http.Request) (*http.Response, error) {
	request.RemoteAddr = doer.remote
	request.TLS = &tls.ConnectionState{}
	recorder := httptest.NewRecorder()
	doer.handler.ServeHTTP(recorder, request)
	if doer.loseFirstReplication && !doer.lost && request.URL.Path == "/ha/v2/replication" && recorder.Code == http.StatusNoContent {
		doer.lost = true
		return nil, errors.New("simulated lost response after peer commit")
	}
	return recorder.Result(), nil
}

func TestHAV2LostReplicationResponseDrainsDurableOutboxAfterDegradedHeartbeat(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	clock := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

	writerModel, _ := newHAReplicationModel("cluster-a")
	if _, err := writerModel.bindRuntimeIdentity("node-a", "node-b", string(haRuntimeV2Writer)); err != nil {
		t.Fatal(err)
	}
	writerCoordinator, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", secret, writerModel)
	_ = writerCoordinator.activate()
	writerAdapter, _ := newHARuntimeV2Adapter(writerCoordinator, haRuntimeV2Writer, "9.9.9.20", 5*time.Second)
	writerStore := testHAV2TransactionStore(t)
	initializeHAV2TransactionStoreForModel(t, writerStore, writerModel)
	writerFirewall := newHAV2RecoverableFirewall()
	if err := writerAdapter.configureTransactions(context.Background(), writerFirewall, writerStore, func() time.Time { return clock }); err != nil {
		t.Fatal(err)
	}
	attestHARuntimeV2Peer(writerAdapter, clock)
	if err := writerAdapter.applyLocalTarget("8.8.8.210", haV2LocalRuntimeSource, "upsert", time.Hour, false); err != nil {
		t.Fatal(err)
	}

	standbyFixture := newHAAPITestFixture(t, noOpFirewallManager{}, []string{"9.9.9.10"})
	standbyModel, _ := newHAReplicationModel("cluster-a")
	if _, err := standbyModel.bindRuntimeIdentity("node-b", "node-a", string(haRuntimeV2Standby)); err != nil {
		t.Fatal(err)
	}
	standbyCoordinator, _ := newHAReplicationCoordinator("cluster-a", "node-b", "node-a", secret, standbyModel)
	_ = standbyCoordinator.activate()
	standbyAdapter, _ := newHARuntimeV2Adapter(standbyCoordinator, haRuntimeV2Standby, "9.9.9.10", 5*time.Second)
	standbyStore := testHAV2TransactionStore(t)
	initializeHAV2TransactionStoreForModel(t, standbyStore, standbyModel)
	standbyFirewall := newHAV2RecoverableFirewall()
	if err := standbyAdapter.configureTransactions(context.Background(), standbyFirewall, standbyStore, func() time.Time { return clock }); err != nil {
		t.Fatal(err)
	}
	standbyAdapter.peerCertificateVerifier = func(*tls.ConnectionState) error { return nil }
	standbyFixture.api.replicationV2 = standbyAdapter
	standbyFixture.api.now = func() time.Time { return clock }

	doer := &haV2LoopbackDoer{handler: standbyFixture.api.handler(), remote: "9.9.9.10:43123", loseFirstReplication: true}
	outbound, err := newHARuntimeV2Outbound(writerAdapter, doer, "https://9.9.9.20:62026", standbyFixture.api.cfg.Token, writerStore.persist, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	outbound.now = func() time.Time { return clock }
	if err := outbound.step(context.Background()); err == nil {
		t.Fatal("lost committed response was not reported")
	}
	if writerCoordinator.state != haCoordinationDegraded || len(writerCoordinator.model.outbox) != 1 {
		t.Fatalf("lost response state=%s outbox=%d", writerCoordinator.state, len(writerCoordinator.model.outbox))
	}
	standbyFirewall.mu.Lock()
	mutationsAfterCommit := len(standbyFirewall.mutations)
	standbyFirewall.mu.Unlock()
	if mutationsAfterCommit != 1 {
		t.Fatalf("standby commit count=%d, want 1", mutationsAfterCommit)
	}

	clock = clock.Add(time.Second)
	if err := outbound.step(context.Background()); err != nil {
		t.Fatalf("degraded idempotent delivery could not acknowledge: %v", err)
	}
	if len(writerCoordinator.model.outbox) != 0 || standbyCoordinator.state != haCoordinationRecovering {
		t.Fatalf("retry did not converge delivery: writer outbox=%d standby=%s", len(writerCoordinator.model.outbox), standbyCoordinator.state)
	}
	standbyFirewall.mu.Lock()
	mutationsAfterRetry := len(standbyFirewall.mutations)
	standbyFirewall.mu.Unlock()
	if mutationsAfterRetry != 1 {
		t.Fatalf("idempotent replay repeated firewall mutation: %d", mutationsAfterRetry)
	}
	unexpected := haReplicationOperation{
		SchemaVersion: haReplicationSchemaVersion, ClusterID: "cluster-a", Epoch: 1,
		NodeID: "node-a", Sequence: 2, Owner: "node-a", Source: "unexpected", IP: "8.8.8.213", Action: "upsert",
		IssuedAt: clock.Format(time.RFC3339), ExpiresAt: clock.Add(time.Hour).Format(time.RFC3339),
	}
	unexpected.OperationID, err = haReplicationOperationDigest(unexpected)
	if err != nil {
		t.Fatal(err)
	}
	unexpectedWire, err := writerCoordinator.envelope(unexpected, clock)
	if err != nil {
		t.Fatal(err)
	}
	unbudgeted := testHARuntimeV2Request(standbyFixture.api, "/ha/v2/replication", standbyFixture.api.cfg.Token, "9.9.9.10:43123", unexpectedWire)
	if unbudgeted.Code != http.StatusConflict || len(standbyCoordinator.model.activeClaims(clock)) != 1 {
		t.Fatalf("recovery delivery budget admitted a new mutation: response=%d claims=%#v", unbudgeted.Code, standbyCoordinator.model.snapshot())
	}
	durableWriter, err := loadHAReplicationModel(writerStore.statePath, os.Geteuid(), "cluster-a")
	if err != nil || len(durableWriter.outbox) != 0 {
		t.Fatalf("durable acknowledgement missing: outbox=%d err=%v", len(durableWriter.outbox), err)
	}
	durableStandby, err := loadHAReplicationModel(standbyStore.statePath, os.Geteuid(), "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	restartedFirewall := newHAV2RecoverableFirewall()
	if err := standbyStore.reconcile(context.Background(), restartedFirewall, durableStandby, clock); err != nil {
		t.Fatal(err)
	}
	restartedFirewall.mu.Lock()
	_, restored := restartedFirewall.targets["8.8.8.210"]
	restartedFirewall.mu.Unlock()
	if !restored {
		t.Fatal("standby restart did not replay the committed replicated ban")
	}
}

func TestHAV2AcknowledgementAllowsOneCheckpointConvergenceWindow(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 30, 0, 0, time.UTC)
	secret := []byte("0123456789abcdef0123456789abcdef")
	writer := testHAV2WriterAdapter(t)
	operation := haReplicationOperation{
		SchemaVersion: haReplicationSchemaVersion, ClusterID: "cluster-a", Epoch: 1,
		NodeID: "node-a", Sequence: 1, Owner: "node-a", Source: "ssh", IP: "8.8.8.214", Action: "upsert",
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	var err error
	operation.OperationID, err = haReplicationOperationDigest(operation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.coordinator.model.enqueue(operation); err != nil {
		t.Fatal(err)
	}
	writer.coordinator.model.compact(now)
	if err := writer.acknowledgeOutbound(operation.OperationID, func(*haReplicationModel) error { return nil }, now); err != nil {
		t.Fatal(err)
	}

	peerModel, _ := newHAReplicationModel("cluster-a")
	peerCoordinator, _ := newHAReplicationCoordinator("cluster-a", "node-b", "node-a", secret, peerModel)
	_ = peerCoordinator.activate()
	peer, _ := newHARuntimeV2Adapter(peerCoordinator, haRuntimeV2Standby, "192.0.2.10", 5*time.Second)
	staleHeartbeat, _ := peer.heartbeat(now.Add(time.Second))
	if err := writer.receiveHeartbeat(staleHeartbeat, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if writer.coordinator.state != haCoordinationHealthy {
		t.Fatalf("stale in-flight checkpoint forced recovery before convergence grace: %s", writer.coordinator.state)
	}
	if _, err := peerModel.apply(operation); err != nil {
		t.Fatal(err)
	}
	peerModel.compact(now.Add(2 * time.Second))
	matchingHeartbeat, _ := peer.heartbeat(now.Add(2 * time.Second))
	if err := writer.receiveHeartbeat(matchingHeartbeat, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if writer.coordinator.state != haCoordinationHealthy || !writer.checkpointGraceUntil.IsZero() {
		t.Fatalf("matching checkpoint did not close convergence grace: state=%s grace=%s", writer.coordinator.state, writer.checkpointGraceUntil)
	}
}

func TestHAV2BunkerWebClaimCannotOverwriteOrDeleteLocalClaim(t *testing.T) {
	api, adapter, coordinator := testHARuntimeV2API(t, haRuntimeV2Writer)
	clock := time.Date(2026, 9, 7, 13, 0, 0, 0, time.UTC)
	api.now = func() time.Time { return clock }
	store := testHAV2TransactionStore(t)
	initializeHAV2TransactionStoreForModel(t, store, coordinator.model)
	underlying := newHAV2RecoverableFirewall()
	if err := adapter.configureTransactions(context.Background(), underlying, store, func() time.Time { return clock }); err != nil {
		t.Fatal(err)
	}
	replicated, err := newHAV2ReplicatedManager(underlying, adapter)
	if err != nil {
		t.Fatal(err)
	}
	api.fwManager = replicated
	attestHARuntimeV2Peer(adapter, clock)
	if err := replicated.BanWithTTL("8.8.8.211", 2*time.Hour); err != nil {
		t.Fatal(err)
	}

	post := requestDirectHAPath(t, api.handler(), http.MethodPost, "/ha/sync", "Bearer "+api.cfg.Token,
		`{"bans":[{"ip":"8.8.8.211","ttl":300,"reason":"BunkerWeb collision","source":"ui"}]}`, "9.9.9.10:43123")
	if post.Code != http.StatusOK {
		t.Fatalf("BunkerWeb ban response=%d body=%q", post.Code, post.Body.String())
	}
	claims := coordinator.model.activeClaims(clock)
	if len(claims) != 2 {
		t.Fatalf("same-IP local and BunkerWeb claims collapsed: %#v", coordinator.model.snapshot())
	}
	var localExpiry time.Time
	for _, claim := range claims {
		if claim.Source == haV2LocalRuntimeSource {
			localExpiry, err = parseCanonicalHATime(claim.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if localExpiry != clock.Add(2*time.Hour) {
		t.Fatalf("BunkerWeb shortened local expiry to %s", localExpiry)
	}
	underlying.mu.Lock()
	mutationsBeforeSweep := len(underlying.mutations)
	underlying.mu.Unlock()
	if err := api.reconcileHABans(clock, maxHALedgerRecords); err != nil {
		t.Fatal(err)
	}
	underlying.mu.Lock()
	mutationsAfterSweep := len(underlying.mutations)
	underlying.mu.Unlock()
	if mutationsAfterSweep != mutationsBeforeSweep {
		t.Fatalf("active BunkerWeb ledger replayed on every sweep: before=%d after=%d", mutationsBeforeSweep, mutationsAfterSweep)
	}

	deleteResponse := requestDirectHAPath(t, api.handler(), http.MethodDelete, "/ha/sync", "Bearer "+api.cfg.Token,
		`{"bans":[{"ip":"8.8.8.211","source":"ui"}]}`, "9.9.9.10:43123")
	if deleteResponse.Code != http.StatusOK {
		t.Fatalf("BunkerWeb delete response=%d body=%q", deleteResponse.Code, deleteResponse.Body.String())
	}
	claims = coordinator.model.activeClaims(clock)
	if len(claims) != 1 || claims[0].Source != haV2LocalRuntimeSource {
		t.Fatalf("BunkerWeb delete removed local ownership: %#v", coordinator.model.snapshot())
	}
	underlying.mu.Lock()
	target, present := underlying.targets["8.8.8.211"]
	underlying.mu.Unlock()
	if !present || target.TTL != 2*time.Hour {
		t.Fatalf("effective local target was not retained: %#v present=%t", target, present)
	}

	durable, err := loadHAReplicationModel(store.statePath, os.Geteuid(), "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	restartedFirewall := newHAV2RecoverableFirewall()
	if err := store.reconcile(context.Background(), restartedFirewall, durable, clock.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	restartedFirewall.mu.Lock()
	_, restored := restartedFirewall.targets["8.8.8.211"]
	restartedFirewall.mu.Unlock()
	if !restored {
		t.Fatal("restart resurrected the BunkerWeb delete over the retained local claim")
	}

	resync := requestDirectHAPath(t, api.handler(), http.MethodPost, "/ha/sync", "Bearer "+api.cfg.Token,
		`{"bans":[{"ip":"8.8.8.211","ttl":300,"reason":"BunkerWeb resync","source":"ui"}]}`, "9.9.9.10:43123")
	if resync.Code != http.StatusOK || len(coordinator.model.activeClaims(clock)) != 2 {
		t.Fatalf("BunkerWeb resync did not restore only its namespaced claim: response=%d claims=%#v", resync.Code, coordinator.model.snapshot())
	}
	clock = clock.Add(6 * time.Minute)
	attestHARuntimeV2Peer(adapter, clock)
	if err := api.reconcileHABans(clock, maxHALedgerRecords); err != nil {
		t.Fatal(err)
	}
	claims = coordinator.model.activeClaims(clock)
	if len(claims) != 1 || claims[0].Source != haV2LocalRuntimeSource {
		t.Fatalf("BunkerWeb expiry removed or replaced local claim: %#v", coordinator.model.snapshot())
	}
	ledger, err := api.readHALedger()
	if err != nil || len(ledger.Bans) != 0 {
		t.Fatalf("expired BunkerWeb provenance was not finalized: ledger=%#v err=%v", ledger, err)
	}
}

func TestHAV2BunkerWebClaimNamespaceSeparatesSourcesAndPeerScopes(t *testing.T) {
	first := haV2BunkerWebClaimSource("ui", "10.0.0.2/32")
	otherSource := haV2BunkerWebClaimSource("scheduler", "10.0.0.2/32")
	otherPeer := haV2BunkerWebClaimSource("ui", "10.0.0.3/32")
	if first == otherSource || first == otherPeer || otherSource == otherPeer {
		t.Fatalf("BunkerWeb provenance namespaces collided: %q %q %q", first, otherSource, otherPeer)
	}
	for _, source := range []string{first, otherSource, otherPeer} {
		if source == haV2LocalRuntimeSource || !validHASource(source) {
			t.Fatalf("invalid or local-colliding BunkerWeb claim source %q", source)
		}
	}
}

func TestHAV2RestartAcceptsDurableWriterWithRetainedBunkerWebLedger(t *testing.T) {
	fixture := newHAAPITestFixture(t, noOpFirewallManager{}, []string{"9.9.9.0/24"})
	engageTestHAV2LegacyFence(t, fixture.api)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- the owner-only recovery fixture directory requires execute permission
		t.Fatal(err)
	}
	fixture.api.cfg.V2Enabled = true
	fixture.api.cfg.ClusterID = "cluster-a"
	fixture.api.cfg.Epoch = 1
	fixture.api.cfg.NodeID = "node-a"
	fixture.api.cfg.PeerID = "node-b"
	fixture.api.cfg.Role = string(haRuntimeV2Writer)
	fixture.api.cfg.StateFile = filepath.Join(directory, "replication-v2.json")
	fixture.api.cfg.TransactionFile = filepath.Join(directory, "replication-v2.wal.json")
	now := time.Date(2026, 9, 7, 14, 0, 0, 0, time.UTC)
	fixture.api.now = func() time.Time { return now }
	_, err := fixture.api.stageHATemporaryBans(haPeerIdentity{IP: "9.9.9.10", Scope: "9.9.9.0/24"},
		[]haTemporaryBanRequest{{IP: "8.8.8.212", TTL: time.Hour, Reason: "restart", Source: "scheduler"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := attestHAV2LegacyHandoff(fixture.api); err == nil || !strings.Contains(err.Error(), "first activation") {
		t.Fatalf("first activation adopted an unbound ledger: %v", err)
	}
	store, err := newHAV2TransactionStore(fixture.api.cfg.StateFile, fixture.api.cfg.TransactionFile, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	model, err := store.loadOrInitialize("cluster-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := model.bindRuntimeIdentity("node-a", "node-b", string(haRuntimeV2Writer)); err != nil {
		t.Fatal(err)
	}
	if err := store.persist(model); err != nil {
		t.Fatal(err)
	}
	if err := attestHAV2LegacyHandoff(fixture.api); err == nil || !strings.Contains(err.Error(), "not represented") {
		t.Fatalf("pending provenance without a durable HA v2 claim was accepted: %v", err)
	}
	bunkerWebClaim := haReplicationOperation{
		SchemaVersion: haReplicationSchemaVersion, ClusterID: "cluster-a", Epoch: 1,
		NodeID: "node-a", Sequence: 1, Owner: "node-a",
		Source: haV2BunkerWebClaimSource("scheduler", "9.9.9.0/24"), IP: "8.8.8.212", Action: "upsert",
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	bunkerWebClaim.OperationID, err = haReplicationOperationDigest(bunkerWebClaim)
	if err != nil {
		t.Fatal(err)
	}
	preparedClaim, err := cloneHAReplicationModel(model)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preparedClaim.enqueue(bunkerWebClaim); err != nil {
		t.Fatal(err)
	}
	if err := store.prepare(testHAV2Journal(t, store, bunkerWebClaim, preparedClaim, now)); err != nil {
		t.Fatal(err)
	}
	if err := attestHAV2LegacyHandoff(fixture.api); err != nil {
		t.Fatalf("prepared BunkerWeb claim journal was rejected before state publication: %v", err)
	}
	model, recovered, err := store.recover(context.Background(), newHAV2RecoverableFirewall(), "cluster-a", 1,
		"node-a", "node-b", string(haRuntimeV2Writer), now)
	if err != nil || !recovered {
		t.Fatalf("recover prepared BunkerWeb claim journal: recovered=%t err=%v", recovered, err)
	}
	fixture.api.bunkerWebSchedulers = nil
	if err := attestHAV2LegacyHandoff(fixture.api); err == nil || !strings.Contains(err.Error(), "scheduler authority") {
		t.Fatalf("removed scheduler scope was accepted with retained provenance: %v", err)
	}
	fixture.api.bunkerWebSchedulers = []netip.Prefix{netip.MustParsePrefix("9.9.9.10/32")}
	if err := attestHAV2LegacyHandoff(fixture.api); err == nil || !strings.Contains(err.Error(), "scheduler authority") {
		t.Fatalf("narrowed scheduler scope was accepted with retained provenance: %v", err)
	}
	fixture.api.bunkerWebSchedulers = []netip.Prefix{netip.MustParsePrefix("9.9.9.0/24")}
	if err := attestHAV2LegacyHandoff(fixture.api); err != nil {
		t.Fatalf("durable writer restart rejected retained provenance ledger: %v", err)
	}

	headCandidate, err := cloneHAReplicationModel(model)
	if err != nil {
		t.Fatal(err)
	}
	if err := headCandidate.setCoordination(haCoordinationDegraded, "pending restart head"); err != nil {
		t.Fatal(err)
	}
	preDigest, _ := model.persistentStateDigest()
	headDigest, _ := headCandidate.persistentStateDigest()
	if err := store.publishHeadJournal(haV2HeadJournal{
		Version: 1, ClusterID: "cluster-a", Epoch: 1, GenesisID: model.genesisID,
		PreStateSHA256: preDigest, CandidateSHA256: headDigest, CandidateState: headCandidate.persistentState(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := saveHAReplicationModel(store.statePath, store.expectedOwnerUID, headCandidate); err != nil {
		t.Fatal(err)
	}
	if err := attestHAV2LegacyHandoff(fixture.api); err != nil {
		t.Fatalf("valid pending head rejected retained provenance ledger: %v", err)
	}
	if err := store.recoverHeadJournal("cluster-a", 1); err != nil {
		t.Fatal(err)
	}

	firewallCandidate, err := cloneHAReplicationModel(headCandidate)
	if err != nil {
		t.Fatal(err)
	}
	operation := testHAReplicationOperationAtEpoch(t, 1, "node-a", 2, "8.8.8.213", "ssh", "upsert")
	if _, err := firewallCandidate.enqueue(operation); err != nil {
		t.Fatal(err)
	}
	journal := testHAV2Journal(t, store, operation, firewallCandidate, now)
	if err := saveHAReplicationModel(store.statePath, store.expectedOwnerUID, firewallCandidate); err != nil {
		t.Fatal(err)
	}
	writeTestHAV2WAL(t, store, journal)
	if err := attestHAV2LegacyHandoff(fixture.api); err != nil {
		t.Fatalf("valid pending firewall WAL rejected retained provenance ledger: %v", err)
	}
}
