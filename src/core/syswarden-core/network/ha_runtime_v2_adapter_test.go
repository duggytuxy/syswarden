package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testHARuntimeV2API(t *testing.T, role haRuntimeV2Role) (*haAPI, *haRuntimeV2Adapter, *haReplicationCoordinator) {
	t.Helper()
	fixture := newHAAPITestFixture(t, noOpFirewallManager{}, []string{"9.9.9.10"})
	model, err := newHAReplicationModel("cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := newHAReplicationCoordinator("cluster-a", "node-b", "node-a", deriveHARuntimeV2Secret(fixture.api.cfg.Token), model)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.activate(); err != nil {
		t.Fatal(err)
	}
	adapter, err := newHARuntimeV2Adapter(coordinator, role, "9.9.9.10", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	adapter.peerCertificateVerifier = func(*tls.ConnectionState) error { return nil }
	fixture.api.replicationV2 = adapter
	fixture.api.now = func() time.Time { return time.Date(2026, 9, 3, 8, 0, 1, 0, time.UTC) }
	return fixture.api, adapter, coordinator
}

func testHARuntimeV2Request(api *haAPI, path, token, remote string, wire []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(wire))
	request.RemoteAddr = remote
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	api.handler().ServeHTTP(response, request)
	return response
}

func attestHARuntimeV2Peer(adapter *haRuntimeV2Adapter, at time.Time) {
	adapter.lastHeartbeat = at.UTC()
	adapter.lastHeartbeatReceivedAt = at.UTC()
	adapter.peerState = haCoordinationHealthy
	adapter.peerView = haCoordinationHealthy
	adapter.peerCheckpointSHA256, _ = adapter.coordinator.model.replicationCheckpointDigest(at)
	adapter.peerCheckpointAt = at.UTC()
	adapter.peerOutboxDepth = 0
}

func TestHARuntimeV2RejectsCrossEpochHeartbeatAndEnvelope(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	receiverModel, _ := newHAReplicationModel("cluster-a")
	if err := receiverModel.setEpoch(2); err != nil {
		t.Fatal(err)
	}
	receiver, _ := newHAReplicationCoordinator("cluster-a", "node-b", "node-a", secret, receiverModel)
	_ = receiver.activate()
	receiverAdapter, _ := newHARuntimeV2Adapter(receiver, haRuntimeV2Standby, "9.9.9.10", 5*time.Second)
	senderModel, _ := newHAReplicationModel("cluster-a")
	sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", secret, senderModel)
	_ = sender.activate()
	senderAdapter, _ := newHARuntimeV2Adapter(sender, haRuntimeV2Writer, "9.9.9.20", 5*time.Second)
	heartbeat, _ := senderAdapter.heartbeat(now)
	if err := receiverAdapter.receiveHeartbeat(heartbeat, now); err == nil || receiver.state != haCoordinationFenced {
		t.Fatalf("cross-epoch heartbeat err=%v state=%s", err, receiver.state)
	}

	receiverModel, _ = newHAReplicationModel("cluster-a")
	_ = receiverModel.setEpoch(2)
	receiver, _ = newHAReplicationCoordinator("cluster-a", "node-b", "node-a", secret, receiverModel)
	_ = receiver.activate()
	operation := testHAReplicationOperation(t, "node-a", 1, "8.8.8.108", "ssh", "upsert")
	envelope, _ := sender.envelope(operation, now)
	if _, err := receiver.authenticate(envelope); err == nil || receiver.state != haCoordinationFenced {
		t.Fatalf("cross-epoch envelope err=%v state=%s", err, receiver.state)
	}
}

func TestHARuntimeV2SameEpochCheckpointDivergenceRequiresRecovery(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	receiverModel, _ := newHAReplicationModel("cluster-a")
	receiver, _ := newHAReplicationCoordinator("cluster-a", "node-b", "node-a", secret, receiverModel)
	_ = receiver.activate()
	receiverAdapter, _ := newHARuntimeV2Adapter(receiver, haRuntimeV2Standby, "9.9.9.10", 5*time.Second)
	senderModel, _ := newHAReplicationModel("cluster-a")
	operation := testHAReplicationOperation(t, "node-a", 1, "8.8.8.110", "ssh", "upsert")
	if _, err := senderModel.apply(operation); err != nil {
		t.Fatal(err)
	}
	senderModel.compact(now)
	sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", secret, senderModel)
	_ = sender.activate()
	senderAdapter, _ := newHARuntimeV2Adapter(sender, haRuntimeV2Writer, "9.9.9.20", 5*time.Second)
	heartbeat, _ := senderAdapter.heartbeat(now)
	if err := receiverAdapter.receiveHeartbeat(heartbeat, now); err != nil {
		t.Fatal(err)
	}
	if receiver.state != haCoordinationRecovering || receiverAdapter.peerReadyLocked(now) {
		t.Fatalf("divergent checkpoint state=%s ready=%t", receiver.state, receiverAdapter.peerReadyLocked(now))
	}
	digest, _ := receiver.stateDigest()
	if err := receiverAdapter.beginOperatorRecovery("node-a", digest); err != nil {
		t.Fatal(err)
	}
	if err := receiverAdapter.activateAfterRecovery(); err == nil {
		t.Fatal("recovery activated while peer checkpoints still diverged")
	}
}

func TestAuditFutureHeartbeatDoesNotExtendPeerAvailabilityPastReceiptTimeout(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	receivedAt := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	receiverModel, _ := newHAReplicationModel("cluster-a")
	receiver, _ := newHAReplicationCoordinator("cluster-a", "node-b", "node-a", secret, receiverModel)
	_ = receiver.activate()
	receiverAdapter, _ := newHARuntimeV2Adapter(receiver, haRuntimeV2Standby, "9.9.9.10", 5*time.Second)
	senderModel, _ := newHAReplicationModel("cluster-a")
	sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", secret, senderModel)
	_ = sender.activate()
	senderAdapter, _ := newHARuntimeV2Adapter(sender, haRuntimeV2Writer, "9.9.9.20", 5*time.Second)
	wire, _ := senderAdapter.heartbeat(receivedAt.Add(5 * time.Second))
	if err := receiverAdapter.receiveHeartbeat(wire, receivedAt); err != nil {
		t.Fatal(err)
	}
	receiverAdapter.checkHeartbeat(receivedAt.Add(6 * time.Second))
	if receiver.state != haCoordinationDegraded || receiverAdapter.peerAuthenticatedLocked(receivedAt.Add(6*time.Second)) {
		t.Fatalf("future sender clock extended peer availability: state=%s", receiver.state)
	}
}

func TestAuditWallClockRollbackAndCatchupCannotReauthenticateOldHeartbeat(t *testing.T) {
	_, adapter, coordinator := testHARuntimeV2API(t, haRuntimeV2Standby)
	receivedAt := time.Now()
	adapter.lastHeartbeat = receivedAt.UTC()
	adapter.lastHeartbeatReceivedAt = receivedAt
	adapter.peerState = haCoordinationHealthy
	adapter.peerView = haCoordinationHealthy

	elapsed := 4 * time.Second
	adapter.elapsedSince = func(start, end time.Time) time.Duration {
		if start != receivedAt {
			t.Fatalf("local deadline lost the original monotonic receipt instant")
		}
		return elapsed
	}
	wallClockAfterRollback := receivedAt.Add(-time.Hour)
	if !adapter.peerAuthenticatedLocked(wallClockAfterRollback) {
		t.Fatal("wall-clock rollback invalidated a heartbeat before its monotonic deadline")
	}

	elapsed = 6 * time.Second
	wallClockAfterCatchup := receivedAt.Add(time.Second)
	adapter.checkHeartbeat(wallClockAfterCatchup)
	if coordinator.state != haCoordinationDegraded || adapter.peerAuthenticatedLocked(wallClockAfterCatchup) {
		t.Fatalf("wall-clock catchup reauthenticated an expired heartbeat: state=%s", coordinator.state)
	}
}

func TestHARuntimeV2ProductionElapsedClockPreservesTimeNowMonotonicDeadline(t *testing.T) {
	model, _ := newHAReplicationModel("cluster-a")
	coordinator, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", []byte("0123456789abcdef0123456789abcdef"), model)
	adapter, err := newHARuntimeV2Adapter(coordinator, haRuntimeV2Writer, "9.9.9.20", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(adapter.startedAt.String(), "m=+") {
		t.Fatalf("adapter startup instant lost its monotonic component: %q", adapter.startedAt.String())
	}
	start := time.Now()
	end := start.Add(6 * time.Second)
	if elapsed := adapter.elapsedSince(start, end); elapsed != 6*time.Second {
		t.Fatalf("production local elapsed clock = %s", elapsed)
	}
	store := testHAV2TransactionStore(t)
	configuredAt := time.Now()
	if err := adapter.configureTransactions(context.Background(), newHAV2RecoverableFirewall(), store, func() time.Time { return configuredAt }); err != nil {
		t.Fatal(err)
	}
	if adapter.startedAt != configuredAt || !strings.Contains(adapter.startedAt.String(), "m=+") {
		t.Fatalf("transaction configuration normalized the local startup instant: got=%q want=%q", adapter.startedAt.String(), configuredAt.String())
	}
}

func TestHARuntimeV2ReceiptAndRecoveryGraceRetainMonotonicInstants(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	receivedAt := time.Now()
	receiverModel, _ := newHAReplicationModel("cluster-a")
	receiver, _ := newHAReplicationCoordinator("cluster-a", "node-b", "node-a", secret, receiverModel)
	_ = receiver.activate()
	receiverAdapter, _ := newHARuntimeV2Adapter(receiver, haRuntimeV2Standby, "9.9.9.10", 5*time.Second)
	senderModel, _ := newHAReplicationModel("cluster-a")
	sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", secret, senderModel)
	_ = sender.activate()
	senderAdapter, _ := newHARuntimeV2Adapter(sender, haRuntimeV2Writer, "9.9.9.20", 5*time.Second)
	wire, _ := senderAdapter.heartbeat(receivedAt)
	if err := receiverAdapter.receiveHeartbeat(wire, receivedAt); err != nil {
		t.Fatal(err)
	}
	if receiverAdapter.lastHeartbeatReceivedAt != receivedAt || !strings.Contains(receiverAdapter.lastHeartbeatReceivedAt.String(), "m=+") {
		t.Fatalf("heartbeat receipt lost its monotonic component: got=%q want=%q", receiverAdapter.lastHeartbeatReceivedAt.String(), receivedAt.String())
	}

	receiver.setState(haCoordinationRecovering, haV2RecoveryPreparedReason)
	receiverAdapter.now = func() time.Time { return receivedAt }
	receiverAdapter.peerState = haCoordinationHealthy
	receiverAdapter.peerView = haCoordinationHealthy
	receiverAdapter.peerCheckpointAt = receivedAt.UTC()
	receiverAdapter.peerCheckpointSHA256, _ = receiver.model.replicationCheckpointDigest(receiverAdapter.peerCheckpointAt)
	if err := receiverAdapter.activateAfterRecovery(); err != nil {
		t.Fatal(err)
	}
	wantGrace := receivedAt.Add(receiverAdapter.heartbeatTimeout)
	if receiverAdapter.recoveryGraceUntil != wantGrace || !strings.Contains(receiverAdapter.recoveryGraceUntil.String(), "m=+") {
		t.Fatalf("recovery grace lost its monotonic component: got=%q want=%q", receiverAdapter.recoveryGraceUntil.String(), wantGrace.String())
	}
}

func TestHARuntimeV2StatusUsesPeerCheckpointBoundary(t *testing.T) {
	_, adapter, coordinator := testHARuntimeV2API(t, haRuntimeV2Standby)
	expiresAt := time.Date(2026, 9, 3, 8, 0, 5, 0, time.UTC)
	operation := testHAReplicationOperation(t, "node-a", 1, "8.8.8.121", "ssh", "upsert")
	operation.ExpiresAt = expiresAt.Format(time.RFC3339)
	operation.OperationID, _ = haReplicationOperationDigest(operation)
	if _, err := coordinator.model.apply(operation); err != nil {
		t.Fatal(err)
	}
	adapter.peerCheckpointAt = expiresAt
	adapter.peerCheckpointSHA256, _ = coordinator.model.replicationCheckpointDigest(expiresAt)
	status, err := adapter.status(expiresAt.Add(time.Second))
	if err != nil || status.CheckpointAt != expiresAt.Format(time.RFC3339Nano) || status.CheckpointSHA256 != adapter.peerCheckpointSHA256 {
		t.Fatalf("status checkpoint crossed tombstone boundary: %#v err=%v", status, err)
	}
}

func TestHARuntimeV2WriterRoleConflictFenceIsDurable(t *testing.T) {
	api, adapter, coordinator := testHARuntimeV2API(t, haRuntimeV2Writer)
	store := testHAV2TransactionStore(t)
	initializeHAV2TransactionStoreForModel(t, store, coordinator.model)
	if err := adapter.configureTransactions(context.Background(), newHAV2RecoverableFirewall(), store, api.now); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.receiveReplication([]byte("{}")); err == nil {
		t.Fatal("writer accepted inbound replication")
	}
	restarted, err := loadHAReplicationModel(adapter.transactionStore.statePath, adapter.transactionStore.expectedOwnerUID, coordinator.clusterID)
	if err != nil || restarted.coordinationState != haCoordinationFenced {
		t.Fatalf("writer role-conflict fence was not durable: state=%v err=%v", restarted, err)
	}
}

func TestHARuntimeV2ReplicationBridgeConvergesAndRejectsReplay(t *testing.T) {
	api, _, receiver := testHARuntimeV2API(t, haRuntimeV2Standby)
	senderModel, _ := newHAReplicationModel("cluster-a")
	sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", deriveHARuntimeV2Secret(api.cfg.Token), senderModel)
	if err := sender.activate(); err != nil {
		t.Fatal(err)
	}
	operation := testHAReplicationOperation(t, "node-a", 1, "8.8.8.10", "ssh", "upsert")
	if _, err := sender.model.enqueue(operation); err != nil {
		t.Fatal(err)
	}
	wire, err := sender.envelope(operation, time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	response := testHARuntimeV2Request(api, "/ha/v2/replication", api.cfg.Token, "9.9.9.10:43123", wire)
	if response.Code != http.StatusNoContent || len(receiver.model.activeClaims(api.now())) != 1 {
		t.Fatalf("replication response=%d body=%q state=%#v", response.Code, response.Body.String(), receiver.model.snapshot())
	}
	response = testHARuntimeV2Request(api, "/ha/v2/replication", api.cfg.Token, "9.9.9.10:43123", wire)
	if response.Code != http.StatusAlreadyReported || receiver.state != haCoordinationHealthy {
		t.Fatalf("replay response=%d state=%s", response.Code, receiver.state)
	}
}

func TestHARuntimeV2StaticWriterIsTheOnlyMutationOrigin(t *testing.T) {
	api, adapter, receiver := testHARuntimeV2API(t, haRuntimeV2Writer)
	local := testHAReplicationOperation(t, "node-b", 1, "8.8.8.20", "ssh", "upsert")
	if changed, err := adapter.enqueueLocal(local); err != nil || !changed {
		t.Fatalf("healthy writer could not enqueue: changed=%v err=%v", changed, err)
	}
	senderModel, _ := newHAReplicationModel("cluster-a")
	sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", deriveHARuntimeV2Secret(api.cfg.Token), senderModel)
	_ = sender.activate()
	remote := testHAReplicationOperation(t, "node-a", 1, "8.8.8.10", "ssh", "upsert")
	wire, _ := sender.envelope(remote, time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
	response := testHARuntimeV2Request(api, "/ha/v2/replication", api.cfg.Token, "9.9.9.10:43123", wire)
	if response.Code != http.StatusConflict || receiver.state != haCoordinationFenced {
		t.Fatalf("writer accepted peer mutation: response=%d state=%s", response.Code, receiver.state)
	}
	if _, err := adapter.enqueueLocal(testHAReplicationOperation(t, "node-b", 2, "8.8.8.21", "ssh", "upsert")); err == nil {
		t.Fatal("fenced writer accepted local mutation")
	}
}

func TestHARuntimeV2FutureReplicatedOperationFencesWithoutMutation(t *testing.T) {
	api, receiverAdapter, receiver := testHARuntimeV2API(t, haRuntimeV2Standby)
	store := testHAV2TransactionStore(t)
	initializeHAV2TransactionStoreForModel(t, store, receiver.model)
	manager := newHAV2RecoverableFirewall()
	if err := receiverAdapter.configureTransactions(context.Background(), manager, store, api.now); err != nil {
		t.Fatal(err)
	}
	attestHARuntimeV2Peer(receiverAdapter, api.now())
	senderModel, _ := newHAReplicationModel("cluster-a")
	sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", deriveHARuntimeV2Secret(api.cfg.Token), senderModel)
	_ = sender.activate()
	operation := testHAReplicationOperation(t, "node-a", 1, "8.8.8.22", "ssh", "upsert")
	operation.IssuedAt = "2026-09-03T08:01:00Z"
	operation.ExpiresAt = "2026-09-03T09:01:00Z"
	operation.OperationID, _ = haReplicationOperationDigest(operation)
	wire, _ := sender.envelope(operation, time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
	response := testHARuntimeV2Request(api, "/ha/v2/replication", api.cfg.Token, "9.9.9.10:43123", wire)
	if response.Code != http.StatusConflict || receiver.state != haCoordinationFenced || len(receiver.model.snapshot()) != 0 {
		t.Fatalf("future operation was not fenced: response=%d state=%s claims=%#v", response.Code, receiver.state, receiver.model.snapshot())
	}
}

func TestHARuntimeV2UnauthenticatedDoSDoesNotFence(t *testing.T) {
	api, _, coordinator := testHARuntimeV2API(t, haRuntimeV2Standby)
	malformed := []byte(`{"not":"an envelope"}`)
	response := testHARuntimeV2Request(api, "/ha/v2/replication", "wrong-token", "9.9.9.10:43123", malformed)
	if response.Code != http.StatusUnauthorized || coordinator.state != haCoordinationHealthy {
		t.Fatalf("unauthenticated body changed state: response=%d state=%s", response.Code, coordinator.state)
	}
	response = testHARuntimeV2Request(api, "/ha/v2/replication", api.cfg.Token, "9.9.9.11:43123", malformed)
	if response.Code != http.StatusForbidden || coordinator.state != haCoordinationHealthy {
		t.Fatalf("wrong source changed state: response=%d state=%s", response.Code, coordinator.state)
	}
	response = testHARuntimeV2Request(api, "/ha/v2/replication", api.cfg.Token, "9.9.9.10:43123", make([]byte, maxHACoordinationEnvelopeBytes+1))
	if response.Code != http.StatusRequestEntityTooLarge || coordinator.state != haCoordinationHealthy {
		t.Fatalf("oversized authenticated body reached coordinator: response=%d state=%s", response.Code, coordinator.state)
	}
}

func TestHARuntimeV2BearerWithoutClientCertificateNeverReachesCoordinator(t *testing.T) {
	api, adapter, coordinator := testHARuntimeV2API(t, haRuntimeV2Standby)
	adapter.peerCertificateVerifier = nil
	response := testHARuntimeV2Request(api, "/ha/v2/replication", api.cfg.Token, "9.9.9.10:43123", []byte(`{"malformed":true}`))
	if response.Code != http.StatusUnauthorized || coordinator.state != haCoordinationHealthy || len(coordinator.model.snapshot()) != 0 {
		t.Fatalf("Bearer-only v2 request reached coordinator: response=%d state=%s", response.Code, coordinator.state)
	}
}

func TestHARuntimeV2HeartbeatPartitionAsymmetryAndOperatorRecovery(t *testing.T) {
	api, receiverAdapter, receiver := testHARuntimeV2API(t, haRuntimeV2Standby)
	senderModel, _ := newHAReplicationModel("cluster-a")
	sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", deriveHARuntimeV2Secret(api.cfg.Token), senderModel)
	if err := sender.activate(); err != nil {
		t.Fatal(err)
	}
	senderAdapter, err := newHARuntimeV2Adapter(sender, haRuntimeV2Writer, "9.9.9.20", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := senderAdapter.heartbeat(time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	response := testHARuntimeV2Request(api, "/ha/v2/heartbeat", api.cfg.Token, "9.9.9.10:43123", wire)
	if response.Code != http.StatusNoContent {
		t.Fatalf("heartbeat=%d %q", response.Code, response.Body.String())
	}
	receiverAdapter.checkHeartbeat(time.Date(2026, 9, 3, 8, 0, 7, 0, time.UTC))
	if receiver.state != haCoordinationDegraded {
		t.Fatalf("partition not detected: %s", receiver.state)
	}

	senderAdapter.peerState = haCoordinationDegraded
	wire, _ = senderAdapter.heartbeat(time.Date(2026, 9, 3, 8, 0, 7, 0, time.UTC))
	api.now = func() time.Time { return time.Date(2026, 9, 3, 8, 0, 7, 0, time.UTC) }
	receiverAdapter.now = api.now
	response = testHARuntimeV2Request(api, "/ha/v2/heartbeat", api.cfg.Token, "9.9.9.10:43123", wire)
	if response.Code != http.StatusNoContent || receiver.state != haCoordinationDegraded {
		t.Fatalf("rejoin state=%s response=%d", receiver.state, response.Code)
	}
	digest, _ := receiver.stateDigest()
	if err := receiverAdapter.beginOperatorRecovery("node-a", digest); err != nil {
		t.Fatal(err)
	}
	if err := receiverAdapter.activateAfterRecovery(); err != nil {
		t.Fatal(err)
	}
	if receiver.state != haCoordinationHealthy {
		t.Fatal("explicit recovery failed")
	}
}

func TestHARuntimeV2RecoveryRequiresPrepareAndAllowsBoundedPeerActivation(t *testing.T) {
	api, receiverAdapter, receiver := testHARuntimeV2API(t, haRuntimeV2Standby)
	base := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	receiverAdapter.now = func() time.Time { return base }
	receiver.setState(haCoordinationRecovering, "asymmetric peer state; operator recovery required")
	receiverAdapter.lastHeartbeat = base
	receiverAdapter.lastHeartbeatReceivedAt = base
	receiverAdapter.peerState = haCoordinationRecovering
	receiverAdapter.peerCheckpointSHA256, _ = receiver.model.replicationCheckpointDigest(base)
	receiverAdapter.peerCheckpointAt = base
	if err := receiverAdapter.activateAfterRecovery(); err == nil {
		t.Fatal("recovery activated without an explicit prepared checkpoint")
	}
	digest, _ := receiver.stateDigest()
	if err := receiverAdapter.beginOperatorRecovery("node-a", digest); err != nil {
		t.Fatal(err)
	}
	if err := receiverAdapter.activateAfterRecovery(); err != nil {
		t.Fatal(err)
	}

	senderModel, _ := newHAReplicationModel("cluster-a")
	sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", deriveHARuntimeV2Secret(api.cfg.Token), senderModel)
	sender.setState(haCoordinationRecovering, haV2RecoveryPreparedReason)
	senderAdapter, _ := newHARuntimeV2Adapter(sender, haRuntimeV2Writer, "9.9.9.20", 5*time.Second)
	senderAdapter.peerState = haCoordinationRecovering
	wire, _ := senderAdapter.heartbeat(base.Add(time.Second))
	api.now = func() time.Time { return base.Add(time.Second) }
	response := testHARuntimeV2Request(api, "/ha/v2/heartbeat", api.cfg.Token, "9.9.9.10:43123", wire)
	if response.Code != http.StatusNoContent || receiver.state != haCoordinationHealthy {
		t.Fatalf("bounded recovery grace rejected peer activation: response=%d state=%s", response.Code, receiver.state)
	}
	receiverAdapter.checkHeartbeat(base.Add(6 * time.Second))
	if receiver.state != haCoordinationRecovering {
		t.Fatalf("expired recovery grace left one-sided healthy state: %s", receiver.state)
	}
}

func TestHARuntimeV2InitialHeartbeatGraceDoesNotDegradeEarly(t *testing.T) {
	_, adapter, coordinator := testHARuntimeV2API(t, haRuntimeV2Writer)
	started := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	adapter.startedAt = started
	adapter.checkHeartbeat(started.Add(4 * time.Second))
	if coordinator.state != haCoordinationHealthy {
		t.Fatalf("node degraded before initial heartbeat deadline: %s", coordinator.state)
	}
	adapter.checkHeartbeat(started.Add(6 * time.Second))
	if coordinator.state != haCoordinationDegraded {
		t.Fatalf("missing initial heartbeat did not degrade after deadline: %s", coordinator.state)
	}
}

func TestHARuntimeV2HeartbeatDetectsStaticRoleSplitBrain(t *testing.T) {
	api, _, receiver := testHARuntimeV2API(t, haRuntimeV2Writer)
	senderModel, _ := newHAReplicationModel("cluster-a")
	sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", deriveHARuntimeV2Secret(api.cfg.Token), senderModel)
	_ = sender.activate()
	senderAdapter, _ := newHARuntimeV2Adapter(sender, haRuntimeV2Writer, "9.9.9.20", 5*time.Second)
	wire, _ := senderAdapter.heartbeat(time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
	response := testHARuntimeV2Request(api, "/ha/v2/heartbeat", api.cfg.Token, "9.9.9.10:43123", wire)
	if response.Code != http.StatusConflict || receiver.state != haCoordinationFenced {
		t.Fatalf("two writers not fenced: response=%d state=%s", response.Code, receiver.state)
	}
}

func TestHARuntimeV2HeartbeatDetectsAsymmetricPeerView(t *testing.T) {
	api, _, receiver := testHARuntimeV2API(t, haRuntimeV2Standby)
	senderModel, _ := newHAReplicationModel("cluster-a")
	sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", deriveHARuntimeV2Secret(api.cfg.Token), senderModel)
	_ = sender.activate()
	senderAdapter, _ := newHARuntimeV2Adapter(sender, haRuntimeV2Writer, "9.9.9.20", 5*time.Second)
	senderAdapter.peerState = haCoordinationDegraded
	wire, _ := senderAdapter.heartbeat(time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
	response := testHARuntimeV2Request(api, "/ha/v2/heartbeat", api.cfg.Token, "9.9.9.10:43123", wire)
	if response.Code != http.StatusNoContent || receiver.state != haCoordinationRecovering {
		t.Fatalf("asymmetric view not held for recovery: response=%d state=%s", response.Code, receiver.state)
	}
}

func TestHARuntimeV2HeartbeatDetectsDegradedPeerState(t *testing.T) {
	api, _, receiver := testHARuntimeV2API(t, haRuntimeV2Standby)
	senderModel, _ := newHAReplicationModel("cluster-a")
	sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", deriveHARuntimeV2Secret(api.cfg.Token), senderModel)
	_ = sender.activate()
	senderAdapter, _ := newHARuntimeV2Adapter(sender, haRuntimeV2Writer, "9.9.9.20", 5*time.Second)
	sender.setState(haCoordinationDegraded, "test peer partition")
	wire, _ := senderAdapter.heartbeat(time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
	response := testHARuntimeV2Request(api, "/ha/v2/heartbeat", api.cfg.Token, "9.9.9.10:43123", wire)
	if response.Code != http.StatusNoContent || receiver.state != haCoordinationRecovering {
		t.Fatalf("degraded peer state not held for recovery: response=%d state=%s", response.Code, receiver.state)
	}
}

func TestHARuntimeV2HeartbeatRejectsUnknownRoleOrState(t *testing.T) {
	tests := map[string]func(*haRuntimeV2Heartbeat){
		"role":      func(heartbeat *haRuntimeV2Heartbeat) { heartbeat.Role = "candidate" },
		"state":     func(heartbeat *haRuntimeV2Heartbeat) { heartbeat.State = "unknown" },
		"peer view": func(heartbeat *haRuntimeV2Heartbeat) { heartbeat.PeerView = "unknown" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			api, _, receiver := testHARuntimeV2API(t, haRuntimeV2Standby)
			senderModel, _ := newHAReplicationModel("cluster-a")
			sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", deriveHARuntimeV2Secret(api.cfg.Token), senderModel)
			_ = sender.activate()
			senderAdapter, _ := newHARuntimeV2Adapter(sender, haRuntimeV2Writer, "9.9.9.20", 5*time.Second)
			wire, _ := senderAdapter.heartbeat(time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
			var heartbeat haRuntimeV2Heartbeat
			if err := json.Unmarshal(wire, &heartbeat); err != nil {
				t.Fatal(err)
			}
			mutate(&heartbeat)
			heartbeat.MAC, _ = senderAdapter.heartbeatMAC(heartbeat)
			wire, _ = json.Marshal(heartbeat)
			response := testHARuntimeV2Request(api, "/ha/v2/heartbeat", api.cfg.Token, "9.9.9.10:43123", wire)
			if response.Code != http.StatusConflict || receiver.state != haCoordinationFenced {
				t.Fatalf("invalid heartbeat accepted: response=%d state=%s", response.Code, receiver.state)
			}
		})
	}
}

func TestHARuntimeV2MixedVersionFailsClosedWithoutMutation(t *testing.T) {
	api, _, receiver := testHARuntimeV2API(t, haRuntimeV2Standby)
	senderModel, _ := newHAReplicationModel("cluster-a")
	sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", deriveHARuntimeV2Secret(api.cfg.Token), senderModel)
	_ = sender.activate()
	senderAdapter, _ := newHARuntimeV2Adapter(sender, haRuntimeV2Writer, "9.9.9.20", 5*time.Second)
	wire, _ := senderAdapter.heartbeat(time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
	var heartbeat haRuntimeV2Heartbeat
	if err := json.Unmarshal(wire, &heartbeat); err != nil {
		t.Fatal(err)
	}
	heartbeat.Version = 2
	heartbeat.MAC, _ = senderAdapter.heartbeatMAC(heartbeat)
	wire, _ = json.Marshal(heartbeat)
	response := testHARuntimeV2Request(api, "/ha/v2/heartbeat", api.cfg.Token, "9.9.9.10:43123", wire)
	if response.Code != http.StatusConflict || receiver.state != haCoordinationHealthy || len(receiver.model.snapshot()) != 0 {
		t.Fatalf("mixed version mutated state: response=%d state=%s", response.Code, receiver.state)
	}
}

func TestHARuntimeV2RoutesAreAbsentByDefault(t *testing.T) {
	fixture := newHAAPITestFixture(t, noOpFirewallManager{}, []string{"9.9.9.10"})
	request := httptest.NewRequest(http.MethodPost, "/ha/v2/heartbeat", strings.NewReader(`{}`))
	request.RemoteAddr = "9.9.9.10:43123"
	response := httptest.NewRecorder()
	fixture.api.handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled v2 route=%d", response.Code)
	}
}

func TestHARuntimeV2LegacyMutationIsRejectedBeforeStandbyLedgerChange(t *testing.T) {
	api, _, _ := testHARuntimeV2API(t, haRuntimeV2Standby)
	response := requestDirectHAPath(t, api.handler(), http.MethodPost, "/ha/sync", "Bearer "+api.cfg.Token,
		`{"bans":[{"ip":"8.8.8.30","ttl":300,"reason":"BunkerWeb ban","source":"bunkerweb"}]}`, "9.9.9.10:43123")
	if response.Code != http.StatusLocked {
		t.Fatalf("standby legacy mutation response=%d body=%q", response.Code, response.Body.String())
	}
	ledger, err := api.readHALedger()
	if err != nil || len(ledger.Bans) != 0 {
		t.Fatalf("standby rejection changed provenance ledger: %#v err=%v", ledger, err)
	}
}

func TestHARuntimeV2BunkerWebMutationUsesRecoverableWriterModel(t *testing.T) {
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
		`{"bans":[{"ip":"8.8.8.31","ttl":300,"reason":"BunkerWeb ban","source":"bunkerweb"}]}`, "9.9.9.10:43123")
	if response.Code != http.StatusOK {
		t.Fatalf("writer BunkerWeb mutation response=%d body=%q", response.Code, response.Body.String())
	}
	ledger, err := api.readHALedger()
	if err != nil || len(ledger.Bans) != 1 || len(coordinator.model.outbox) != 1 || len(coordinator.model.activeClaims(api.now())) != 1 {
		t.Fatalf("BunkerWeb mutation bypassed replicated ownership: ledger=%#v model=%#v err=%v", ledger, coordinator.model.persistentState(), err)
	}
	manager.mu.Lock()
	_, present := manager.targets["8.8.8.31"]
	manager.mu.Unlock()
	if !present {
		t.Fatal("BunkerWeb mutation did not reach recoverable firewall transaction")
	}
}

func TestHARuntimeV2RejectsPersistedStateFromTheWrongStaticWriter(t *testing.T) {
	model, _ := newHAReplicationModel("cluster-a")
	peerOperation := testHAReplicationOperation(t, "node-b", 1, "8.8.8.23", "ssh", "upsert")
	if _, err := model.apply(peerOperation); err != nil {
		t.Fatal(err)
	}
	coordinator, err := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", []byte("0123456789abcdef0123456789abcdef"), model)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newHARuntimeV2Adapter(coordinator, haRuntimeV2Writer, "9.9.9.10", 5*time.Second); err == nil {
		t.Fatal("writer accepted persisted claims owned by its standby")
	}
}
