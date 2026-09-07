package network

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"syswarden-core/firewall"
)

const (
	haRuntimeV2HeartbeatVersion   = 1
	maxHARuntimeV2HeartbeatBytes  = 16 * 1024
	haV2RecoveryPreparedReason    = "explicit recovery pending activation"
	haV2TransactionRecoveryReason = "recovered pending HA v2 transaction; explicit recovery required"
)

type haRuntimeV2Role string

const (
	haRuntimeV2Writer  haRuntimeV2Role = "writer"
	haRuntimeV2Standby haRuntimeV2Role = "standby"
)

type haRuntimeV2Heartbeat struct {
	Version          int                 `json:"version"`
	ClusterID        string              `json:"cluster_id"`
	Epoch            uint64              `json:"epoch"`
	NodeID           string              `json:"node_id"`
	RecipientID      string              `json:"recipient_id"`
	Role             haRuntimeV2Role     `json:"role"`
	State            haCoordinationState `json:"state"`
	PeerView         haCoordinationState `json:"peer_view"`
	CheckpointSHA256 string              `json:"checkpoint_sha256"`
	CheckpointAt     string              `json:"checkpoint_at"`
	OutboxDepth      int                 `json:"outbox_depth"`
	SentAt           string              `json:"sent_at"`
	MAC              string              `json:"mac"`
}

type haRuntimeV2HeartbeatPayload struct {
	Version          int                 `json:"version"`
	ClusterID        string              `json:"cluster_id"`
	Epoch            uint64              `json:"epoch"`
	NodeID           string              `json:"node_id"`
	RecipientID      string              `json:"recipient_id"`
	Role             haRuntimeV2Role     `json:"role"`
	State            haCoordinationState `json:"state"`
	PeerView         haCoordinationState `json:"peer_view"`
	CheckpointSHA256 string              `json:"checkpoint_sha256"`
	CheckpointAt     string              `json:"checkpoint_at"`
	OutboxDepth      int                 `json:"outbox_depth"`
	SentAt           string              `json:"sent_at"`
}

type haRuntimeV2Adapter struct {
	coordinator             *haReplicationCoordinator
	role                    haRuntimeV2Role
	peerAddress             netip.Addr
	heartbeatTimeout        time.Duration
	mu                      sync.Mutex
	startedAt               time.Time
	lastHeartbeat           time.Time
	lastHeartbeatReceivedAt time.Time
	recoveryGraceUntil      time.Time
	checkpointGraceUntil    time.Time
	peerCertificateVerifier func(*tls.ConnectionState) error
	transactionManager      firewall.RecoverableMutationManager
	transactionStore        *haV2TransactionStore
	transactionContext      context.Context
	now                     func() time.Time
	elapsedSince            func(time.Time, time.Time) time.Duration
	peerState               haCoordinationState
	peerView                haCoordinationState
	peerCheckpointSHA256    string
	peerCheckpointAt        time.Time
	peerOutboxDepth         int
	peerDeliveryBudget      int
	pendingTransaction      bool
}

type haRuntimeV2Status struct {
	ClusterID            string              `json:"cluster_id"`
	Epoch                uint64              `json:"epoch"`
	NodeID               string              `json:"node_id"`
	PeerID               string              `json:"peer_id"`
	Role                 haRuntimeV2Role     `json:"role"`
	State                haCoordinationState `json:"state"`
	Reason               string              `json:"reason,omitempty"`
	StateSHA256          string              `json:"state_sha256"`
	CheckpointSHA256     string              `json:"checkpoint_sha256"`
	CheckpointAt         string              `json:"checkpoint_at"`
	PeerCheckpointSHA256 string              `json:"peer_checkpoint_sha256,omitempty"`
	LastHeartbeat        string              `json:"last_heartbeat,omitempty"`
	OutboxDepth          int                 `json:"outbox_depth"`
	ActiveClaims         int                 `json:"active_claims"`
}

func (adapter *haRuntimeV2Adapter) status(now time.Time) (haRuntimeV2Status, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	digest, err := adapter.coordinator.stateDigest()
	if err != nil {
		return haRuntimeV2Status{}, err
	}
	checkpointAt := now.UTC()
	if !adapter.peerCheckpointAt.IsZero() {
		checkpointAt = adapter.peerCheckpointAt
	}
	checkpoint, err := adapter.coordinator.model.replicationCheckpointDigest(checkpointAt)
	if err != nil {
		return haRuntimeV2Status{}, err
	}
	state := adapter.coordinator.state
	reason := adapter.coordinator.reason
	if state == haCoordinationHealthy && !adapter.peerReadyLocked(now) {
		state = haCoordinationDegraded
		reason = "awaiting a recent authenticated healthy peer heartbeat"
	}
	status := haRuntimeV2Status{
		ClusterID: adapter.coordinator.clusterID, Epoch: adapter.coordinator.epoch,
		NodeID: adapter.coordinator.localID, PeerID: adapter.coordinator.peerID, Role: adapter.role,
		State: state, Reason: reason, StateSHA256: digest, CheckpointSHA256: checkpoint,
		CheckpointAt:         checkpointAt.Format(time.RFC3339Nano),
		PeerCheckpointSHA256: adapter.peerCheckpointSHA256,
		OutboxDepth:          len(adapter.coordinator.model.outbox), ActiveClaims: len(adapter.coordinator.model.activeClaims(now)),
	}
	if !adapter.lastHeartbeat.IsZero() {
		status.LastHeartbeat = adapter.lastHeartbeat.UTC().Format(time.RFC3339Nano)
	}
	return status, nil
}

func (adapter *haRuntimeV2Adapter) recentPeerHeartbeatLocked(now time.Time) bool {
	if adapter.lastHeartbeat.IsZero() || adapter.lastHeartbeatReceivedAt.IsZero() || adapter.peerState == haCoordinationFenced {
		return false
	}
	delta := adapter.elapsedSince(adapter.lastHeartbeatReceivedAt, now)
	return delta >= 0 && delta <= adapter.heartbeatTimeout
}

func (adapter *haRuntimeV2Adapter) peerAuthenticatedLocked(now time.Time) bool {
	return adapter.recentPeerHeartbeatLocked(now) && adapter.peerState == haCoordinationHealthy && adapter.peerView == haCoordinationHealthy
}

func (adapter *haRuntimeV2Adapter) recoveryDeliveryAllowedLocked(now time.Time) bool {
	return adapter.role == haRuntimeV2Standby && adapter.coordinator.state != haCoordinationFenced &&
		adapter.recentPeerHeartbeatLocked(now) && adapter.peerOutboxDepth > 0 && adapter.peerDeliveryBudget > 0
}

func (adapter *haRuntimeV2Adapter) peerReadyLocked(now time.Time) bool {
	if !adapter.peerAuthenticatedLocked(now) || adapter.peerOutboxDepth != 0 || len(adapter.coordinator.model.outbox) != 0 || !isLowerHexSHA256(adapter.peerCheckpointSHA256) {
		return false
	}
	checkpoint, err := adapter.coordinator.model.replicationCheckpointDigest(adapter.peerCheckpointAt)
	return err == nil && hmac.Equal([]byte(checkpoint), []byte(adapter.peerCheckpointSHA256))
}

func (adapter *haRuntimeV2Adapter) localMutationReadinessLocked(now time.Time) error {
	if adapter.role != haRuntimeV2Writer {
		return fmt.Errorf("HA v2 static standby cannot originate firewall mutations")
	}
	if adapter.coordinator.state != haCoordinationHealthy {
		return fmt.Errorf("HA v2 local mutation requires healthy coordination")
	}
	if !adapter.peerAuthenticatedLocked(now) {
		return fmt.Errorf("HA v2 local mutation requires a recent authenticated healthy peer heartbeat")
	}
	if len(adapter.coordinator.model.outbox) > 0 && adapter.peerOutboxDepth == 0 && isLowerHexSHA256(adapter.peerCheckpointSHA256) {
		return nil
	}
	if !adapter.peerReadyLocked(now) {
		return fmt.Errorf("HA v2 local mutation requires an identical quiescent peer checkpoint")
	}
	return nil
}

func (adapter *haRuntimeV2Adapter) localMutationReadiness(now time.Time) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.localMutationReadinessLocked(now)
}

func (adapter *haRuntimeV2Adapter) receiveReplication(wire []byte) (bool, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if adapter.role != haRuntimeV2Standby {
		adapter.coordinator.fence("HA v2 static writer received a peer mutation")
		return false, errors.Join(fmt.Errorf("HA v2 static writer refuses peer mutations"), adapter.persistCoordinationLocked())
	}
	if adapter.transactionManager == nil || adapter.transactionStore == nil {
		return adapter.coordinator.receive(wire)
	}
	now := adapter.now()
	wireNow := now.UTC()
	recoveryDelivery := adapter.coordinator.state != haCoordinationHealthy || !adapter.peerAuthenticatedLocked(now)
	if recoveryDelivery && !adapter.recoveryDeliveryAllowedLocked(now) {
		return false, fmt.Errorf("HA v2 replication requires a recent authenticated healthy peer heartbeat")
	}
	decoded, err := decodeHACoordinationEnvelope(wire)
	if err != nil {
		return false, err
	}
	sentAt, err := parseCanonicalHATime(decoded.SentAt)
	if err != nil || sentAt.After(wireNow.Add(adapter.heartbeatTimeout)) || wireNow.Sub(sentAt) > adapter.heartbeatTimeout {
		return false, fmt.Errorf("HA v2 replication envelope is outside the freshness window")
	}
	operation, err := adapter.coordinator.authenticate(wire)
	if err != nil {
		if errors.Is(err, errHACoordinationReplay) && recoveryDelivery {
			adapter.peerDeliveryBudget--
		}
		if persistErr := adapter.persistCoordinationLocked(); persistErr != nil && !errors.Is(err, errHACoordinationReplay) {
			return false, errors.Join(err, persistErr)
		}
		return false, err
	}
	issuedAt, err := parseCanonicalHATime(operation.IssuedAt)
	if err != nil || issuedAt.After(wireNow.Add(adapter.heartbeatTimeout)) {
		adapter.coordinator.fence("HA v2 replicated operation clock is invalid")
		return false, errors.Join(fmt.Errorf("HA v2 replicated operation clock is invalid"), adapter.persistCoordinationLocked())
	}
	candidate, err := cloneHAReplicationModel(adapter.coordinator.model)
	if err != nil {
		adapter.coordinator.fence("HA v2 model clone failed")
		return false, errors.Join(err, adapter.persistCoordinationLocked())
	}
	expectedPreState, err := adapter.coordinator.stateDigest()
	if err != nil {
		return false, err
	}
	changed, err := candidate.apply(operation)
	if err != nil {
		adapter.coordinator.fence("HA v2 candidate divergence")
		return false, errors.Join(err, adapter.persistCoordinationLocked())
	}
	if !changed {
		return false, errHACoordinationReplay
	}
	candidate.compact(now)
	if err := adapter.transactionStore.execute(adapter.transactionContext, adapter.transactionManager, operation, candidate, expectedPreState, now); err != nil {
		adapter.coordinator.fence("HA v2 recoverable peer mutation failed")
		// The pending WAL owns the durable crash proof. Persisting this older
		// in-memory model here would create a state digest not bound by it.
		return false, adapter.persistFailureFenceUnlessWALLocked(err, candidate)
	}
	adapter.coordinator.model = candidate
	if recoveryDelivery {
		adapter.peerDeliveryBudget--
	}
	return true, nil
}

func (adapter *haRuntimeV2Adapter) persistCoordinationLocked() error {
	if adapter.transactionStore == nil {
		return nil
	}
	if adapter.pendingTransaction {
		return fmt.Errorf("HA v2 persistence is blocked by a pending recoverable transaction")
	}
	return adapter.transactionStore.persist(adapter.coordinator.model)
}

func (adapter *haRuntimeV2Adapter) persistFailureFenceUnlessWALLocked(cause error, candidate *haReplicationModel) error {
	if adapter.transactionStore == nil {
		return cause
	}
	_, _, pending, err := readHAV2Transaction(adapter.transactionStore)
	if err != nil {
		adapter.pendingTransaction = true
		return errors.Join(cause, fmt.Errorf("attest HA v2 failure WAL: %w", err))
	}
	if pending {
		adapter.pendingTransaction = true
		return cause
	}
	durable, loadErr := loadHAReplicationModel(adapter.transactionStore.statePath, adapter.transactionStore.expectedOwnerUID, adapter.coordinator.clusterID)
	if loadErr != nil {
		return errors.Join(cause, fmt.Errorf("attest HA v2 transaction outcome: %w", loadErr))
	}
	if anchorErr := adapter.transactionStore.attestStateAnchor(durable); anchorErr != nil {
		return errors.Join(cause, fmt.Errorf("attest HA v2 transaction outcome: %w", anchorErr))
	}
	if candidate != nil {
		durableDigest, digestErr := durable.persistentStateDigest()
		candidateDigest, candidateErr := candidate.persistentStateDigest()
		if digestErr != nil || candidateErr != nil {
			return errors.Join(cause, digestErr, candidateErr)
		}
		if durableDigest == candidateDigest {
			durable = candidate
		}
	}
	// A commit unlink followed by a failed directory fsync is ambiguous: the
	// applied WAL may reappear after a crash. Persist the exact recovery model
	// and digest that the WAL binds so either outcome converges in one restart.
	if err := durable.setCoordination(haCoordinationFenced, haV2TransactionRecoveryReason); err != nil {
		return errors.Join(cause, err)
	}
	if err := adapter.transactionStore.persist(durable); err != nil {
		return errors.Join(cause, err)
	}
	adapter.coordinator.model = durable
	adapter.coordinator.state = durable.coordinationState
	adapter.coordinator.reason = durable.coordinationReason
	return cause
}

func (adapter *haRuntimeV2Adapter) enqueueLocal(operation haReplicationOperation) (bool, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.enqueueLocalLocked(operation)
}

func (adapter *haRuntimeV2Adapter) enqueueLocalLocked(operation haReplicationOperation) (bool, error) {
	if adapter.role != haRuntimeV2Writer || adapter.coordinator.state != haCoordinationHealthy {
		return false, fmt.Errorf("HA v2 local mutation requires the healthy static writer")
	}
	if adapter.transactionManager == nil || adapter.transactionStore == nil {
		return adapter.coordinator.model.enqueue(operation)
	}
	if err := adapter.localMutationReadinessLocked(adapter.now()); err != nil {
		return false, err
	}
	candidate, err := cloneHAReplicationModel(adapter.coordinator.model)
	if err != nil {
		adapter.coordinator.fence("HA v2 model clone failed")
		return false, errors.Join(err, adapter.persistCoordinationLocked())
	}
	expectedPreState, err := adapter.coordinator.stateDigest()
	if err != nil {
		return false, err
	}
	changed, err := candidate.enqueue(operation)
	if err != nil || !changed {
		return changed, err
	}
	now := adapter.now().UTC()
	candidate.compact(now)
	if err := adapter.transactionStore.execute(adapter.transactionContext, adapter.transactionManager, operation, candidate, expectedPreState, now); err != nil {
		adapter.coordinator.fence("HA v2 recoverable local mutation failed")
		// Recovery durably applies the WAL candidate and its bound fence.
		return false, adapter.persistFailureFenceUnlessWALLocked(err, candidate)
	}
	adapter.coordinator.model = candidate
	return true, nil
}

func (adapter *haRuntimeV2Adapter) applyLocalTarget(ip, source, action string, ttl time.Duration, permanent bool) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	evaluationNow := adapter.now()
	if err := adapter.localMutationReadinessLocked(evaluationNow); err != nil {
		return err
	}
	now := evaluationNow.UTC().Truncate(time.Second)
	canonical, err := canonicalHAAddress(ip)
	if err != nil {
		return err
	}
	sequence, err := adapter.coordinator.model.nextSequence(adapter.coordinator.localID)
	if err != nil {
		return err
	}
	operation := haReplicationOperation{
		SchemaVersion: haReplicationSchemaVersion, ClusterID: adapter.coordinator.clusterID,
		Epoch: adapter.coordinator.epoch, NodeID: adapter.coordinator.localID, Sequence: sequence, Owner: adapter.coordinator.localID,
		Source: source, IP: canonical, Action: action, IssuedAt: now.Format(time.RFC3339),
	}
	if action == "upsert" {
		if !permanent {
			if ttl < firewall.MinimumBanTTL || ttl > firewall.MaximumBanTTL || ttl%time.Second != 0 {
				return fmt.Errorf("invalid HA v2 local mutation TTL")
			}
			operation.ExpiresAt = now.Add(ttl).Format(time.RFC3339)
		}
	} else if action == "delete" || action == "expiry" {
		operation.TombstoneUntil = now.Add(haV2TombstoneRetention).Format(time.RFC3339)
	} else {
		return fmt.Errorf("invalid HA v2 local mutation action")
	}
	operation.OperationID, err = haReplicationOperationDigest(operation)
	if err != nil {
		return err
	}
	_, err = adapter.enqueueLocalLocked(operation)
	return err
}

func (adapter *haRuntimeV2Adapter) configureTransactions(ctx context.Context, manager firewall.RecoverableMutationManager, store *haV2TransactionStore, now func() time.Time) error {
	if ctx == nil || manager == nil || store == nil || now == nil {
		return fmt.Errorf("invalid HA v2 recoverable transaction configuration")
	}
	adapter.transactionContext = ctx
	adapter.transactionManager = manager
	adapter.transactionStore = store
	adapter.now = now
	adapter.startedAt = now()
	return nil
}

func (adapter *haRuntimeV2Adapter) beginOperatorRecovery(peerID, expectedLocalDigest string) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if adapter.pendingTransaction {
		return fmt.Errorf("HA v2 recovery requires restart recovery of the pending transaction")
	}
	if err := adapter.coordinator.beginRecovery(peerID, expectedLocalDigest); err != nil {
		return errors.Join(err, adapter.persistCoordinationLocked())
	}
	adapter.recoveryGraceUntil = time.Time{}
	return adapter.persistCoordinationLocked()
}

func (adapter *haRuntimeV2Adapter) activateAfterRecovery() error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if adapter.pendingTransaction {
		return fmt.Errorf("HA v2 activation requires restart recovery of the pending transaction")
	}
	now := adapter.now()
	if adapter.coordinator.state != haCoordinationRecovering || adapter.coordinator.reason != haV2RecoveryPreparedReason {
		return fmt.Errorf("HA v2 recovery activation requires an explicit prepared checkpoint")
	}
	if adapter.lastHeartbeatReceivedAt.IsZero() || adapter.elapsedSince(adapter.lastHeartbeatReceivedAt, now) > adapter.heartbeatTimeout ||
		(adapter.peerState != haCoordinationHealthy && adapter.peerState != haCoordinationRecovering) {
		return fmt.Errorf("HA v2 recovery activation requires a recent authenticated peer heartbeat")
	}
	checkpoint, err := adapter.coordinator.model.replicationCheckpointDigest(adapter.peerCheckpointAt)
	if err != nil || adapter.peerOutboxDepth != 0 || len(adapter.coordinator.model.outbox) != 0 ||
		!isLowerHexSHA256(adapter.peerCheckpointSHA256) || !hmac.Equal([]byte(checkpoint), []byte(adapter.peerCheckpointSHA256)) {
		return fmt.Errorf("HA v2 recovery activation requires an identical quiescent peer checkpoint")
	}
	if err := adapter.coordinator.activate(); err != nil {
		return err
	}
	adapter.recoveryGraceUntil = now.Add(adapter.heartbeatTimeout)
	if err := adapter.persistCoordinationLocked(); err != nil {
		adapter.recoveryGraceUntil = time.Time{}
		adapter.coordinator.fence("HA v2 recovery activation persistence failed")
		return errors.Join(err, adapter.persistCoordinationLocked())
	}
	return nil
}

func (adapter *haRuntimeV2Adapter) markOutboundFailure(reason string) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	before := adapter.coordinator.state
	adapter.coordinator.markPeerUnavailable(reason)
	if before != adapter.coordinator.state {
		_ = adapter.persistCoordinationLocked()
	}
}

func (adapter *haRuntimeV2Adapter) outboundOperations() []haReplicationOperation {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	operations := make([]haReplicationOperation, 0, len(adapter.coordinator.model.outbox))
	for _, operation := range adapter.coordinator.model.outbox {
		operations = append(operations, operation)
	}
	return operations
}

func (adapter *haRuntimeV2Adapter) outboundEnvelope(operation haReplicationOperation, now time.Time) ([]byte, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.coordinator.envelope(operation, now)
}

func (adapter *haRuntimeV2Adapter) acknowledgeOutbound(operationID string, persist func(*haReplicationModel) error, now time.Time) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if persist == nil {
		return fmt.Errorf("HA v2 acknowledgement persistence is unavailable")
	}
	if adapter.pendingTransaction {
		return fmt.Errorf("HA v2 acknowledgement is blocked by a pending recoverable transaction")
	}
	candidate, err := cloneHAReplicationModel(adapter.coordinator.model)
	if err != nil {
		return err
	}
	if err := candidate.acknowledge(operationID); err != nil {
		return err
	}
	if err := persist(candidate); err != nil {
		adapter.coordinator.fence("HA v2 acknowledgement persistence failed")
		return err
	}
	adapter.coordinator.model = candidate
	adapter.checkpointGraceUntil = now.Add(adapter.heartbeatTimeout)
	return nil
}

func newHARuntimeV2Adapter(coordinator *haReplicationCoordinator, role haRuntimeV2Role, peerAddress string, heartbeatTimeout time.Duration) (*haRuntimeV2Adapter, error) {
	address, err := netip.ParseAddr(peerAddress)
	if err != nil || address.Is4In6() || address.Zone() != "" ||
		(role != haRuntimeV2Writer && role != haRuntimeV2Standby) || heartbeatTimeout < time.Second || heartbeatTimeout > 2*time.Minute ||
		coordinator == nil {
		return nil, fmt.Errorf("invalid HA runtime v2 adapter configuration")
	}
	if err := coordinator.model.validateStaticRole(coordinator.localID, coordinator.peerID, string(role)); err != nil {
		return nil, err
	}
	return &haRuntimeV2Adapter{
		coordinator: coordinator, role: role, peerAddress: address, heartbeatTimeout: heartbeatTimeout,
		transactionContext: context.Background(), now: time.Now, startedAt: time.Now(),
		elapsedSince: func(start, end time.Time) time.Duration { return end.Sub(start) },
		peerState:    haCoordinationHealthy, peerView: haCoordinationHealthy,
	}, nil
}

func (adapter *haRuntimeV2Adapter) heartbeatMAC(heartbeat haRuntimeV2Heartbeat) (string, error) {
	payload := haRuntimeV2HeartbeatPayload{
		Version: heartbeat.Version, ClusterID: heartbeat.ClusterID, Epoch: heartbeat.Epoch, NodeID: heartbeat.NodeID,
		RecipientID: heartbeat.RecipientID, Role: heartbeat.Role, State: heartbeat.State,
		PeerView: heartbeat.PeerView, CheckpointSHA256: heartbeat.CheckpointSHA256,
		CheckpointAt: heartbeat.CheckpointAt, OutboxDepth: heartbeat.OutboxDepth, SentAt: heartbeat.SentAt,
	}
	wire, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, adapter.coordinator.secret)
	_, _ = mac.Write(wire)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (adapter *haRuntimeV2Adapter) heartbeat(now time.Time) ([]byte, error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	checkpointAt := now.UTC()
	checkpoint, err := adapter.coordinator.model.replicationCheckpointDigest(checkpointAt)
	if err != nil {
		return nil, err
	}
	heartbeat := haRuntimeV2Heartbeat{
		Version: haRuntimeV2HeartbeatVersion, ClusterID: adapter.coordinator.clusterID, Epoch: adapter.coordinator.epoch,
		NodeID: adapter.coordinator.localID, RecipientID: adapter.coordinator.peerID,
		Role: adapter.role, State: adapter.coordinator.state, PeerView: adapter.peerState,
		CheckpointSHA256: checkpoint, OutboxDepth: len(adapter.coordinator.model.outbox),
		CheckpointAt: checkpointAt.Format(time.RFC3339Nano),
		SentAt:       now.UTC().Format(time.RFC3339Nano),
	}
	mac, err := adapter.heartbeatMAC(heartbeat)
	if err != nil {
		return nil, err
	}
	heartbeat.MAC = mac
	return json.Marshal(heartbeat)
}

func decodeHARuntimeV2Heartbeat(wire []byte) (haRuntimeV2Heartbeat, error) {
	if len(wire) == 0 || len(wire) > maxHARuntimeV2HeartbeatBytes {
		return haRuntimeV2Heartbeat{}, fmt.Errorf("HA v2 heartbeat exceeds bounds")
	}
	if err := rejectHADuplicateJSONKeys(wire); err != nil {
		return haRuntimeV2Heartbeat{}, err
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(wire), maxHARuntimeV2HeartbeatBytes+1))
	decoder.DisallowUnknownFields()
	var heartbeat haRuntimeV2Heartbeat
	if err := decoder.Decode(&heartbeat); err != nil {
		return haRuntimeV2Heartbeat{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return haRuntimeV2Heartbeat{}, fmt.Errorf("HA v2 heartbeat has trailing JSON")
	}
	return heartbeat, nil
}

func validHARuntimeV2CoordinationState(state haCoordinationState) bool {
	switch state {
	case haCoordinationHealthy, haCoordinationDegraded, haCoordinationFenced, haCoordinationRecovering:
		return true
	default:
		return false
	}
}

func (adapter *haRuntimeV2Adapter) receiveHeartbeat(wire []byte, now time.Time) error {
	heartbeat, err := decodeHARuntimeV2Heartbeat(wire)
	if err != nil {
		return err
	}
	if heartbeat.Version != haRuntimeV2HeartbeatVersion {
		return fmt.Errorf("unsupported HA v2 heartbeat version")
	}
	expectedMAC, err := adapter.heartbeatMAC(heartbeat)
	if err != nil || !hmac.Equal([]byte(expectedMAC), []byte(heartbeat.MAC)) {
		return fmt.Errorf("invalid HA v2 heartbeat authentication")
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if heartbeat.ClusterID != adapter.coordinator.clusterID || heartbeat.Epoch != adapter.coordinator.epoch || heartbeat.NodeID != adapter.coordinator.peerID ||
		heartbeat.RecipientID != adapter.coordinator.localID {
		adapter.coordinator.fence("HA v2 heartbeat identity conflict")
		return errors.Join(fmt.Errorf("HA v2 heartbeat identity conflict"), adapter.persistCoordinationLocked())
	}
	expectedPeerRole := haRuntimeV2Writer
	if adapter.role == haRuntimeV2Writer {
		expectedPeerRole = haRuntimeV2Standby
	}
	if heartbeat.Role != expectedPeerRole || !validHARuntimeV2CoordinationState(heartbeat.State) || !validHARuntimeV2CoordinationState(heartbeat.PeerView) ||
		!isLowerHexSHA256(heartbeat.CheckpointSHA256) || heartbeat.OutboxDepth < 0 || heartbeat.OutboxDepth > maxHAReplicationOutbox {
		adapter.coordinator.fence("HA v2 heartbeat role or state conflict")
		return errors.Join(fmt.Errorf("HA v2 heartbeat role or state conflict"), adapter.persistCoordinationLocked())
	}
	sentAt, err := time.Parse(time.RFC3339Nano, heartbeat.SentAt)
	if err != nil || sentAt.UTC().Format(time.RFC3339Nano) != heartbeat.SentAt || sentAt.After(now.UTC().Add(adapter.heartbeatTimeout)) || now.UTC().Sub(sentAt) > adapter.heartbeatTimeout {
		return fmt.Errorf("invalid HA v2 heartbeat time")
	}
	if !adapter.lastHeartbeat.IsZero() && !sentAt.After(adapter.lastHeartbeat) {
		return errHACoordinationReplay
	}
	checkpointAt, err := time.Parse(time.RFC3339Nano, heartbeat.CheckpointAt)
	if err != nil || checkpointAt.UTC().Format(time.RFC3339Nano) != heartbeat.CheckpointAt || !checkpointAt.Equal(sentAt) {
		return fmt.Errorf("invalid HA v2 heartbeat checkpoint time")
	}
	adapter.lastHeartbeat = sentAt
	adapter.lastHeartbeatReceivedAt = now
	adapter.peerState = heartbeat.State
	adapter.peerView = heartbeat.PeerView
	adapter.peerCheckpointSHA256 = heartbeat.CheckpointSHA256
	adapter.peerCheckpointAt = checkpointAt.UTC()
	adapter.peerOutboxDepth = heartbeat.OutboxDepth
	adapter.peerDeliveryBudget = heartbeat.OutboxDepth
	stateBefore := adapter.coordinator.state
	localCheckpoint, err := adapter.coordinator.model.replicationCheckpointDigest(checkpointAt)
	if err != nil {
		adapter.coordinator.fence("HA v2 local checkpoint is invalid")
		return errors.Join(err, adapter.persistCoordinationLocked())
	}
	checkpointMismatch := !hmac.Equal([]byte(localCheckpoint), []byte(heartbeat.CheckpointSHA256))
	pendingConvergence := heartbeat.OutboxDepth > 0 || len(adapter.coordinator.model.outbox) > 0
	checkpointGrace := !adapter.checkpointGraceUntil.IsZero() && now.Before(adapter.checkpointGraceUntil)
	if adapter.coordinator.state == haCoordinationHealthy && heartbeat.State == haCoordinationHealthy && heartbeat.PeerView == haCoordinationHealthy &&
		checkpointMismatch && !pendingConvergence && !checkpointGrace {
		adapter.coordinator.setState(haCoordinationRecovering, "HA v2 peer checkpoint divergence; operator recovery required")
	}
	if adapter.coordinator.state == haCoordinationHealthy &&
		(heartbeat.State != haCoordinationHealthy || heartbeat.PeerView != haCoordinationHealthy) {
		inRecoveryGrace := !adapter.recoveryGraceUntil.IsZero() && now.Before(adapter.recoveryGraceUntil) &&
			(heartbeat.State == haCoordinationHealthy || heartbeat.State == haCoordinationRecovering)
		if !inRecoveryGrace {
			adapter.recoveryGraceUntil = time.Time{}
			adapter.coordinator.setState(haCoordinationRecovering, "asymmetric peer state; operator recovery required")
		}
	}
	if heartbeat.State == haCoordinationHealthy && heartbeat.PeerView == haCoordinationHealthy {
		adapter.recoveryGraceUntil = time.Time{}
	}
	if !checkpointMismatch {
		adapter.checkpointGraceUntil = time.Time{}
	}
	if stateBefore != adapter.coordinator.state {
		return adapter.persistCoordinationLocked()
	}
	return nil
}

func (adapter *haRuntimeV2Adapter) checkHeartbeat(now time.Time) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	before := adapter.coordinator.state
	deadlineExceeded := !adapter.lastHeartbeatReceivedAt.IsZero() && adapter.elapsedSince(adapter.lastHeartbeatReceivedAt, now) > adapter.heartbeatTimeout
	if adapter.lastHeartbeat.IsZero() && !adapter.startedAt.IsZero() {
		deadlineExceeded = adapter.elapsedSince(adapter.startedAt, now) > adapter.heartbeatTimeout
	}
	if deadlineExceeded {
		adapter.recoveryGraceUntil = time.Time{}
		adapter.checkpointGraceUntil = time.Time{}
		adapter.coordinator.markPeerUnavailable("HA v2 heartbeat deadline exceeded")
		if before != adapter.coordinator.state {
			_ = adapter.persistCoordinationLocked()
		}
	} else if adapter.coordinator.state == haCoordinationHealthy && !adapter.recoveryGraceUntil.IsZero() &&
		!now.Before(adapter.recoveryGraceUntil) &&
		(adapter.peerState != haCoordinationHealthy || adapter.peerView != haCoordinationHealthy) {
		adapter.recoveryGraceUntil = time.Time{}
		adapter.coordinator.setState(haCoordinationRecovering, "HA v2 recovery grace expired before peer activation")
		_ = adapter.persistCoordinationLocked()
	} else if adapter.coordinator.state == haCoordinationHealthy && !adapter.checkpointGraceUntil.IsZero() &&
		!now.Before(adapter.checkpointGraceUntil) && adapter.peerOutboxDepth == 0 && len(adapter.coordinator.model.outbox) == 0 &&
		isLowerHexSHA256(adapter.peerCheckpointSHA256) {
		checkpoint, err := adapter.coordinator.model.replicationCheckpointDigest(adapter.peerCheckpointAt)
		adapter.checkpointGraceUntil = time.Time{}
		if err != nil || !hmac.Equal([]byte(checkpoint), []byte(adapter.peerCheckpointSHA256)) {
			adapter.coordinator.setState(haCoordinationRecovering, "HA v2 peer checkpoint divergence after delivery convergence grace")
			_ = adapter.persistCoordinationLocked()
		}
	}
}

func (adapter *haRuntimeV2Adapter) expireLocalClaims(now time.Time, limit int) error {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if adapter.pendingTransaction {
		return fmt.Errorf("HA v2 expiry is blocked by a pending recoverable transaction")
	}
	if limit < 1 {
		return nil
	}
	evaluationNow := now
	now = now.UTC().Truncate(time.Second)
	compacted := adapter.coordinator.model.compact(now)
	if adapter.role != haRuntimeV2Writer || adapter.coordinator.state != haCoordinationHealthy || !adapter.peerReadyLocked(evaluationNow) {
		if compacted {
			if err := adapter.persistCoordinationLocked(); err != nil {
				adapter.coordinator.fence("HA v2 compaction persistence failed")
				return err
			}
		}
		return nil
	}
	expired := make([]haReplicationClaim, 0)
	for _, claim := range adapter.coordinator.model.snapshot() {
		if claim.Owner != adapter.coordinator.localID || claim.Action != "upsert" || claim.ExpiresAt == "" {
			continue
		}
		expiresAt, err := parseCanonicalHATime(claim.ExpiresAt)
		if err != nil {
			adapter.coordinator.fence("HA v2 stored expiry is invalid")
			return errors.Join(err, adapter.persistCoordinationLocked())
		}
		if !expiresAt.After(now) {
			expired = append(expired, claim)
		}
	}
	if len(expired) > limit {
		expired = expired[:limit]
	}
	for _, claim := range expired {
		sequence, err := adapter.coordinator.model.nextSequence(adapter.coordinator.localID)
		if err != nil {
			return err
		}
		operation := haReplicationOperation{
			SchemaVersion: haReplicationSchemaVersion, ClusterID: adapter.coordinator.clusterID,
			Epoch: adapter.coordinator.epoch, NodeID: adapter.coordinator.localID, Sequence: sequence, Owner: adapter.coordinator.localID,
			Source: claim.Source, IP: claim.IP, Action: "expiry", IssuedAt: now.Format(time.RFC3339),
			TombstoneUntil: now.Add(haV2TombstoneRetention).Format(time.RFC3339),
		}
		operation.OperationID, err = haReplicationOperationDigest(operation)
		if err != nil {
			return err
		}
		if _, err := adapter.enqueueLocalLocked(operation); err != nil {
			return err
		}
	}
	if adapter.coordinator.model.compact(now) || compacted {
		if err := adapter.persistCoordinationLocked(); err != nil {
			adapter.coordinator.fence("HA v2 expiry persistence failed")
			return err
		}
	}
	return nil
}

func (adapter *haRuntimeV2Adapter) validateAuthorizedPeer(peer haPeerIdentity) error {
	address, err := netip.ParseAddr(peer.IP)
	if err != nil || address != adapter.peerAddress || peer.Scope != netip.PrefixFrom(adapter.peerAddress, adapter.peerAddress.BitLen()).String() {
		return fmt.Errorf("HA v2 requires an exact attested peer address")
	}
	return nil
}

func readHARuntimeV2Body(w http.ResponseWriter, request *http.Request, limit int64) ([]byte, bool) {
	if request.Body == nil || request.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
		return nil, false
	}
	reader := http.MaxBytesReader(w, request.Body, limit)
	wire, err := io.ReadAll(reader)
	if err != nil || len(wire) == 0 {
		http.Error(w, "Request body exceeds bounds", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	return wire, true
}

func (api *haAPI) authorizeV2(w http.ResponseWriter, request *http.Request) (*haRuntimeV2Adapter, bool) {
	adapter := api.replicationV2
	if adapter == nil {
		http.NotFound(w, request)
		return nil, false
	}
	peer, authorized := api.authorizePeer(w, request)
	if !authorized {
		return nil, false
	}
	if err := adapter.validateAuthorizedPeer(peer); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil, false
	}
	if adapter.peerCertificateVerifier == nil || adapter.peerCertificateVerifier(request.TLS) != nil {
		http.Error(w, "Client certificate required", http.StatusUnauthorized)
		return nil, false
	}
	return adapter, true
}

func (api *haAPI) handleV2Replication(w http.ResponseWriter, request *http.Request) {
	adapter, authorized := api.authorizeV2(w, request)
	if !authorized {
		return
	}
	if request.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	wire, ok := readHARuntimeV2Body(w, request, maxHACoordinationEnvelopeBytes)
	if !ok {
		return
	}
	envelope, decodeErr := decodeHACoordinationEnvelope(wire)
	if decodeErr != nil || validateHAReplicationOperation(envelope.Operation) != nil {
		http.Error(w, "HA v2 replication rejected", http.StatusBadRequest)
		return
	}
	if envelope.Operation.Action == "upsert" {
		if err := api.validateHAMutationTargets(haMutationRequest{ips: []string{envelope.Operation.IP}}); err != nil {
			http.Error(w, "Rejected firewall target", http.StatusBadRequest)
			return
		}
	}
	if _, err := adapter.receiveReplication(wire); err != nil {
		status := http.StatusConflict
		if errors.Is(err, errHACoordinationReplay) {
			status = http.StatusAlreadyReported
		}
		http.Error(w, "HA v2 replication rejected", status)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *haAPI) handleV2Heartbeat(w http.ResponseWriter, request *http.Request) {
	adapter, authorized := api.authorizeV2(w, request)
	if !authorized {
		return
	}
	if request.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	wire, ok := readHARuntimeV2Body(w, request, maxHARuntimeV2HeartbeatBytes)
	if !ok {
		return
	}
	if err := adapter.receiveHeartbeat(wire, api.now()); err != nil {
		http.Error(w, "HA v2 heartbeat rejected", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type haRuntimeV2RecoveryRequest struct {
	Action              string `json:"action"`
	PeerID              string `json:"peer_id,omitempty"`
	ExpectedLocalSHA256 string `json:"expected_local_sha256,omitempty"`
}

func (api *haAPI) handleV2Recovery(w http.ResponseWriter, request *http.Request) {
	adapter, authorized := api.authorizeV2(w, request)
	if !authorized {
		return
	}
	if request.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	wire, ok := readHARuntimeV2Body(w, request, maxHARuntimeV2HeartbeatBytes)
	if !ok {
		return
	}
	if err := rejectHADuplicateJSONKeys(wire); err != nil {
		http.Error(w, "Invalid recovery request", http.StatusBadRequest)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var recovery haRuntimeV2RecoveryRequest
	if err := decoder.Decode(&recovery); err != nil {
		http.Error(w, "Invalid recovery request", http.StatusBadRequest)
		return
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		http.Error(w, "Invalid recovery request", http.StatusBadRequest)
		return
	}
	var err error
	switch recovery.Action {
	case "prepare":
		if recovery.PeerID == "" || recovery.ExpectedLocalSHA256 == "" {
			err = fmt.Errorf("recovery evidence is incomplete")
		} else {
			err = adapter.beginOperatorRecovery(recovery.PeerID, recovery.ExpectedLocalSHA256)
		}
	case "activate":
		if recovery.PeerID != "" || recovery.ExpectedLocalSHA256 != "" {
			err = fmt.Errorf("activation must not carry stale recovery evidence")
		} else {
			err = adapter.activateAfterRecovery()
		}
	default:
		err = fmt.Errorf("unsupported recovery action")
	}
	if err != nil {
		http.Error(w, "HA v2 recovery rejected", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func deriveHARuntimeV2Secret(existingToken string) []byte {
	digest := sha256.Sum256([]byte("syswarden-ha-runtime-v2\x00" + strings.TrimSpace(existingToken)))
	return digest[:]
}
