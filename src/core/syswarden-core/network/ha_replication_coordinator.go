package network

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	haCoordinationEnvelopeVersion  = 1
	maxHACoordinationEnvelopeBytes = 96 * 1024
)

type haCoordinationState string

const (
	haCoordinationHealthy    haCoordinationState = "healthy"
	haCoordinationDegraded   haCoordinationState = "degraded"
	haCoordinationFenced     haCoordinationState = "fenced"
	haCoordinationRecovering haCoordinationState = "recovering"
)

var errHACoordinationReplay = errors.New("HA coordination replay rejected")

type haCoordinationEnvelope struct {
	Version     int                    `json:"version"`
	ClusterID   string                 `json:"cluster_id"`
	Epoch       uint64                 `json:"epoch"`
	SenderID    string                 `json:"sender_id"`
	RecipientID string                 `json:"recipient_id"`
	MessageID   string                 `json:"message_id"`
	SentAt      string                 `json:"sent_at"`
	Operation   haReplicationOperation `json:"operation"`
	MAC         string                 `json:"mac"`
}

type haCoordinationAuthenticatedPayload struct {
	Version     int                    `json:"version"`
	ClusterID   string                 `json:"cluster_id"`
	Epoch       uint64                 `json:"epoch"`
	SenderID    string                 `json:"sender_id"`
	RecipientID string                 `json:"recipient_id"`
	MessageID   string                 `json:"message_id"`
	SentAt      string                 `json:"sent_at"`
	Operation   haReplicationOperation `json:"operation"`
}

type haReplicationCoordinator struct {
	clusterID string
	epoch     uint64
	localID   string
	peerID    string
	secret    []byte
	model     *haReplicationModel
	state     haCoordinationState
	reason    string
}

func validHACoordinationPersistence(state haCoordinationState, reason string) bool {
	if len(reason) > 512 {
		return false
	}
	for _, character := range reason {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	switch state {
	case haCoordinationHealthy:
		return reason == ""
	case haCoordinationDegraded, haCoordinationFenced, haCoordinationRecovering:
		return reason != ""
	default:
		return false
	}
}

func (coordinator *haReplicationCoordinator) setState(state haCoordinationState, reason string) {
	coordinator.state, coordinator.reason = state, reason
	coordinator.model.coordinationState, coordinator.model.coordinationReason = state, reason
}

func newHAReplicationCoordinator(clusterID, localID, peerID string, secret []byte, model *haReplicationModel) (*haReplicationCoordinator, error) {
	if !haReplicationIDRE.MatchString(clusterID) || !haReplicationIDRE.MatchString(localID) ||
		!haReplicationIDRE.MatchString(peerID) || localID == peerID || len(secret) < 32 ||
		model == nil || model.clusterID != clusterID {
		return nil, fmt.Errorf("invalid HA coordination identity or secret")
	}
	if err := model.validateMembership(localID, peerID); err != nil {
		return nil, err
	}
	return &haReplicationCoordinator{
		clusterID: clusterID, epoch: model.epoch, localID: localID, peerID: peerID,
		secret: append([]byte(nil), secret...), model: model,
		state: model.coordinationState, reason: model.coordinationReason,
	}, nil
}

func (coordinator *haReplicationCoordinator) close() {
	for index := range coordinator.secret {
		coordinator.secret[index] = 0
	}
	coordinator.secret = nil
}

func (coordinator *haReplicationCoordinator) activate() error {
	if coordinator.state == haCoordinationFenced {
		return fmt.Errorf("HA coordination is fenced")
	}
	coordinator.setState(haCoordinationHealthy, "")
	return nil
}

func (coordinator *haReplicationCoordinator) markPeerUnavailable(reason string) {
	if coordinator.state == haCoordinationHealthy {
		coordinator.setState(haCoordinationDegraded, reason)
	}
}

func (coordinator *haReplicationCoordinator) fence(reason string) {
	coordinator.setState(haCoordinationFenced, reason)
}

func (coordinator *haReplicationCoordinator) stateDigest() (string, error) {
	return coordinator.model.persistentStateDigest()
}

func (coordinator *haReplicationCoordinator) beginRecovery(peerID, expectedLocalDigest string) error {
	if coordinator.state != haCoordinationFenced && coordinator.state != haCoordinationDegraded && coordinator.state != haCoordinationRecovering {
		return fmt.Errorf("HA coordination recovery is not required")
	}
	actual, err := coordinator.stateDigest()
	if err != nil {
		return err
	}
	if peerID != coordinator.peerID || !isLowerHexSHA256(expectedLocalDigest) ||
		!hmac.Equal([]byte(actual), []byte(expectedLocalDigest)) {
		coordinator.fence("recovery identity or checkpoint mismatch")
		return fmt.Errorf("HA coordination recovery evidence mismatch")
	}
	coordinator.setState(haCoordinationRecovering, haV2RecoveryPreparedReason)
	return nil
}

func haCoordinationPayload(envelope haCoordinationEnvelope) haCoordinationAuthenticatedPayload {
	return haCoordinationAuthenticatedPayload{
		Version: envelope.Version, ClusterID: envelope.ClusterID, SenderID: envelope.SenderID,
		Epoch:       envelope.Epoch,
		RecipientID: envelope.RecipientID, MessageID: envelope.MessageID,
		SentAt: envelope.SentAt, Operation: envelope.Operation,
	}
}

func haCoordinationMAC(secret []byte, envelope haCoordinationEnvelope) (string, error) {
	wire, err := json.Marshal(haCoordinationPayload(envelope))
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(wire)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (coordinator *haReplicationCoordinator) envelope(operation haReplicationOperation, now time.Time) ([]byte, error) {
	if coordinator.state != haCoordinationHealthy && coordinator.state != haCoordinationDegraded {
		return nil, fmt.Errorf("HA coordination cannot emit while %s", coordinator.state)
	}
	if operation.ClusterID != coordinator.clusterID || operation.Epoch != coordinator.epoch || operation.NodeID != coordinator.localID {
		coordinator.fence("local operation identity conflict")
		return nil, fmt.Errorf("HA coordination local identity conflict")
	}
	envelope := haCoordinationEnvelope{
		Version: haCoordinationEnvelopeVersion, ClusterID: coordinator.clusterID, Epoch: coordinator.epoch,
		SenderID: coordinator.localID, RecipientID: coordinator.peerID,
		MessageID: operation.OperationID, SentAt: now.UTC().Format(time.RFC3339), Operation: operation,
	}
	if _, err := parseCanonicalHATime(envelope.SentAt); err != nil {
		return nil, err
	}
	mac, err := haCoordinationMAC(coordinator.secret, envelope)
	if err != nil {
		return nil, err
	}
	envelope.MAC = mac
	wire, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	if len(wire) > maxHACoordinationEnvelopeBytes {
		return nil, fmt.Errorf("HA coordination envelope exceeds bounds")
	}
	return wire, nil
}

func decodeHACoordinationEnvelope(wire []byte) (haCoordinationEnvelope, error) {
	if len(wire) == 0 || len(wire) > maxHACoordinationEnvelopeBytes {
		return haCoordinationEnvelope{}, fmt.Errorf("HA coordination envelope exceeds bounds")
	}
	if err := rejectHADuplicateJSONKeys(wire); err != nil {
		return haCoordinationEnvelope{}, err
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(wire), maxHACoordinationEnvelopeBytes+1))
	decoder.DisallowUnknownFields()
	var envelope haCoordinationEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return haCoordinationEnvelope{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return haCoordinationEnvelope{}, fmt.Errorf("HA coordination envelope has trailing JSON")
	}
	return envelope, nil
}

func (coordinator *haReplicationCoordinator) authenticate(wire []byte) (haReplicationOperation, error) {
	if coordinator.state == haCoordinationFenced {
		return haReplicationOperation{}, fmt.Errorf("HA coordination is fenced")
	}
	envelope, err := decodeHACoordinationEnvelope(wire)
	if err != nil {
		coordinator.fence("malformed coordination envelope")
		return haReplicationOperation{}, err
	}
	if envelope.Version != haCoordinationEnvelopeVersion || envelope.ClusterID != coordinator.clusterID || envelope.Epoch != coordinator.epoch ||
		envelope.SenderID != coordinator.peerID || envelope.RecipientID != coordinator.localID ||
		envelope.MessageID != envelope.Operation.OperationID || envelope.Operation.NodeID != envelope.SenderID ||
		envelope.Operation.ClusterID != envelope.ClusterID || envelope.Operation.Epoch != envelope.Epoch {
		coordinator.fence("coordination identity conflict")
		return haReplicationOperation{}, fmt.Errorf("HA coordination identity conflict")
	}
	if _, err := parseCanonicalHATime(envelope.SentAt); err != nil || !isLowerHexSHA256(envelope.MAC) {
		coordinator.fence("invalid coordination metadata")
		return haReplicationOperation{}, fmt.Errorf("invalid HA coordination metadata")
	}
	expectedMAC, err := haCoordinationMAC(coordinator.secret, envelope)
	if err != nil || !hmac.Equal([]byte(expectedMAC), []byte(envelope.MAC)) {
		coordinator.fence("coordination integrity failure")
		return haReplicationOperation{}, fmt.Errorf("HA coordination integrity failure")
	}
	if coordinator.model.operationCovered(envelope.Operation) {
		return envelope.Operation, errHACoordinationReplay
	}
	return envelope.Operation, nil
}

func (coordinator *haReplicationCoordinator) receive(wire []byte) (bool, error) {
	operation, err := coordinator.authenticate(wire)
	if err != nil {
		return false, err
	}
	changed, err := coordinator.model.apply(operation)
	if err != nil {
		coordinator.fence("replication divergence: " + err.Error())
		return false, err
	}
	if coordinator.state == haCoordinationDegraded {
		coordinator.setState(haCoordinationRecovering, "peer returned; explicit activation required")
	}
	return changed, nil
}
