package network

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"syswarden-core/firewall"
)

const (
	haReplicationSchemaVersion = 1
	maxHAReplicationWireBytes  = 64 * 1024
	maxHAReplicationOperations = 16384
	maxHAReplicationOutbox     = 4096
	maxHAReplicationStateBytes = 16 * 1024 * 1024
	haReplicationStateVersion  = 1
	haV2TombstoneRetention     = 30 * 24 * time.Hour
)

var haReplicationIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type haReplicationOperation struct {
	SchemaVersion  int    `json:"schema_version"`
	ClusterID      string `json:"cluster_id"`
	Epoch          uint64 `json:"epoch"`
	NodeID         string `json:"node_id"`
	Sequence       uint64 `json:"sequence"`
	OperationID    string `json:"operation_id"`
	Owner          string `json:"owner"`
	Source         string `json:"source"`
	IP             string `json:"ip"`
	Action         string `json:"action"`
	IssuedAt       string `json:"issued_at"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	TombstoneUntil string `json:"tombstone_until,omitempty"`
}

type haReplicationDigestPayload struct {
	SchemaVersion  int    `json:"schema_version"`
	ClusterID      string `json:"cluster_id"`
	Epoch          uint64 `json:"epoch"`
	NodeID         string `json:"node_id"`
	Sequence       uint64 `json:"sequence"`
	Owner          string `json:"owner"`
	Source         string `json:"source"`
	IP             string `json:"ip"`
	Action         string `json:"action"`
	IssuedAt       string `json:"issued_at"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	TombstoneUntil string `json:"tombstone_until,omitempty"`
}

type haReplicationClaim struct {
	Owner          string
	Source         string
	IP             string
	Action         string
	Sequence       uint64
	OperationID    string
	ExpiresAt      string
	TombstoneUntil string
}

type haReplicationModel struct {
	clusterID          string
	epoch              uint64
	genesisID          string
	localNodeID        string
	peerNodeID         string
	staticRole         string
	coordinationState  haCoordinationState
	coordinationReason string
	claims             map[string]haReplicationOperation
	sequences          map[string]map[uint64]string
	seen               map[string]struct{}
	highWater          map[string]uint64
	outbox             map[string]haReplicationOperation
}

type haReplicationSequenceRecord struct {
	NodeID      string `json:"node_id"`
	Sequence    uint64 `json:"sequence"`
	OperationID string `json:"operation_id"`
}

type haReplicationHighWater struct {
	NodeID   string `json:"node_id"`
	Sequence uint64 `json:"sequence"`
}

type haReplicationPersistentState struct {
	Version            int                           `json:"version"`
	ClusterID          string                        `json:"cluster_id"`
	Epoch              uint64                        `json:"epoch"`
	GenesisID          string                        `json:"genesis_id"`
	LocalNodeID        string                        `json:"local_node_id,omitempty"`
	PeerNodeID         string                        `json:"peer_node_id,omitempty"`
	StaticRole         string                        `json:"static_role,omitempty"`
	CoordinationState  haCoordinationState           `json:"coordination_state"`
	CoordinationReason string                        `json:"coordination_reason,omitempty"`
	Claims             []haReplicationOperation      `json:"claims"`
	Sequences          []haReplicationSequenceRecord `json:"sequences"`
	HighWater          []haReplicationHighWater      `json:"high_water"`
	Outbox             []haReplicationOperation      `json:"outbox"`
}

// haReplicationCheckpointState contains only the replicated, peer-comparable
// portion of the model. Local identity, role, coordination status, genesis,
// and the writer-only delivery outbox are deliberately excluded.
type haReplicationCheckpointState struct {
	Version   int                           `json:"version"`
	ClusterID string                        `json:"cluster_id"`
	Epoch     uint64                        `json:"epoch"`
	Claims    []haReplicationOperation      `json:"claims"`
	Sequences []haReplicationSequenceRecord `json:"sequences"`
	HighWater []haReplicationHighWater      `json:"high_water"`
}

func newHAReplicationModel(clusterID string) (*haReplicationModel, error) {
	if !haReplicationIDRE.MatchString(clusterID) {
		return nil, fmt.Errorf("invalid HA replication cluster ID")
	}
	var genesis [sha256.Size]byte
	if _, err := rand.Read(genesis[:]); err != nil {
		return nil, fmt.Errorf("generate HA replication genesis identity: %w", err)
	}
	return &haReplicationModel{
		clusterID: clusterID, epoch: 1, genesisID: hex.EncodeToString(genesis[:]), coordinationState: haCoordinationRecovering,
		coordinationReason: "new HA v2 state requires activation",
		claims:             make(map[string]haReplicationOperation),
		sequences:          make(map[string]map[uint64]string),
		seen:               make(map[string]struct{}),
		highWater:          make(map[string]uint64),
		outbox:             make(map[string]haReplicationOperation),
	}, nil
}

func (model *haReplicationModel) setEpoch(epoch uint64) error {
	if model == nil || epoch == 0 {
		return fmt.Errorf("invalid HA replication epoch")
	}
	if (len(model.claims) > 0 || len(model.sequences) > 0 || len(model.highWater) > 0 || len(model.outbox) > 0) && model.epoch != epoch {
		return fmt.Errorf("HA replication epoch cannot change with non-empty state")
	}
	model.epoch = epoch
	return nil
}

func (model *haReplicationModel) setCoordination(state haCoordinationState, reason string) error {
	if model == nil || !validHACoordinationPersistence(state, reason) {
		return fmt.Errorf("invalid HA replication coordination state")
	}
	model.coordinationState = state
	model.coordinationReason = reason
	return nil
}

func (model *haReplicationModel) validateMembership(localID, peerID string) error {
	if model == nil || !haReplicationIDRE.MatchString(localID) || !haReplicationIDRE.MatchString(peerID) || localID == peerID {
		return fmt.Errorf("invalid HA replication membership")
	}
	allowed := func(nodeID string) bool { return nodeID == localID || nodeID == peerID }
	if model.localNodeID != "" && (model.localNodeID != localID || model.peerNodeID != peerID) {
		return fmt.Errorf("HA replication persisted identity does not match configured membership")
	}
	for _, operation := range model.claims {
		if !allowed(operation.NodeID) {
			return fmt.Errorf("HA replication claim belongs to an undeclared node")
		}
	}
	for nodeID := range model.sequences {
		if !allowed(nodeID) {
			return fmt.Errorf("HA replication sequence belongs to an undeclared node")
		}
	}
	for nodeID := range model.highWater {
		if !allowed(nodeID) {
			return fmt.Errorf("HA replication high-water mark belongs to an undeclared node")
		}
	}
	for _, operation := range model.outbox {
		if !allowed(operation.NodeID) {
			return fmt.Errorf("HA replication outbox belongs to an undeclared node")
		}
	}
	return nil
}

func (model *haReplicationModel) bindRuntimeIdentity(localID, peerID, role string) (bool, error) {
	if model == nil || !haReplicationIDRE.MatchString(localID) || !haReplicationIDRE.MatchString(peerID) || localID == peerID ||
		(role != string(haRuntimeV2Writer) && role != string(haRuntimeV2Standby)) {
		return false, fmt.Errorf("invalid HA v2 runtime identity binding")
	}
	if model.localNodeID == "" && model.peerNodeID == "" && model.staticRole == "" {
		if len(model.claims) != 0 || len(model.sequences) != 0 || len(model.highWater) != 0 || len(model.outbox) != 0 {
			return false, fmt.Errorf("HA v2 non-empty state has no persisted runtime identity")
		}
		model.localNodeID, model.peerNodeID, model.staticRole = localID, peerID, role
		return true, nil
	}
	if model.localNodeID != localID || model.peerNodeID != peerID || model.staticRole != role {
		return false, fmt.Errorf("HA v2 runtime identity conflicts with persisted cluster epoch")
	}
	return false, nil
}

func (model *haReplicationModel) validateStaticRole(localID, peerID, role string) error {
	if err := model.validateMembership(localID, peerID); err != nil {
		return err
	}
	if role != string(haRuntimeV2Writer) && role != string(haRuntimeV2Standby) {
		return fmt.Errorf("invalid HA v2 static role")
	}
	if model.staticRole != "" && model.staticRole != role {
		return fmt.Errorf("HA v2 static role conflicts with the persisted cluster epoch")
	}
	expectedWriter := localID
	if role == string(haRuntimeV2Standby) {
		expectedWriter = peerID
		if len(model.outbox) != 0 {
			return fmt.Errorf("HA v2 standby state contains a local replication outbox")
		}
	}
	for _, operation := range model.claims {
		if operation.NodeID != expectedWriter {
			return fmt.Errorf("HA v2 persisted claim conflicts with the static writer role")
		}
	}
	for nodeID := range model.sequences {
		if nodeID != expectedWriter {
			return fmt.Errorf("HA v2 persisted sequence conflicts with the static writer role")
		}
	}
	for nodeID := range model.highWater {
		if nodeID != expectedWriter {
			return fmt.Errorf("HA v2 persisted high-water mark conflicts with the static writer role")
		}
	}
	for _, operation := range model.outbox {
		if operation.NodeID != localID {
			return fmt.Errorf("HA v2 persisted outbox conflicts with local identity")
		}
	}
	return nil
}

func haReplicationOperationDigest(operation haReplicationOperation) (string, error) {
	payload := haReplicationDigestPayload{
		SchemaVersion: operation.SchemaVersion, ClusterID: operation.ClusterID,
		Epoch: operation.Epoch, NodeID: operation.NodeID, Sequence: operation.Sequence, Owner: operation.Owner,
		Source: operation.Source, IP: operation.IP, Action: operation.Action,
		IssuedAt: operation.IssuedAt, ExpiresAt: operation.ExpiresAt,
		TombstoneUntil: operation.TombstoneUntil,
	}
	wire, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

func validateHAReplicationOperation(operation haReplicationOperation) error {
	if operation.SchemaVersion != haReplicationSchemaVersion {
		return fmt.Errorf("unsupported HA replication schema version %d", operation.SchemaVersion)
	}
	if !haReplicationIDRE.MatchString(operation.ClusterID) ||
		!haReplicationIDRE.MatchString(operation.NodeID) || operation.Owner != operation.NodeID ||
		operation.Epoch == 0 || operation.Sequence == 0 || !isLowerHexSHA256(operation.OperationID) ||
		!validHASource(operation.Source) {
		return fmt.Errorf("invalid HA replication identity")
	}
	canonicalIP, err := canonicalHAAddress(operation.IP)
	if err != nil || canonicalIP != operation.IP {
		return fmt.Errorf("invalid HA replication address")
	}
	issuedAt, err := parseCanonicalHATime(operation.IssuedAt)
	if err != nil {
		return fmt.Errorf("invalid HA replication issue time")
	}
	switch operation.Action {
	case "upsert":
		if operation.TombstoneUntil != "" {
			return fmt.Errorf("upsert must not carry a tombstone deadline")
		}
		if operation.ExpiresAt != "" {
			expiresAt, parseErr := parseCanonicalHATime(operation.ExpiresAt)
			lifetime := expiresAt.Sub(issuedAt)
			if parseErr != nil || lifetime < firewall.MinimumBanTTL || lifetime > firewall.MaximumBanTTL || lifetime%time.Second != 0 {
				return fmt.Errorf("invalid HA replication expiry")
			}
		}
	case "delete", "expiry":
		if operation.ExpiresAt != "" {
			return fmt.Errorf("tombstone must not carry an active expiry")
		}
		until, parseErr := parseCanonicalHATime(operation.TombstoneUntil)
		if parseErr != nil || until.Sub(issuedAt) != haV2TombstoneRetention {
			return fmt.Errorf("invalid HA replication tombstone retention")
		}
	default:
		return fmt.Errorf("invalid HA replication action")
	}
	expected, err := haReplicationOperationDigest(operation)
	if err != nil || expected != operation.OperationID {
		return fmt.Errorf("invalid HA replication operation digest")
	}
	return nil
}

func decodeHAReplicationOperation(wire []byte) (haReplicationOperation, error) {
	if len(wire) == 0 || len(wire) > maxHAReplicationWireBytes {
		return haReplicationOperation{}, fmt.Errorf("HA replication operation exceeds bounds")
	}
	if err := rejectHADuplicateJSONKeys(wire); err != nil {
		return haReplicationOperation{}, fmt.Errorf("decode HA replication operation: %w", err)
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(wire), maxHAReplicationWireBytes+1))
	decoder.DisallowUnknownFields()
	var operation haReplicationOperation
	if err := decoder.Decode(&operation); err != nil {
		return haReplicationOperation{}, fmt.Errorf("decode HA replication operation: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return haReplicationOperation{}, fmt.Errorf("decode HA replication operation: trailing JSON")
	}
	if err := validateHAReplicationOperation(operation); err != nil {
		return haReplicationOperation{}, err
	}
	return operation, nil
}

func haReplicationClaimKey(operation haReplicationOperation) string {
	return operation.Owner + "\x00" + operation.Source + "\x00" + operation.IP
}

func (model *haReplicationModel) apply(operation haReplicationOperation) (bool, error) {
	if model == nil || model.clusterID == "" {
		return false, fmt.Errorf("uninitialized HA replication model")
	}
	if err := validateHAReplicationOperation(operation); err != nil {
		return false, err
	}
	if operation.ClusterID != model.clusterID || operation.Epoch != model.epoch {
		return false, fmt.Errorf("HA replication cluster epoch mismatch")
	}
	if operation.Sequence <= model.highWater[operation.NodeID] {
		return false, nil
	}
	if _, duplicate := model.seen[operation.OperationID]; duplicate {
		return false, nil
	}
	nodeSequences := model.sequences[operation.NodeID]
	if existingID, exists := nodeSequences[operation.Sequence]; exists {
		if existingID == operation.OperationID {
			return false, nil
		}
		return false, fmt.Errorf("conflicting HA replication node sequence")
	}
	if len(model.seen) >= maxHAReplicationOperations {
		return false, fmt.Errorf("HA replication operation quota exceeded")
	}
	key := haReplicationClaimKey(operation)
	if _, exists := model.claims[key]; !exists && len(model.claims) >= maxHAReplicationOperations {
		return false, fmt.Errorf("HA replication claim quota exceeded")
	}
	if nodeSequences == nil {
		nodeSequences = make(map[uint64]string)
		model.sequences[operation.NodeID] = nodeSequences
	}
	nodeSequences[operation.Sequence] = operation.OperationID
	model.seen[operation.OperationID] = struct{}{}
	current, exists := model.claims[key]
	if exists && current.Sequence > operation.Sequence {
		// The operation still advances replay evidence even though a newer claim
		// already determines the effective firewall state.
		return true, nil
	}
	model.claims[key] = operation
	return true, nil
}

func (model *haReplicationModel) enqueue(operation haReplicationOperation) (bool, error) {
	if len(model.outbox) >= maxHAReplicationOutbox {
		if _, exists := model.outbox[operation.OperationID]; !exists {
			return false, fmt.Errorf("HA replication outbox quota exceeded")
		}
	}
	changed, err := model.apply(operation)
	if err != nil {
		return false, err
	}
	if _, exists := model.outbox[operation.OperationID]; exists {
		return changed, nil
	}
	model.outbox[operation.OperationID] = operation
	return true, nil
}

func (model *haReplicationModel) acknowledge(operationID string) error {
	if !isLowerHexSHA256(operationID) {
		return fmt.Errorf("invalid HA replication acknowledgement")
	}
	delete(model.outbox, operationID)
	return nil
}

func (model *haReplicationModel) operationCovered(operation haReplicationOperation) bool {
	if operation.Sequence <= model.highWater[operation.NodeID] {
		return true
	}
	_, seen := model.seen[operation.OperationID]
	return seen
}

func (model *haReplicationModel) compact(now time.Time) bool {
	changed := false
	for nodeID, records := range model.sequences {
		frontier := model.highWater[nodeID]
		originalFrontier := frontier
		for {
			operationID, exists := records[frontier+1]
			if !exists {
				break
			}
			frontier++
			delete(records, frontier)
			delete(model.seen, operationID)
		}
		if frontier != originalFrontier {
			changed = true
		}
		model.highWater[nodeID] = frontier
		if len(records) == 0 {
			delete(model.sequences, nodeID)
		}
	}
	for key, operation := range model.claims {
		if operation.Action == "upsert" || operation.Sequence > model.highWater[operation.NodeID] {
			continue
		}
		until, err := parseCanonicalHATime(operation.TombstoneUntil)
		if err == nil && !until.After(now.UTC()) {
			delete(model.claims, key)
			changed = true
		}
	}
	return changed
}

func (model *haReplicationModel) snapshot() []haReplicationClaim {
	claims := make([]haReplicationClaim, 0, len(model.claims))
	for _, operation := range model.claims {
		claims = append(claims, haReplicationClaim{
			Owner: operation.Owner, Source: operation.Source, IP: operation.IP,
			Action: operation.Action, Sequence: operation.Sequence, OperationID: operation.OperationID,
			ExpiresAt: operation.ExpiresAt, TombstoneUntil: operation.TombstoneUntil,
		})
	}
	sort.Slice(claims, func(i, j int) bool {
		if claims[i].IP != claims[j].IP {
			return claims[i].IP < claims[j].IP
		}
		if claims[i].Source != claims[j].Source {
			return claims[i].Source < claims[j].Source
		}
		return claims[i].Owner < claims[j].Owner
	})
	return claims
}

func (model *haReplicationModel) persistentState() haReplicationPersistentState {
	state := haReplicationPersistentState{
		Version: haReplicationStateVersion, ClusterID: model.clusterID, Epoch: model.epoch, GenesisID: model.genesisID,
		LocalNodeID: model.localNodeID, PeerNodeID: model.peerNodeID, StaticRole: model.staticRole,
		CoordinationState: model.coordinationState, CoordinationReason: model.coordinationReason,
	}
	for _, operation := range model.claims {
		state.Claims = append(state.Claims, operation)
	}
	for nodeID, records := range model.sequences {
		for sequence, operationID := range records {
			state.Sequences = append(state.Sequences, haReplicationSequenceRecord{NodeID: nodeID, Sequence: sequence, OperationID: operationID})
		}
	}
	for nodeID, sequence := range model.highWater {
		if sequence > 0 {
			state.HighWater = append(state.HighWater, haReplicationHighWater{NodeID: nodeID, Sequence: sequence})
		}
	}
	for _, operation := range model.outbox {
		state.Outbox = append(state.Outbox, operation)
	}
	sort.Slice(state.Claims, func(i, j int) bool { return state.Claims[i].OperationID < state.Claims[j].OperationID })
	sort.Slice(state.Sequences, func(i, j int) bool {
		if state.Sequences[i].NodeID != state.Sequences[j].NodeID {
			return state.Sequences[i].NodeID < state.Sequences[j].NodeID
		}
		return state.Sequences[i].Sequence < state.Sequences[j].Sequence
	})
	sort.Slice(state.HighWater, func(i, j int) bool { return state.HighWater[i].NodeID < state.HighWater[j].NodeID })
	sort.Slice(state.Outbox, func(i, j int) bool { return state.Outbox[i].OperationID < state.Outbox[j].OperationID })
	return state
}

func (model *haReplicationModel) persistentStateDigest() (string, error) {
	if model == nil {
		return "", fmt.Errorf("uninitialized HA replication model")
	}
	wire, err := json.Marshal(model.persistentState())
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

func (model *haReplicationModel) replicationCheckpointDigest(at time.Time) (string, error) {
	if model == nil {
		return "", fmt.Errorf("uninitialized HA replication model")
	}
	state := model.persistentState()
	claims := make([]haReplicationOperation, 0, len(state.Claims))
	for _, operation := range state.Claims {
		if operation.Action == "delete" || operation.Action == "expiry" {
			until, err := parseCanonicalHATime(operation.TombstoneUntil)
			if err != nil {
				return "", err
			}
			if !until.After(at.UTC()) {
				continue
			}
		}
		claims = append(claims, operation)
	}
	checkpoint := haReplicationCheckpointState{
		Version: state.Version, ClusterID: state.ClusterID, Epoch: state.Epoch,
		Claims: claims, Sequences: state.Sequences, HighWater: state.HighWater,
	}
	wire, err := json.Marshal(checkpoint)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

func cloneHAReplicationModel(model *haReplicationModel) (*haReplicationModel, error) {
	if model == nil {
		return nil, fmt.Errorf("cannot clone an uninitialized HA replication model")
	}
	return validateHAReplicationPersistentState(model.persistentState())
}

func (model *haReplicationModel) nextSequence(nodeID string) (uint64, error) {
	if model == nil || !haReplicationIDRE.MatchString(nodeID) {
		return 0, fmt.Errorf("invalid HA replication sequence identity")
	}
	maximum := model.highWater[nodeID]
	for sequence := range model.sequences[nodeID] {
		if sequence > maximum {
			maximum = sequence
		}
	}
	if maximum == ^uint64(0) {
		return 0, fmt.Errorf("HA replication sequence exhausted")
	}
	return maximum + 1, nil
}

func validateHAReplicationPersistentState(state haReplicationPersistentState) (*haReplicationModel, error) {
	identityEmpty := state.LocalNodeID == "" && state.PeerNodeID == "" && state.StaticRole == ""
	identityValid := haReplicationIDRE.MatchString(state.LocalNodeID) && haReplicationIDRE.MatchString(state.PeerNodeID) &&
		state.LocalNodeID != state.PeerNodeID && (state.StaticRole == string(haRuntimeV2Writer) || state.StaticRole == string(haRuntimeV2Standby))
	if state.Version != haReplicationStateVersion || state.Epoch == 0 || !isLowerHexSHA256(state.GenesisID) || !validHACoordinationPersistence(state.CoordinationState, state.CoordinationReason) || len(state.Claims) > maxHAReplicationOperations ||
		len(state.Sequences) > maxHAReplicationOperations || len(state.HighWater) > maxHAReplicationOperations ||
		len(state.Outbox) > maxHAReplicationOutbox || (!identityEmpty && !identityValid) {
		return nil, fmt.Errorf("invalid HA replication persistent state bounds")
	}
	model, err := newHAReplicationModel(state.ClusterID)
	if err != nil {
		return nil, err
	}
	model.epoch = state.Epoch
	model.genesisID = state.GenesisID
	model.localNodeID = state.LocalNodeID
	model.peerNodeID = state.PeerNodeID
	model.staticRole = state.StaticRole
	model.coordinationState = state.CoordinationState
	model.coordinationReason = state.CoordinationReason
	for index, entry := range state.HighWater {
		if !haReplicationIDRE.MatchString(entry.NodeID) || entry.Sequence == 0 || index > 0 && state.HighWater[index-1].NodeID >= entry.NodeID {
			return nil, fmt.Errorf("invalid HA replication high-water marks")
		}
		model.highWater[entry.NodeID] = entry.Sequence
	}
	for index, entry := range state.Sequences {
		if !haReplicationIDRE.MatchString(entry.NodeID) || entry.Sequence == 0 || !isLowerHexSHA256(entry.OperationID) ||
			entry.Sequence <= model.highWater[entry.NodeID] || index > 0 && (state.Sequences[index-1].NodeID > entry.NodeID || state.Sequences[index-1].NodeID == entry.NodeID && state.Sequences[index-1].Sequence >= entry.Sequence) {
			return nil, fmt.Errorf("invalid HA replication sequence records")
		}
		if _, duplicate := model.seen[entry.OperationID]; duplicate {
			return nil, fmt.Errorf("duplicate HA replication operation ID")
		}
		if model.sequences[entry.NodeID] == nil {
			model.sequences[entry.NodeID] = make(map[uint64]string)
		}
		model.sequences[entry.NodeID][entry.Sequence] = entry.OperationID
		model.seen[entry.OperationID] = struct{}{}
	}
	for index, operation := range state.Claims {
		if err := validateHAReplicationOperation(operation); err != nil || operation.ClusterID != state.ClusterID || operation.Epoch != state.Epoch ||
			index > 0 && state.Claims[index-1].OperationID >= operation.OperationID {
			return nil, fmt.Errorf("invalid HA replication persisted claim")
		}
		if operation.Sequence > model.highWater[operation.NodeID] && model.sequences[operation.NodeID][operation.Sequence] != operation.OperationID {
			return nil, fmt.Errorf("HA replication claim lacks sequence evidence")
		}
		key := haReplicationClaimKey(operation)
		if _, duplicate := model.claims[key]; duplicate {
			return nil, fmt.Errorf("duplicate HA replication claim")
		}
		model.claims[key] = operation
	}
	for index, operation := range state.Outbox {
		if err := validateHAReplicationOperation(operation); err != nil || operation.ClusterID != state.ClusterID || operation.Epoch != state.Epoch ||
			index > 0 && state.Outbox[index-1].OperationID >= operation.OperationID {
			return nil, fmt.Errorf("invalid HA replication persisted outbox")
		}
		if operation.Sequence > model.highWater[operation.NodeID] && model.sequences[operation.NodeID][operation.Sequence] != operation.OperationID {
			return nil, fmt.Errorf("HA replication outbox lacks sequence evidence")
		}
		model.outbox[operation.OperationID] = operation
	}
	return model, nil
}

func openHAReplicationStoreDirectory(path string, expectedOwnerUID int) (*os.Root, string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path {
		return nil, "", fmt.Errorf("HA replication state path must be absolute and canonical")
	}
	directoryPath, name := filepath.Dir(clean), filepath.Base(clean)
	info, err := os.Lstat(directoryPath)
	if err != nil {
		return nil, "", err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	if ownerErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || owner != expectedOwnerUID {
		return nil, "", fmt.Errorf("HA replication directory must be real and owner-only")
	}
	root, err := os.OpenRoot(directoryPath)
	if err != nil {
		return nil, "", err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		return nil, "", fmt.Errorf("HA replication directory changed while opening")
	}
	return root, name, nil
}

func saveHAReplicationModel(path string, expectedOwnerUID int, model *haReplicationModel) error {
	root, name, err := openHAReplicationStoreDirectory(path, expectedOwnerUID)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := lockHADataDirectory(root)
	if err != nil {
		return err
	}
	defer unlockHADataDirectory(lock)
	if info, statErr := root.Lstat(name); statErr == nil {
		owner, ownerErr := haFenceOwnerUID(info)
		if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != expectedOwnerUID {
			return fmt.Errorf("HA replication state must be an owner-only regular file")
		}
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return statErr
	}
	state := model.persistentState()
	if _, err := validateHAReplicationPersistentState(state); err != nil {
		return err
	}
	wire, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(wire) > maxHAReplicationStateBytes {
		return fmt.Errorf("HA replication state exceeds bounds")
	}
	return publishHAFileAtomically(root, name, wire)
}

func loadHAReplicationModel(path string, expectedOwnerUID int, clusterID string) (*haReplicationModel, error) {
	root, name, err := openHAReplicationStoreDirectory(path, expectedOwnerUID)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	lock, err := lockHADataDirectory(root)
	if err != nil {
		return nil, err
	}
	defer unlockHADataDirectory(lock)
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != expectedOwnerUID {
		return nil, fmt.Errorf("HA replication state must be an owner-only regular file")
	}
	wire, err := readHARegularFileBounded(root, name, maxHAReplicationStateBytes)
	if err != nil {
		return nil, err
	}
	if err := rejectHADuplicateJSONKeys(wire); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var state haReplicationPersistentState
	if err := decoder.Decode(&state); err != nil {
		return nil, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("HA replication state has trailing JSON")
	}
	model, err := validateHAReplicationPersistentState(state)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("HA replication state bytes are not canonical")
	}
	if model.clusterID != clusterID {
		return nil, fmt.Errorf("HA replication cluster identity mismatch")
	}
	return model, nil
}

func (model *haReplicationModel) activeClaims(at time.Time) []haReplicationClaim {
	canonicalNow := at.UTC()
	claims := model.snapshot()
	active := claims[:0]
	for _, claim := range claims {
		if claim.Action != "upsert" {
			continue
		}
		if claim.ExpiresAt != "" {
			expiresAt, err := parseCanonicalHATime(claim.ExpiresAt)
			if err != nil || !expiresAt.After(canonicalNow) {
				continue
			}
		}
		active = append(active, claim)
	}
	return active
}
