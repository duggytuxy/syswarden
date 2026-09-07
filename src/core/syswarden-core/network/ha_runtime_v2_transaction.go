package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"sync"
	"syscall"
	"time"

	"syswarden-core/firewall"
)

const (
	haV2FirewallTransactionVersion = 1
	maxHAV2TransactionBytes        = 16 * 1024 * 1024
	haV2StateAnchorVersion         = 1
	maxHAV2StateAnchorBytes        = 4 * 1024
	maxHAV2HeadJournalBytes        = 16 * 1024 * 1024
	haV2TransactionPrepared        = "prepared"
	haV2TransactionApplied         = "applied"
	haV2TransactionRecovered       = "recovered"
)

type haV2FirewallTarget struct {
	Entry     string `json:"entry"`
	Present   bool   `json:"present"`
	Permanent bool   `json:"permanent"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type haV2FirewallTransaction struct {
	Version         int                          `json:"version"`
	TransactionID   string                       `json:"transaction_id"`
	ClusterID       string                       `json:"cluster_id"`
	Epoch           uint64                       `json:"epoch"`
	Stage           string                       `json:"stage"`
	PreStateSHA256  string                       `json:"pre_state_sha256"`
	CandidateSHA256 string                       `json:"candidate_state_sha256"`
	RecoverySHA256  string                       `json:"recovery_state_sha256"`
	EvaluatedAt     string                       `json:"evaluated_at"`
	Operation       haReplicationOperation       `json:"operation"`
	Target          haV2FirewallTarget           `json:"target"`
	CandidateState  haReplicationPersistentState `json:"candidate_state"`
}

type haV2TransactionStore struct {
	statePath           string
	anchorPath          string
	transactionPath     string
	expectedOwnerUID    int
	afterRemove         func() error
	headPath            string
	instanceLockPath    string
	instanceLock        *os.File
	instanceMu          sync.Mutex
	headMu              sync.Mutex
	observedHead        string
	beforeInstanceFlock func() error
	afterHeadRemove     func() error
}

type haV2HeadJournal struct {
	Version         int                          `json:"version"`
	Initializing    bool                         `json:"initializing,omitempty"`
	ClusterID       string                       `json:"cluster_id"`
	Epoch           uint64                       `json:"epoch"`
	GenesisID       string                       `json:"genesis_id"`
	PreStateSHA256  string                       `json:"pre_state_sha256"`
	CandidateSHA256 string                       `json:"candidate_state_sha256"`
	CandidateState  haReplicationPersistentState `json:"candidate_state"`
}

type haV2StateAnchor struct {
	Version     int    `json:"version"`
	ClusterID   string `json:"cluster_id"`
	Epoch       uint64 `json:"epoch"`
	GenesisID   string `json:"genesis_id"`
	StateSHA256 string `json:"state_sha256"`
}

var haV2RetainedLeases struct {
	sync.Mutex
	stores []*haV2TransactionStore
}

func retainHAV2InstanceLease(store *haV2TransactionStore) {
	haV2RetainedLeases.Lock()
	defer haV2RetainedLeases.Unlock()
	haV2RetainedLeases.stores = append(haV2RetainedLeases.stores, store)
}

func newHAV2TransactionStore(statePath, transactionPath string, expectedOwnerUID int) (*haV2TransactionStore, error) {
	anchorPath := statePath + ".anchor.json"
	headPath := statePath + ".head.wal.json"
	instanceLockPath := statePath + ".instance.lock"
	if statePath == transactionPath || anchorPath == transactionPath || headPath == transactionPath || instanceLockPath == transactionPath || expectedOwnerUID < 0 {
		return nil, fmt.Errorf("invalid HA v2 transaction store configuration")
	}
	stateRoot, _, err := openHAReplicationStoreDirectory(statePath, expectedOwnerUID)
	if err != nil {
		return nil, fmt.Errorf("open HA v2 state directory: %w", err)
	}
	_ = stateRoot.Close()
	transactionRoot, _, err := openHAReplicationStoreDirectory(transactionPath, expectedOwnerUID)
	if err != nil {
		return nil, fmt.Errorf("open HA v2 transaction directory: %w", err)
	}
	_ = transactionRoot.Close()
	anchorRoot, _, err := openHAReplicationStoreDirectory(anchorPath, expectedOwnerUID)
	if err != nil {
		return nil, fmt.Errorf("open HA v2 anchor directory: %w", err)
	}
	_ = anchorRoot.Close()
	headRoot, _, err := openHAReplicationStoreDirectory(headPath, expectedOwnerUID)
	if err != nil {
		return nil, fmt.Errorf("open HA v2 head journal directory: %w", err)
	}
	_ = headRoot.Close()
	return &haV2TransactionStore{statePath: statePath, anchorPath: anchorPath, transactionPath: transactionPath, headPath: headPath, instanceLockPath: instanceLockPath, expectedOwnerUID: expectedOwnerUID}, nil
}

func (store *haV2TransactionStore) acquireInstanceLock() error {
	store.instanceMu.Lock()
	defer store.instanceMu.Unlock()
	if store.instanceLock != nil {
		return fmt.Errorf("HA v2 instance lock is already held")
	}
	root, name, err := openHAReplicationStoreDirectory(store.instanceLockPath, store.expectedOwnerUID)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	pathInfo, pathErr := root.Lstat(name)
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if ownerErr != nil || pathErr != nil || !os.SameFile(info, pathInfo) || !statOK || stat.Nlink != 1 ||
		!info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != store.expectedOwnerUID {
		_ = file.Close()
		return fmt.Errorf("HA v2 instance lock must be an owner-only regular file")
	}
	if store.beforeInstanceFlock != nil {
		if err := store.beforeInstanceFlock(); err != nil {
			_ = file.Close()
			return err
		}
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return fmt.Errorf("another HA v2 runtime holds the instance lock: %w", err)
	}
	postInfo, postErr := file.Stat()
	postPathInfo, postPathErr := root.Lstat(name)
	if postErr != nil || postPathErr != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
		return fmt.Errorf("HA v2 instance lock changed during acquisition")
	}
	postOwner, postOwnerErr := haFenceOwnerUID(postInfo)
	postStat, postStatOK := postInfo.Sys().(*syscall.Stat_t)
	if postOwnerErr != nil || !os.SameFile(postInfo, postPathInfo) ||
		!postStatOK || postStat.Nlink != 1 || !postInfo.Mode().IsRegular() || postInfo.Mode().Perm() != 0600 || postOwner != store.expectedOwnerUID {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
		return fmt.Errorf("HA v2 instance lock changed during acquisition")
	}
	store.instanceLock = file
	return nil
}

func (store *haV2TransactionStore) releaseInstanceLock() {
	store.instanceMu.Lock()
	defer store.instanceMu.Unlock()
	if store.instanceLock == nil {
		return
	}
	_ = syscall.Flock(int(store.instanceLock.Fd()), syscall.LOCK_UN)
	_ = store.instanceLock.Close()
	store.instanceLock = nil
}

func validateHAV2StateAnchor(anchor haV2StateAnchor) error {
	if anchor.Version != haV2StateAnchorVersion || !haReplicationIDRE.MatchString(anchor.ClusterID) || anchor.Epoch == 0 ||
		!isLowerHexSHA256(anchor.GenesisID) || !isLowerHexSHA256(anchor.StateSHA256) {
		return fmt.Errorf("invalid HA v2 state anchor")
	}
	return nil
}

func readHAV2StateAnchorLocked(root *os.Root, name string, expectedOwnerUID int) (haV2StateAnchor, bool, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return haV2StateAnchor{}, false, nil
	}
	if err != nil {
		return haV2StateAnchor{}, false, err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != expectedOwnerUID {
		return haV2StateAnchor{}, false, fmt.Errorf("HA v2 state anchor must be an owner-only regular file")
	}
	wire, err := readHARegularFileBounded(root, name, maxHAV2StateAnchorBytes)
	if err != nil {
		return haV2StateAnchor{}, false, err
	}
	if err := rejectHADuplicateJSONKeys(wire); err != nil {
		return haV2StateAnchor{}, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var anchor haV2StateAnchor
	if err := decoder.Decode(&anchor); err != nil {
		return haV2StateAnchor{}, false, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return haV2StateAnchor{}, false, fmt.Errorf("HA v2 state anchor has trailing JSON")
	}
	canonical, marshalErr := json.Marshal(anchor)
	if marshalErr != nil || !bytes.Equal(canonical, wire) {
		return haV2StateAnchor{}, false, fmt.Errorf("HA v2 state anchor bytes are not canonical")
	}
	if err := validateHAV2StateAnchor(anchor); err != nil {
		return haV2StateAnchor{}, false, err
	}
	return anchor, true, nil
}

func readHAV2StateAnchor(path string, expectedOwnerUID int) (haV2StateAnchor, bool, error) {
	root, name, err := openHAReplicationStoreDirectory(path, expectedOwnerUID)
	if err != nil {
		return haV2StateAnchor{}, false, err
	}
	defer root.Close()
	lock, err := lockHADataDirectory(root)
	if err != nil {
		return haV2StateAnchor{}, false, err
	}
	defer unlockHADataDirectory(lock)
	return readHAV2StateAnchorLocked(root, name, expectedOwnerUID)
}

func stateAnchorForModel(model *haReplicationModel) (haV2StateAnchor, error) {
	digest, err := model.persistentStateDigest()
	if err != nil {
		return haV2StateAnchor{}, err
	}
	anchor := haV2StateAnchor{
		Version: haV2StateAnchorVersion, ClusterID: model.clusterID, Epoch: model.epoch,
		GenesisID: model.genesisID, StateSHA256: digest,
	}
	if err := validateHAV2StateAnchor(anchor); err != nil {
		return haV2StateAnchor{}, err
	}
	return anchor, nil
}

func (store *haV2TransactionStore) writeStateAnchor(model *haReplicationModel, create bool) error {
	anchor, err := stateAnchorForModel(model)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(anchor)
	if err != nil {
		return err
	}
	root, name, err := openHAReplicationStoreDirectory(store.anchorPath, store.expectedOwnerUID)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := lockHADataDirectory(root)
	if err != nil {
		return err
	}
	defer unlockHADataDirectory(lock)
	existing, present, err := readHAV2StateAnchorLocked(root, name, store.expectedOwnerUID)
	if err != nil {
		return err
	}
	if create {
		if present {
			return fmt.Errorf("HA v2 state anchor already exists")
		}
	} else if !present || existing.ClusterID != anchor.ClusterID || existing.Epoch != anchor.Epoch || existing.GenesisID != anchor.GenesisID {
		return fmt.Errorf("HA v2 durable state anchor identity mismatch")
	}
	return publishHAFileAtomically(root, name, wire)
}

func (store *haV2TransactionStore) attestStateAnchor(model *haReplicationModel) error {
	anchor, present, err := readHAV2StateAnchor(store.anchorPath, store.expectedOwnerUID)
	if err != nil {
		return err
	}
	expected, expectedErr := stateAnchorForModel(model)
	if expectedErr != nil {
		return expectedErr
	}
	if !present || anchor != expected {
		return fmt.Errorf("HA v2 durable state anchor mismatch")
	}
	return nil
}

func canonicalHAV2HeadJournal(journal haV2HeadJournal) ([]byte, *haReplicationModel, error) {
	model, err := validateHAReplicationPersistentState(journal.CandidateState)
	if err != nil || journal.Version != 1 || model.clusterID != journal.ClusterID || model.epoch != journal.Epoch ||
		model.genesisID != journal.GenesisID || (!journal.Initializing && !isLowerHexSHA256(journal.PreStateSHA256)) ||
		(journal.Initializing && journal.PreStateSHA256 != "") || !isLowerHexSHA256(journal.CandidateSHA256) {
		return nil, nil, fmt.Errorf("invalid HA v2 head journal")
	}
	digest, err := model.persistentStateDigest()
	if err != nil || digest != journal.CandidateSHA256 {
		return nil, nil, fmt.Errorf("invalid HA v2 head journal candidate digest")
	}
	wire, err := json.Marshal(journal)
	if err != nil || len(wire) > maxHAV2HeadJournalBytes {
		return nil, nil, fmt.Errorf("HA v2 head journal exceeds bounds")
	}
	return wire, model, nil
}

func (store *haV2TransactionStore) readHeadJournal() (haV2HeadJournal, *haReplicationModel, bool, error) {
	root, name, err := openHAReplicationStoreDirectory(store.headPath, store.expectedOwnerUID)
	if err != nil {
		return haV2HeadJournal{}, nil, false, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return haV2HeadJournal{}, nil, false, nil
	}
	if err != nil {
		return haV2HeadJournal{}, nil, false, err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != store.expectedOwnerUID {
		return haV2HeadJournal{}, nil, false, fmt.Errorf("HA v2 head journal must be an owner-only regular file")
	}
	wire, err := readHARegularFileBounded(root, name, maxHAV2HeadJournalBytes)
	if err != nil || rejectHADuplicateJSONKeys(wire) != nil {
		return haV2HeadJournal{}, nil, false, fmt.Errorf("invalid HA v2 head journal bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var journal haV2HeadJournal
	if err := decoder.Decode(&journal); err != nil {
		return journal, nil, false, err
	}
	canonical, model, err := canonicalHAV2HeadJournal(journal)
	if err != nil || !bytes.Equal(canonical, wire) {
		return journal, nil, false, fmt.Errorf("HA v2 head journal bytes are not canonical")
	}
	return journal, model, true, nil
}

func (store *haV2TransactionStore) publishHeadJournal(journal haV2HeadJournal) error {
	wire, _, err := canonicalHAV2HeadJournal(journal)
	if err != nil {
		return err
	}
	root, name, err := openHAReplicationStoreDirectory(store.headPath, store.expectedOwnerUID)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
		if err == nil {
			return fmt.Errorf("HA v2 head journal is already pending")
		}
		return err
	}
	return publishHAFileAtomically(root, name, wire)
}

func (store *haV2TransactionStore) removeHeadJournal() error {
	root, name, err := openHAReplicationStoreDirectory(store.headPath, store.expectedOwnerUID)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Remove(name); err != nil {
		return err
	}
	if store.afterHeadRemove != nil {
		if err := store.afterHeadRemove(); err != nil {
			if _, statErr := root.Lstat(name); errors.Is(statErr, fs.ErrNotExist) {
				return nil
			}
			return err
		}
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		// If unlink is already visible, either crash outcome is recoverable:
		// the committed candidate remains authoritative, or the journal
		// reappears and idempotently republishes that same candidate.
		if _, statErr := root.Lstat(name); errors.Is(statErr, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return nil
}

func (store *haV2TransactionStore) attestHeadJournalDurablePair(clusterID string, epoch uint64) (*haReplicationModel, bool, bool, error) {
	journal, candidate, present, err := store.readHeadJournal()
	if err != nil || !present {
		return nil, present, false, err
	}
	if journal.ClusterID != clusterID || journal.Epoch != epoch {
		return nil, true, false, fmt.Errorf("pending HA v2 head journal belongs to a different cluster epoch")
	}
	if _, _, firewallPending, err := readHAV2Transaction(store); err != nil {
		return nil, true, false, fmt.Errorf("attest firewall WAL before head recovery: %w", err)
	} else if firewallPending {
		return nil, true, false, fmt.Errorf("HA v2 head recovery refuses simultaneous firewall WAL")
	}
	anchor, exists, err := readHAV2StateAnchor(store.anchorPath, store.expectedOwnerUID)
	if err != nil {
		return nil, true, false, fmt.Errorf("HA v2 head journal cannot attest the durable anchor")
	}
	state, stateErr := loadHAReplicationModel(store.statePath, store.expectedOwnerUID, clusterID)
	stateMissing := errors.Is(stateErr, fs.ErrNotExist)
	stateDigest := ""
	if stateErr == nil {
		stateDigest, _ = state.persistentStateDigest()
	} else if !stateMissing {
		return nil, true, false, stateErr
	}
	allowed := false
	if journal.Initializing {
		allowed = (stateMissing && !exists) || (stateDigest == journal.CandidateSHA256 && !exists) ||
			(stateDigest == journal.CandidateSHA256 && exists && anchor.GenesisID == journal.GenesisID && anchor.Epoch == epoch && anchor.StateSHA256 == journal.CandidateSHA256)
	} else if exists && anchor.GenesisID == journal.GenesisID && anchor.Epoch == epoch {
		allowed = (stateDigest == journal.PreStateSHA256 && anchor.StateSHA256 == journal.PreStateSHA256) ||
			(stateDigest == journal.CandidateSHA256 && anchor.StateSHA256 == journal.PreStateSHA256) ||
			(stateDigest == journal.CandidateSHA256 && anchor.StateSHA256 == journal.CandidateSHA256)
	}
	if !allowed {
		return nil, true, false, fmt.Errorf("HA v2 head journal does not match a permitted durable pair")
	}
	return candidate, true, !exists, nil
}

func (store *haV2TransactionStore) recoverHeadJournal(clusterID string, epoch uint64) error {
	candidate, present, createAnchor, err := store.attestHeadJournalDurablePair(clusterID, epoch)
	if err != nil || !present {
		return err
	}
	if err := saveHAReplicationModel(store.statePath, store.expectedOwnerUID, candidate); err != nil {
		return err
	}
	if err := store.writeStateAnchor(candidate, createAnchor); err != nil {
		return err
	}
	return store.removeHeadJournal()
}

func (store *haV2TransactionStore) loadOrInitialize(clusterID string, epoch uint64) (*haReplicationModel, error) {
	if err := store.recoverHeadJournal(clusterID, epoch); err != nil {
		return nil, err
	}
	model, err := loadHAReplicationModel(store.statePath, store.expectedOwnerUID, clusterID)
	if err == nil {
		if model.epoch != epoch {
			return nil, fmt.Errorf("HA v2 state epoch mismatch")
		}
		if err := store.attestStateAnchor(model); err != nil {
			return nil, err
		}
		store.observedHead, _ = model.persistentStateDigest()
		return model, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if _, present, anchorErr := readHAV2StateAnchor(store.anchorPath, store.expectedOwnerUID); anchorErr != nil {
		return nil, anchorErr
	} else if present {
		return nil, fmt.Errorf("HA v2 replication state is missing for an established cluster epoch")
	}
	model, err = newHAReplicationModel(clusterID)
	if err != nil {
		return nil, err
	}
	if err := model.setEpoch(epoch); err != nil {
		return nil, err
	}
	model.coordinationState = haCoordinationHealthy
	model.coordinationReason = ""
	candidateDigest, err := model.persistentStateDigest()
	if err != nil {
		return nil, err
	}
	if err := store.publishHeadJournal(haV2HeadJournal{Version: 1, Initializing: true, ClusterID: clusterID, Epoch: epoch,
		GenesisID: model.genesisID, CandidateSHA256: candidateDigest, CandidateState: model.persistentState()}); err != nil {
		return nil, err
	}
	if err := saveHAReplicationModel(store.statePath, store.expectedOwnerUID, model); err != nil {
		return nil, err
	}
	if err := store.writeStateAnchor(model, true); err != nil {
		return nil, err
	}
	if err := store.removeHeadJournal(); err != nil {
		return nil, err
	}
	store.observedHead = candidateDigest
	return model, nil
}

func desiredHAV2FirewallTarget(model *haReplicationModel, ip string, now time.Time) (haV2FirewallTarget, firewall.RecoverableMutation, error) {
	canonical, err := canonicalHAAddress(ip)
	if err != nil || canonical != ip || model == nil {
		return haV2FirewallTarget{}, firewall.RecoverableMutation{}, fmt.Errorf("invalid HA v2 desired firewall target")
	}
	target := haV2FirewallTarget{Entry: canonical}
	latest := time.Time{}
	for _, claim := range model.activeClaims(now) {
		if claim.IP != canonical {
			continue
		}
		target.Present = true
		if claim.ExpiresAt == "" {
			target.Permanent = true
			target.ExpiresAt = ""
			break
		}
		expiresAt, parseErr := parseCanonicalHATime(claim.ExpiresAt)
		if parseErr != nil {
			return haV2FirewallTarget{}, firewall.RecoverableMutation{}, parseErr
		}
		if expiresAt.After(latest) {
			latest = expiresAt
		}
	}
	mutation := firewall.RecoverableMutation{Entry: canonical, Present: target.Present, Permanent: target.Permanent}
	if !target.Present || target.Permanent {
		return target, mutation, nil
	}
	target.ExpiresAt = latest.UTC().Format(time.RFC3339)
	mutation.TTL = boundedHARemainingTTL(latest, now.UTC())
	return target, mutation, nil
}

func validateHAV2FirewallTransaction(journal haV2FirewallTransaction) (*haReplicationModel, error) {
	if journal.Version != haV2FirewallTransactionVersion || journal.TransactionID != journal.Operation.OperationID ||
		journal.ClusterID == "" || journal.Epoch == 0 || journal.Operation.ClusterID != journal.ClusterID || journal.Operation.Epoch != journal.Epoch {
		return nil, fmt.Errorf("invalid HA v2 firewall transaction identity")
	}
	if (journal.Stage != haV2TransactionPrepared && journal.Stage != haV2TransactionApplied && journal.Stage != haV2TransactionRecovered) ||
		!isLowerHexSHA256(journal.PreStateSHA256) || !isLowerHexSHA256(journal.CandidateSHA256) || !isLowerHexSHA256(journal.RecoverySHA256) {
		return nil, fmt.Errorf("invalid HA v2 firewall transaction proof")
	}
	if err := validateHAReplicationOperation(journal.Operation); err != nil {
		return nil, err
	}
	model, err := validateHAReplicationPersistentState(journal.CandidateState)
	if err != nil || model.clusterID != journal.ClusterID || model.epoch != journal.Epoch || !model.operationCovered(journal.Operation) {
		return nil, fmt.Errorf("invalid HA v2 firewall transaction candidate state")
	}
	candidateDigest, err := model.persistentStateDigest()
	if err != nil || candidateDigest != journal.CandidateSHA256 {
		return nil, fmt.Errorf("invalid HA v2 firewall transaction candidate digest")
	}
	recovery := *model
	if err := recovery.setCoordination(haCoordinationFenced, haV2TransactionRecoveryReason); err != nil {
		return nil, err
	}
	recoveryDigest, err := recovery.persistentStateDigest()
	if err != nil || recoveryDigest != journal.RecoverySHA256 {
		return nil, fmt.Errorf("invalid HA v2 firewall transaction recovery digest")
	}
	if journal.Target.Entry != journal.Operation.IP {
		return nil, fmt.Errorf("HA v2 firewall transaction target mismatch")
	}
	evaluatedAt, err := parseCanonicalHATime(journal.EvaluatedAt)
	if err != nil {
		return nil, fmt.Errorf("invalid HA v2 firewall transaction evaluation time")
	}
	expectedTarget, _, err := desiredHAV2FirewallTarget(model, journal.Operation.IP, evaluatedAt)
	if err != nil || expectedTarget != journal.Target {
		return nil, fmt.Errorf("HA v2 firewall transaction target does not match its candidate model")
	}
	if !journal.Target.Present && (journal.Target.Permanent || journal.Target.ExpiresAt != "") {
		return nil, fmt.Errorf("invalid absent HA v2 firewall transaction target")
	}
	if journal.Target.Permanent && journal.Target.ExpiresAt != "" {
		return nil, fmt.Errorf("invalid permanent HA v2 firewall transaction target")
	}
	if journal.Target.Present && !journal.Target.Permanent {
		if _, err := parseCanonicalHATime(journal.Target.ExpiresAt); err != nil {
			return nil, fmt.Errorf("invalid timed HA v2 firewall transaction target")
		}
	}
	return model, nil
}

func canonicalHAV2TransactionBytes(journal haV2FirewallTransaction) ([]byte, error) {
	if _, err := validateHAV2FirewallTransaction(journal); err != nil {
		return nil, err
	}
	wire, err := json.Marshal(journal)
	if err != nil {
		return nil, err
	}
	if len(wire) > maxHAV2TransactionBytes {
		return nil, fmt.Errorf("HA v2 firewall transaction exceeds bounds")
	}
	return wire, nil
}

func readHAV2Transaction(store *haV2TransactionStore) (haV2FirewallTransaction, []byte, bool, error) {
	root, name, err := openHAReplicationStoreDirectory(store.transactionPath, store.expectedOwnerUID)
	if err != nil {
		return haV2FirewallTransaction{}, nil, false, err
	}
	defer root.Close()
	lock, err := lockHADataDirectory(root)
	if err != nil {
		return haV2FirewallTransaction{}, nil, false, err
	}
	defer unlockHADataDirectory(lock)
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return haV2FirewallTransaction{}, nil, false, nil
	}
	if err != nil {
		return haV2FirewallTransaction{}, nil, false, err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != store.expectedOwnerUID {
		return haV2FirewallTransaction{}, nil, false, fmt.Errorf("HA v2 firewall transaction must be an owner-only regular file")
	}
	wire, err := readHARegularFileBounded(root, name, maxHAV2TransactionBytes)
	if err != nil {
		return haV2FirewallTransaction{}, nil, false, err
	}
	if err := rejectHADuplicateJSONKeys(wire); err != nil {
		return haV2FirewallTransaction{}, nil, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var journal haV2FirewallTransaction
	if err := decoder.Decode(&journal); err != nil {
		return haV2FirewallTransaction{}, nil, false, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return haV2FirewallTransaction{}, nil, false, fmt.Errorf("HA v2 firewall transaction has trailing JSON")
	}
	canonical, err := canonicalHAV2TransactionBytes(journal)
	if err != nil || !bytes.Equal(canonical, wire) {
		return haV2FirewallTransaction{}, nil, false, fmt.Errorf("HA v2 firewall transaction bytes are not canonical")
	}
	return journal, wire, true, nil
}

func (store *haV2TransactionStore) prepare(journal haV2FirewallTransaction) error {
	if journal.Stage != haV2TransactionPrepared {
		return fmt.Errorf("new HA v2 firewall transaction must be prepared")
	}
	if _, _, pending, err := store.readHeadJournal(); err != nil {
		return fmt.Errorf("attest HA v2 head journal before firewall transaction: %w", err)
	} else if pending {
		return fmt.Errorf("HA v2 firewall transaction is blocked by a pending head journal")
	}
	wire, err := canonicalHAV2TransactionBytes(journal)
	if err != nil {
		return err
	}
	existing, existingWire, present, err := readHAV2Transaction(store)
	if err != nil {
		return err
	}
	if present {
		if existing.TransactionID == journal.TransactionID && bytes.Equal(existingWire, wire) {
			return nil
		}
		return fmt.Errorf("another HA v2 firewall transaction is pending")
	}
	anchor, anchorPresent, err := readHAV2StateAnchor(store.anchorPath, store.expectedOwnerUID)
	if err != nil || !anchorPresent || anchor.ClusterID != journal.ClusterID || anchor.Epoch != journal.Epoch ||
		anchor.GenesisID != journal.CandidateState.GenesisID || anchor.StateSHA256 != journal.PreStateSHA256 {
		return fmt.Errorf("HA v2 transaction pre-state does not match the durable anchor")
	}
	root, name, err := openHAReplicationStoreDirectory(store.transactionPath, store.expectedOwnerUID)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := lockHADataDirectory(root)
	if err != nil {
		return err
	}
	defer unlockHADataDirectory(lock)
	if _, err := root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
		if err == nil {
			return fmt.Errorf("HA v2 firewall transaction appeared during prepare")
		}
		return err
	}
	return publishHAFileAtomically(root, name, wire)
}

func (store *haV2TransactionStore) persist(model *haReplicationModel) error {
	store.headMu.Lock()
	defer store.headMu.Unlock()
	anchor, present, err := readHAV2StateAnchor(store.anchorPath, store.expectedOwnerUID)
	if err != nil || !present || model == nil || anchor.ClusterID != model.clusterID || anchor.Epoch != model.epoch || anchor.GenesisID != model.genesisID {
		return fmt.Errorf("HA v2 head update cannot attest its pre-state")
	}
	durable, err := loadHAReplicationModel(store.statePath, store.expectedOwnerUID, model.clusterID)
	if err != nil {
		return err
	}
	preDigest, err := durable.persistentStateDigest()
	if err != nil || preDigest != anchor.StateSHA256 || store.observedHead == "" || preDigest != store.observedHead {
		return fmt.Errorf("HA v2 head update pre-state mismatch")
	}
	candidateDigest, err := model.persistentStateDigest()
	if err != nil {
		return err
	}
	journal := haV2HeadJournal{Version: 1, ClusterID: model.clusterID, Epoch: model.epoch, GenesisID: model.genesisID,
		PreStateSHA256: preDigest, CandidateSHA256: candidateDigest, CandidateState: model.persistentState()}
	if err := store.publishHeadJournal(journal); err != nil {
		return err
	}
	if err := saveHAReplicationModel(store.statePath, store.expectedOwnerUID, model); err != nil {
		return err
	}
	if err := store.writeStateAnchor(model, false); err != nil {
		return err
	}
	if err := store.removeHeadJournal(); err != nil {
		return err
	}
	store.observedHead = candidateDigest
	return nil
}

func (store *haV2TransactionStore) persistUnderFirewallWAL(model *haReplicationModel) error {
	if err := saveHAReplicationModel(store.statePath, store.expectedOwnerUID, model); err != nil {
		return err
	}
	if err := store.writeStateAnchor(model, false); err != nil {
		return err
	}
	store.observedHead, _ = model.persistentStateDigest()
	return nil
}

func (store *haV2TransactionStore) advanceTransactionStage(journal haV2FirewallTransaction, next string) error {
	if (journal.Stage != haV2TransactionPrepared || next != haV2TransactionApplied) &&
		(journal.Stage != haV2TransactionApplied || next != haV2TransactionRecovered) {
		return fmt.Errorf("invalid HA v2 transaction stage transition")
	}
	expectedWire, err := canonicalHAV2TransactionBytes(journal)
	if err != nil {
		return err
	}
	journal.Stage = next
	appliedWire, err := canonicalHAV2TransactionBytes(journal)
	if err != nil {
		return err
	}
	root, name, err := openHAReplicationStoreDirectory(store.transactionPath, store.expectedOwnerUID)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := lockHADataDirectory(root)
	if err != nil {
		return err
	}
	defer unlockHADataDirectory(lock)
	info, err := root.Lstat(name)
	if err != nil {
		return err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner != store.expectedOwnerUID {
		return fmt.Errorf("HA v2 firewall transaction must be an owner-only regular file")
	}
	currentWire, err := readHARegularFileBounded(root, name, maxHAV2TransactionBytes)
	if err != nil || !bytes.Equal(currentWire, expectedWire) {
		return fmt.Errorf("HA v2 firewall transaction changed before stage advancement")
	}
	return publishHAFileAtomically(root, name, appliedWire)
}

func (store *haV2TransactionStore) persistAndAdvance(journal haV2FirewallTransaction, model *haReplicationModel) error {
	if err := store.persistUnderFirewallWAL(model); err != nil {
		return err
	}
	return store.advanceTransactionStage(journal, haV2TransactionApplied)
}

func (store *haV2TransactionStore) attestTransactionStage(journal haV2FirewallTransaction, candidate *haReplicationModel) error {
	anchor, present, err := readHAV2StateAnchor(store.anchorPath, store.expectedOwnerUID)
	if err != nil || !present || candidate == nil || anchor.ClusterID != journal.ClusterID || anchor.Epoch != journal.Epoch ||
		anchor.GenesisID != candidate.genesisID {
		return fmt.Errorf("HA v2 transaction stage cannot attest the durable anchor")
	}
	state, err := loadHAReplicationModel(store.statePath, store.expectedOwnerUID, journal.ClusterID)
	if err != nil || state.epoch != journal.Epoch || state.genesisID != candidate.genesisID {
		return fmt.Errorf("HA v2 transaction stage cannot attest the durable state")
	}
	stateDigest, err := state.persistentStateDigest()
	if err != nil {
		return fmt.Errorf("HA v2 transaction stage cannot digest the durable state")
	}
	allowed := false
	switch journal.Stage {
	case haV2TransactionPrepared:
		allowed = (stateDigest == journal.PreStateSHA256 && anchor.StateSHA256 == journal.PreStateSHA256) ||
			(stateDigest == journal.CandidateSHA256 && anchor.StateSHA256 == journal.PreStateSHA256) ||
			(stateDigest == journal.CandidateSHA256 && anchor.StateSHA256 == journal.CandidateSHA256)
	case haV2TransactionApplied:
		allowed = (stateDigest == journal.CandidateSHA256 && anchor.StateSHA256 == journal.CandidateSHA256) ||
			(stateDigest == journal.RecoverySHA256 && anchor.StateSHA256 == journal.CandidateSHA256) ||
			(stateDigest == journal.RecoverySHA256 && anchor.StateSHA256 == journal.RecoverySHA256)
	case haV2TransactionRecovered:
		allowed = stateDigest == journal.RecoverySHA256 && anchor.StateSHA256 == journal.RecoverySHA256
	}
	if !allowed {
		return fmt.Errorf("HA v2 transaction stage does not match a permitted durable state and anchor pair")
	}
	return nil
}

func (store *haV2TransactionStore) commit(transactionID string, expectedStage string) error {
	journal, _, present, err := readHAV2Transaction(store)
	if err != nil || !present {
		if err != nil {
			return err
		}
		return fmt.Errorf("HA v2 firewall transaction disappeared before commit")
	}
	if journal.TransactionID != transactionID || journal.Stage != expectedStage {
		return fmt.Errorf("HA v2 firewall transaction identity changed before commit")
	}
	root, name, err := openHAReplicationStoreDirectory(store.transactionPath, store.expectedOwnerUID)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := lockHADataDirectory(root)
	if err != nil {
		return err
	}
	defer unlockHADataDirectory(lock)
	if err := root.Remove(name); err != nil {
		return err
	}
	if store.afterRemove != nil {
		if err := store.afterRemove(); err != nil {
			return err
		}
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (store *haV2TransactionStore) execute(ctx context.Context, manager firewall.RecoverableMutationManager, operation haReplicationOperation, candidate *haReplicationModel, expectedPreState string, now time.Time) error {
	target, mutation, err := desiredHAV2FirewallTarget(candidate, operation.IP, now)
	if err != nil {
		return err
	}
	anchor, present, err := readHAV2StateAnchor(store.anchorPath, store.expectedOwnerUID)
	if err != nil || !present || anchor.ClusterID != candidate.clusterID || anchor.Epoch != candidate.epoch || anchor.GenesisID != candidate.genesisID ||
		!isLowerHexSHA256(expectedPreState) || anchor.StateSHA256 != expectedPreState || store.observedHead != expectedPreState {
		return fmt.Errorf("HA v2 transaction cannot attest its durable pre-state")
	}
	durable, err := loadHAReplicationModel(store.statePath, store.expectedOwnerUID, candidate.clusterID)
	if err != nil {
		return err
	}
	durableDigest, err := durable.persistentStateDigest()
	if err != nil || durableDigest != expectedPreState {
		return fmt.Errorf("HA v2 transaction candidate is stale")
	}
	candidateDigest, err := candidate.persistentStateDigest()
	if err != nil {
		return err
	}
	journal := haV2FirewallTransaction{
		Version: haV2FirewallTransactionVersion, TransactionID: operation.OperationID,
		ClusterID: candidate.clusterID, Epoch: candidate.epoch, Stage: haV2TransactionPrepared,
		PreStateSHA256: expectedPreState, CandidateSHA256: candidateDigest,
		EvaluatedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339), Operation: operation,
		Target: target, CandidateState: candidate.persistentState(),
	}
	recovery := *candidate
	if err := recovery.setCoordination(haCoordinationFenced, haV2TransactionRecoveryReason); err != nil {
		return err
	}
	journal.RecoverySHA256, err = recovery.persistentStateDigest()
	if err != nil {
		return err
	}
	return manager.RunRecoverableMutation(ctx, mutation, firewall.RecoverableMutationHooks{
		Prepare: func() error { return store.prepare(journal) },
		Persist: func() error { return store.persistAndAdvance(journal, candidate) },
		Commit:  func() error { return store.commit(journal.TransactionID, haV2TransactionApplied) },
	})
}

// reconcile replays the exact effective state for every address retained by
// the durable model. This restores both timed and permanent HA-owned entries
// after a clean host restart, while retained delete and expiry tombstones make
// stale entries converge to absence. Each address uses the same WAL protocol
// as a live operation.
func (store *haV2TransactionStore) reconcile(ctx context.Context, manager firewall.RecoverableMutationManager, model *haReplicationModel, now time.Time) error {
	if ctx == nil || manager == nil || model == nil {
		return fmt.Errorf("HA v2 restart reconciliation dependencies are unavailable")
	}
	representatives := make(map[string]haReplicationOperation)
	for _, operation := range model.claims {
		current, exists := representatives[operation.IP]
		if !exists || operation.OperationID < current.OperationID {
			representatives[operation.IP] = operation
		}
	}
	addresses := make([]string, 0, len(representatives))
	for address := range representatives {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	for _, address := range addresses {
		if err := store.execute(ctx, manager, representatives[address], model, store.observedHead, now); err != nil {
			return fmt.Errorf("reconcile HA v2 firewall address %s: %w", address, err)
		}
	}
	return nil
}

func (store *haV2TransactionStore) recover(ctx context.Context, manager firewall.RecoverableMutationManager, clusterID string, epoch uint64, localID, peerID, role string, now time.Time) (*haReplicationModel, bool, error) {
	if _, _, headPending, headErr := store.readHeadJournal(); headErr != nil {
		return nil, false, fmt.Errorf("attest HA v2 head journal before firewall recovery: %w", headErr)
	} else if headPending {
		return nil, false, fmt.Errorf("HA v2 firewall recovery refuses simultaneous head journal")
	}
	journal, _, present, err := readHAV2Transaction(store)
	if err != nil || !present {
		return nil, present, err
	}
	candidate, err := validateHAV2FirewallTransaction(journal)
	if err != nil {
		return nil, true, err
	}
	if candidate.clusterID != clusterID || candidate.epoch != epoch {
		return nil, true, fmt.Errorf("pending HA v2 transaction belongs to a different cluster epoch")
	}
	if err := store.attestTransactionStage(journal, candidate); err != nil {
		return nil, true, fmt.Errorf("pending HA v2 transaction proof mismatch: %w", err)
	}
	identityBound, err := candidate.bindRuntimeIdentity(localID, peerID, role)
	if err != nil {
		return nil, true, fmt.Errorf("pending HA v2 transaction identity mismatch: %w", err)
	}
	if identityBound {
		return nil, true, fmt.Errorf("pending HA v2 transaction lacks a durable runtime identity")
	}
	if err := candidate.validateStaticRole(localID, peerID, role); err != nil {
		return nil, true, fmt.Errorf("pending HA v2 transaction role mismatch: %w", err)
	}
	recovery := *candidate
	if err := recovery.setCoordination(haCoordinationFenced, haV2TransactionRecoveryReason); err != nil {
		return nil, true, err
	}
	recoveryTarget := journal.Target
	if recoveryTarget.Present && !recoveryTarget.Permanent {
		expiresAt, parseErr := parseCanonicalHATime(recoveryTarget.ExpiresAt)
		if parseErr != nil {
			return nil, true, parseErr
		}
		if !expiresAt.After(now.UTC()) {
			recoveryTarget = haV2FirewallTarget{Entry: recoveryTarget.Entry}
		}
	}
	mutation := firewall.RecoverableMutation{Entry: recoveryTarget.Entry, Present: recoveryTarget.Present, Permanent: recoveryTarget.Permanent}
	if recoveryTarget.Present && !recoveryTarget.Permanent {
		expiresAt, _ := parseCanonicalHATime(recoveryTarget.ExpiresAt)
		mutation.TTL = boundedHARemainingTTL(expiresAt, now.UTC())
	}
	err = manager.RunRecoverableMutation(ctx, mutation, firewall.RecoverableMutationHooks{
		Prepare: func() error {
			current, _, stillPresent, readErr := readHAV2Transaction(store)
			if readErr != nil || !stillPresent || current.TransactionID != journal.TransactionID {
				return fmt.Errorf("HA v2 recovery journal changed: %w", readErr)
			}
			return nil
		},
		Persist: func() error {
			if journal.Stage == haV2TransactionPrepared {
				if err := store.persistAndAdvance(journal, candidate); err != nil {
					return err
				}
				journal.Stage = haV2TransactionApplied
			}
			if journal.Stage == haV2TransactionApplied {
				if err := store.persistUnderFirewallWAL(&recovery); err != nil {
					return err
				}
				return store.advanceTransactionStage(journal, haV2TransactionRecovered)
			}
			return nil
		},
		Commit: func() error {
			return store.commit(journal.TransactionID, haV2TransactionRecovered)
		},
	})
	if err != nil {
		return nil, true, err
	}
	store.observedHead, _ = recovery.persistentStateDigest()
	return &recovery, true, nil
}
