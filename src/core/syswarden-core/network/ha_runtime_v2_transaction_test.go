package network

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"syswarden-core/firewall"
)

type haV2RecoverableFirewall struct {
	mu                sync.Mutex
	targets           map[string]firewall.RecoverableMutation
	mutations         []firewall.RecoverableMutation
	failAfter         string
	failBeforePrepare bool
}

func newHAV2RecoverableFirewall() *haV2RecoverableFirewall {
	return &haV2RecoverableFirewall{targets: make(map[string]firewall.RecoverableMutation)}
}

func (manager *haV2RecoverableFirewall) Name() string { return "test-nftables" }

func (manager *haV2RecoverableFirewall) Ban(ip string) error {
	return fmt.Errorf("direct test firewall Ban bypassed recoverable transaction for %s", ip)
}

func (manager *haV2RecoverableFirewall) Unban(ip string) error {
	return fmt.Errorf("direct test firewall Unban bypassed recoverable transaction for %s", ip)
}

func (manager *haV2RecoverableFirewall) RunRecoverableMutation(_ context.Context, mutation firewall.RecoverableMutation, hooks firewall.RecoverableMutationHooks) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.failBeforePrepare {
		return errors.New("simulated failure before WAL prepare")
	}
	if err := hooks.Prepare(); err != nil {
		return err
	}
	if manager.failAfter == "prepare" {
		return errors.New("simulated crash after WAL prepare")
	}
	if mutation.Present {
		manager.targets[mutation.Entry] = mutation
	} else {
		delete(manager.targets, mutation.Entry)
	}
	manager.mutations = append(manager.mutations, mutation)
	if manager.failAfter == "mutation" {
		return errors.New("simulated crash after firewall mutation")
	}
	if err := hooks.Persist(); err != nil {
		return err
	}
	if manager.failAfter == "persist" {
		return errors.New("simulated crash after model persistence")
	}
	return hooks.Commit()
}

func testHAV2TransactionStore(t *testing.T) *haV2TransactionStore {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil { // #nosec G302 -- the owner-only transaction fixture directory requires execute permission
		t.Fatal(err)
	}
	store, err := newHAV2TransactionStore(
		filepath.Join(directory, "replication-v2.json"),
		filepath.Join(directory, "replication-v2.wal.json"),
		os.Geteuid(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testHAV2TransactionalModel(t *testing.T, store *haV2TransactionStore, epoch uint64) *haReplicationModel {
	t.Helper()
	model, err := store.loadOrInitialize("cluster-a", epoch)
	if err != nil {
		t.Fatal(err)
	}
	return model
}

func initializeHAV2TransactionStoreForModel(t *testing.T, store *haV2TransactionStore, model *haReplicationModel) {
	t.Helper()
	if err := saveHAReplicationModel(store.statePath, store.expectedOwnerUID, model); err != nil {
		t.Fatal(err)
	}
	if err := store.writeStateAnchor(model, true); err != nil {
		t.Fatal(err)
	}
	store.observedHead, _ = model.persistentStateDigest()
}

func testHAV2Journal(t *testing.T, store *haV2TransactionStore, operation haReplicationOperation, candidate *haReplicationModel, now time.Time) haV2FirewallTransaction {
	t.Helper()
	anchor, present, err := readHAV2StateAnchor(store.anchorPath, store.expectedOwnerUID)
	if err != nil || !present {
		t.Fatalf("read test HA v2 anchor: present=%t err=%v", present, err)
	}
	candidateDigest, err := candidate.persistentStateDigest()
	if err != nil {
		t.Fatal(err)
	}
	recovery := *candidate
	if err := recovery.setCoordination(haCoordinationFenced, "recovered pending HA v2 transaction; explicit recovery required"); err != nil {
		t.Fatal(err)
	}
	recoveryDigest, err := recovery.persistentStateDigest()
	if err != nil {
		t.Fatal(err)
	}
	target, _, err := desiredHAV2FirewallTarget(candidate, operation.IP, now)
	if err != nil {
		t.Fatal(err)
	}
	return haV2FirewallTransaction{
		Version: haV2FirewallTransactionVersion, TransactionID: operation.OperationID,
		ClusterID: candidate.clusterID, Epoch: candidate.epoch, Stage: haV2TransactionPrepared,
		PreStateSHA256: anchor.StateSHA256, CandidateSHA256: candidateDigest, RecoverySHA256: recoveryDigest,
		EvaluatedAt: now.Format(time.RFC3339), Operation: operation, Target: target,
		CandidateState: candidate.persistentState(),
	}
}

func writeTestHAV2WAL(t *testing.T, store *haV2TransactionStore, journal haV2FirewallTransaction) {
	t.Helper()
	wire, err := canonicalHAV2TransactionBytes(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.transactionPath, wire, 0600); err != nil {
		t.Fatal(err)
	}
}

func bindTestHAV2Writer(t *testing.T, store *haV2TransactionStore, model *haReplicationModel) {
	t.Helper()
	changed, err := model.bindRuntimeIdentity("node-a", "node-b", string(haRuntimeV2Writer))
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		if err := store.persist(model); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHAV2StateAnchorDistinguishesRestartFromStateLossOrReplacement(t *testing.T) {
	store := testHAV2TransactionStore(t)
	original := testHAV2TransactionalModel(t, store, 4)
	restarted, err := store.loadOrInitialize("cluster-a", 4)
	if err != nil || restarted.genesisID != original.genesisID {
		t.Fatalf("intact restart rejected or changed genesis: restarted=%#v err=%v", restarted, err)
	}
	if err := os.Remove(store.statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.loadOrInitialize("cluster-a", 4); err == nil {
		t.Fatal("missing established state was treated as first start")
	}

	replacement, err := newHAReplicationModel("cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := replacement.setEpoch(4); err != nil {
		t.Fatal(err)
	}
	replacement.coordinationState = haCoordinationHealthy
	replacement.coordinationReason = ""
	if err := saveHAReplicationModel(store.statePath, store.expectedOwnerUID, replacement); err != nil {
		t.Fatal(err)
	}
	if _, err := store.loadOrInitialize("cluster-a", 4); err == nil {
		t.Fatal("replacement state with a different genesis was accepted")
	}
}

func TestHAV2StateAnchorRejectsRestartUnderAnotherEpoch(t *testing.T) {
	store := testHAV2TransactionStore(t)
	_ = testHAV2TransactionalModel(t, store, 6)
	if _, err := store.loadOrInitialize("cluster-a", 7); err == nil {
		t.Fatal("retained state restarted under another epoch")
	}
}

func TestHAV2StateAnchorRejectsSameGenesisRollback(t *testing.T) {
	store := testHAV2TransactionStore(t)
	model := testHAV2TransactionalModel(t, store, 8)
	oldWire, err := os.ReadFile(store.statePath)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := cloneHAReplicationModel(model)
	if err != nil {
		t.Fatal(err)
	}
	operation := testHAReplicationOperationAtEpoch(t, 8, "node-a", 1, "8.8.8.113", "ssh", "upsert")
	if _, err := candidate.enqueue(operation); err != nil {
		t.Fatal(err)
	}
	candidate.compact(time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC))
	if err := store.persist(candidate); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.statePath, oldWire, 0600); err != nil { // #nosec G703 -- statePath is a fixed product filename beneath a test-owned transaction directory
		t.Fatal(err)
	}
	if _, err := store.loadOrInitialize("cluster-a", 8); err == nil {
		t.Fatal("same-genesis state rollback was accepted against the durable head")
	}
}

func TestHAV2TransactionRecoversCrashesWithoutFirewallModelSplit(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	for _, stage := range []string{"mutation", "persist"} {
		t.Run(stage, func(t *testing.T) {
			store := testHAV2TransactionStore(t)
			model := testHAV2TransactionalModel(t, store, 7)
			if _, err := model.bindRuntimeIdentity("node-a", "node-b", string(haRuntimeV2Writer)); err != nil {
				t.Fatal(err)
			}
			candidate, err := cloneHAReplicationModel(model)
			if err != nil {
				t.Fatal(err)
			}
			operation := testHAReplicationOperationAtEpoch(t, 7, "node-a", 1, "8.8.8.91", "ssh", "upsert")
			if changed, err := candidate.enqueue(operation); err != nil || !changed {
				t.Fatalf("candidate enqueue changed=%t err=%v", changed, err)
			}
			manager := newHAV2RecoverableFirewall()
			manager.failAfter = stage
			if err := store.execute(context.Background(), manager, operation, candidate, store.observedHead, now); err == nil {
				t.Fatal("simulated crash was not surfaced")
			}
			if _, _, present, err := readHAV2Transaction(store); err != nil || !present {
				t.Fatalf("recoverable WAL missing after %s failure: present=%t err=%v", stage, present, err)
			}
			manager.failAfter = ""
			recovered, present, err := store.recover(context.Background(), manager, "cluster-a", 7, "node-a", "node-b", string(haRuntimeV2Writer), now.Add(time.Minute))
			if err != nil || !present {
				t.Fatalf("recovery present=%t err=%v", present, err)
			}
			if len(recovered.activeClaims(now.Add(time.Minute))) != 1 {
				t.Fatalf("recovered model does not contain active claim: %#v", recovered.snapshot())
			}
			if recovered.coordinationState != haCoordinationFenced {
				t.Fatalf("ambiguous restart resumed coordination as %s", recovered.coordinationState)
			}
			if _, _, present, err := readHAV2Transaction(store); err != nil || present {
				t.Fatalf("committed WAL remained after recovery: present=%t err=%v", present, err)
			}
			persisted, err := loadHAReplicationModel(store.statePath, os.Geteuid(), "cluster-a")
			if err != nil || len(persisted.activeClaims(now.Add(time.Minute))) != 1 {
				t.Fatalf("recovered model was not durable: %#v err=%v", persisted, err)
			}
			manager.mu.Lock()
			_, enforced := manager.targets[operation.IP]
			manager.mu.Unlock()
			if !enforced {
				t.Fatal("recovery did not converge the authoritative firewall")
			}
		})
	}
}

func TestHAV2RecoveryRejectsSameEpochOldWALBesideAdvancedState(t *testing.T) {
	for _, stage := range []string{haV2TransactionPrepared, haV2TransactionApplied} {
		t.Run(stage, func(t *testing.T) {
			now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
			store := testHAV2TransactionStore(t)
			model := testHAV2TransactionalModel(t, store, 12)
			bindTestHAV2Writer(t, store, model)
			firstCandidate, _ := cloneHAReplicationModel(model)
			first := testHAReplicationOperationAtEpoch(t, 12, "node-a", 1, "8.8.8.114", "ssh", "upsert")
			if _, err := firstCandidate.enqueue(first); err != nil {
				t.Fatal(err)
			}
			firstCandidate.compact(now)
			oldJournal := testHAV2Journal(t, store, first, firstCandidate, now)
			oldJournal.Stage = stage

			secondCandidate, _ := cloneHAReplicationModel(firstCandidate)
			second := testHAReplicationOperationAtEpoch(t, 12, "node-a", 2, "8.8.8.115", "ssh", "upsert")
			if _, err := secondCandidate.enqueue(second); err != nil {
				t.Fatal(err)
			}
			secondCandidate.compact(now)
			if err := store.persist(secondCandidate); err != nil {
				t.Fatal(err)
			}
			advancedDigest, _ := secondCandidate.persistentStateDigest()
			writeTestHAV2WAL(t, store, oldJournal)
			manager := newHAV2RecoverableFirewall()
			if _, present, err := store.recover(context.Background(), manager, "cluster-a", 12, "node-a", "node-b", string(haRuntimeV2Writer), now); err == nil || !present {
				t.Fatalf("same-epoch old WAL recovery present=%t err=%v", present, err)
			}
			persisted, err := loadHAReplicationModel(store.statePath, store.expectedOwnerUID, "cluster-a")
			if err != nil {
				t.Fatal(err)
			}
			gotDigest, _ := persisted.persistentStateDigest()
			if gotDigest != advancedDigest || len(manager.mutations) != 0 {
				t.Fatalf("old WAL rolled durable state back: digest=%s want=%s mutations=%d", gotDigest, advancedDigest, len(manager.mutations))
			}
		})
	}
}

func TestHAV2RecoveryRequiresStageSpecificDurableDigest(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	t.Run("prepared WAL resumes candidate head", func(t *testing.T) {
		store := testHAV2TransactionStore(t)
		model := testHAV2TransactionalModel(t, store, 13)
		bindTestHAV2Writer(t, store, model)
		candidate, _ := cloneHAReplicationModel(model)
		operation := testHAReplicationOperationAtEpoch(t, 13, "node-a", 1, "8.8.8.116", "ssh", "upsert")
		_, _ = candidate.enqueue(operation)
		candidate.compact(now)
		journal := testHAV2Journal(t, store, operation, candidate, now)
		if err := store.persist(candidate); err != nil {
			t.Fatal(err)
		}
		writeTestHAV2WAL(t, store, journal)
		if recovered, present, err := store.recover(context.Background(), newHAV2RecoverableFirewall(), "cluster-a", 13, "node-a", "node-b", string(haRuntimeV2Writer), now); err != nil || !present || recovered.coordinationState != haCoordinationFenced {
			t.Fatalf("prepared WAL did not resume candidate-stage durable head: present=%t state=%v err=%v", present, recovered, err)
		}
	})

	t.Run("applied WAL rejects pre-state head", func(t *testing.T) {
		store := testHAV2TransactionStore(t)
		model := testHAV2TransactionalModel(t, store, 14)
		bindTestHAV2Writer(t, store, model)
		candidate, _ := cloneHAReplicationModel(model)
		operation := testHAReplicationOperationAtEpoch(t, 14, "node-a", 1, "8.8.8.117", "ssh", "upsert")
		_, _ = candidate.enqueue(operation)
		candidate.compact(now)
		journal := testHAV2Journal(t, store, operation, candidate, now)
		journal.Stage = haV2TransactionApplied
		writeTestHAV2WAL(t, store, journal)
		if _, _, err := store.recover(context.Background(), newHAV2RecoverableFirewall(), "cluster-a", 14, "node-a", "node-b", string(haRuntimeV2Writer), now); err == nil {
			t.Fatal("applied WAL accepted a pre-state durable head")
		}
	})

	t.Run("applied WAL resumes candidate head", func(t *testing.T) {
		store := testHAV2TransactionStore(t)
		model := testHAV2TransactionalModel(t, store, 15)
		bindTestHAV2Writer(t, store, model)
		candidate, _ := cloneHAReplicationModel(model)
		operation := testHAReplicationOperationAtEpoch(t, 15, "node-a", 1, "8.8.8.118", "ssh", "upsert")
		_, _ = candidate.enqueue(operation)
		candidate.compact(now)
		journal := testHAV2Journal(t, store, operation, candidate, now)
		if err := store.prepare(journal); err != nil {
			t.Fatal(err)
		}
		if err := store.persistAndAdvance(journal, candidate); err != nil {
			t.Fatal(err)
		}
		recovered, present, err := store.recover(context.Background(), newHAV2RecoverableFirewall(), "cluster-a", 15, "node-a", "node-b", string(haRuntimeV2Writer), now)
		if err != nil || !present || !recovered.operationCovered(operation) {
			t.Fatalf("applied WAL recovery present=%t recovered=%#v err=%v", present, recovered, err)
		}
	})
}

func TestHAV2RecoveryResumesEveryDurableCrashBoundary(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	for _, crashBoundary := range []string{"candidate-state-pre-anchor", "recovery-state-candidate-anchor", "recovery-state-recovery-anchor"} {
		t.Run(crashBoundary, func(t *testing.T) {
			store := testHAV2TransactionStore(t)
			model := testHAV2TransactionalModel(t, store, 17)
			bindTestHAV2Writer(t, store, model)
			candidate, _ := cloneHAReplicationModel(model)
			operation := testHAReplicationOperationAtEpoch(t, 17, "node-a", 1, "8.8.8.122", "ssh", "upsert")
			_, _ = candidate.enqueue(operation)
			candidate.compact(now)
			journal := testHAV2Journal(t, store, operation, candidate, now)
			recovery := *candidate
			if err := recovery.setCoordination(haCoordinationFenced, "recovered pending HA v2 transaction; explicit recovery required"); err != nil {
				t.Fatal(err)
			}
			switch crashBoundary {
			case "candidate-state-pre-anchor":
				if err := saveHAReplicationModel(store.statePath, store.expectedOwnerUID, candidate); err != nil {
					t.Fatal(err)
				}
			case "recovery-state-candidate-anchor":
				journal.Stage = haV2TransactionApplied
				if err := store.persist(candidate); err != nil {
					t.Fatal(err)
				}
				if err := saveHAReplicationModel(store.statePath, store.expectedOwnerUID, &recovery); err != nil {
					t.Fatal(err)
				}
			case "recovery-state-recovery-anchor":
				journal.Stage = haV2TransactionApplied
				if err := store.persist(&recovery); err != nil {
					t.Fatal(err)
				}
			}
			writeTestHAV2WAL(t, store, journal)
			recovered, present, err := store.recover(context.Background(), newHAV2RecoverableFirewall(), "cluster-a", 17, "node-a", "node-b", string(haRuntimeV2Writer), now)
			if err != nil || !present || recovered.coordinationState != haCoordinationFenced {
				t.Fatalf("crash boundary was not recovered in one restart: present=%t state=%v err=%v", present, recovered, err)
			}
			if _, _, pending, err := readHAV2Transaction(store); err != nil || pending {
				t.Fatalf("recovered WAL remains pending: pending=%t err=%v", pending, err)
			}
		})
	}
}

func TestHAV2AdapterFailureKeepsWALBoundForFirstRestart(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	for _, stage := range []string{"prepare", "mutation", "persist"} {
		t.Run(stage, func(t *testing.T) {
			api, adapter, coordinator := testHARuntimeV2API(t, haRuntimeV2Writer)
			api.now = func() time.Time { return now }
			store := testHAV2TransactionStore(t)
			if _, err := coordinator.model.bindRuntimeIdentity("node-b", "node-a", string(haRuntimeV2Writer)); err != nil {
				t.Fatal(err)
			}
			initializeHAV2TransactionStoreForModel(t, store, coordinator.model)
			manager := newHAV2RecoverableFirewall()
			manager.failAfter = stage
			if err := adapter.configureTransactions(context.Background(), manager, store, api.now); err != nil {
				t.Fatal(err)
			}
			attestHARuntimeV2Peer(adapter, now)
			if err := adapter.applyLocalTarget("8.8.8.123", "ssh", "upsert", 5*time.Minute, false); err == nil {
				t.Fatal("simulated adapter transaction failure was not surfaced")
			}
			digest, _ := adapter.coordinator.stateDigest()
			if err := adapter.beginOperatorRecovery("node-a", digest); err == nil {
				t.Fatal("operator recovery mutated state while a WAL was pending")
			}
			manager.failAfter = ""
			recovered, present, err := store.recover(context.Background(), manager, "cluster-a", coordinator.epoch, "node-b", "node-a", string(haRuntimeV2Writer), now)
			if err != nil || !present || recovered.coordinationState != haCoordinationFenced {
				t.Fatalf("first restart could not recover adapter WAL: present=%t state=%v err=%v", present, recovered, err)
			}
		})
	}
}

func TestHAV2AdapterFailureBeforeWALPersistsFence(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	api, adapter, coordinator := testHARuntimeV2API(t, haRuntimeV2Writer)
	api.now = func() time.Time { return now }
	store := testHAV2TransactionStore(t)
	if _, err := coordinator.model.bindRuntimeIdentity("node-b", "node-a", string(haRuntimeV2Writer)); err != nil {
		t.Fatal(err)
	}
	initializeHAV2TransactionStoreForModel(t, store, coordinator.model)
	manager := newHAV2RecoverableFirewall()
	manager.failBeforePrepare = true
	if err := adapter.configureTransactions(context.Background(), manager, store, api.now); err != nil {
		t.Fatal(err)
	}
	attestHARuntimeV2Peer(adapter, now)
	if err := adapter.applyLocalTarget("8.8.8.124", "ssh", "upsert", 5*time.Minute, false); err == nil {
		t.Fatal("pre-WAL backend failure was not surfaced")
	}
	if _, _, pending, err := readHAV2Transaction(store); err != nil || pending {
		t.Fatalf("pre-WAL failure created a journal: pending=%t err=%v", pending, err)
	}
	restarted, err := loadHAReplicationModel(store.statePath, store.expectedOwnerUID, "cluster-a")
	if err != nil || restarted.coordinationState != haCoordinationFenced {
		t.Fatalf("pre-WAL failure fence was not durable: state=%v err=%v", restarted, err)
	}
}

func TestHAV2HeadJournalRecoversEveryPublicationBoundary(t *testing.T) {
	for _, boundary := range []string{"pre-pre", "candidate-pre", "candidate-candidate"} {
		t.Run(boundary, func(t *testing.T) {
			store := testHAV2TransactionStore(t)
			model := testHAV2TransactionalModel(t, store, 18)
			bindTestHAV2Writer(t, store, model)
			candidate, _ := cloneHAReplicationModel(model)
			if err := candidate.setCoordination(haCoordinationDegraded, "test durable head"); err != nil {
				t.Fatal(err)
			}
			preDigest, _ := model.persistentStateDigest()
			candidateDigest, _ := candidate.persistentStateDigest()
			journal := haV2HeadJournal{Version: 1, ClusterID: candidate.clusterID, Epoch: candidate.epoch, GenesisID: candidate.genesisID,
				PreStateSHA256: preDigest, CandidateSHA256: candidateDigest, CandidateState: candidate.persistentState()}
			if err := store.publishHeadJournal(journal); err != nil {
				t.Fatal(err)
			}
			if boundary != "pre-pre" {
				if err := saveHAReplicationModel(store.statePath, store.expectedOwnerUID, candidate); err != nil {
					t.Fatal(err)
				}
			}
			if boundary == "candidate-candidate" {
				if err := store.writeStateAnchor(candidate, false); err != nil {
					t.Fatal(err)
				}
			}
			recovered, err := store.loadOrInitialize("cluster-a", 18)
			if err != nil || recovered.coordinationState != haCoordinationDegraded {
				t.Fatalf("head boundary did not recover: state=%v err=%v", recovered, err)
			}
			if _, _, pending, err := store.readHeadJournal(); err != nil || pending {
				t.Fatalf("head journal remains pending: pending=%t err=%v", pending, err)
			}
		})
	}
}

func TestHAV2InitializationHeadJournalRecoversEveryBoundary(t *testing.T) {
	for _, boundary := range []string{"absent-absent", "candidate-absent", "candidate-candidate"} {
		t.Run(boundary, func(t *testing.T) {
			store := testHAV2TransactionStore(t)
			candidate, _ := newHAReplicationModel("cluster-a")
			if err := candidate.setEpoch(20); err != nil {
				t.Fatal(err)
			}
			candidate.coordinationState = haCoordinationHealthy
			candidate.coordinationReason = ""
			digest, _ := candidate.persistentStateDigest()
			if err := store.publishHeadJournal(haV2HeadJournal{Version: 1, Initializing: true, ClusterID: "cluster-a", Epoch: 20,
				GenesisID: candidate.genesisID, CandidateSHA256: digest, CandidateState: candidate.persistentState()}); err != nil {
				t.Fatal(err)
			}
			if boundary != "absent-absent" {
				if err := saveHAReplicationModel(store.statePath, store.expectedOwnerUID, candidate); err != nil {
					t.Fatal(err)
				}
			}
			if boundary == "candidate-candidate" {
				if err := store.writeStateAnchor(candidate, true); err != nil {
					t.Fatal(err)
				}
			}
			recovered, err := store.loadOrInitialize("cluster-a", 20)
			if err != nil || recovered.genesisID != candidate.genesisID {
				t.Fatalf("initialization boundary did not recover: model=%v err=%v", recovered, err)
			}
		})
	}
}

func TestHAV2CommitUnlinkSyncErrorAdoptsDurableCandidate(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	api, adapter, coordinator := testHARuntimeV2API(t, haRuntimeV2Writer)
	api.now = func() time.Time { return now }
	store := testHAV2TransactionStore(t)
	if _, err := coordinator.model.bindRuntimeIdentity("node-b", "node-a", string(haRuntimeV2Writer)); err != nil {
		t.Fatal(err)
	}
	initializeHAV2TransactionStoreForModel(t, store, coordinator.model)
	store.afterRemove = func() error { return errors.New("simulated directory sync failure after WAL unlink") }
	manager := newHAV2RecoverableFirewall()
	if err := adapter.configureTransactions(context.Background(), manager, store, api.now); err != nil {
		t.Fatal(err)
	}
	attestHARuntimeV2Peer(adapter, now)
	if err := adapter.applyLocalTarget("8.8.8.125", "ssh", "upsert", 5*time.Minute, false); err == nil {
		t.Fatal("commit sync ambiguity was not surfaced")
	}
	restarted, err := loadHAReplicationModel(store.statePath, store.expectedOwnerUID, "cluster-a")
	if err != nil || restarted.coordinationState != haCoordinationFenced || len(restarted.snapshot()) != 1 {
		t.Fatalf("commit ambiguity lost its applied candidate: state=%v err=%v", restarted, err)
	}
	status, err := adapter.status(now)
	if err != nil || status.Reason != restarted.coordinationReason {
		t.Fatalf("runtime status reason diverged from durable model: status=%#v durable=%q err=%v", status, restarted.coordinationReason, err)
	}
	if _, present := manager.targets["8.8.8.125"]; !present {
		t.Fatal("commit ambiguity lost the applied firewall mutation")
	}
}

func TestAuditCommitUnlinkCrashResurrectionRemainsRecoverable(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	stateDirectory := t.TempDir()
	transactionDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0700); err != nil { // #nosec G302 -- the owner-only state fixture directory requires execute permission
		t.Fatal(err)
	}
	if err := os.Chmod(transactionDirectory, 0700); err != nil { // #nosec G302 -- the owner-only transaction fixture directory requires execute permission
		t.Fatal(err)
	}
	store, err := newHAV2TransactionStore(
		filepath.Join(stateDirectory, "replication-v2.json"),
		filepath.Join(transactionDirectory, "replication-v2.wal.json"),
		os.Geteuid(),
	)
	if err != nil {
		t.Fatal(err)
	}
	api, adapter, coordinator := testHARuntimeV2API(t, haRuntimeV2Writer)
	api.now = func() time.Time { return now }
	if _, err := coordinator.model.bindRuntimeIdentity("node-b", "node-a", string(haRuntimeV2Writer)); err != nil {
		t.Fatal(err)
	}
	initializeHAV2TransactionStoreForModel(t, store, coordinator.model)
	candidate, err := cloneHAReplicationModel(coordinator.model)
	if err != nil {
		t.Fatal(err)
	}
	operation := testHAReplicationOperation(t, "node-b", 1, "8.8.8.126", "ssh", "upsert")
	if _, err := candidate.enqueue(operation); err != nil {
		t.Fatal(err)
	}
	expectedPreState, _ := coordinator.stateDigest()
	resurrected := testHAV2Journal(t, store, operation, candidate, now)
	resurrected.Stage = haV2TransactionApplied
	store.afterRemove = func() error { return errors.New("simulated transaction-directory sync failure after visible unlink") }
	manager := newHAV2RecoverableFirewall()
	if err := adapter.configureTransactions(context.Background(), manager, store, api.now); err != nil {
		t.Fatal(err)
	}
	executeErr := store.execute(context.Background(), manager, operation, candidate, expectedPreState, now)
	if executeErr == nil {
		t.Fatal("commit unlink ambiguity was not surfaced")
	}
	coordinator.fence("HA v2 recoverable local mutation failed")
	if err := adapter.persistFailureFenceUnlessWALLocked(executeErr, candidate); err == nil {
		t.Fatal("ambiguous commit failure was not returned")
	}
	durable, err := loadHAReplicationModel(store.statePath, store.expectedOwnerUID, "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	durableDigest, _ := durable.persistentStateDigest()
	if durableDigest != resurrected.RecoverySHA256 {
		t.Fatalf("ambiguous commit persisted digest %s, want WAL recovery %s", durableDigest, resurrected.RecoverySHA256)
	}

	store.afterRemove = nil
	writeTestHAV2WAL(t, store, resurrected)
	restarted, present, err := store.recover(context.Background(), manager, "cluster-a", coordinator.epoch, "node-b", "node-a", string(haRuntimeV2Writer), now)
	if err != nil || !present || restarted == nil {
		t.Fatalf("resurrected applied WAL did not recover in one restart: present=%t model=%v err=%v", present, restarted, err)
	}
	restartedDigest, _ := restarted.persistentStateDigest()
	if restartedDigest != resurrected.RecoverySHA256 || restarted.coordinationReason != haV2TransactionRecoveryReason {
		t.Fatalf("resurrected WAL converged to the wrong recovery state: digest=%s reason=%q", restartedDigest, restarted.coordinationReason)
	}
	if _, _, pending, err := readHAV2Transaction(store); err != nil || pending {
		t.Fatalf("resurrected WAL remained after one restart: pending=%t err=%v", pending, err)
	}
}

func TestPendingHeadWALCannotRaceFirewallWAL(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	api, adapter, coordinator := testHARuntimeV2API(t, haRuntimeV2Writer)
	api.now = func() time.Time { return now }
	store := testHAV2TransactionStore(t)
	if _, err := coordinator.model.bindRuntimeIdentity("node-b", "node-a", string(haRuntimeV2Writer)); err != nil {
		t.Fatal(err)
	}
	initializeHAV2TransactionStoreForModel(t, store, coordinator.model)
	headCandidate, _ := cloneHAReplicationModel(coordinator.model)
	if err := headCandidate.setCoordination(haCoordinationDegraded, "pending head"); err != nil {
		t.Fatal(err)
	}
	preDigest, _ := coordinator.model.persistentStateDigest()
	candidateDigest, _ := headCandidate.persistentStateDigest()
	if err := store.publishHeadJournal(haV2HeadJournal{Version: 1, ClusterID: "cluster-a", Epoch: coordinator.epoch,
		GenesisID: coordinator.model.genesisID, PreStateSHA256: preDigest, CandidateSHA256: candidateDigest,
		CandidateState: headCandidate.persistentState()}); err != nil {
		t.Fatal(err)
	}
	manager := newHAV2RecoverableFirewall()
	if err := adapter.configureTransactions(context.Background(), manager, store, api.now); err != nil {
		t.Fatal(err)
	}
	attestHARuntimeV2Peer(adapter, now)
	if err := adapter.applyLocalTarget("8.8.8.126", "ssh", "upsert", 5*time.Minute, false); err == nil {
		t.Fatal("firewall mutation raced a pending head journal")
	}
	if len(manager.mutations) != 0 || adapter.coordinator.state != haCoordinationFenced {
		t.Fatalf("head collision mutated firewall or stayed healthy: mutations=%d state=%s", len(manager.mutations), adapter.coordinator.state)
	}
	if _, _, pending, err := readHAV2Transaction(store); err != nil || pending {
		t.Fatalf("head collision created a firewall WAL: pending=%t err=%v", pending, err)
	}
}

func TestHAV2StartupRejectsSimultaneousJournalsBeforeMutation(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	store := testHAV2TransactionStore(t)
	model := testHAV2TransactionalModel(t, store, 19)
	bindTestHAV2Writer(t, store, model)
	headCandidate, _ := cloneHAReplicationModel(model)
	if err := headCandidate.setCoordination(haCoordinationDegraded, "pending head"); err != nil {
		t.Fatal(err)
	}
	preDigest, _ := model.persistentStateDigest()
	headDigest, _ := headCandidate.persistentStateDigest()
	if err := store.publishHeadJournal(haV2HeadJournal{Version: 1, ClusterID: "cluster-a", Epoch: 19, GenesisID: model.genesisID,
		PreStateSHA256: preDigest, CandidateSHA256: headDigest, CandidateState: headCandidate.persistentState()}); err != nil {
		t.Fatal(err)
	}
	firewallCandidate, _ := cloneHAReplicationModel(model)
	operation := testHAReplicationOperationAtEpoch(t, 19, "node-a", 1, "8.8.8.127", "ssh", "upsert")
	_, _ = firewallCandidate.enqueue(operation)
	journal := testHAV2Journal(t, store, operation, firewallCandidate, now)
	writeTestHAV2WAL(t, store, journal)
	manager := newHAV2RecoverableFirewall()
	if err := store.recoverHeadJournal("cluster-a", 19); err == nil {
		t.Fatal("head recovery accepted simultaneous journals")
	}
	if _, _, err := store.recover(context.Background(), manager, "cluster-a", 19, "node-a", "node-b", string(haRuntimeV2Writer), now); err == nil {
		t.Fatal("firewall recovery accepted simultaneous journals")
	}
	if len(manager.mutations) != 0 {
		t.Fatalf("simultaneous journals mutated firewall: %d", len(manager.mutations))
	}
}

func TestAuditSecondProcessCanRollbackDurableFence(t *testing.T) {
	storeA := testHAV2TransactionStore(t)
	modelA := testHAV2TransactionalModel(t, storeA, 41)
	storeB, err := newHAV2TransactionStore(storeA.statePath, storeA.transactionPath, storeA.expectedOwnerUID)
	if err != nil {
		t.Fatal(err)
	}
	modelB, err := storeB.loadOrInitialize("cluster-a", 41)
	if err != nil {
		t.Fatal(err)
	}
	if err := modelA.setCoordination(haCoordinationFenced, "durable fence"); err != nil {
		t.Fatal(err)
	}
	if err := storeA.persist(modelA); err != nil {
		t.Fatal(err)
	}
	if err := storeB.persist(modelB); err == nil {
		t.Fatal("stale second-process snapshot rolled back a durable fence")
	}
	restarted, err := loadHAReplicationModel(storeA.statePath, storeA.expectedOwnerUID, "cluster-a")
	if err != nil || restarted.coordinationState != haCoordinationFenced {
		t.Fatalf("durable fence was rolled back: state=%v err=%v", restarted, err)
	}
}

func TestHAV2StaleFirewallCandidateIsRejectedBeforeMutation(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	storeA := testHAV2TransactionStore(t)
	modelA := testHAV2TransactionalModel(t, storeA, 42)
	bindTestHAV2Writer(t, storeA, modelA)
	storeB, err := newHAV2TransactionStore(storeA.statePath, storeA.transactionPath, storeA.expectedOwnerUID)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := storeB.loadOrInitialize("cluster-a", 42)
	if err != nil {
		t.Fatal(err)
	}
	expectedStale := storeB.observedHead
	if err := modelA.setCoordination(haCoordinationFenced, "newer durable fence"); err != nil {
		t.Fatal(err)
	}
	if err := storeA.persist(modelA); err != nil {
		t.Fatal(err)
	}
	candidate, _ := cloneHAReplicationModel(stale)
	operation := testHAReplicationOperationAtEpoch(t, 42, "node-a", 1, "8.8.8.128", "ssh", "upsert")
	_, _ = candidate.enqueue(operation)
	manager := newHAV2RecoverableFirewall()
	if err := storeB.execute(context.Background(), manager, operation, candidate, expectedStale, now); err == nil {
		t.Fatal("stale firewall candidate was accepted")
	}
	if len(manager.mutations) != 0 {
		t.Fatalf("stale firewall candidate mutated the firewall: %d", len(manager.mutations))
	}
}

func TestHAV2HeadWALUnlinkSyncAmbiguityKeepsCommittedCandidate(t *testing.T) {
	store := testHAV2TransactionStore(t)
	model := testHAV2TransactionalModel(t, store, 43)
	if err := model.setCoordination(haCoordinationDegraded, "head commit ambiguity"); err != nil {
		t.Fatal(err)
	}
	store.afterHeadRemove = func() error { return errors.New("simulated head directory sync failure") }
	if err := store.persist(model); err != nil {
		t.Fatalf("visible head unlink remained ambiguous: %v", err)
	}
	restarted, err := store.loadOrInitialize("cluster-a", 43)
	if err != nil || restarted.coordinationState != haCoordinationDegraded {
		t.Fatalf("head ambiguity lost committed candidate: state=%v err=%v", restarted, err)
	}
}

func TestHAV2UnreadableFirewallWALLatchesRuntime(t *testing.T) {
	api, adapter, coordinator := testHARuntimeV2API(t, haRuntimeV2Writer)
	store := testHAV2TransactionStore(t)
	initializeHAV2TransactionStoreForModel(t, store, coordinator.model)
	if err := adapter.configureTransactions(context.Background(), newHAV2RecoverableFirewall(), store, api.now); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.transactionPath, []byte("{}"), 0644); err != nil { // #nosec G306 -- this adversarial fixture deliberately creates an unsafe WAL mode
		t.Fatal(err)
	}
	cause := errors.New("simulated transaction failure")
	if err := adapter.persistFailureFenceUnlessWALLocked(cause, coordinator.model); err == nil || !adapter.pendingTransaction {
		t.Fatalf("unreadable firewall WAL did not latch runtime: pending=%t err=%v", adapter.pendingTransaction, err)
	}
	digest, _ := coordinator.stateDigest()
	if err := adapter.beginOperatorRecovery("node-a", digest); err == nil {
		t.Fatal("operator recovery bypassed unreadable WAL latch")
	}
}

func TestHAV2InstanceLockIsExclusiveAndReleased(t *testing.T) {
	storeA := testHAV2TransactionStore(t)
	storeB, err := newHAV2TransactionStore(storeA.statePath, storeA.transactionPath, storeA.expectedOwnerUID)
	if err != nil {
		t.Fatal(err)
	}
	if err := storeA.acquireInstanceLock(); err != nil {
		t.Fatal(err)
	}
	if err := storeB.acquireInstanceLock(); err == nil {
		t.Fatal("second HA v2 runtime acquired the instance lock")
	}
	storeA.releaseInstanceLock()
	if err := storeB.acquireInstanceLock(); err != nil {
		t.Fatalf("released HA v2 instance lock could not be reacquired: %v", err)
	}
	storeB.releaseInstanceLock()
}

func TestHAV2RetainedInstanceLockSurvivesContextCancellation(t *testing.T) {
	storeA := testHAV2TransactionStore(t)
	storeB, err := newHAV2TransactionStore(storeA.statePath, storeA.transactionPath, storeA.expectedOwnerUID)
	if err != nil {
		t.Fatal(err)
	}
	if err := storeA.acquireInstanceLock(); err != nil {
		t.Fatal(err)
	}
	retainHAV2InstanceLease(storeA)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	<-ctx.Done()
	if err := storeB.acquireInstanceLock(); err == nil {
		storeB.releaseInstanceLock()
		t.Fatal("context cancellation released the process-lifetime HA v2 lease")
	}
}

func TestHAV2InstanceLockRejectsSymlinkLooseModeOwnerAndHardlink(t *testing.T) {
	for _, testCase := range []string{"symlink", "mode", "owner", "hardlink"} {
		t.Run(testCase, func(t *testing.T) {
			store := testHAV2TransactionStore(t)
			if testCase == "symlink" {
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("lock"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, store.instanceLockPath); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(store.instanceLockPath, nil, 0644); err != nil { // #nosec G306 -- this adversarial fixture deliberately creates an unsafe lock mode
					t.Fatal(err)
				}
				if testCase != "mode" {
					if err := os.Chmod(store.instanceLockPath, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if testCase == "owner" {
					store.expectedOwnerUID++
				}
				if testCase == "hardlink" {
					if err := os.Link(store.instanceLockPath, filepath.Join(t.TempDir(), "alias")); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := store.acquireInstanceLock(); err == nil {
				store.releaseInstanceLock()
				t.Fatalf("unsafe %s instance lock was accepted", testCase)
			}
		})
	}
}

func TestHAV2InstanceLockRejectsPathReplacementDuringAcquisition(t *testing.T) {
	store := testHAV2TransactionStore(t)
	store.beforeInstanceFlock = func() error {
		if err := os.Remove(store.instanceLockPath); err != nil {
			return err
		}
		return os.WriteFile(store.instanceLockPath, nil, 0600)
	}
	if err := store.acquireInstanceLock(); err == nil {
		store.releaseInstanceLock()
		t.Fatal("instance lock path replacement was accepted")
	}
	if store.instanceLock != nil {
		t.Fatal("rejected instance lock remained held")
	}
}

func TestHAV2TransactionRejectsTamperedWALTarget(t *testing.T) {
	store := testHAV2TransactionStore(t)
	model := testHAV2TransactionalModel(t, store, 1)
	candidate, _ := cloneHAReplicationModel(model)
	operation := testHAReplicationOperation(t, "node-a", 1, "8.8.8.92", "ssh", "upsert")
	_, _ = candidate.enqueue(operation)
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	journal := testHAV2Journal(t, store, operation, candidate, now)
	journal.Target.Permanent = true
	journal.Target.ExpiresAt = ""
	if err := store.prepare(journal); err == nil {
		t.Fatal("WAL target inconsistent with its candidate model was accepted")
	}
}

func TestHAV2TransactionRejectsOperationFromAnotherEpoch(t *testing.T) {
	store := testHAV2TransactionStore(t)
	model := testHAV2TransactionalModel(t, store, 2)
	candidate, _ := cloneHAReplicationModel(model)
	operation := testHAReplicationOperationAtEpoch(t, 2, "node-a", 1, "8.8.8.109", "ssh", "upsert")
	if _, err := candidate.enqueue(operation); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	journal := testHAV2Journal(t, store, operation, candidate, now)
	foreign := operation
	foreign.Epoch = 1
	foreign.OperationID, _ = haReplicationOperationDigest(foreign)
	journal.TransactionID = foreign.OperationID
	journal.Operation = foreign
	if err := store.prepare(journal); err == nil {
		t.Fatal("cross-epoch WAL operation was accepted")
	}
}

func TestHAV2CleanRestartReconcilesPersistedFirewallState(t *testing.T) {
	store := testHAV2TransactionStore(t)
	model := testHAV2TransactionalModel(t, store, 5)
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	active := testHAReplicationOperationAtEpoch(t, 5, "node-a", 1, "8.8.8.94", "ssh", "upsert")
	active.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339)
	active.OperationID, _ = haReplicationOperationDigest(active)
	deleted := testHAReplicationOperationAtEpoch(t, 5, "node-a", 2, "8.8.8.95", "ssh", "delete")
	if _, err := model.apply(active); err != nil {
		t.Fatal(err)
	}
	if _, err := model.apply(deleted); err != nil {
		t.Fatal(err)
	}
	if err := store.persist(model); err != nil {
		t.Fatal(err)
	}

	restarted, err := loadHAReplicationModel(store.statePath, os.Geteuid(), "cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	manager := newHAV2RecoverableFirewall()
	manager.targets[deleted.IP] = firewall.RecoverableMutation{Entry: deleted.IP, Present: true, Permanent: true}
	if err := store.reconcile(context.Background(), manager, restarted, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	activeTarget, activePresent := manager.targets[active.IP]
	_, deletedPresent := manager.targets[deleted.IP]
	mutationCount := len(manager.mutations)
	manager.mu.Unlock()
	if !activePresent || activeTarget.Permanent || activeTarget.TTL != 59*time.Minute {
		t.Fatalf("restart did not restore timed state exactly: %#v", activeTarget)
	}
	if deletedPresent || mutationCount != 2 {
		t.Fatalf("restart did not apply retained absence: deleted=%t mutations=%d", deletedPresent, mutationCount)
	}
	if _, _, present, err := readHAV2Transaction(store); err != nil || present {
		t.Fatalf("restart reconciliation left a WAL: present=%t err=%v", present, err)
	}
}

func TestHAV2InboundTransactionsAreIdempotentAcrossReplayAndDelete(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	store := testHAV2TransactionStore(t)
	model := testHAV2TransactionalModel(t, store, 3)
	receiver, err := newHAReplicationCoordinator("cluster-a", "node-b", "node-a", []byte("0123456789abcdef0123456789abcdef"), model)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := newHARuntimeV2Adapter(receiver, haRuntimeV2Standby, "9.9.9.10", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	manager := newHAV2RecoverableFirewall()
	if err := adapter.configureTransactions(context.Background(), manager, store, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	attestHARuntimeV2Peer(adapter, now)
	senderModel, _ := newHAReplicationModel("cluster-a")
	_ = senderModel.setEpoch(3)
	sender, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", []byte("0123456789abcdef0123456789abcdef"), senderModel)
	_ = sender.activate()

	upsert := testHAReplicationOperationAtEpoch(t, 3, "node-a", 1, "8.8.8.93", "ssh", "upsert")
	upsertWire, _ := sender.envelope(upsert, now)
	if changed, err := adapter.receiveReplication(upsertWire); err != nil || !changed {
		t.Fatalf("upsert changed=%t err=%v", changed, err)
	}
	if changed, err := adapter.receiveReplication(upsertWire); !errors.Is(err, errHACoordinationReplay) || changed {
		t.Fatalf("replay changed=%t err=%v", changed, err)
	}
	manager.mu.Lock()
	mutationCount := len(manager.mutations)
	manager.mu.Unlock()
	if mutationCount != 1 {
		t.Fatalf("replay caused %d firewall mutations", mutationCount)
	}

	deleted := testHAReplicationOperationAtEpoch(t, 3, "node-a", 2, "8.8.8.93", "ssh", "delete")
	deleteWire, _ := sender.envelope(deleted, now)
	if changed, err := adapter.receiveReplication(deleteWire); err != nil || !changed {
		t.Fatalf("delete changed=%t err=%v", changed, err)
	}
	manager.mu.Lock()
	_, present := manager.targets[upsert.IP]
	manager.mu.Unlock()
	if present || len(receiver.model.activeClaims(now)) != 0 {
		t.Fatal("delete did not converge both firewall and model")
	}
	if receiver.model.highWater["node-a"] != 2 || len(receiver.model.sequences["node-a"]) != 0 || len(receiver.model.seen) != 0 {
		t.Fatalf("standby replay evidence was not compacted: %#v", receiver.model.persistentState())
	}
	if changed, err := receiver.model.apply(upsert); err != nil || changed || len(receiver.model.activeClaims(now)) != 0 {
		t.Fatalf("old upsert resurrected after delete: changed=%t err=%v", changed, err)
	}
}

func TestHAV2WriterSerializesConcurrentMutationsAndExpiresToTombstone(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	store := testHAV2TransactionStore(t)
	model := testHAV2TransactionalModel(t, store, 9)
	coordinator, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", []byte("0123456789abcdef0123456789abcdef"), model)
	adapter, _ := newHARuntimeV2Adapter(coordinator, haRuntimeV2Writer, "9.9.9.10", 5*time.Second)
	manager := newHAV2RecoverableFirewall()
	clock := now
	if err := adapter.configureTransactions(context.Background(), manager, store, func() time.Time { return clock }); err != nil {
		t.Fatal(err)
	}
	attestHARuntimeV2Peer(adapter, clock)
	replicated, err := newHAV2ReplicatedManager(manager, adapter)
	if err != nil {
		t.Fatal(err)
	}

	const count = 16
	errorsByCall := make(chan error, count)
	var group sync.WaitGroup
	for index := 0; index < count; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			errorsByCall <- replicated.BanWithTTL(fmt.Sprintf("8.8.4.%d", index+1), time.Hour)
		}(index)
	}
	group.Wait()
	close(errorsByCall)
	for err := range errorsByCall {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(coordinator.model.outbox) != count || len(coordinator.model.sequences["node-a"]) != 0 || coordinator.model.highWater["node-a"] != count {
		t.Fatalf("concurrent writer state outbox=%d sequences=%d high_water=%d", len(coordinator.model.outbox), len(coordinator.model.sequences["node-a"]), coordinator.model.highWater["node-a"])
	}
	for operationID := range coordinator.model.outbox {
		if err := coordinator.model.acknowledge(operationID); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.persist(coordinator.model); err != nil {
		t.Fatal(err)
	}

	clock = now.Add(2 * time.Hour)
	attestHARuntimeV2Peer(adapter, clock)
	if err := adapter.expireLocalClaims(clock, count); err != nil {
		t.Fatal(err)
	}
	if active := coordinator.model.activeClaims(clock); len(active) != 0 {
		t.Fatalf("expired claims remain active: %#v", active)
	}
	manager.mu.Lock()
	remaining := len(manager.targets)
	manager.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("expiry left %d authoritative firewall targets", remaining)
	}
	for _, claim := range coordinator.model.snapshot() {
		if claim.Action != "expiry" || claim.TombstoneUntil == "" {
			t.Fatalf("expiry did not retain a non-resurrection tombstone: %#v", claim)
		}
	}
}

func TestHAV2ReplicatedWriterWaitsForAuthenticatedPeerHeartbeat(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	store := testHAV2TransactionStore(t)
	model := testHAV2TransactionalModel(t, store, 11)
	coordinator, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", []byte("0123456789abcdef0123456789abcdef"), model)
	adapter, _ := newHARuntimeV2Adapter(coordinator, haRuntimeV2Writer, "9.9.9.10", 5*time.Second)
	manager := newHAV2RecoverableFirewall()
	if err := adapter.configureTransactions(context.Background(), manager, store, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	replicated, err := newHAV2ReplicatedManager(manager, adapter)
	if err != nil {
		t.Fatal(err)
	}
	if err := replicated.BanWithTTL("8.8.8.107", time.Hour); err == nil {
		t.Fatal("writer mutated before receiving an authenticated peer heartbeat")
	}
	if len(coordinator.model.snapshot()) != 0 || len(manager.targets) != 0 {
		t.Fatalf("pre-heartbeat rejection changed state: model=%#v targets=%#v", coordinator.model.snapshot(), manager.targets)
	}
	attestHARuntimeV2Peer(adapter, now)
	if err := replicated.BanWithTTL("8.8.8.107", time.Hour); err != nil {
		t.Fatalf("ready writer rejected mutation: %v", err)
	}
}

func TestHAV2StandbyCompactsExpiredTombstonesDurably(t *testing.T) {
	issued := time.Date(2026, 8, 1, 8, 0, 0, 0, time.UTC)
	now := issued.Add(haV2TombstoneRetention + time.Second)
	store := testHAV2TransactionStore(t)
	model := testHAV2TransactionalModel(t, store, 10)
	operation := testHAReplicationOperationAtEpoch(t, 10, "node-a", 1, "8.8.8.106", "ssh", "delete")
	operation.IssuedAt = issued.Format(time.RFC3339)
	operation.TombstoneUntil = issued.Add(haV2TombstoneRetention).Format(time.RFC3339)
	operation.OperationID, _ = haReplicationOperationDigest(operation)
	if _, err := model.apply(operation); err != nil {
		t.Fatal(err)
	}
	model.compact(issued)
	if err := store.persist(model); err != nil {
		t.Fatal(err)
	}
	coordinator, _ := newHAReplicationCoordinator("cluster-a", "node-b", "node-a", []byte("0123456789abcdef0123456789abcdef"), model)
	adapter, _ := newHARuntimeV2Adapter(coordinator, haRuntimeV2Standby, "9.9.9.10", 5*time.Second)
	manager := newHAV2RecoverableFirewall()
	if err := adapter.configureTransactions(context.Background(), manager, store, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	if err := adapter.expireLocalClaims(now, 16); err != nil {
		t.Fatal(err)
	}
	if len(coordinator.model.snapshot()) != 0 {
		t.Fatalf("standby retained an expired tombstone: %#v", coordinator.model.snapshot())
	}
	restarted, err := loadHAReplicationModel(store.statePath, os.Geteuid(), "cluster-a")
	if err != nil || len(restarted.snapshot()) != 0 || restarted.highWater["node-a"] != 1 {
		t.Fatalf("standby compaction was not durable: %#v err=%v", restarted, err)
	}
}

func TestHAV2ReadOnlySnapshotDistinguishesLifecycleStatesAndIsBounded(t *testing.T) {
	now := time.Date(2026, 9, 3, 9, 0, 0, 0, time.UTC)
	model, _ := newHAReplicationModel("cluster-a")
	model.coordinationState = haCoordinationHealthy
	model.coordinationReason = ""
	operations := []haReplicationOperation{
		testHAReplicationOperation(t, "node-a", 1, "8.8.8.101", "ssh", "upsert"),
		testHAReplicationOperation(t, "node-a", 2, "8.8.8.102", "ssh", "upsert"),
		testHAReplicationOperation(t, "node-a", 3, "8.8.8.103", "ssh", "delete"),
		testHAReplicationOperation(t, "node-a", 4, "8.8.8.104", "ssh", "expiry"),
	}
	operations[1].ExpiresAt = "2026-09-03T08:30:00Z"
	operations[1].OperationID, _ = haReplicationOperationDigest(operations[1])
	for _, operation := range operations {
		if _, err := model.apply(operation); err != nil {
			t.Fatal(err)
		}
	}
	coordinator, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", []byte("0123456789abcdef0123456789abcdef"), model)
	adapter, _ := newHARuntimeV2Adapter(coordinator, haRuntimeV2Writer, "9.9.9.10", 5*time.Second)
	adapter.now = func() time.Time { return now }
	manager := &haV2ReplicatedManager{underlying: noOpFirewallManager{}, adapter: adapter}
	snapshot, err := manager.HAReplicationStateSnapshot(4)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Active != 1 || snapshot.Expired != 1 || snapshot.Deleted != 1 || snapshot.Tombstoned != 1 || snapshot.Truncated || len(snapshot.Claims) != 4 {
		t.Fatalf("unexpected lifecycle snapshot: %#v", snapshot)
	}
	if !isLowerHexSHA256(snapshot.ModelSHA256) || !isLowerHexSHA256(snapshot.CheckpointSHA256) ||
		snapshot.CheckpointAt != now.Format(time.RFC3339Nano) || snapshot.CapturedAt != now.Format(time.RFC3339) {
		t.Fatalf("snapshot evidence is not canonical: %#v", snapshot)
	}
	stable, err := manager.HAReplicationStateSnapshot(4)
	if err != nil || stable.ModelSHA256 != snapshot.ModelSHA256 || stable.CheckpointSHA256 != snapshot.CheckpointSHA256 ||
		stable.CheckpointAt != snapshot.CheckpointAt || stable.CapturedAt != snapshot.CapturedAt {
		t.Fatalf("unchanged runtime snapshot is unstable: %#v err=%v", stable, err)
	}
	states := make(map[string]bool)
	for _, claim := range snapshot.Claims {
		states[claim.State] = true
	}
	for _, state := range []string{"active", "expired", "deleted", "tombstoned"} {
		if !states[state] {
			t.Fatalf("snapshot omitted %s state", state)
		}
	}
	limited, err := manager.HAReplicationStateSnapshot(2)
	if err != nil || !limited.Truncated || len(limited.Claims) != 2 || limited.Active+limited.Expired+limited.Deleted+limited.Tombstoned != 4 {
		t.Fatalf("bounded snapshot lost complete counters: %#v err=%v", limited, err)
	}
	for _, invalid := range []int{0, 1025} {
		if _, err := manager.HAReplicationStateSnapshot(invalid); err == nil {
			t.Fatalf("snapshot accepted invalid bound %d", invalid)
		}
	}
	additional := testHAReplicationOperation(t, "node-a", 5, "8.8.8.105", "ssh", "upsert")
	if _, err := coordinator.model.apply(additional); err != nil {
		t.Fatal(err)
	}
	changed, err := manager.HAReplicationStateSnapshot(5)
	if err != nil || changed.ModelSHA256 == snapshot.ModelSHA256 || changed.CapturedAt != snapshot.CapturedAt {
		t.Fatalf("model mutation did not change only its digest evidence: %#v err=%v", changed, err)
	}
}

func TestHAV2ReadOnlySnapshotUsesPreciseReceiptForReadiness(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 950000000, time.UTC)
	model, _ := newHAReplicationModel("cluster-a")
	model.coordinationState = haCoordinationHealthy
	coordinator, _ := newHAReplicationCoordinator("cluster-a", "node-a", "node-b", []byte("0123456789abcdef0123456789abcdef"), model)
	adapter, _ := newHARuntimeV2Adapter(coordinator, haRuntimeV2Writer, "9.9.9.10", 5*time.Second)
	adapter.now = func() time.Time { return now }
	attestHARuntimeV2Peer(adapter, now.Add(-50*time.Millisecond))
	manager := &haV2ReplicatedManager{underlying: noOpFirewallManager{}, adapter: adapter}
	snapshot, err := manager.HAReplicationStateSnapshot(1)
	if err != nil || snapshot.Coordination != string(haCoordinationHealthy) || snapshot.CapturedAt != now.Truncate(time.Second).Format(time.RFC3339) {
		t.Fatalf("subsecond receipt was misclassified: %#v err=%v", snapshot, err)
	}
}
