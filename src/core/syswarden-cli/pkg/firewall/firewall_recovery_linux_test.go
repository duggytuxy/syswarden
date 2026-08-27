//go:build linux

package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEarlyAuthoritativeRecoveryRunsBeforeNewPreparation_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	statePath := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
	if err := os.WriteFile(statePath, []byte("known-good\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := minimalVerificationPlan(0)
	previousTable := nftTableTarget{family: "inet", name: "syswarden"}
	runner := newFakeNFTRunner(plan, previousTable)
	runner.currentTables = expectedTableTargets(plan)
	journal, err := newNFTTransactionJournal(
		stateDirectory,
		recoveryFixtureTransactionID,
		"table inet syswarden {\n}\n",
		true,
		nftDynamicSetPresence{},
		[]byte("interrupted-candidate\n"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionApplied); err != nil {
		t.Fatal(err)
	}

	previousLockPath := nftRuntimeLockPath
	nftRuntimeLockPath = filepath.Join(t.TempDir(), "firewall-recovery.lock")
	defer func() { nftRuntimeLockPath = previousLockPath }()
	factoryCalls := 0
	if err := recoverPendingAuthoritativeTransactionAt(
		stateDirectory,
		func() (nftCommandRunner, error) {
			factoryCalls++
			return runner, nil
		},
	); err != nil {
		t.Fatalf("early recovery error: %v", err)
	}
	if factoryCalls != 1 || runner.rollbackApplyCalls != 1 {
		t.Fatalf("early recovery factory/rollback calls = %d/%d, want 1/1", factoryCalls, runner.rollbackApplyCalls)
	}
	content, err := readPrivateRootedNFTFile(statePath, maximumNFTJournalFieldBytes)
	if err != nil || string(content) != "known-good\n" {
		t.Fatalf("early recovery persistent policy = %q, %v", content, err)
	}
	if _, err := os.Lstat(nftTransactionJournalPath(stateDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("early recovery left journal: %v", err)
	}

	// A subsequent candidate preparation failure cannot undo or postpone the
	// already completed recovery.
	preparationErr := errors.New("synthetic new candidate preparation failure")
	prepareCandidate := func() error { return preparationErr }
	if err := prepareCandidate(); !errors.Is(err, preparationErr) {
		t.Fatalf("synthetic preparation error = %v", err)
	}
	if runner.rollbackApplyCalls != 1 {
		t.Fatalf("new preparation failure changed recovery count to %d", runner.rollbackApplyCalls)
	}
}

func TestEarlyAuthoritativeRecoveryWithoutJournalDoesNotRequireNFT_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	previousLockPath := nftRuntimeLockPath
	nftRuntimeLockPath = filepath.Join(t.TempDir(), "firewall-recovery.lock")
	defer func() { nftRuntimeLockPath = previousLockPath }()
	if err := recoverPendingAuthoritativeTransactionAt(
		stateDirectory,
		func() (nftCommandRunner, error) {
			t.Fatal("runner factory called without a recovery journal")
			return nil, errors.New("unreachable")
		},
	); err != nil {
		t.Fatalf("journal-free early recovery error: %v", err)
	}
}
