//go:build linux

package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const recoveryFixtureTransactionID = "0123456789abcdef"

func TestNFTTransactionJournalRoundTripAndTamperRejection_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	statePath := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
	if err := os.WriteFile(statePath, []byte("known-good\n"), 0600); err != nil {
		t.Fatal(err)
	}
	journal, err := newNFTTransactionJournal(
		stateDirectory,
		recoveryFixtureTransactionID,
		"table inet syswarden {\n}\n",
		true,
		nftDynamicSetPresence{InetIPv4: true},
		[]byte(minimalNftRules()),
	)
	if err != nil {
		t.Fatalf("newNFTTransactionJournal() error: %v", err)
	}
	if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionApplied); err != nil {
		t.Fatalf("updateNFTTransactionJournal() error: %v", err)
	}
	loaded, err := readNFTTransactionJournal(stateDirectory)
	if err != nil {
		t.Fatalf("readNFTTransactionJournal() error: %v", err)
	}
	if loaded.TransactionID != recoveryFixtureTransactionID || loaded.Phase != nftTransactionApplied ||
		string(loaded.PreviousPersistent) != "known-good\n" || !loaded.PreviousDynamicSets.InetIPv4 {
		t.Fatalf("journal round trip = %#v", loaded)
	}

	path := nftTransactionJournalPath(stateDirectory)
	content, err := os.ReadFile(path) // #nosec G304 -- path is the fixed journal name beneath this test's private state directory
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(content), journal.RollbackSHA256, strings.Repeat("0", 64), 1)
	if err := os.WriteFile(path, []byte(tampered), 0600); err != nil { // #nosec G703 -- path is the fixed journal name beneath this test's private state directory
		t.Fatal(err)
	}
	if _, err := readNFTTransactionJournal(stateDirectory); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered journal error = %v, want digest mismatch", err)
	}
}

func TestRecoverPendingNFTTransactionDoesNotResurrectFullyExpiredTTLBan_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	plan := recoveryPlanWithDynamicSets()
	runner := newFakeNFTRunner(
		plan,
		nftTableTarget{family: "inet", name: "syswarden"},
		nftTableTarget{family: "netdev", name: "syswarden_hw_drop"},
	)
	runner.currentTables = expectedTableTargets(plan)
	runner.rulesetDocuments = [][]byte{nftVerificationJSONWithoutDynamicBans(plan)}
	const expired = "198.51.100.77 timeout 3600s expires 1s"
	rollback := "table inet syswarden {\n\tset banned_ips { type ipv4_addr; flags interval,timeout; elements = { " + expired + " } }\n}\n"
	journal, err := newNFTTransactionJournal(
		stateDirectory,
		recoveryFixtureTransactionID,
		rollback,
		true,
		nftDynamicSetPresence{InetIPv4: true},
		[]byte(minimalNftRules()),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionApplied); err != nil {
		t.Fatal(err)
	}
	if err := recoverPendingNftablesTransaction(context.Background(), runner, stateDirectory); err != nil {
		t.Fatalf("recoverPendingNftablesTransaction() error: %v", err)
	}
	flush := "flush set inet syswarden banned_ips\n"
	flushIndex := strings.LastIndex(runner.lastRollback, flush)
	expiredIndex := strings.Index(runner.lastRollback, expired)
	if flushIndex < 0 || expiredIndex < 0 || expiredIndex > flushIndex {
		t.Fatalf("rollback did not flush the stale journal element after restoring the table:\n%s", runner.lastRollback)
	}
	if strings.Contains(runner.lastRollback[flushIndex+len(flush):], "add element inet syswarden banned_ips") {
		t.Fatalf("rollback resurrected an expired live ban:\n%s", runner.lastRollback)
	}
	for _, unexpected := range []string{
		"flush set inet syswarden banned_ips6",
		"flush set netdev syswarden_hw_drop banned_ips",
		"flush set netdev syswarden_hw_drop banned_ips6",
	} {
		if strings.Contains(runner.lastRollback, unexpected) {
			t.Fatalf("rollback flushed a dynamic set absent from the previous policy %q:\n%s", unexpected, runner.lastRollback)
		}
	}
}

func TestRecoverPendingNFTTransactionDoesNotResurrectQuarantinedMaximumInterval_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	plan := recoveryPlanWithDynamicSets()
	runner := newFakeNFTRunner(
		plan,
		nftTableTarget{family: "inet", name: "syswarden"},
		nftTableTarget{family: "netdev", name: "syswarden_hw_drop"},
	)
	runner.currentTables = expectedTableTargets(plan)
	// The applied candidate is the already-quarantined live state: all four
	// dynamic sets exist, but the maximum-ending interval is absent.
	runner.rulesetDocuments = [][]byte{nftVerificationJSONWithoutDynamicBans(plan)}
	const unsafeInterval = "45.87.249.145-255.255.255.255"
	rollback := "table netdev syswarden_hw_drop {\n\tset banned_ips { type ipv4_addr; flags interval,timeout; elements = { " + unsafeInterval + " timeout 3600s expires 1800s } }\n}\n"
	journal, err := newNFTTransactionJournal(
		stateDirectory,
		recoveryFixtureTransactionID,
		rollback,
		true,
		nftDynamicSetPresence{NetdevIPv4: true},
		[]byte(minimalNftRules()),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionApplied); err != nil {
		t.Fatal(err)
	}
	if err := recoverPendingNftablesTransaction(context.Background(), runner, stateDirectory); err != nil {
		t.Fatalf("recoverPendingNftablesTransaction() error: %v", err)
	}
	flush := "flush set netdev syswarden_hw_drop banned_ips\n"
	flushIndex := strings.LastIndex(runner.lastRollback, flush)
	unsafeIndex := strings.Index(runner.lastRollback, unsafeInterval)
	if unsafeIndex < 0 || flushIndex < 0 || unsafeIndex > flushIndex {
		t.Fatalf("rollback did not clear the quarantined interval after restoring the raw table:\n%s", runner.lastRollback)
	}
	if strings.Contains(runner.lastRollback[flushIndex+len(flush):], unsafeInterval) {
		t.Fatalf("rollback re-added a quarantined maximum-ending interval:\n%s", runner.lastRollback)
	}
}

func TestNFTTransactionJournalRejectsUnsafeDirectoryAndLinkedFile_SW_FW_005(t *testing.T) {
	t.Run("symlink state directory", func(t *testing.T) {
		root := t.TempDir()
		realDirectory := filepath.Join(root, "real")
		if err := os.Mkdir(realDirectory, 0700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "state")
		if err := os.Symlink(realDirectory, link); err != nil {
			t.Fatal(err)
		}
		if _, err := newNFTTransactionJournal(link, recoveryFixtureTransactionID, "", false, nftDynamicSetPresence{}, nil); err == nil {
			t.Fatal("journal accepted a symbolic-link state directory")
		}
	})

	t.Run("group writable state directory", func(t *testing.T) {
		stateDirectory := t.TempDir()
		if err := os.Chmod(stateDirectory, 0770); err != nil { // #nosec G302 -- adversarial fixture deliberately proves a group-writable state directory is rejected
			t.Fatal(err)
		}
		if _, err := newNFTTransactionJournal(stateDirectory, recoveryFixtureTransactionID, "", false, nftDynamicSetPresence{}, nil); err == nil {
			t.Fatal("journal accepted a group-writable state directory")
		}
	})

	t.Run("hard-linked journal", func(t *testing.T) {
		stateDirectory := t.TempDir()
		if _, err := newNFTTransactionJournal(stateDirectory, recoveryFixtureTransactionID, "", false, nftDynamicSetPresence{}, nil); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(nftTransactionJournalPath(stateDirectory), filepath.Join(stateDirectory, "journal-copy")); err != nil {
			t.Fatal(err)
		}
		if _, err := readNFTTransactionJournal(stateDirectory); err == nil || !strings.Contains(err.Error(), "link count") {
			t.Fatalf("hard-linked journal error = %v, want link-count refusal", err)
		}
	})

	t.Run("non-private journal mode", func(t *testing.T) {
		stateDirectory := t.TempDir()
		if _, err := newNFTTransactionJournal(stateDirectory, recoveryFixtureTransactionID, "", false, nftDynamicSetPresence{}, nil); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(nftTransactionJournalPath(stateDirectory), 0640); err != nil { // #nosec G302 -- adversarial fixture deliberately proves a non-private journal mode is rejected
			t.Fatal(err)
		}
		if _, err := readNFTTransactionJournal(stateDirectory); err == nil || !strings.Contains(err.Error(), "private regular file") {
			t.Fatalf("non-private journal error = %v, want mode refusal", err)
		}
	})
}

func TestNFTTransactionJournalRejectsOversizedPreviousPolicyBeforeRead_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	statePath := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
	file, err := os.OpenFile(statePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600) // #nosec G304 -- statePath is a fixed filename beneath this test's private temporary directory
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maximumNFTJournalFieldBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := newNFTTransactionJournal(stateDirectory, recoveryFixtureTransactionID, "", false, nftDynamicSetPresence{}, nil); err == nil || !strings.Contains(err.Error(), "bounded private regular file") {
		t.Fatalf("oversized previous policy error = %v", err)
	}
}

func TestNFTTransactionJournalCreateDoesNotReplaceExistingJournal_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	first, err := newNFTTransactionJournal(
		stateDirectory,
		recoveryFixtureTransactionID,
		"table inet syswarden {\n}\n",
		true,
		nftDynamicSetPresence{},
		[]byte("first-candidate\n"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newNFTTransactionJournal(
		stateDirectory,
		"fedcba9876543210",
		"table inet syswarden {\n}\n",
		true,
		nftDynamicSetPresence{},
		[]byte("second-candidate\n"),
	); err == nil {
		t.Fatal("new journal replaced an existing durable transaction")
	}
	loaded, err := readNFTTransactionJournal(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TransactionID != first.TransactionID || loaded.CandidatePersistentSHA256 != first.CandidatePersistentSHA256 {
		t.Fatalf("existing journal changed after no-replace collision: %#v", loaded)
	}
}

func TestNFTTransactionJournalRejectsInvalidPhaseTransitionWithoutChangingDisk_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	journal, err := newNFTTransactionJournal(
		stateDirectory,
		recoveryFixtureTransactionID,
		"",
		false,
		nftDynamicSetPresence{},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionVerified); err == nil {
		t.Fatal("journal accepted prepared-to-verified phase jump")
	}
	loaded, err := readNFTTransactionJournal(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Phase != nftTransactionPrepared || loaded.Phase != nftTransactionPrepared {
		t.Fatalf("invalid transition changed memory/disk phase to %q/%q", journal.Phase, loaded.Phase)
	}
}

func TestNFTTransactionJournalCorruptionFailsClosed_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	_, err := newNFTTransactionJournal(
		stateDirectory,
		recoveryFixtureTransactionID,
		"",
		false,
		nftDynamicSetPresence{},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	path := nftTransactionJournalPath(stateDirectory)
	content, err := os.ReadFile(path) // #nosec G304 -- path is the fixed journal name beneath this test's private state directory
	if err != nil {
		t.Fatal(err)
	}
	if len(content) < 2 {
		t.Fatal("journal fixture is unexpectedly short")
	}
	if err := os.WriteFile(path, content[:len(content)/2], 0600); err != nil { // #nosec G703 -- path is the fixed journal name beneath this test's private state directory
		t.Fatal(err)
	}
	runner := newFakeNFTRunner(minimalVerificationPlan(0))
	if err := recoverPendingNftablesTransaction(context.Background(), runner, stateDirectory); err == nil {
		t.Fatal("recovery accepted a truncated journal")
	}
	if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("corrupt journal mutated nftables: apply/rollback=%d/%d", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("corrupt journal was not retained for explicit repair: %v", err)
	}
}

func TestVerifyNFTPersistentPolicyRejectsDigestMismatch_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	path := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
	if err := os.WriteFile(path, []byte("candidate\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyNFTPersistentPolicy(path, true, nftSHA256Hex([]byte("different\n"))); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("persistent digest error = %v, want mismatch", err)
	}
}

func recoveryPlanWithDynamicSets() nftVerificationPlan {
	plan := minimalVerificationPlan(0)
	plan.tables[nftObjectKey{family: "netdev", name: "syswarden_hw_drop"}] = struct{}{}
	for _, key := range nftDynamicBanSets {
		plan.sets[key] = -1
	}
	return plan
}

func TestRecoverPendingNFTTransactionRestoresPreviousKernelAndPersistentPolicy_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	statePath := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
	if err := os.WriteFile(statePath, []byte("known-good\n"), 0600); err != nil {
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
		[]byte(minimalNftRules()),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionApplied); err != nil {
		t.Fatal(err)
	}
	if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionVerified); err != nil {
		t.Fatal(err)
	}

	if err := recoverPendingNftablesTransaction(context.Background(), runner, stateDirectory); err != nil {
		t.Fatalf("recoverPendingNftablesTransaction() error: %v", err)
	}
	if runner.rollbackApplyCalls != 1 {
		t.Fatalf("rollback calls = %d, want 1", runner.rollbackApplyCalls)
	}
	content, err := readRootedNFTFile(statePath)
	if err != nil || string(content) != "known-good\n" {
		t.Fatalf("restored persistent policy = %q, %v", content, err)
	}
	if _, err := os.Lstat(nftTransactionJournalPath(stateDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal remains after recovery: %v", err)
	}
}

func TestRecoverPersistedNFTTransactionKeepsCommittedCandidate_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	statePath := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
	if err := os.WriteFile(statePath, []byte("known-good\n"), 0600); err != nil {
		t.Fatal(err)
	}
	candidate := []byte(minimalNftRules())
	journal, err := newNFTTransactionJournal(
		stateDirectory,
		recoveryFixtureTransactionID,
		"table inet syswarden {\n}\n",
		true,
		nftDynamicSetPresence{},
		candidate,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []nftTransactionPhase{
		nftTransactionApplied,
		nftTransactionVerified,
		nftTransactionPersisted,
	} {
		if phase == nftTransactionPersisted {
			if err := os.WriteFile(statePath, candidate, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := updateNFTTransactionJournal(stateDirectory, journal, phase); err != nil {
			t.Fatal(err)
		}
	}
	runner := newFakeNFTRunner(minimalVerificationPlan(0))
	if err := recoverPendingNftablesTransaction(context.Background(), runner, stateDirectory); err != nil {
		t.Fatalf("recoverPendingNftablesTransaction() error: %v", err)
	}
	if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("persisted recovery mutated nftables: apply/rollback=%d/%d", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
	content, err := readPrivateRootedNFTFile(statePath, maximumNFTJournalFieldBytes)
	if err != nil || string(content) != string(candidate) {
		t.Fatalf("committed candidate after recovery = %q, %v", content, err)
	}
	if _, err := os.Lstat(nftTransactionJournalPath(stateDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("persisted journal remains after cleanup: %v", err)
	}
}

func TestRecoverPersistedNFTTransactionFailsClosedOnCandidateMismatch_SW_FW_005(t *testing.T) {
	for _, test := range []struct {
		name      string
		published []byte
		missing   bool
	}{
		{name: "digest mismatch", published: []byte("different\n")},
		{name: "candidate missing", missing: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateDirectory := t.TempDir()
			statePath := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
			if err := os.WriteFile(statePath, []byte("known-good\n"), 0600); err != nil {
				t.Fatal(err)
			}
			candidate := []byte(minimalNftRules())
			journal, err := newNFTTransactionJournal(
				stateDirectory,
				recoveryFixtureTransactionID,
				"table inet syswarden {\n}\n",
				true,
				nftDynamicSetPresence{},
				candidate,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionApplied); err != nil {
				t.Fatal(err)
			}
			if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionVerified); err != nil {
				t.Fatal(err)
			}
			if test.missing {
				if err := os.Remove(statePath); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(statePath, test.published, 0600); err != nil {
				t.Fatal(err)
			}
			if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionPersisted); err != nil {
				t.Fatal(err)
			}
			runner := newFakeNFTRunner(minimalVerificationPlan(0))
			err = recoverPendingNftablesTransaction(context.Background(), runner, stateDirectory)
			if err == nil || !strings.Contains(err.Error(), "verify published candidate") {
				t.Fatalf("persisted recovery error = %v, want published-candidate refusal", err)
			}
			if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
				t.Fatalf("mismatched persisted recovery mutated nftables: apply/rollback=%d/%d", runner.mainApplyCalls, runner.rollbackApplyCalls)
			}
			if _, err := readNFTTransactionJournal(stateDirectory); err != nil {
				t.Fatalf("mismatched persisted journal was not retained: %v", err)
			}
		})
	}
}

func TestRecoverPersistedNFTTransactionUnlinkSyncFailureDoesNotRollback_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	statePath := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
	if err := os.WriteFile(statePath, []byte("known-good\n"), 0600); err != nil {
		t.Fatal(err)
	}
	candidate := []byte(minimalNftRules())
	journal, err := newNFTTransactionJournal(
		stateDirectory,
		recoveryFixtureTransactionID,
		"table inet syswarden {\n}\n",
		true,
		nftDynamicSetPresence{},
		candidate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionApplied); err != nil {
		t.Fatal(err)
	}
	if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionVerified); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, candidate, 0600); err != nil {
		t.Fatal(err)
	}
	if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionPersisted); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("directory fsync unavailable after unlink")
	previousSync := nftJournalRemovalDirectorySync
	nftJournalRemovalDirectorySync = func(string) error { return sentinel }
	defer func() { nftJournalRemovalDirectorySync = previousSync }()

	runner := newFakeNFTRunner(minimalVerificationPlan(0))
	err = recoverPendingNftablesTransaction(context.Background(), runner, stateDirectory)
	if err == nil || !strings.Contains(err.Error(), "candidate remains committed") ||
		!strings.Contains(err.Error(), "cleanup durability is uncertain") {
		t.Fatalf("persisted recovery error = %v, want committed cleanup uncertainty", err)
	}
	if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("persisted cleanup uncertainty mutated nftables: apply/rollback=%d/%d", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
	content, readErr := readPrivateRootedNFTFile(statePath, maximumNFTJournalFieldBytes)
	if readErr != nil || string(content) != string(candidate) {
		t.Fatalf("committed candidate after cleanup uncertainty = %q, %v", content, readErr)
	}
	if _, statErr := os.Lstat(nftTransactionJournalPath(stateDirectory)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("journal path remains after successful unlink: %v", statErr)
	}
}

func TestRecoverPendingFirstInstallRemovesUncommittedCandidate_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	plan := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(plan)
	runner.currentTables = expectedTableTargets(plan)

	journal, err := newNFTTransactionJournal(
		stateDirectory,
		recoveryFixtureTransactionID,
		"",
		false,
		nftDynamicSetPresence{},
		[]byte(minimalNftRules()),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateNFTTransactionJournal(stateDirectory, journal, nftTransactionApplied); err != nil {
		t.Fatal(err)
	}
	if err := recoverPendingNftablesTransaction(context.Background(), runner, stateDirectory); err != nil {
		t.Fatalf("recoverPendingNftablesTransaction() error: %v", err)
	}
	if runner.rollbackApplyCalls != 1 || len(runner.currentTables) != 0 {
		t.Fatalf("first-install recovery rollback calls/tables = %d/%v", runner.rollbackApplyCalls, runner.currentTables)
	}
	if _, err := os.Lstat(filepath.Join(stateDirectory, filepath.Base(nftStateFile))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first-install recovery left persistent candidate: %v", err)
	}
}

func TestNextTransactionRecoversInterruptedOperationBeforeFreshApply_SW_FW_005(t *testing.T) {
	stateDirectory := t.TempDir()
	statePath := filepath.Join(stateDirectory, filepath.Base(nftStateFile))
	if err := os.WriteFile(statePath, []byte("known-good\n"), 0600); err != nil {
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

	if _, err := applyNftablesTransaction(context.Background(), runner, stateDirectory, minimalNftRules(), nil, plan); err != nil {
		t.Fatalf("fresh transaction after recovery error: %v", err)
	}
	if runner.rollbackApplyCalls != 1 || runner.mainApplyCalls != 1 {
		t.Fatalf("recovery/apply calls = %d/%d, want 1/1", runner.rollbackApplyCalls, runner.mainApplyCalls)
	}
	content, err := readRootedNFTFile(statePath)
	if err != nil || string(content) != minimalNftRules() {
		t.Fatalf("fresh persistent policy = %q, %v", content, err)
	}
	if _, err := os.Lstat(nftTransactionJournalPath(stateDirectory)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal remains after fresh transaction: %v", err)
	}
}

func TestNormalTransactionRemovesJournalOnSuccessAndRollback_SW_FW_005(t *testing.T) {
	for _, test := range []struct {
		name          string
		countGap      int
		wantError     bool
		wantRollbacks int
	}{
		{name: "success"},
		{name: "verified mismatch", countGap: -1, wantError: true, wantRollbacks: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateDirectory := t.TempDir()
			plan := minimalVerificationPlan(1)
			runner := newFakeNFTRunner(plan, nftTableTarget{family: "inet", name: "syswarden"})
			runner.verificationCountGap = test.countGap
			populations := []nftSetPopulation{{name: "fixture_set", entries: []string{"192.0.2.1"}}}
			_, err := applyNftablesTransaction(context.Background(), runner, stateDirectory, minimalNftRules(), populations, plan)
			if (err != nil) != test.wantError {
				t.Fatalf("transaction error = %v, wantError=%v", err, test.wantError)
			}
			if runner.rollbackApplyCalls != test.wantRollbacks {
				t.Fatalf("rollback calls = %d, want %d", runner.rollbackApplyCalls, test.wantRollbacks)
			}
			if _, err := os.Lstat(nftTransactionJournalPath(stateDirectory)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("journal remains after completed transaction: %v", err)
			}
		})
	}
}
