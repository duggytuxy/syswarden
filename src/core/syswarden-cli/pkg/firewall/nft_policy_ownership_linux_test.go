//go:build linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func fixtureNFTPolicyGeneration(t *testing.T, fixture nftCurrentFileFixture) *nftPolicyGeneration {
	t.Helper()
	operator, err := compileOperatorPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &nftPolicyGeneration{Base: fixture.inputs().Base, OperatorChain: operator.chain}
}

func TestNFTPolicyOwnershipIndependentFixtures(t *testing.T) {
	for index, fixture := range fixtureNFTCurrentFiles(t) {
		t.Run(fmt.Sprintf("case-%02d", index), func(t *testing.T) {
			source := []byte(fixture.Source)
			generation := fixtureNFTPolicyGeneration(t, fixture)
			receipt, err := prepareNFTPolicyOwnership(source, generation, recoveryFixtureTransactionID)
			if err != nil {
				t.Fatal(err)
			}
			// Mutation of caller-owned input after capture cannot change the
			// immutable record that the transaction will publish.
			generation.Base.Interfaces[0] = "caller-changed"
			input, err := currentNFTInputsFromOwnership(source, receipt)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := inspectNFTCurrentPersistenceRuntime(source, fixture.InetJSON, fixture.NetdevJSON, fixture.ARPJSON, input); err != nil {
				t.Fatal(err)
			}
			for index, population := range fixture.Populations {
				if input.Populations[index].Name != population.Name || !slices.Equal(input.Populations[index].Entries, population.Entries) {
					t.Fatal("ownership reconstruction changed independently generated populations")
				}
			}
			if _, err := currentNFTInputsFromOwnership(append(bytes.Clone(source), '\n'), receipt); err == nil {
				t.Fatal("changed persistent source was adopted")
			}
			if _, err := decodeNFTPolicyOwnership(append(bytes.Clone(receipt), '\n')); err == nil {
				t.Fatal("noncanonical ownership was accepted")
			}
		})
	}
}

func fixtureNFTPolicyOwnershipJournal(t *testing.T, previous bool) (string, *nftTransactionJournal) {
	t.Helper()
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	fixtures := fixtureNFTCurrentFiles(t)
	if previous {
		old, err := prepareNFTPolicyOwnership([]byte(fixtures[0].Source), fixtureNFTPolicyGeneration(t, fixtures[0]), "1111111111111111")
		if err != nil {
			t.Fatal(err)
		}
		if err := root.WriteFile(filepath.Base(nftStateFile), []byte(fixtures[0].Source), 0600); err != nil {
			t.Fatal(err)
		}
		if err := root.WriteFile(nftPolicyOwnershipName, old, 0600); err != nil {
			t.Fatal(err)
		}
	}
	candidate := []byte(fixtures[1].Source)
	ownership, err := prepareNFTPolicyOwnership(candidate, fixtureNFTPolicyGeneration(t, fixtures[1]), recoveryFixtureTransactionID)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := newNFTTransactionJournal(directory, recoveryFixtureTransactionID, "", false, nftDynamicSetPresence{}, candidate, ownership)
	if err != nil {
		t.Fatal(err)
	}
	if err := commitNFTPolicyOwnership(directory, journal); err == nil {
		t.Fatal("ownership became publishable before the commit boundary")
	}
	for _, phase := range []nftTransactionPhase{nftTransactionApplied, nftTransactionVerified, nftTransactionPersisted} {
		if phase == nftTransactionPersisted {
			if err := root.WriteFile(filepath.Base(nftStateFile), candidate, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := updateNFTTransactionJournal(directory, journal, phase); err != nil {
			t.Fatal(err)
		}
	}
	return directory, journal
}

func TestNFTPolicyOwnershipCommitInterruptionRecovery(t *testing.T) {
	for _, previous := range []bool{false, true} {
		for _, phase := range []string{"policy-ownership-staged", "policy-ownership-published", "policy-ownership-durable"} {
			t.Run(fmt.Sprintf("previous-%t-%s", previous, phase), func(t *testing.T) {
				directory, journal := fixtureNFTPolicyOwnershipJournal(t, previous)
				sentinel := errors.New("simulated process interruption")
				ops := defaultLegacyRetirementFileOps()
				ops.checkpoint = func(at string) error {
					if at == phase {
						return sentinel
					}
					return nil
				}
				if err := commitNFTPolicyOwnershipUsing(directory, journal, ops); !errors.Is(err, sentinel) {
					t.Fatal("unexpected interruption result", err)
				}
				if _, err := readNFTTransactionJournal(directory); err != nil {
					t.Fatal("lost transaction needed for recovery", err)
				}
				runner := newFakeNFTRunner(minimalVerificationPlan(0))
				if err := recoverPendingNftablesTransaction(context.Background(), runner, directory); err != nil {
					t.Fatal(err)
				}
				if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
					t.Fatal("committed receipt recovery changed kernel policy")
				}
				receipt, err := readOptionalNFTPolicyOwnership(filepath.Join(directory, nftPolicyOwnershipName))
				if err != nil || !bytes.Equal(receipt, journal.CandidateOwnership) {
					t.Fatal("committed ownership was not recovered", err)
				}
				for _, name := range []string{nftTransactionJournalName, ".firewall-ownership-" + journal.TransactionID + ".pending"} {
					if _, err := os.Lstat(filepath.Join(directory, name)); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("completed transaction retained active staging state", name, err)
					}
				}
			})
		}
	}
}

func TestNFTPolicyOwnershipRefusesChangedEvidence(t *testing.T) {
	for _, target := range []string{nftPolicyOwnershipName, filepath.Base(nftStateFile), nftTransactionJournalName} {
		t.Run(target, func(t *testing.T) {
			directory, journal := fixtureNFTPolicyOwnershipJournal(t, true)
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			changed := []byte("administrator-owned replacement\n")
			if err := root.WriteFile(target, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if err := commitNFTPolicyOwnership(directory, journal); err == nil {
				t.Fatal("changed evidence was accepted")
			}
			got, err := root.ReadFile(target)
			if err != nil || !bytes.Equal(got, changed) {
				t.Fatal("changed evidence was overwritten", err)
			}
		})
	}
}

func TestNFTPolicyOwnershipUncommittedRecoveryPreservesPrevious(t *testing.T) {
	directory, journal := fixtureNFTPolicyOwnershipJournal(t, true)
	// The candidate file may have reached disk before its committed phase.
	// Recovery must restore the prior policy without minting a new receipt.
	journal.Phase = nftTransactionVerified
	if err := writeNFTTransactionJournal(directory, journal, false); err != nil {
		t.Fatal(err)
	}
	runner := newFakeNFTRunner(minimalVerificationPlan(0))
	if err := recoverPendingNftablesTransaction(context.Background(), runner, directory); err != nil {
		t.Fatal(err)
	}
	receipt, err := readOptionalNFTPolicyOwnership(filepath.Join(directory, nftPolicyOwnershipName))
	if err != nil || !bytes.Equal(receipt, journal.PreviousOwnership) {
		t.Fatal("uncommitted recovery changed previous ownership", err)
	}
	source, err := readPrivateRootedNFTFile(filepath.Join(directory, filepath.Base(nftStateFile)), maximumNFTJournalFieldBytes)
	if err != nil || !bytes.Equal(source, journal.PreviousPersistent) {
		t.Fatal("uncommitted policy was not restored", err)
	}
	if _, err := currentNFTInputsFromOwnership(source, receipt); err != nil {
		t.Fatal("restored ownership no longer matches the previous policy", err)
	}
}

func TestNFTPolicyOwnershipPreservesUnsupportedRetirementInputs(t *testing.T) {
	fixture := fixtureNFTCurrentFiles(t)[0]
	generation := fixtureNFTPolicyGeneration(t, fixture)
	// A configured HA listener may equal SSH when cloaking is disabled.
	// The writer supports it even though automatic retirement is conservative.
	generation.Base.Inet.TCPPorts = append(generation.Base.Inet.TCPPorts, generation.Base.Inet.SSHPort)
	receipt, err := prepareNFTPolicyOwnership([]byte(fixture.Source), generation, recoveryFixtureTransactionID)
	if err != nil {
		t.Fatal("receipt capture imposed retirement restrictions on the writer", err)
	}
	if _, err := currentNFTInputsFromOwnership([]byte(fixture.Source), receipt); err == nil {
		t.Fatal("unrecognized retirement inputs were silently adopted")
	}
}

func TestNFTPolicyOwnershipPreservesConcurrentReplacement(t *testing.T) {
	directory, journal := fixtureNFTPolicyOwnershipJournal(t, true)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	replacement := []byte("concurrent administrator receipt\n")
	ops := defaultLegacyRetirementFileOps()
	rename := ops.rename
	injected := false
	ops.rename = func(oldFD int, oldName string, newFD int, newName string, flags uint) error {
		if flags == unix.RENAME_EXCHANGE && !injected {
			injected = true
			if err := root.WriteFile(nftPolicyOwnershipName, replacement, 0600); err != nil {
				return err
			}
		}
		return rename(oldFD, oldName, newFD, newName, flags)
	}
	if err := commitNFTPolicyOwnershipUsing(directory, journal, ops); err == nil {
		t.Fatal("concurrent replacement was accepted")
	}
	got, err := root.ReadFile(nftPolicyOwnershipName)
	if err != nil || !bytes.Equal(got, replacement) {
		t.Fatal("concurrent administrator content was not restored", err)
	}
	if _, err := readNFTTransactionJournal(directory); err != nil {
		t.Fatal("recovery journal was not preserved", err)
	}
}

func TestNFTPolicyOwnershipTransactionPublishesWriterReceipt(t *testing.T) {
	fixture := fixtureNFTCurrentFiles(t)[7]
	operator, err := compileOperatorPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	var populations []nftSetPopulation
	for _, population := range fixture.Populations {
		kind := nftAddressPopulation
		if strings.Contains(population.Name, "_ports") {
			kind = nftAddressPortPopulation
		}
		populations = append(populations, nftSetPopulation{population.Name, population.Entries, kind, strings.Contains(population.Name, "_ssh_bypass")})
	}
	verification := buildNftVerificationPlan(populations, fixture.ARP, operator.verificationPlan())
	verification.generation = fixtureNFTPolicyGeneration(t, fixture)
	runner := newFakeNFTRunner(verification)
	runner.rulesetDocuments = [][]byte{[]byte("{\"nftables\":[]}"), nftVerificationJSONWithoutDynamicBans(verification)}
	directory := t.TempDir()
	base, _, _ := strings.Cut(fixture.Source, "add element ")
	transaction, err := applyNftablesTransactionLocked(context.Background(), runner, directory, base, populations, verification, recoveryFixtureTransactionID, nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := readOptionalNFTPolicyOwnership(filepath.Join(directory, nftPolicyOwnershipName))
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeNFTPolicyOwnership(receipt)
	if err != nil || record.Transaction != transaction {
		t.Fatal("the real transaction did not publish its writer receipt", err)
	}
	if _, err := currentNFTInputsFromOwnership([]byte(fixture.Source), receipt); err != nil {
		t.Fatal(err)
	}
}
