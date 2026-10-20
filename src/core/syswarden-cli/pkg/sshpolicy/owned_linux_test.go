//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syswarden-cli/pkg/sshselection"
	"testing"

	"golang.org/x/sys/unix"
)

func ownedPublicationFixture(t *testing.T) (*inventoryFixture, migrationPlan, sshTransactionDependencies, *sshJournal) {
	t.Helper()
	f, plan, deps := transactionFixture(t)
	result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
	if err != nil || !result.Published {
		t.Fatal(result, err)
	}
	return f, plan, deps, fixtureJournal(t, f)
}

func TestSSHOwnedPublicationIsRepeatableObservation(t *testing.T) {
	f, plan, deps, journal := ownedPublicationFixture(t)
	prepared, err := journal.read()
	if err != nil {
		t.Fatal(err)
	}
	before, err := stableSSHRollback(journal, prepared.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	records, err := observeSSHOwnedRecords(journal)
	if err != nil {
		t.Fatal(err)
	}
	journal.syncDirectory = func(*os.File) error {
		t.Fatal("read-only verification attempted durability repair")
		return unix.EIO
	}
	for range 2 {
		result, err := verifySSHOwnedPublication(context.Background(), journal, plan.summary.PlanSHA256,
			deps.parserDigest, deps.run, deps.checkParser)
		if err != nil || !result.OwnershipVerified || !result.PublicationObserved || !result.ParserVerified ||
			result.RuntimeActivated || result.AccessVerified || result.ContextsVerified != len(plan.intent.Contexts) ||
			result.PlanSHA256 != plan.summary.PlanSHA256 || result.Transaction != prepared.Transaction ||
			result.ParserSHA256 != deps.parserDigest || result.Profile != plan.intent.Profile {
			t.Fatal("owned verification failed or claimed activation", result, err)
		}
		after, err := stableSSHRollback(journal, prepared.Transaction)
		afterRecords, recordsErr := observeSSHOwnedRecords(journal)
		if err != nil || recordsErr != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, afterRecords) {
			t.Fatal("observation changed configuration or retained history", err, recordsErr)
		}
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps); err == nil {
		t.Fatal("observation authorized a repeated publication")
	}
}

func TestSSHOwnedPublicationRequiresExactOriginalAuthorization(t *testing.T) {
	for _, scenario := range []string{"missing plan", "wrong plan", "uppercase plan", "wrong parser", "cancelled", "nil context", "nil runner", "nil guard", "nil journal", "retained", "poisoned", "changed parser"} {
		t.Run(scenario, func(t *testing.T) {
			_, plan, deps, journal := ownedPublicationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var input context.Context = ctx
			approved := plan.summary.PlanSHA256
			switch scenario {
			case "missing plan":
				approved = ""
			case "wrong plan":
				approved = strings.Repeat("0", 64)
			case "uppercase plan":
				approved = strings.ToUpper(approved)
			case "wrong parser":
				deps.parserDigest = strings.Repeat("b", 64)
			case "cancelled":
				cancel()
			case "nil context":
				input = nil
			case "nil runner":
				deps.run = nil
			case "nil guard":
				deps.checkParser = nil
			case "nil journal":
				journal = nil
			case "retained":
				journal.retained = &sshRetainedJournal{}
			case "poisoned":
				journal.poisoned = true
			case "changed parser":
				deps.checkParser = func() error { return ErrInventoryChanged }
			}
			result, err := verifySSHOwnedPublication(input, journal, approved, deps.parserDigest, deps.run, deps.checkParser)
			if err == nil || result != (OwnedSummary{}) {
				t.Fatal("accepted invalid ownership prerequisite or returned partial success", result, err)
			}
		})
	}
}

func TestSSHOwnedPublicationRejectsChangedFiles(t *testing.T) {
	for _, scenario := range []string{"main", "drop-in", "drop-in replacement", "drop-in mode", "selection", "intent", "original stage", "drop stage", "extra configuration", "extra journal", "missing intent", "noncanonical record", "record mode", "owner receipt"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal := ownedPublicationFixture(t)
			p, err := journal.read()
			if err != nil {
				t.Fatal(err)
			}
			fs, err := os.OpenRoot(f.base)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.Close()
			relative := func(name string) string { return strings.TrimPrefix(name, "/") }
			switch scenario {
			case "main":
				f.write(MainPath, includeDropIns+"PasswordAuthentication yes\n")
			case "drop-in":
				f.write(DropInPath, "AllowTcpForwarding yes\n")
			case "drop-in replacement":
				if err := fs.Rename(relative(DropInPath), relative(DropInPath)+".displaced"); err != nil {
					t.Fatal(err)
				}
				f.write(DropInPath, string(p.DropIn.Data))
			case "drop-in mode":
				if err := fs.Chmod(relative(DropInPath), 0640); err != nil {
					t.Fatal(err)
				}
			case "selection":
				f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
			case "intent":
				f.write(IntentPath, strings.ReplaceAll(validIntentJSON, "forwarding", "cis"))
			case "original stage":
				stage, err := sshMainStagePath(p.Transaction)
				if err != nil {
					t.Fatal(err)
				}
				f.write(stage, "PasswordAuthentication yes\n")
			case "drop stage":
				stage, err := sshDropStagePath(p.Transaction)
				if err != nil {
					t.Fatal(err)
				}
				f.write(stage, "# unexpected inverse candidate\n")
			case "extra configuration":
				f.write("/etc/ssh/sshd_config.d/90-administrator.conf", "# new input\n")
			case "extra journal":
				f.write(sshJournalDirectory+"/unexpected.json", "{}")
			case "missing intent":
				if err := fs.Remove(relative(sshJournalDirectory + "/" + sshPublicationName(2, false))); err != nil {
					t.Fatal(err)
				}
			case "noncanonical record":
				name := sshJournalDirectory + "/" + sshPublicationName(2, true)
				data, err := fs.ReadFile(relative(name))
				if err != nil {
					t.Fatal(err)
				}
				f.write(name, string(data)+"\n")
			case "record mode":
				if err := fs.Chmod(relative(sshJournalDirectory+"/"+sshPublicationName(2, true)), 0644); err != nil {
					t.Fatal(err)
				}
			case "owner receipt":
				f.write(sshStateParent+"/"+sshOwnerName, "{}")
			}
			calls := 0
			run := func(context.Context, *parserImage, string, string) ([]byte, error) {
				calls++
				return nil, errors.New("must not run parser with changed history")
			}
			result, err := verifySSHOwnedPublication(context.Background(), journal, plan.summary.PlanSHA256, deps.parserDigest, run, deps.checkParser)
			if err == nil || result != (OwnedSummary{}) || calls != 0 {
				t.Fatal("changed state reached parser or returned success", calls, result, err)
			}
		})
	}
}

func TestSSHOwnedPublicationRefusesEveryIncompletePhase(t *testing.T) {
	for failure := 1; failure <= 3; failure++ {
		t.Run(fmt.Sprintf("before-completion-%d", failure), func(t *testing.T) {
			f, plan, deps := transactionFixture(t)
			sync := deps.publication.sync
			count := 0
			deps.publication.sync = func(file *os.File) error {
				count++
				if count == failure {
					return unix.EIO
				}
				return sync(file)
			}
			result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
			if err == nil || !result.RecoveryRequired {
				t.Fatal("fixture failed to interrupt publication", result, err)
			}
			journal := fixtureJournal(t, f)
			summary, err := verifySSHOwnedPublication(context.Background(), journal, plan.summary.PlanSHA256, deps.parserDigest, deps.run, deps.checkParser)
			if err == nil || summary != (OwnedSummary{}) {
				t.Fatal("incomplete publication accepted", summary, err)
			}
		})
	}
}

func TestSSHOwnedPublicationRejectsRollbackAndRetirement(t *testing.T) {
	f, p, owner := restoredRetirementFixture(t)
	journal := fixtureJournal(t, f)
	if _, err := verifySSHOwnedPublication(context.Background(), journal, p.PlanSHA256, p.ParserSHA256,
		publicationFixtureParser(f), func() error { return nil }); err == nil {
		t.Fatal("restored configuration claimed as an owned publication")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := retireRestoredFixture(f, p, owner, sshProvisionDefaults()); err != nil {
		t.Fatal(err)
	}
	if journal, err := openSSHJournal(f.root, os.Geteuid()); err == nil {
		_ = journal.Close()
		t.Fatal("retired history adopted as active")
	}
}

func TestSSHOwnedPublicationGuardsEveryParserBoundary(t *testing.T) {
	for _, scenario := range []string{"configuration drift", "history replacement", "history removed", "parser drift", "cancelled", "parser failure", "effective mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal := ownedPublicationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			changed := false
			check := func() error {
				if changed && scenario == "parser drift" {
					return ErrInventoryChanged
				}
				return nil
			}
			calls := 0
			run := func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
				calls++
				output, err := deps.run(ctx, image, mode, access)
				if !changed && (scenario != "effective mismatch" || (image == nil && mode == "effective")) {
					changed = true
					switch scenario {
					case "configuration drift":
						f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
					case "history replacement":
						replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshPublicationName(1, true))
					case "history removed":
						fs, err := os.OpenRoot(f.base)
						if err != nil {
							t.Fatal(err)
						}
						defer fs.Close()
						if err := fs.Remove(strings.TrimPrefix(sshJournalDirectory+"/"+sshPublicationName(1, true), "/")); err != nil {
							t.Fatal(err)
						}
					case "cancelled":
						cancel()
					case "parser failure":
						err = errors.New("fixture parser failure")
					case "effective mismatch":
						output = []byte(strings.ReplaceAll(string(output), "allowtcpforwarding no", "allowtcpforwarding yes"))
					}
				}
				return output, err
			}
			result, err := verifySSHOwnedPublication(ctx, journal, plan.summary.PlanSHA256, deps.parserDigest, run, check)
			if !changed || err == nil || result != (OwnedSummary{}) || (scenario != "effective mismatch" && calls != 1) {
				t.Fatal("parser boundary accepted changed input or partial success", calls, result, err)
			}
		})
	}
}

func TestSSHOwnedProductionEntryRejectsMissingAuthorization(t *testing.T) {
	for _, approved := range []string{"", "not-a-digest", strings.Repeat("A", 64)} {
		if result, err := VerifyOwned(approved); err == nil || result != (OwnedSummary{}) {
			t.Fatal("invalid production authorization accepted", result, err)
		}
	}
}
