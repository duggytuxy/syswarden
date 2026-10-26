//go:build linux

package sshpolicy

import (
	"bytes"
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

func runtimeRecoveryFixture(t *testing.T, evidence, uncertain bool) (*inventoryFixture, migrationPlan, sshTransactionDependencies, *sshJournal) {
	t.Helper()
	f, plan, deps, journal := activationAssessmentFixture(t, uncertain)
	if evidence {
		// Opaque history is preserved, never used as access authority. Even
		// expired or unappraised bytes cannot complete this restoration.
		if err := journal.writeRecord(sshAccessEvidenceName, []byte(`{"historical":"not authority"}`)); err != nil {
			t.Fatal(err)
		}
	}
	return f, plan, deps, journal
}

func runtimeRecoveryBinder(t *testing.T, journal *sshJournal, calls, closes *int) sshRecoveryBind {
	t.Helper()
	return func(ctx context.Context, guard func() error, _ *sshRecoveryPolicyAnchor) (sshActivationLease, error) {
		if err := errors.Join(ctx.Err(), guard()); err != nil {
			return nil, err
		}
		return &activationTestLease{strings.Repeat("b", 64), func() error { return nil },
			func(ctx context.Context, guard func() error) error {
				*calls++
				if err := errors.Join(ctx.Err(), guard()); err != nil {
					return err
				}
				prepared, err := journal.read()
				if err != nil {
					t.Fatal(err)
				}
				current, err := stableSSHRollback(journal, prepared.Transaction)
				if err != nil || !matchesSSHRecovery(current, MainPath, prepared.MainBefore) || current.Nodes[DropInPath] != (sshStoredStamp{}) {
					t.Fatal("reload preceded exact restoration", err)
				}
				if _, err := journal.readRecord(sshRuntimeRecoveryReloadName); err != nil {
					t.Fatal("reload preceded durable separate intent", err)
				}
				other, err := openSSHJournal(journal.root, journal.uid)
				if err == nil {
					_ = other.Close()
					t.Fatal("recovery released the exclusive journal lock")
				}
				return nil
			}, func() error { *closes++; return nil }}, nil
	}
}

func runtimeRecoveryPlan(t *testing.T, journal *sshJournal, plan migrationPlan, deps sshTransactionDependencies, bind sshRecoveryBind) string {
	t.Helper()
	result, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, "",
		deps.run, deps.checkParser, bind, sshPublicationDefaults())
	if err != nil || !lowerDigest.MatchString(result.RecoverySHA256) || !result.RecoveryRequired || result.IntentDurable ||
		result.ConfigurationRestored || result.RequestReturned {
		t.Fatal("invalid read-only recovery plan", result, err)
	}
	return result.RecoverySHA256
}

func TestSSHRuntimeRecoveryRestoresExactInodesAndNeverClaimsAccess(t *testing.T) {
	for _, evidence := range []bool{false, true} {
		for _, uncertain := range []bool{false, true} {
			t.Run(fmt.Sprintf("evidence-%v-uncertain-%v", evidence, uncertain), func(t *testing.T) {
				f, plan, deps, journal := runtimeRecoveryFixture(t, evidence, uncertain)
				before, err := observeSSHRecordMembership(journal, true, evidence)
				if err != nil {
					t.Fatal(err)
				}
				calls, closes := 0, 0
				bind := runtimeRecoveryBinder(t, journal, &calls, &closes)
				approved := runtimeRecoveryPlan(t, journal, plan, deps, bind)
				if again := runtimeRecoveryPlan(t, journal, plan, deps, bind); again != approved || calls != 0 {
					t.Fatal("inspection mutated or changed approval")
				}
				result, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
					deps.run, deps.checkParser, bind, sshPublicationDefaults())
				if err != nil || !result.ConfigurationRestored || !result.RequestReturned || !result.IntentDurable ||
					!result.RecoveryRequired || !journal.poisoned || calls != 1 || closes != 3 {
					t.Fatal("restoration or uncertainty boundary failed", result, calls, closes, err)
				}
				if err := journal.Close(); err != nil {
					t.Fatal(err)
				}
				journal = fixtureJournal(t, f)
				after, err := observeSSHRuntimeRecoveryRecords(journal)
				if err != nil || len(after) != len(before)+6 {
					t.Fatal("wrong history membership", err)
				}
				for name, hash := range before {
					if after[name] != hash {
						t.Fatal("original evidence changed", name)
					}
				}
				if err := rollbackSSHConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.run, deps.checkParser, sshPublicationDefaults()); err == nil {
					t.Fatal("file-only rollback acquired runtime authority")
				}
				result, err = recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
					deps.run, deps.checkParser, runtimeRecoveryBinder(t, journal, &calls, &closes), sshPublicationDefaults())
				if err == nil || result.RequestReturned || calls != 1 {
					t.Fatal("restoring reload replayed", result, err)
				}
			})
		}
	}
}

// Use the actual serialized target: a fixture lease without its mutex cannot
// detect reentrant identity/check calls from the request's policy guard.
func TestSSHRuntimeRecoveryWithSerializedTarget(t *testing.T) {
	_, plan, deps, journal := runtimeRecoveryFixture(t, false, false)
	sends, observations, closes := 0, 0, 0
	bind := func(ctx context.Context, guard func() error, _ *sshRecoveryPolicyAnchor) (sshActivationLease, error) {
		if err := errors.Join(ctx.Err(), guard()); err != nil {
			return nil, err
		}
		return &sshActivationTarget{
			ctx: ctx, target: strings.Repeat("b", 64),
			verify: func(context.Context) error { return nil },
			send:   func() error { sends++; return nil },
			after: func(ctx context.Context, guard func() error) error {
				observations++
				return errors.Join(ctx.Err(), guard())
			},
			closeFn: func() error { closes++; return nil },
		}, nil
	}
	approved := runtimeRecoveryPlan(t, journal, plan, deps, bind)
	result, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
		deps.run, deps.checkParser, bind, sshPublicationDefaults())
	if err != nil || !result.ConfigurationRestored || !result.RequestReturned || !result.RecoveryRequired ||
		sends != 1 || observations != 1 || closes != 2 {
		t.Fatal("serialized recovery request failed", result, sends, observations, closes, err)
	}
}

func TestSSHRuntimeRecoveryResumesBeforeReloadButNeverReplaysReloadIntent(t *testing.T) {
	for _, kind := range []string{"journal-sync", "directory-sync", "rename-before", "rename-after"} {
		limit := map[string]int{"journal-sync": 6, "directory-sync": 8, "rename-before": 2, "rename-after": 2}[kind]
		for failAt := 1; failAt <= limit; failAt++ {
			t.Run(fmt.Sprintf("%s-%d", kind, failAt), func(t *testing.T) {
				f, plan, deps, journal := runtimeRecoveryFixture(t, true, false)
				calls, closes := 0, 0
				bind := runtimeRecoveryBinder(t, journal, &calls, &closes)
				approved := runtimeRecoveryPlan(t, journal, plan, deps, bind)
				ops := sshPublicationDefaults()
				count := 0
				syncFail := func(file *os.File) error {
					count++
					if count == failAt {
						return unix.EIO
					}
					return file.Sync()
				}
				switch kind {
				case "journal-sync":
					// Count record writes only; the explicit resume durability
					// sync has the same directory but no new record.
					seen := 10
					journal.syncDirectory = func(file *os.File) error {
						names, err := sshDirectoryNames(file, 16)
						if err != nil {
							return err
						}
						if len(names) > seen {
							seen = len(names)
							return syncFail(file)
						}
						return file.Sync()
					}
				case "directory-sync":
					ops.sync = syncFail
				default:
					ops.rename = func(a int, b string, c int, d string, flags uint) error {
						count++
						if count == failAt && kind == "rename-before" {
							return unix.EIO
						}
						if err := unix.Renameat2(a, b, c, d, flags); err != nil {
							return err
						}
						if count == failAt {
							return unix.EIO
						}
						return nil
					}
				}
				result, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
					deps.run, deps.checkParser, bind, ops)
				if err == nil || !result.RecoveryRequired || result.RequestReturned || calls != 0 || !journal.poisoned {
					t.Fatal("failure was concealed or requested reload", result, count, calls, err)
				}
				if err := journal.Close(); err != nil {
					t.Fatal(err)
				}
				journal = fixtureJournal(t, f)
				result, err = recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
					deps.run, deps.checkParser, runtimeRecoveryBinder(t, journal, &calls, &closes), sshPublicationDefaults())
				if kind == "journal-sync" && failAt == 6 {
					if err == nil || calls != 0 {
						t.Fatal("uncertain reload intent allowed replay", err)
					}
				} else if err != nil || !result.ConfigurationRestored || !result.RequestReturned || !result.RecoveryRequired || calls != 1 {
					t.Fatal("explicit exact resume failed", result, calls, err)
				}
			})
		}
	}
}

func TestSSHRuntimeRecoveryRejectsChangedApprovalInputs(t *testing.T) {
	for _, kind := range []string{"original-approval", "recovery-approval", "parser", "main", "drop", "selection", "intent", "record-replacement", "extra-record", "extra-evidence", "target", "closed-lease", "cancelled", "bind-error"} {
		t.Run(kind, func(t *testing.T) {
			f, plan, deps, journal := runtimeRecoveryFixture(t, false, false)
			calls, closes := 0, 0
			bind := runtimeRecoveryBinder(t, journal, &calls, &closes)
			approved := runtimeRecoveryPlan(t, journal, plan, deps, bind)
			original := plan.summary.PlanSHA256
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch kind {
			case "original-approval":
				original = strings.Repeat("0", 64)
			case "recovery-approval":
				approved = original
			case "parser":
				deps.parserDigest = strings.Repeat("0", 64)
			case "main":
				f.write(MainPath, "Port 2323\n")
			case "drop":
				f.write(DropInPath, "AllowTcpForwarding yes\n")
			case "selection":
				f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
			case "intent":
				f.write(sshJournalDirectory+"/"+sshActivationIntentName, "{}")
			case "record-replacement":
				replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshPublicationName(1, true))
			case "extra-record":
				f.write(sshJournalDirectory+"/unknown", "{}")
			case "extra-evidence":
				if err := journal.writeRecord(sshAccessEvidenceName, []byte(`{}`)); err != nil {
					t.Fatal(err)
				}
			case "target", "closed-lease", "bind-error":
				previous := bind
				bind = func(ctx context.Context, guard func() error, anchor *sshRecoveryPolicyAnchor) (sshActivationLease, error) {
					lease, err := previous(ctx, guard, anchor)
					if err == nil {
						switch kind {
						case "target":
							lease.(*activationTestLease).target = strings.Repeat("c", 64)
						case "closed-lease":
							lease.(*activationTestLease).checkFn = func() error { return ErrInventoryClosed }
						case "bind-error":
							err = unix.EIO
						}
					}
					return lease, err
				}
			case "cancelled":
				cancel()
			}
			result, err := recoverSSHActivatedConfiguration(ctx, journal, original, deps.parserDigest, approved,
				deps.run, deps.checkParser, bind, sshPublicationDefaults())
			if err == nil || result.IntentDurable || result.RequestReturned || calls != 0 {
				t.Fatal("invalid prerequisites authorized recovery", result, err)
			}
			if _, err := os.Lstat(f.path(sshJournalDirectory + "/" + sshRuntimeRecoveryName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid prerequisites created recovery history", err)
			}
		})
	}
}

func TestSSHRuntimeRecoveryParserFailureAfterRestorationResumes(t *testing.T) {
	f, plan, deps, journal := runtimeRecoveryFixture(t, false, false)
	calls, closes := 0, 0
	bind := runtimeRecoveryBinder(t, journal, &calls, &closes)
	approved := runtimeRecoveryPlan(t, journal, plan, deps, bind)
	run := func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
		if image == nil {
			if _, err := os.Lstat(f.path(DropInPath)); errors.Is(err, os.ErrNotExist) {
				return nil, unix.EIO
			}
		}
		return deps.run(ctx, image, mode, access)
	}
	result, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
		run, deps.checkParser, bind, sshPublicationDefaults())
	if err == nil || result.ConfigurationRestored || result.RequestReturned || calls != 0 {
		t.Fatal("parser failure accepted", result, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal = fixtureJournal(t, f)
	result, err = recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
		deps.run, deps.checkParser, runtimeRecoveryBinder(t, journal, &calls, &closes), sshPublicationDefaults())
	if err != nil || !result.ConfigurationRestored || !result.RequestReturned || calls != 1 {
		t.Fatal("restored parser verification did not resume", result, err)
	}
}

func TestSSHRuntimeRecoveryRequestFailureRetainsAllEvidence(t *testing.T) {
	for _, kind := range []string{"request-error", "cancel-in-request", "target-in-request", "close-error"} {
		t.Run(kind, func(t *testing.T) {
			f, plan, deps, journal := runtimeRecoveryFixture(t, true, false)
			calls, closes := 0, 0
			bind := runtimeRecoveryBinder(t, journal, &calls, &closes)
			approved := runtimeRecoveryPlan(t, journal, plan, deps, bind)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			wrapped := func(ctx context.Context, guard func() error, anchor *sshRecoveryPolicyAnchor) (sshActivationLease, error) {
				lease, err := bind(ctx, guard, anchor)
				if err != nil {
					return lease, err
				}
				l := lease.(*activationTestLease)
				request := l.requestFn
				l.requestFn = func(ctx context.Context, guard func() error) error {
					if err := request(ctx, guard); err != nil {
						return err
					}
					if kind == "cancel-in-request" {
						cancel()
					}
					if kind == "target-in-request" {
						l.target = strings.Repeat("c", 64)
					}
					if kind == "request-error" {
						return unix.EIO
					}
					return nil
				}
				if kind == "close-error" {
					l.closeFn = func() error { closes++; return unix.EIO }
				}
				return l, nil
			}
			result, err := recoverSSHActivatedConfiguration(ctx, journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
				deps.run, deps.checkParser, wrapped, sshPublicationDefaults())
			if err == nil || !result.ConfigurationRestored || !result.RecoveryRequired || calls != 1 || !journal.poisoned {
				t.Fatal("request uncertainty cleared", result, err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			journal = fixtureJournal(t, f)
			wire, err := journal.readRecord(sshRuntimeRecoveryReloadName)
			if err != nil || !bytes.Contains(wire, []byte(approved)) {
				t.Fatal("lost separately bound reload intent", err)
			}
			before, err := observeSSHRuntimeRecoveryRecords(journal)
			if err != nil {
				t.Fatal(err)
			}
			_, err = recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
				deps.run, deps.checkParser, runtimeRecoveryBinder(t, journal, &calls, &closes), sshPublicationDefaults())
			after, readErr := observeSSHRuntimeRecoveryRecords(journal)
			if err == nil || readErr != nil || calls != 1 || !reflect.DeepEqual(before, after) {
				t.Fatal("replay mutated retained evidence", err, readErr)
			}
		})
	}
}

func TestSSHRuntimeRecoveryResumeRefusesChangedHistoryAndTarget(t *testing.T) {
	for _, kind := range []string{"extra-evidence", "record-replacement", "noncanonical", "unknown-field", "wrong-domain", "mode", "target", "missing-original", "changed-main"} {
		t.Run(kind, func(t *testing.T) {
			f, plan, deps, journal := runtimeRecoveryFixture(t, false, false)
			calls, closes := 0, 0
			approved := runtimeRecoveryPlan(t, journal, plan, deps, runtimeRecoveryBinder(t, journal, &calls, &closes))
			ops := sshPublicationDefaults()
			ops.sync = func(*os.File) error { return unix.EIO }
			_, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
				deps.run, deps.checkParser, runtimeRecoveryBinder(t, journal, &calls, &closes), ops)
			if err == nil || calls != 0 {
				t.Fatal("fixture did not stop after recovery intent", err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			journal = fixtureJournal(t, f)
			name := sshJournalDirectory + "/" + sshRuntimeRecoveryName
			wire, err := journal.readRecord(sshRuntimeRecoveryName)
			if err != nil {
				t.Fatal(err)
			}
			bind := runtimeRecoveryBinder(t, journal, &calls, &closes)
			switch kind {
			case "extra-evidence":
				if err := journal.writeRecord(sshAccessEvidenceName, []byte(`{}`)); err != nil {
					t.Fatal(err)
				}
			case "record-replacement":
				replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshPublicationName(1, true))
			case "noncanonical":
				f.write(name, string(wire)+"\n")
			case "unknown-field":
				f.write(name, strings.Replace(string(wire), "{", `{"unknown":true,`, 1))
			case "wrong-domain":
				f.write(name, strings.Replace(string(wire), sshRuntimeRecoveryDomain, "unknown", 1))
			case "mode":
				if err := os.Chmod(f.path(name), 0644); err != nil { // #nosec G302 -- Unsafe private-history fixture; production record modes remain 0600.
					t.Fatal(err)
				}
			case "target":
				previous := bind
				bind = func(ctx context.Context, guard func() error, anchor *sshRecoveryPolicyAnchor) (sshActivationLease, error) {
					lease, err := previous(ctx, guard, anchor)
					if err == nil {
						lease.(*activationTestLease).target = strings.Repeat("c", 64)
					}
					return lease, err
				}
			case "missing-original":
				if err := os.Remove(f.path(sshJournalDirectory + "/" + sshPublicationName(1, true))); err != nil {
					t.Fatal(err)
				}
			case "changed-main":
				f.write(MainPath, "Port 2323\n")
			}
			ops = sshPublicationDefaults()
			ops.rename = func(int, string, int, string, uint) error { t.Fatal("drift reached rename"); return unix.EIO }
			ops.sync = func(*os.File) error { t.Fatal("drift reached durability mutation"); return unix.EIO }
			_, err = recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
				deps.run, deps.checkParser, bind, ops)
			if err == nil || calls != 0 {
				t.Fatal("resume adopted changed history or target", err)
			}
		})
	}
}
