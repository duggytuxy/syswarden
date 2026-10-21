//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"syswarden-cli/pkg/sshselection"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type activationTestLease struct {
	target    string
	checkFn   func() error
	requestFn func(context.Context, func() error) error
	closeFn   func() error
}

func (l *activationTestLease) identity() string { return l.target }
func (l *activationTestLease) check() error     { return l.checkFn() }
func (l *activationTestLease) request(ctx context.Context, guard func() error) error {
	return l.requestFn(ctx, guard)
}
func (l *activationTestLease) Close() error { return l.closeFn() }

func activationTestBinder(t *testing.T, journal *sshJournal, calls, closed *int) sshActivationBind {
	t.Helper()
	return func(ctx context.Context, guard func() error) (sshActivationLease, error) {
		if err := errors.Join(ctx.Err(), guard()); err != nil {
			return nil, err
		}
		return &activationTestLease{strings.Repeat("a", 64), func() error { return nil },
			func(ctx context.Context, policyGuard func() error) error {
				*calls++
				if err := errors.Join(ctx.Err(), policyGuard()); err != nil {
					return err
				}
				if _, err := journal.readRecord(sshActivationIntentName); err != nil {
					t.Fatal("request preceded durable intent", err)
				}
				competing, err := openSSHJournal(journal.root, journal.uid)
				if err == nil {
					_ = competing.Close()
					t.Fatal("activation lost exclusive journal lock")
				}
				return nil
			}, func() error { *closed++; return nil }}, nil
	}
}

func TestSSHActivationRecordsUncertaintyBeforeRequest(t *testing.T) {
	f, plan, deps, journal := ownedPublicationFixture(t)
	prepared, err := journal.read()
	if err != nil {
		t.Fatal(err)
	}
	before, err := stableSSHRollback(journal, prepared.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	calls, closed := 0, 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	bind := activationTestBinder(t, journal, &calls, &closed)
	result, err := attemptSSHActivation(ctx, journal, plan.summary.PlanSHA256, deps.parserDigest, deps.run, deps.checkParser,
		func(ctx context.Context, guard func() error) (sshActivationLease, error) {
			if end, ok := ctx.Deadline(); !ok || end.After(deadline) {
				t.Fatal("expanded deadline")
			}
			return bind(ctx, guard)
		})
	if err != nil || result.Transaction != prepared.Transaction || !result.IntentDurable || !result.RequestReturned || !result.RecoveryRequired || calls != 1 || closed != 1 || !journal.poisoned {
		t.Fatal(result, calls, closed, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := fixtureJournal(t, f)
	wire, err := reopened.readRecord(sshActivationIntentName)
	if err != nil {
		t.Fatal(err)
	}
	var intent sshActivationIntent
	if err := json.Unmarshal(wire, &intent); err != nil {
		t.Fatal(err)
	}
	if intent.Schema != 1 || intent.Transaction != prepared.Transaction || intent.Plan != plan.summary.PlanSHA256 || intent.Parser != deps.parserDigest || !lowerDigest.MatchString(intent.Prepared) || !lowerDigest.MatchString(intent.Publication) || !lowerDigest.MatchString(intent.Records) || intent.Target != strings.Repeat("a", 64) {
		t.Fatal("intent lost binding", intent)
	}
	for _, private := range []string{"AllowTcpForwarding", "192.0.2.", "/etc/ssh/"} {
		if strings.Contains(string(wire), private) {
			t.Fatal("intent exposed raw configuration")
		}
	}
	after, err := stableSSHRollback(reopened, prepared.Transaction)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("request boundary changed configuration", err)
	}
	result, err = attemptSSHActivation(ctx, reopened, plan.summary.PlanSHA256, deps.parserDigest, deps.run, deps.checkParser, bind)
	if err == nil || result != (sshActivationResult{}) || calls != 1 {
		t.Fatal("replayed activation", result, err)
	}
	if err := rollbackSSHConfiguration(ctx, reopened, plan.summary.PlanSHA256, deps.run, deps.checkParser, sshPublicationDefaults()); err == nil {
		t.Fatal("file-only rollback ignored runtime uncertainty")
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	recovery, err := recoverSSHTransaction(ctx, f.root, os.Geteuid(), plan.summary.PlanSHA256, deps.parserDigest, deps.run, deps.checkParser, sshPublicationDefaults())
	if err == nil || !recovery.RecoveryRequired || recovery.Restored || recovery.Aborted {
		t.Fatal("recovery accepted uncertain runtime", recovery, err)
	}
}

func TestSSHActivationRefusesBeforeIntent(t *testing.T) {
	for _, scenario := range []string{"nil-context", "cancelled", "nil-binder", "nil-runner", "nil-parser-check", "wrong-plan", "wrong-parser", "disabled-selection", "unknown-history", "nil-lease", "bind-error", "bind-partial-error", "invalid-target", "target-drift", "lease-check", "parser-drift", "selection-drift"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal := ownedPublicationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var input context.Context = ctx
			calls, closed := 0, 0
			bind := activationTestBinder(t, journal, &calls, &closed)
			approved := plan.summary.PlanSHA256
			switch scenario {
			case "nil-context":
				input = nil
			case "cancelled":
				cancel()
			case "nil-binder":
				bind = nil
			case "nil-runner":
				deps.run = nil
			case "nil-parser-check":
				deps.checkParser = nil
			case "wrong-plan":
				approved = strings.Repeat("b", 64)
			case "wrong-parser":
				deps.parserDigest = strings.Repeat("b", 64)
			case "disabled-selection":
				f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
			case "unknown-history":
				f.write(sshJournalDirectory+"/unexpected.json", "{}")
			default:
				original := bind
				bind = func(ctx context.Context, guard func() error) (sshActivationLease, error) {
					lease, err := original(ctx, guard)
					if err != nil {
						return nil, err
					}
					l := lease.(*activationTestLease)
					switch scenario {
					case "nil-lease":
						_ = l.Close()
						return nil, nil
					case "bind-error":
						_ = l.Close()
						return nil, unix.EIO
					case "bind-partial-error":
						return l, unix.EIO
					case "invalid-target":
						l.target = "invalid"
					case "target-drift":
						l.checkFn = func() error { l.target = strings.Repeat("c", 64); return nil }
					case "lease-check":
						l.checkFn = func() error { return unix.ESRCH }
					case "parser-drift":
						deps.checkParser = func() error { return unix.EIO }
						l.checkFn = deps.checkParser
					case "selection-drift":
						f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
					}
					return l, nil
				}
			}
			result, err := attemptSSHActivation(input, journal, approved, deps.parserDigest, deps.run, deps.checkParser, bind)
			if err == nil || result != (sshActivationResult{}) || calls != 0 {
				t.Fatal("invalid preflight reached intent or request", result, calls, err)
			}
			if _, err := os.Lstat(f.path(sshJournalDirectory + "/" + sshActivationIntentName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("preflight left intent", err)
			}
			if closed > 1 {
				t.Fatal("closed lease twice")
			}
		})
	}
}

func TestSSHActivationFailuresKeepFence(t *testing.T) {
	for _, scenario := range []string{"sync-error", "cancel-after-sync", "policy-after-sync", "record-after-sync", "target-after-sync", "request-error", "cancel-in-request", "policy-in-request", "record-replaced", "extra-record", "close-error"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal := ownedPublicationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, closed := 0, 0
			original := activationTestBinder(t, journal, &calls, &closed)
			var lease *activationTestLease
			bind := func(ctx context.Context, guard func() error) (sshActivationLease, error) {
				l, err := original(ctx, guard)
				if err != nil {
					return nil, err
				}
				lease = l.(*activationTestLease)
				request := lease.requestFn
				lease.requestFn = func(ctx context.Context, guard func() error) error {
					if err := request(ctx, guard); err != nil {
						return err
					}
					switch scenario {
					case "request-error":
						return unix.EIO
					case "cancel-in-request":
						cancel()
					case "policy-in-request":
						f.write(DropInPath, "AllowTcpForwarding yes\n")
					case "record-replaced":
						replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshActivationIntentName)
					case "extra-record":
						f.write(sshJournalDirectory+"/unexpected.json", "{}")
					}
					return nil
				}
				if scenario == "close-error" {
					lease.closeFn = func() error { closed++; return unix.EIO }
				}
				return lease, nil
			}
			journal.syncDirectory = func(file *os.File) error {
				if scenario == "sync-error" {
					return unix.EIO
				}
				if err := file.Sync(); err != nil {
					return err
				}
				switch scenario {
				case "cancel-after-sync":
					cancel()
				case "policy-after-sync":
					f.write(DropInPath, "AllowTcpForwarding yes\n")
				case "record-after-sync":
					replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshPreparedRecord)
				case "target-after-sync":
					lease.target = strings.Repeat("b", 64)
				}
				return nil
			}
			result, err := attemptSSHActivation(ctx, journal, plan.summary.PlanSHA256, deps.parserDigest, deps.run, deps.checkParser, bind)
			if err == nil || !result.RecoveryRequired || result.Transaction == "" || closed != 1 || !journal.poisoned {
				t.Fatal("lost recovery boundary", result, calls, closed, err)
			}
			if strings.Contains(scenario, "sync") && calls != 0 {
				t.Fatal("dispatched through failed persistence or drift")
			}
			if scenario == "sync-error" && result.IntentDurable {
				t.Fatal("claimed uncertain durability")
			}
			if scenario != "close-error" && result.RequestReturned {
				t.Fatal("claimed request returned after failure")
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			reopened := fixtureJournal(t, f)
			if err := reopened.requireNoSSHActivation(); err == nil {
				t.Fatal("lost activation fence after reopen")
			}
		})
	}
}

func TestSSHActivationPresenceBlocksFileOnlyRecovery(t *testing.T) {
	for _, scenario := range []string{"malformed", "symlink", "directory", "world-writable", "valid-looking"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal := ownedPublicationFixture(t)
			name := sshJournalDirectory + "/" + sshActivationIntentName
			switch scenario {
			case "symlink":
				if err := os.Symlink("missing", f.path(name)); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(f.path(name), 0700); err != nil {
					t.Fatal(err)
				}
			default:
				f.write(name, "{}")
				if scenario == "world-writable" {
					if err := os.Chmod(f.path(name), 0666); err != nil { // #nosec G302 -- Intentional unsafe permissions in an isolated fixture; activation recovery must refuse this evidence.
						t.Fatal(err)
					}
				}
			}
			if err := journal.requireNoSSHActivation(); err == nil {
				t.Fatal("ambiguous evidence was treated as absent")
			}
			if _, err := inspectSSHPublication(journal); err == nil {
				t.Fatal("publication ignored possible activation")
			}
			if err := rollbackSSHConfiguration(context.Background(), journal, plan.summary.PlanSHA256, deps.run, deps.checkParser, sshPublicationDefaults()); err == nil {
				t.Fatal("rollback ignored possible activation")
			}
			if restoredSSHRecordName(sshActivationIntentName) {
				t.Fatal("file-only retirement admits activation")
			}
			if _, _, err := observeSSHRestoredFiles(journal.directory, journal.uid); err == nil {
				t.Fatal("restored history admits activation")
			}
		})
	}
}

func TestSSHActivationAppearingDuringRollbackPreventsMutation(t *testing.T) {
	f, plan, deps, journal := ownedPublicationFixture(t)
	prepared, err := journal.read()
	if err != nil {
		t.Fatal(err)
	}
	before, err := stableSSHRollback(journal, prepared.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	mutations := 0
	ops := sshPublicationDefaults()
	ops.rename = func(int, string, int, string, uint) error { mutations++; return unix.EIO }
	journal.syncDirectory = func(file *os.File) error {
		f.write(sshJournalDirectory+"/"+sshActivationIntentName, "{}")
		return file.Sync()
	}
	if err := rollbackSSHConfiguration(context.Background(), journal, plan.summary.PlanSHA256, deps.run, deps.checkParser, ops); err == nil || mutations != 0 {
		t.Fatal("rollback crossed runtime fence", mutations, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := fixtureJournal(t, f)
	after, err := stableSSHRollback(reopened, prepared.Transaction)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("changed policy despite runtime uncertainty", err)
	}
}

func TestSSHActivationExcludesRestoredRetirement(t *testing.T) {
	f, prepared, owner := restoredRetirementFixture(t)
	f.write(sshJournalDirectory+"/"+sshActivationIntentName, "{}")
	if err := retireRestoredFixture(f, prepared, owner, sshProvisionDefaults()); err == nil {
		t.Fatal("retired possible activation as file-only recovery")
	}
	if _, err := os.Stat(f.path(sshJournalDirectory + "/" + sshActivationIntentName)); err != nil {
		t.Fatal("lost runtime evidence", err)
	}
}

func TestSSHActivationForwardPublicationFence(t *testing.T) {
	f, plan, before, main, drop := preparationFixture(t)
	journal := fixtureJournal(t, f)
	if err := journal.write(fixturePreparation(t, plan, before, main, drop)); err != nil {
		t.Fatal(err)
	}
	if err := journal.requireNoPublicationRecords(); err != nil {
		t.Fatal("fixture is not a fresh preparation", err)
	}
	f.write(sshJournalDirectory+"/"+sshActivationIntentName, "{}")
	if err := journal.requireNoPublicationRecords(); err == nil {
		t.Fatal("publication accepted activation evidence")
	}
}
