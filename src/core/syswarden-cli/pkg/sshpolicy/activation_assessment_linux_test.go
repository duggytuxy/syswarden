//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"syswarden-cli/pkg/sshselection"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func activationAssessmentFixture(t *testing.T, uncertainSync bool) (*inventoryFixture, migrationPlan, sshTransactionDependencies, *sshJournal) {
	t.Helper()
	f, plan, deps, journal := ownedPublicationFixture(t)
	calls, closed := 0, 0
	if uncertainSync {
		journal.syncDirectory = func(*os.File) error { return unix.EIO }
	}
	result, err := attemptSSHActivation(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest,
		deps.run, deps.checkParser, activationTestBinder(t, journal, &calls, &closed))
	if (err != nil) != uncertainSync || !result.RecoveryRequired || closed != 1 ||
		(!uncertainSync && calls != 1) || (uncertainSync && calls != 0) {
		t.Fatal("invalid activation fixture", result, calls, closed, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	return f, plan, deps, fixtureJournal(t, f)
}

func TestSSHActivationAssessmentPreservesUncertainty(t *testing.T) {
	for _, uncertainSync := range []bool{false, true} {
		t.Run(map[bool]string{false: "returned-request", true: "unacknowledged-sync"}[uncertainSync], func(t *testing.T) {
			f, plan, deps, journal := activationAssessmentFixture(t, uncertainSync)
			prepared, err := journal.read()
			if err != nil {
				t.Fatal(err)
			}
			before, err := stableSSHRollback(journal, prepared.Transaction)
			if err != nil {
				t.Fatal(err)
			}
			records, err := observeSSHOwnedRecordSet(journal, true)
			if err != nil {
				t.Fatal(err)
			}
			journal.syncDirectory = func(*os.File) error { t.Fatal("assessment repaired durability"); return unix.EIO }
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			deadline, _ := ctx.Deadline()
			calls := 0
			observe := func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
				calls++
				if end, ok := ctx.Deadline(); !ok || end.After(deadline) {
					t.Fatal("assessment expanded deadline")
				}
				other, err := openSSHJournal(f.root, os.Geteuid())
				if err == nil {
					_ = other.Close()
					t.Fatal("assessment released its journal lock")
				}
				return ownedEndpointListener(deps.parserDigest)(ctx, expected, guard)
			}
			for range 2 {
				got, err := assessSSHActivation(ctx, journal, plan.summary.PlanSHA256, deps.parserDigest,
					ownedEndpointParser(deps.run), deps.checkParser, observe)
				if err != nil || !got.RecoveryRequired || !got.IntentObserved || !got.Publication.OwnershipVerified ||
					!got.Publication.ParserVerified || !got.Endpoints.ConfiguredEndpointsMatched || got.Publication.RuntimeActivated ||
					got.Publication.AccessVerified || got.TargetSHA256 != strings.Repeat("a", 64) ||
					got.Publication.PlanSHA256 != plan.summary.PlanSHA256 || got.Publication.Transaction != prepared.Transaction {
					t.Fatal("assessment lost evidence boundary", got, err)
				}
				wire, err := json.Marshal(got)
				if err != nil || strings.Contains(string(wire), "192.0.2.") || strings.Contains(string(wire), "AllowTcpForwarding") {
					t.Fatal("summary disclosed configuration", err)
				}
				after, err := stableSSHRollback(journal, prepared.Transaction)
				current, recordErr := observeSSHOwnedRecordSet(journal, true)
				if err != nil || recordErr != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, current) {
					t.Fatal("assessment changed protected state", err, recordErr)
				}
			}
			if calls != 2 {
				t.Fatal("assessment reused runtime observations")
			}
			if _, err := verifySSHOwnedPublication(ctx, journal, plan.summary.PlanSHA256, deps.parserDigest, deps.run, deps.checkParser); err == nil {
				t.Fatal("assessment bypassed publication-only verification")
			}
			if err := rollbackSSHConfiguration(ctx, journal, plan.summary.PlanSHA256, deps.run, deps.checkParser, sshPublicationDefaults()); err == nil {
				t.Fatal("assessment authorized file-only rollback")
			}
			attempts, closed := 0, 0
			if _, err := attemptSSHActivation(ctx, journal, plan.summary.PlanSHA256, deps.parserDigest, deps.run, deps.checkParser,
				activationTestBinder(t, journal, &attempts, &closed)); err == nil || attempts != 0 {
				t.Fatal("assessment authorized replay")
			}
		})
	}
}

func TestSSHActivationAssessmentRejectsInvalidHistory(t *testing.T) {
	scenarios := []string{"missing-intent", "unknown-record", "missing-phase", "rollback", "malformed", "oversized", "unknown-field", "duplicate-field", "case-folded", "noncanonical", "null", "schema", "transaction", "prepared", "plan", "parser", "publication", "records", "target", "record-replacement", "mode", "symlink", "directory", "fifo", "hard-link", "changed-main", "changed-policy", "changed-original", "disabled-selection", "wrong-approval", "wrong-parser", "poisoned", "retained", "nil-journal"}
	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal := activationAssessmentFixture(t, false)
			name := sshJournalDirectory + "/" + sshActivationIntentName
			wire, err := journal.readRecord(sshActivationIntentName)
			if err != nil {
				t.Fatal(err)
			}
			var intent sshActivationIntent
			if err := json.Unmarshal(wire, &intent); err != nil {
				t.Fatal(err)
			}
			approved := plan.summary.PlanSHA256
			switch scenario {
			case "missing-intent":
				err = os.Remove(f.path(name))
			case "unknown-record":
				f.write(sshJournalDirectory+"/extra.json", "{}")
			case "missing-phase":
				err = os.Remove(f.path(sshJournalDirectory + "/" + sshPublicationName(2, true)))
			case "rollback":
				f.write(sshJournalDirectory+"/"+sshRollbackStartName, "{}")
			case "malformed":
				f.write(name, "{")
			case "oversized":
				f.write(name, strings.Repeat(" ", 2049))
			case "unknown-field":
				f.write(name, strings.Replace(string(wire), "{", `{"extra":1,`, 1))
			case "duplicate-field":
				f.write(name, strings.Replace(string(wire), "{", `{"schema":1,`, 1))
			case "case-folded":
				f.write(name, strings.Replace(string(wire), `"schema"`, `"Schema"`, 1))
			case "noncanonical":
				f.write(name, string(wire)+"\n")
			case "null":
				f.write(name, "null")
			case "record-replacement":
				replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshPublicationName(1, true))
			case "mode":
				err = os.Chmod(f.path(name), 0644) // #nosec G302 -- Deliberately unsafe fixture permissions; assessment must reject this record. Production permissions are unchanged.
			case "symlink", "directory", "fifo", "hard-link":
				if err = os.Remove(f.path(name)); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "symlink":
					err = os.Symlink(f.path(MainPath), f.path(name))
				case "directory":
					err = os.Mkdir(f.path(name), 0700)
				case "fifo":
					err = unix.Mkfifo(f.path(name), 0600)
				case "hard-link":
					err = os.Link(f.path(sshJournalDirectory+"/"+sshPreparedRecord), f.path(name))
				}
			case "changed-main":
				f.write(MainPath, includeDropIns+"PasswordAuthentication yes\n")
			case "changed-policy":
				f.write(DropInPath, "AllowTcpForwarding yes\n")
			case "changed-original":
				stage, stageErr := sshMainStagePath(intent.Transaction)
				if stageErr != nil {
					t.Fatal(stageErr)
				}
				f.write(stage, "# changed original\n")
			case "disabled-selection":
				f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
			case "wrong-approval":
				approved = strings.Repeat("b", 64)
			case "wrong-parser":
				deps.parserDigest = strings.Repeat("c", 64)
			case "poisoned":
				journal.poisoned = true
			case "retained":
				journal.retained = &sshRetainedJournal{}
			case "nil-journal":
				journal = nil
			default:
				wrong := strings.Repeat("d", 64)
				switch scenario {
				case "schema":
					intent.Schema = 2
				case "transaction":
					intent.Transaction = wrong
				case "prepared":
					intent.Prepared = wrong
				case "plan":
					intent.Plan = wrong
				case "parser":
					intent.Parser = wrong
				case "publication":
					intent.Publication = wrong
				case "records":
					intent.Records = wrong
				case "target":
					intent.Target = "invalid"
				}
				changed, marshalErr := json.Marshal(intent)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				f.write(name, string(changed))
			}
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			observe := func(context.Context, []netip.AddrPort, func() error) (ListenerSummary, error) {
				calls++
				return ListenerSummary{}, nil
			}
			got, err := assessSSHActivation(t.Context(), journal, approved, deps.parserDigest, ownedEndpointParser(deps.run), deps.checkParser, observe)
			if err == nil || calls != 0 || !reflect.DeepEqual(got, ActivationAssessment{}) {
				t.Fatal("invalid history reached runtime", got, calls, err)
			}
		})
	}
}

func TestSSHActivationAssessmentRejectsRuntimeDrift(t *testing.T) {
	for _, scenario := range []string{"intent", "same-byte-intent", "old-record", "unknown-record", "owner", "policy", "selection", "parser", "cancel", "observer-error", "false-proof", "manager-proof"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal := activationAssessmentFixture(t, false)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			changed := false
			check := func() error {
				if changed && scenario == "parser" {
					return ErrInventoryChanged
				}
				return nil
			}
			observe := func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
				got, err := ownedEndpointListener(deps.parserDigest)(ctx, expected, guard)
				if err != nil {
					t.Fatal(err)
				}
				changed = true
				switch scenario {
				case "intent":
					f.write(sshJournalDirectory+"/"+sshActivationIntentName, "{}")
				case "same-byte-intent":
					replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshActivationIntentName)
				case "old-record":
					replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshPublicationName(3, true))
				case "unknown-record":
					f.write(sshJournalDirectory+"/extra.json", "{}")
				case "owner":
					f.write(sshStateParent+"/"+sshOwnerName, "{}")
				case "policy":
					f.write(DropInPath, "AllowTcpForwarding yes\n")
				case "selection":
					f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
				case "cancel":
					cancel()
				case "observer-error":
					return got, unix.EIO
				case "false-proof":
					got.Process.AccessVerified = true
				case "manager-proof":
					got.Process.Manager.RuntimeActivated = true
				}
				return got, nil
			}
			got, err := assessSSHActivation(ctx, journal, plan.summary.PlanSHA256, deps.parserDigest, ownedEndpointParser(deps.run), check, observe)
			if !changed || err == nil || !reflect.DeepEqual(got, ActivationAssessment{}) {
				t.Fatal("accepted drift or partial result", got, err)
			}
		})
	}
}

func TestSSHActivationAssessmentFailsClosedBeforeObservation(t *testing.T) {
	for _, scenario := range []string{"nil-context", "cancelled", "nil-runner", "nil-check", "nil-observer", "parser-error", "parser-drift", "drift-during-parser"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal := activationAssessmentFixture(t, false)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var input context.Context = ctx
			calls := 0
			var observe sshEndpointObserver = func(context.Context, []netip.AddrPort, func() error) (ListenerSummary, error) {
				calls++
				return ListenerSummary{}, nil
			}
			switch scenario {
			case "nil-context":
				input = nil
			case "cancelled":
				cancel()
			case "nil-runner":
				deps.run = nil
			case "nil-check":
				deps.checkParser = nil
			case "nil-observer":
				observe = nil
			case "parser-error":
				deps.run = func(context.Context, *parserImage, string, string) ([]byte, error) { return nil, unix.EIO }
			case "parser-drift":
				deps.checkParser = func() error { return unix.EIO }
			case "drift-during-parser":
				original := deps.run
				deps.run = func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
					f.write(sshJournalDirectory+"/"+sshActivationIntentName, "{}")
					return original(ctx, image, mode, access)
				}
			}
			got, err := assessSSHActivation(input, journal, plan.summary.PlanSHA256, deps.parserDigest, deps.run, deps.checkParser, observe)
			if err == nil || calls != 0 || !reflect.DeepEqual(got, ActivationAssessment{}) {
				t.Fatal(got, calls, err)
			}
		})
	}
}

func TestSSHActivationAssessmentProductionRequiresApproval(t *testing.T) {
	for _, approved := range []string{"", "invalid", strings.Repeat("A", 64)} {
		if got, err := AssessSystemdActivation(approved); err == nil || !reflect.DeepEqual(got, ActivationAssessment{}) {
			t.Fatal(got, err)
		}
	}
	if os.Geteuid() != 0 {
		if got, err := AssessSystemdActivation(strings.Repeat("a", 64)); err == nil || !reflect.DeepEqual(got, ActivationAssessment{}) {
			t.Fatal(got, err)
		}
	}
}
