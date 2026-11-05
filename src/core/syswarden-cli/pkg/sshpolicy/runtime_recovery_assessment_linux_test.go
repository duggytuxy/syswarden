//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"syswarden-cli/pkg/sshselection"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func recoveryAssessmentFixture(t *testing.T, uncertain bool) (*inventoryFixture, migrationPlan, sshTransactionDependencies, *sshJournal, string) {
	t.Helper()
	f, plan, deps, journal := runtimeRecoveryFixture(t, true, false)
	calls, closes := 0, 0
	bind := runtimeRecoveryBinder(t, journal, &calls, &closes)
	approved := runtimeRecoveryPlan(t, journal, plan, deps, bind)
	if uncertain {
		original := journal.syncDirectory
		journal.syncDirectory = func(file *os.File) error {
			if _, err := os.Lstat(f.path(sshJournalDirectory + "/" + sshRuntimeRecoveryReloadName)); err == nil {
				return unix.EIO // Reload intent is visible, but no request ran.
			}
			return original(file)
		}
	}
	result, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
		deps.run, deps.checkParser, bind, sshPublicationDefaults())
	if (err != nil) != uncertain || !result.ConfigurationRestored || !result.RecoveryRequired ||
		result.RequestReturned != !uncertain || calls != map[bool]int{true: 0, false: 1}[uncertain] {
		t.Fatal("invalid recovery assessment fixture", result, calls, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	return f, plan, deps, fixtureJournal(t, f), approved
}

func TestSSHRecoveryAssessmentPreservesUncertaintyAndHistory(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(fmt.Sprintf("request-not-dispatched-%v", uncertain), func(t *testing.T) {
			f, plan, deps, journal, approved := recoveryAssessmentFixture(t, uncertain)
			prepared, err := journal.read()
			if err != nil {
				t.Fatal(err)
			}
			before, err := stableSSHRollback(journal, prepared.Transaction)
			if err != nil {
				t.Fatal(err)
			}
			records, err := observeSSHRuntimeRecoveryRecords(journal)
			if err != nil {
				t.Fatal(err)
			}
			journal.syncDirectory = func(*os.File) error { t.Fatal("assessment repaired durability"); return unix.EIO }
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			deadline, _ := ctx.Deadline()
			observations := 0
			observe := func(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
				observations++
				if end, ok := ctx.Deadline(); !ok || end.After(deadline) {
					t.Fatal("expanded deadline")
				}
				competing, err := openSSHJournal(f.root, os.Geteuid())
				if err == nil {
					_ = competing.Close()
					t.Fatal("assessment released journal lock")
				}
				return ownedEndpointListener(deps.parserDigest)(ctx, expected, guard)
			}
			for range 2 {
				got, err := assessSSHRuntimeRecovery(ctx, journal, plan.summary.PlanSHA256, approved, deps.parserDigest,
					ownedEndpointParser(deps.run), deps.checkParser, observe)
				if err != nil || got.Schema != 1 || !got.ConfigurationRestored || !got.ParserVerified || !got.ReloadIntentObserved ||
					!got.RecoveryRequired || got.RuntimeActivated || got.AccessVerified || !got.Endpoints.ConfiguredEndpointsMatched ||
					got.Transaction != prepared.Transaction || got.RecoverySHA256 != approved || got.RecordedTargetSHA256 != strings.Repeat("b", 64) {
					t.Fatal("assessment exceeded its evidence", got, err)
				}
				wire, err := json.Marshal(got)
				if err != nil || strings.Contains(string(wire), "192.0.2.") || strings.Contains(string(wire), "AllowTcpForwarding") {
					t.Fatal("private configuration disclosed", err)
				}
				after, err := stableSSHRollback(journal, prepared.Transaction)
				current, recordErr := observeSSHRuntimeRecoveryRecords(journal)
				if errors.Join(err, recordErr) != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(records, current) {
					t.Fatal("assessment changed state", err, recordErr)
				}
			}
			if observations != 2 {
				t.Fatal("assessment cached runtime observation")
			}
			calls, closes := 0, 0
			if _, err := recoverSSHActivatedConfiguration(ctx, journal, plan.summary.PlanSHA256, deps.parserDigest, approved, deps.run, deps.checkParser, runtimeRecoveryBinder(t, journal, &calls, &closes), sshPublicationDefaults()); err == nil || calls != 0 {
				t.Fatal("assessment authorized replay")
			}
			if err := rollbackSSHConfiguration(ctx, journal, plan.summary.PlanSHA256, deps.run, deps.checkParser, sshPublicationDefaults()); err == nil {
				t.Fatal("assessment authorized file-only rollback")
			}
		})
	}
}

func TestSSHRecoveryAssessmentRefusesIncompleteOrChangedHistory(t *testing.T) {
	for _, scenario := range []string{"missing-reload", "missing-intent", "missing-inverse", "extra", "original-replaced", "changed-main", "active-drop-in", "changed-retained", "selection", "wrong-plan", "wrong-recovery", "wrong-parser", "poisoned", "retained", "nil-journal", "reload-schema", "reload-target", "reload-restored", "reload-recovery", "reload-extra", "reload-duplicate", "reload-case", "reload-whitespace", "reload-null", "intent-extra", "intent-duplicate", "intent-null", "reload-symlink", "reload-directory", "reload-hard-link", "reload-fifo"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal, approved := recoveryAssessmentFixture(t, false)
			original := plan.summary.PlanSHA256
			name := sshJournalDirectory + "/" + sshRuntimeRecoveryReloadName
			wire, err := journal.readRecord(sshRuntimeRecoveryReloadName)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "missing-reload":
				err = os.Remove(f.path(name))
			case "missing-intent":
				err = os.Remove(f.path(sshJournalDirectory + "/" + sshRuntimeRecoveryName))
			case "missing-inverse":
				err = os.Remove(f.path(sshJournalDirectory + "/" + sshRuntimeRecoveryPhase(2, true)))
			case "extra":
				f.write(sshJournalDirectory+"/extra.json", "{}")
			case "original-replaced":
				replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshPublicationName(1, true))
			case "changed-main":
				f.write(MainPath, "# administrator changed original\n")
			case "active-drop-in":
				f.write(DropInPath, "AllowTcpForwarding no\n")
			case "changed-retained":
				p, e := journal.read()
				if e != nil {
					t.Fatal(e)
				}
				stage, e := sshDropStagePath(p.Transaction)
				if e != nil {
					t.Fatal(e)
				}
				f.write(stage, "# changed retained policy\n")
			case "selection":
				f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
			case "wrong-plan":
				original = strings.Repeat("c", 64)
			case "wrong-recovery":
				approved = strings.Repeat("d", 64)
			case "wrong-parser":
				deps.parserDigest = strings.Repeat("e", 64)
			case "poisoned":
				journal.poisoned = true
			case "retained":
				journal.retained = &sshRetainedJournal{}
			case "nil-journal":
				journal = nil
			case "reload-extra":
				f.write(name, strings.Replace(string(wire), "{", `{"extra":1,`, 1))
			case "reload-duplicate":
				f.write(name, strings.Replace(string(wire), "{", `{"schema":1,`, 1))
			case "reload-case":
				f.write(name, strings.Replace(string(wire), `"schema"`, `"Schema"`, 1))
			case "reload-whitespace":
				f.write(name, string(wire)+"\n")
			case "reload-null":
				f.write(name, "null")
			case "intent-extra", "intent-duplicate", "intent-null":
				name = sshJournalDirectory + "/" + sshRuntimeRecoveryName
				b, e := journal.readRecord(sshRuntimeRecoveryName)
				if e != nil {
					t.Fatal(e)
				}
				value := strings.Replace(string(b), "{", `{"extra":1,`, 1)
				if scenario == "intent-duplicate" {
					value = strings.Replace(string(b), "{", `{"schema":1,`, 1)
				}
				if scenario == "intent-null" {
					value = "null"
				}
				f.write(name, value)
			case "reload-symlink", "reload-directory", "reload-hard-link", "reload-fifo":
				if e := os.Remove(f.path(name)); e != nil {
					t.Fatal(e)
				}
				switch scenario {
				case "reload-symlink":
					err = os.Symlink(f.path(MainPath), f.path(name))
				case "reload-directory":
					err = os.Mkdir(f.path(name), 0700)
				case "reload-hard-link":
					err = os.Link(f.path(sshJournalDirectory+"/"+sshPreparedRecord), f.path(name))
				case "reload-fifo":
					err = unix.Mkfifo(f.path(name), 0600)
				}
			default:
				var r sshRuntimeRecoveryReload
				if e := json.Unmarshal(wire, &r); e != nil {
					t.Fatal(e)
				}
				switch scenario {
				case "reload-schema":
					r.Schema = 2
				case "reload-target":
					r.Target = strings.Repeat("f", 64)
				case "reload-restored":
					r.Restored = strings.Repeat("f", 64)
				case "reload-recovery":
					r.Recovery = strings.Repeat("f", 64)
				}
				b, e := json.Marshal(r)
				if e != nil {
					t.Fatal(e)
				}
				f.write(name, string(b))
			}
			if err != nil {
				t.Fatal(err)
			}
			observe := func(context.Context, []netip.AddrPort, func() error) (ListenerSummary, error) {
				t.Fatal("invalid history reached live observation")
				return ListenerSummary{}, nil
			}
			got, err := assessSSHRuntimeRecovery(t.Context(), journal, original, approved, deps.parserDigest, ownedEndpointParser(deps.run), deps.checkParser, observe)
			if err == nil || !reflect.DeepEqual(got, RecoveryAssessment{}) {
				t.Fatal("invalid history accepted", got, err)
			}
		})
	}
}

func TestSSHRecoveryAssessmentRejectsObservationDrift(t *testing.T) {
	for _, scenario := range []string{"same-byte-reload", "original-record", "phase", "main", "retained", "selection", "owner", "extra", "parser", "cancel", "observer-error", "false-proof", "manager-proof"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal, approved := recoveryAssessmentFixture(t, false)
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
				case "same-byte-reload":
					replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshRuntimeRecoveryReloadName)
				case "original-record":
					replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshActivationIntentName)
				case "phase":
					replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshRuntimeRecoveryPhase(2, true))
				case "main":
					f.write(MainPath, "# changed\n")
				case "retained":
					p, e := journal.read()
					if e != nil {
						t.Fatal(e)
					}
					stage, e := sshDropStagePath(p.Transaction)
					if e != nil {
						t.Fatal(e)
					}
					f.write(stage, "# changed\n")
				case "selection":
					f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
				case "owner":
					f.write(sshStateParent+"/"+sshOwnerName, "{}")
				case "extra":
					f.write(sshJournalDirectory+"/extra.json", "{}")
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
			got, err := assessSSHRuntimeRecovery(ctx, journal, plan.summary.PlanSHA256, approved, deps.parserDigest, ownedEndpointParser(deps.run), check, observe)
			if !changed || err == nil || !reflect.DeepEqual(got, RecoveryAssessment{}) {
				t.Fatal("drift accepted", got, err)
			}
		})
	}
}

func TestSSHRecoveryAssessmentSessionAndInputBoundaries(t *testing.T) {
	good := strings.Repeat("a", 64)
	for _, scenario := range []string{"nil-context", "cancelled", "bad-plan", "bad-recovery", "nil-opener", "nil-observer"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var input context.Context = ctx
			original, recovery := good, good
			open := func(context.Context) (*sshRecoverySession, error) {
				t.Fatal("invalid input opened resources")
				return nil, nil
			}
			observe := ownedEndpointListener(good)
			switch scenario {
			case "nil-context":
				input = nil
			case "cancelled":
				cancel()
			case "bad-plan":
				original = ""
			case "bad-recovery":
				recovery = strings.ToUpper(good)
			case "nil-opener":
				open = nil
			case "nil-observer":
				observe = nil
			}
			got, err := assessSSHRecoverySession(input, original, recovery, open, observe)
			if err == nil || !reflect.DeepEqual(got, RecoveryAssessment{}) {
				t.Fatal(got, err)
			}
		})
	}
	for _, scenario := range []string{"success", "close-error", "open-error", "nil-session", "missing-close", "parser-failure", "nil-runner", "nil-check"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal, approved := recoveryAssessmentFixture(t, false)
			closes := 0
			open := func(ctx context.Context) (*sshRecoverySession, error) {
				if ctx != t.Context() {
					t.Fatal("lost caller context")
				}
				s := &sshRecoverySession{journal: journal, parser: deps.parserDigest, run: ownedEndpointParser(deps.run), check: deps.checkParser,
					bind: func(context.Context, func() error, *sshRecoveryPolicyAnchor) (sshActivationLease, error) {
						t.Fatal("assessment acquired mutation lease")
						return nil, nil
					},
					close: func() error {
						closes++
						err := journal.Close()
						if scenario == "close-error" {
							return errors.Join(err, unix.EIO)
						}
						return err
					}}
				switch scenario {
				case "open-error":
					return s, unix.EIO
				case "nil-session":
					return nil, nil
				case "missing-close":
					s.close = nil
				case "parser-failure":
					s.check = func() error { return unix.EIO }
				case "nil-runner":
					s.run = nil
				case "nil-check":
					s.check = nil
				}
				return s, nil
			}
			got, err := assessSSHRecoverySession(t.Context(), plan.summary.PlanSHA256, approved, open, ownedEndpointListener(deps.parserDigest))
			if (err == nil) != (scenario == "success") {
				t.Fatal(got, err)
			}
			if err != nil && !reflect.DeepEqual(got, RecoveryAssessment{}) {
				t.Fatal("partial assessment escaped", got, err)
			}
			want := 1
			if scenario == "nil-session" || scenario == "missing-close" {
				want = 0
			}
			if closes != want {
				t.Fatal("lost resource ownership", closes)
			}
			if want == 1 {
				reopened := fixtureJournal(t, f)
				if e := reopened.Close(); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
	if _, err := AssessSystemdRecovery(t.Context(), good, ""); err == nil {
		t.Fatal("missing recovery approval accepted")
	}
	if os.Geteuid() != 0 {
		if _, err := AssessSystemdRecovery(t.Context(), good, good); err == nil {
			t.Fatal("non-root assessment accepted")
		}
	}
}
