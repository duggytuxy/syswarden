//go:build linux

package sshpolicy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// An isolated child supplies real old/new address-space handles. Socket images
// remain explicit test fixtures; this helper never signals an SSH daemon.
func restoringReloadObservationFixture(t *testing.T) *sshRestoringReloadObservation {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestSSHExecMemoryFixtureChild$")
	command.Env = []string{"SYSWARDEN_EXEC_MEMORY_CHILD=before", "GOMAXPROCS=2"}
	stdin, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		cancel()
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = command.Wait(); cancel() })
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || line != "before\n" {
		t.Fatal("fixture did not start", err)
	}
	proc, err := os.Open(fmt.Sprintf("/proc/%d", command.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proc.Close() })
	memory, err := pinSSHExecMemory(proc, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	execution := &sshExecReload{before: memory, open: func() (*sshExecMemory, error) { return pinSSHExecMemory(proc, os.Geteuid()) }}
	t.Cleanup(func() { _ = execution.Close() })
	if _, err := stdin.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "after\n" {
		t.Fatal("fixture did not exec", err)
	}
	if err := execution.observe(ctx, func() error { return ctx.Err() }); err != nil {
		t.Fatal(err)
	}
	listeners, sockets := sshReloadListenerFixture(t)
	listeners.read = func(context.Context) ([]sshListenerSocket, error) { return slices.Clone(sockets), nil }
	return &sshRestoringReloadObservation{target: strings.Repeat("b", 64), processSummary: strings.Repeat("d", 64),
		listeners: listeners, execution: execution, after: slices.Clone(sockets)}
}

func observedRecoveryBinder(t *testing.T, observation *sshRestoringReloadObservation, calls *int) sshRecoveryBind {
	t.Helper()
	return func(ctx context.Context, guard func() error, _ *sshRecoveryPolicyAnchor) (sshActivationLease, error) {
		if err := errors.Join(ctx.Err(), guard()); err != nil {
			return nil, err
		}
		lease := &sshActivationTarget{ctx: ctx, target: observation.target,
			verify: func(context.Context) error { return nil }, send: func() error { *calls++; return nil }, closeFn: func() error { return nil }}
		lease.after = func(ctx context.Context, guard func() error) error {
			if err := observation.recheck(ctx, guard); err != nil {
				return err
			}
			lease.observation = observation // Explicit private test capability.
			return nil
		}
		return lease, nil
	}
}

func TestSSHRuntimeRecoveryObservationDurableBindingsAndNoReplay(t *testing.T) {
	f, plan, deps, journal := runtimeRecoveryFixture(t, true, false)
	observation := restoringReloadObservationFixture(t)
	calls := 0
	bind := observedRecoveryBinder(t, observation, &calls)
	approved := runtimeRecoveryPlan(t, journal, plan, deps, bind)
	before, err := observeSSHRuntimeRecoveryRecords(journal)
	if err != nil {
		t.Fatal(err)
	}
	result, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
		deps.run, deps.checkParser, bind, sshPublicationDefaults())
	if err != nil || !result.RequestReturned || !result.ReloadObservationDurable || !result.RecoveryRequired || calls != 1 ||
		!lowerDigest.MatchString(result.ReloadObservationSHA256) || !lowerDigest.MatchString(result.ReloadObservationImageSHA256) {
		t.Fatal("durable observation failed", result, calls, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal = fixtureJournal(t, f)
	records, err := observeSSHRuntimeRecoveryRecords(journal)
	if err != nil || len(records) != len(before)+7 {
		t.Fatal("invalid new-purpose history", err)
	}
	for name, digest := range before {
		if records[name] != digest {
			t.Fatal("original history changed", name)
		}
	}
	intentWire, err := journal.readRecord(sshRuntimeRecoveryName)
	if err != nil {
		t.Fatal(err)
	}
	var intent sshRuntimeRecoveryIntent
	if err := json.Unmarshal(intentWire, &intent); err != nil {
		t.Fatal(err)
	}
	reloadWire, err := journal.readRecord(sshRuntimeRecoveryReloadName)
	if err != nil {
		t.Fatal(err)
	}
	var reload sshRuntimeRecoveryReload
	if err := json.Unmarshal(reloadWire, &reload); err != nil {
		t.Fatal(err)
	}
	journal.syncDirectory = func(*os.File) error { t.Fatal("reader repaired durability"); return unix.EIO }
	record, image, err := readSSHRuntimeRecoveryObservation(journal, intent, approved, reload.Restored, reloadWire)
	wantSockets, socketErr := sshActivationDigest(observation.after)
	if err != nil || socketErr != nil || image == nil || record.AfterSocketsSHA256 != wantSockets ||
		record.ProcessSummarySHA256 != observation.processSummary || record.Parser != deps.parserDigest ||
		digestBytes(image.data) != result.ReloadObservationSHA256 || sshImageDigest(*image) != result.ReloadObservationImageSHA256 {
		t.Fatal("observation binding failed", record, err, socketErr)
	}
	if restoredSSHRecordName(sshRuntimeRecoveryObservationName) {
		t.Fatal("runtime observation gained file-only retirement authority")
	}
	_, err = recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
		deps.run, deps.checkParser, bind, sshPublicationDefaults())
	after, readErr := observeSSHRuntimeRecoveryRecords(journal)
	if err == nil || readErr != nil || calls != 1 || !reflect.DeepEqual(records, after) {
		t.Fatal("recorded observation allowed replay or changed history", err, readErr)
	}
	if err := os.Remove(f.path(sshJournalDirectory + "/" + sshRuntimeRecoveryReloadName)); err != nil {
		t.Fatal(err)
	}
	_, err = recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
		deps.run, deps.checkParser, bind, sshPublicationDefaults())
	if err == nil || calls != 1 {
		t.Fatal("orphaned observation allowed replay", err)
	}
}

func TestSSHRuntimeRecoveryObservationPublicationFailureRetainsFence(t *testing.T) {
	for _, scenario := range []string{"directory-sync", "late-runtime-drift", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal := runtimeRecoveryFixture(t, false, false)
			observation := restoringReloadObservationFixture(t)
			calls := 0
			bind := observedRecoveryBinder(t, observation, &calls)
			approved := runtimeRecoveryPlan(t, journal, plan, deps, bind)
			journal.syncDirectory = func(file *os.File) error {
				if _, err := os.Lstat(f.path(sshJournalDirectory + "/" + sshRuntimeRecoveryObservationName)); err == nil {
					switch scenario {
					case "directory-sync":
						return unix.EIO
					case "late-runtime-drift":
						observation.after[0].Cookie++
					case "replacement":
						replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshRuntimeRecoveryObservationName)
					}
				}
				return file.Sync()
			}
			result, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
				deps.run, deps.checkParser, bind, sshPublicationDefaults())
			if err == nil || !result.RequestReturned || result.ReloadObservationDurable || !result.RecoveryRequired || calls != 1 || !journal.poisoned {
				t.Fatal("publication failure concealed", result, err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			journal = fixtureJournal(t, f)
			before, err := observeSSHRuntimeRecoveryRecords(journal)
			if err != nil || before[sshRuntimeRecoveryReloadName] == "" || before[sshRuntimeRecoveryObservationName] == "" {
				t.Fatal("uncertain records were lost", err)
			}
			_, err = recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
				deps.run, deps.checkParser, bind, sshPublicationDefaults())
			after, readErr := observeSSHRuntimeRecoveryRecords(journal)
			if err == nil || readErr != nil || calls != 1 || !reflect.DeepEqual(before, after) {
				t.Fatal("failed observation allowed replay", err, readErr)
			}
		})
	}
}

func TestSSHRuntimeRecoveryObservationReaderRejectsInvalidBindings(t *testing.T) {
	for _, scenario := range []string{"schema", "purpose", "method", "transaction", "plan", "recovery", "reload", "reload-image", "restored", "parser", "target", "process", "before", "after", "same-generation", "unknown-field", "noncanonical", "reload-replacement"} {
		t.Run(scenario, func(t *testing.T) {
			f, _, _, journal, approved := recoveryAssessmentFixture(t, false)
			intentWire, err := journal.readRecord(sshRuntimeRecoveryName)
			if err != nil {
				t.Fatal(err)
			}
			var intent sshRuntimeRecoveryIntent
			if err := json.Unmarshal(intentWire, &intent); err != nil {
				t.Fatal(err)
			}
			reloadImage, err := readSSHPrivateChild(journal.directory, sshRuntimeRecoveryReloadName, journal.uid, maxSSHJournalBytes)
			if err != nil {
				t.Fatal(err)
			}
			var reload sshRuntimeRecoveryReload
			if err := json.Unmarshal(reloadImage.data, &reload); err != nil {
				t.Fatal(err)
			}
			record, image, err := readSSHRuntimeRecoveryObservation(journal, intent, approved, reload.Restored, reloadImage.data)
			if err != nil || image != nil || record != (sshRuntimeRecoveryObservation{}) {
				t.Fatal("legacy successful return fabricated observation", err)
			}
			record = sshRuntimeRecoveryObservation{Schema: 1, Purpose: sshRuntimeRecoveryObservationPurpose,
				Transaction: intent.Transaction, Plan: intent.Plan, Recovery: approved,
				ReloadIntent: digestBytes(reloadImage.data), ReloadIntentImage: sshImageDigest(reloadImage), Restored: reload.Restored,
				Parser: intent.Parser, Target: intent.Target, Method: sshRuntimeRecoveryObservationMethod,
				ProcessSummarySHA256: strings.Repeat("a", 64), BeforeSocketsSHA256: strings.Repeat("b", 64), AfterSocketsSHA256: strings.Repeat("c", 64)}
			switch scenario {
			case "schema":
				record.Schema++
			case "purpose":
				record.Purpose = "other"
			case "method":
				record.Method = "authentication-only"
			case "transaction":
				record.Transaction = strings.Repeat("0", 64)
			case "plan":
				record.Plan = strings.Repeat("0", 64)
			case "recovery":
				record.Recovery = strings.Repeat("0", 64)
			case "reload":
				record.ReloadIntent = strings.Repeat("0", 64)
			case "reload-image":
				record.ReloadIntentImage = strings.Repeat("0", 64)
			case "restored":
				record.Restored = strings.Repeat("0", 64)
			case "parser":
				record.Parser = strings.Repeat("0", 64)
			case "target":
				record.Target = strings.Repeat("0", 64)
			case "process":
				record.ProcessSummarySHA256 = "invalid"
			case "before":
				record.BeforeSocketsSHA256 = "invalid"
			case "after":
				record.AfterSocketsSHA256 = "invalid"
			case "same-generation":
				record.AfterSocketsSHA256 = record.BeforeSocketsSHA256
			}
			wire, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "noncanonical" {
				wire = append(wire, '\n')
			}
			if scenario == "unknown-field" {
				wire = bytes.Replace(wire, []byte("{"), []byte(`{"caller_success":true,`), 1)
			}
			if err := journal.writeRecord(sshRuntimeRecoveryObservationName, wire); err != nil {
				t.Fatal(err)
			}
			if scenario == "reload-replacement" {
				replaceRestoredFixtureRecord(t, f, sshJournalDirectory+"/"+sshRuntimeRecoveryReloadName)
			}
			if _, image, err := readSSHRuntimeRecoveryObservation(journal, intent, approved, reload.Restored, reloadImage.data); err == nil || image != nil {
				t.Fatal("invalid observation accepted", scenario, err)
			}
		})
	}
}

func TestSSHRestoringReloadCapabilityRequiresKernelObservations(t *testing.T) {
	observation := restoringReloadObservationFixture(t)
	guard := func() error { return nil }
	if err := observation.recheck(t.Context(), guard); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"missing-exec", "unretired", "old-listeners", "changed-generation", "canceled", "guard"} {
		t.Run(scenario, func(t *testing.T) {
			copy := *observation
			copy.after = slices.Clone(observation.after)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			check := guard
			switch scenario {
			case "missing-exec":
				copy.execution = nil
			case "unretired":
				copy.execution = &sshExecReload{before: observation.execution.after, after: observation.execution.after}
			case "old-listeners":
				copy.after = slices.Clone(observation.listeners.before)
			case "changed-generation":
				copy.after[0].Cookie++
			case "canceled":
				cancel()
			case "guard":
				check = func() error { return unix.EIO }
			}
			if err := copy.recheck(ctx, check); err == nil {
				t.Fatal("incomplete observation accepted")
			}
		})
	}
	lease := &sshActivationTarget{ctx: t.Context(), target: observation.target, observation: observation}
	if _, err := lease.restoringReloadObservation(t.Context(), guard); err == nil {
		t.Fatal("unattempted lease yielded observation")
	}
	lease.attempted = true
	lease.target = strings.Repeat("e", 64)
	if _, err := lease.restoringReloadObservation(t.Context(), guard); err == nil {
		t.Fatal("changed target yielded observation")
	}
	lease.target = observation.target
	lease.closed = true
	if _, err := lease.restoringReloadObservation(t.Context(), guard); err == nil {
		t.Fatal("closed lease yielded observation")
	}
}

func TestSSHRestoringReloadCapabilityClearedAfterRequestFailure(t *testing.T) {
	for _, scenario := range []string{"after-error", "final-guard", "cancel-after-observation"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			afterRan := false
			guard := func() error {
				if afterRan && scenario == "final-guard" {
					return unix.EIO
				}
				return nil
			}
			lease := &sshActivationTarget{ctx: ctx, target: strings.Repeat("b", 64),
				verify: func(context.Context) error { return nil }, send: func() error { return nil }, closeFn: func() error { return nil }}
			lease.after = func(context.Context, func() error) error {
				afterRan = true
				lease.observation = &sshRestoringReloadObservation{} // Sentinel, never a usable capability.
				if scenario == "after-error" {
					return unix.EIO
				}
				if scenario == "cancel-after-observation" {
					cancel()
				}
				return nil
			}
			if err := lease.request(ctx, guard); err == nil || !lease.attempted || lease.observation != nil {
				t.Fatal("failed request retained its provisional capability", err)
			}
			if err := lease.request(t.Context(), func() error { return nil }); err == nil {
				t.Fatal("failed request replayed")
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
