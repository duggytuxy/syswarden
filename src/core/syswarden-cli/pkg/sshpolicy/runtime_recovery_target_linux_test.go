//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func recoveryTargetFixture(t *testing.T, startup StartupSummary, parser, selection string, values sshEffective) string {
	t.Helper()
	endpoints, err := sshExpectedEndpoints(values)
	if err != nil {
		t.Fatal(err)
	}
	process := ProcessSummary{Schema: 1, Startup: &startup, IdentitySHA256: strings.Repeat("c", 64),
		ExecutableSHA256: parser, ProcessObserved: true, ExecutableVerified: true}
	// Preserve the existing production v4 encoding, including startup, parser,
	// process identity, expected endpoints, namespace and socket generation.
	target, err := sshActivationDigest([]any{"systemd-pidfd-sighup-exec-listeners-v4", process,
		selection, endpoints, uint64(7), []sshListenerSocket{sshListenerFixture(3, 33)}})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestSSHRecoveryPolicyAnchorPreservesV1SelectionAndV4Target(t *testing.T) {
	startup := StartupSummary{Schema: 1, DeclarationVerified: true, CommandSHA256: strings.Repeat("a", 64)}
	parser := strings.Repeat("b", 64)
	published := sshEffective{"port": {"2222"}, "addressfamily": {"inet"}, "listenaddress": {"192.0.2.1:2222"}, "allowtcpforwarding": {"no"}}
	current := maps.Clone(published)
	current["allowtcpforwarding"] = []string{"yes"}
	oldSelection, err := sshActivationDigest([]any{"ssh-configuration-selection-v1", parser, startup, MainPath, published})
	if err != nil {
		t.Fatal(err)
	}
	oldTarget := recoveryTargetFixture(t, startup, parser, oldSelection, published)
	for _, phase := range []sshEffective{published, current} {
		anchor := &sshRecoveryPolicyAnchor{parser, published, phase}
		selection, err := anchor.selection(startup, parser, phase)
		if err != nil || selection != oldSelection || recoveryTargetFixture(t, startup, parser, selection, phase) != oldTarget {
			t.Fatal("validated inverse phase changed the existing selection or target identity", err)
		}
	}
	legacyCurrent, err := sshActivationDigest([]any{"ssh-configuration-selection-v1", parser, startup, MainPath, current})
	if err != nil || recoveryTargetFixture(t, startup, parser, legacyCurrent, current) == oldTarget {
		t.Fatal("fixture does not expose the former policy-dependent target drift", err)
	}
	for _, scenario := range []string{"parser", "startup-command", "startup-environment", "startup-unverified", "endpoint", "current-value"} {
		t.Run(scenario, func(t *testing.T) {
			anchor := &sshRecoveryPolicyAnchor{parser, published, current}
			changedStartup, changedParser, actual := startup, parser, maps.Clone(current)
			switch scenario {
			case "parser":
				changedParser = strings.Repeat("d", 64)
			case "startup-command":
				changedStartup.CommandSHA256 = strings.Repeat("e", 64)
			case "startup-environment":
				changedStartup.EnvironmentSHA256 = strings.Repeat("f", 64)
			case "startup-unverified":
				changedStartup.DeclarationVerified = false
			case "endpoint":
				actual["listenaddress"] = []string{"192.0.2.2:2222"}
				anchor.current = actual // Even a purported inverse cannot change endpoints.
			case "current-value":
				actual["allowtcpforwarding"] = []string{"no"}
			}
			selection, err := anchor.selection(changedStartup, changedParser, actual)
			if scenario == "startup-command" || scenario == "startup-environment" {
				if err != nil || recoveryTargetFixture(t, changedStartup, changedParser, selection, actual) == oldTarget {
					t.Fatal("changed startup could retain the saved recovery authority", err)
				}
			} else if err == nil || selection != "" {
				t.Fatal("unverified parser, endpoint or current policy accepted", err)
			}
		})
	}
}

func TestSSHRuntimeRecoveryReopenPreservesPolicyBoundTarget(t *testing.T) {
	for failAt := 1; failAt <= 2; failAt++ {
		t.Run(fmt.Sprintf("inverse-rename-%d", failAt), func(t *testing.T) {
			f, plan, deps, journal := runtimeRecoveryFixture(t, true, false)
			deps.run = ownedEndpointParser(deps.run)
			startup := StartupSummary{Schema: 1, DeclarationVerified: true, CommandSHA256: strings.Repeat("a", 64)}
			calls, closes := 0, 0
			legacy := false
			bind := func(ctx context.Context, guard func() error, anchor *sshRecoveryPolicyAnchor) (sshActivationLease, error) {
				wire, err := deps.run(ctx, nil, "effective", "")
				if err != nil {
					return nil, err
				}
				actual, err := parseEffective(wire)
				if err != nil {
					return nil, err
				}
				selection, err := anchor.selection(startup, deps.parserDigest, actual)
				if legacy {
					selection, err = sshActivationDigest([]any{"ssh-configuration-selection-v1", deps.parserDigest, startup, MainPath, actual})
				}
				if err != nil {
					return nil, err
				}
				lease, err := runtimeRecoveryBinder(t, journal, &calls, &closes)(ctx, guard, anchor)
				if err == nil {
					lease.(*activationTestLease).target = recoveryTargetFixture(t, startup, deps.parserDigest, selection, actual)
				}
				return lease, err
			}
			approved := runtimeRecoveryPlan(t, journal, plan, deps, bind)
			ops := sshPublicationDefaults()
			renames := 0
			ops.rename = func(a int, b string, c int, d string, flags uint) error {
				if err := unix.Renameat2(a, b, c, d, flags); err != nil {
					return err
				}
				renames++
				if renames == failAt {
					return unix.EIO
				}
				return nil
			}
			partial, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
				deps.run, deps.checkParser, bind, ops)
			if !errors.Is(err, unix.EIO) || renames != failAt || partial.RequestReturned || calls != 0 || !partial.RecoveryRequired {
				t.Fatal("interruption escaped the pre-reload inverse phase", partial, err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			journal = fixtureJournal(t, f)
			before, err := observeSSHRuntimeRecoveryRecords(journal)
			if err != nil || before[sshRuntimeRecoveryReloadName] != "" {
				t.Fatal("interruption recorded a reload", err)
			}
			wire, err := journal.readRecord(sshRuntimeRecoveryName)
			var intent sshRuntimeRecoveryIntent
			if err != nil || json.Unmarshal(wire, &intent) != nil {
				t.Fatal("missing saved recovery authority", err)
			}
			// Recorded v1 intents must retain a valid target even though the
			// private, unrecorded preparation is allowed to bind it later.
			intent.Target = ""
			for _, fresh := range []bool{false, true} {
				if _, _, err := validateSSHRuntimeRecoveryHistory(journal, intent, plan.summary.PlanSHA256, deps.parserDigest, before, fresh); err == nil {
					t.Fatal("recorded intent accepted without its target")
				}
			}
			if failAt == 2 {
				legacy = true
				result, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, "",
					deps.run, deps.checkParser, bind, sshPublicationDefaults())
				if !errors.Is(err, ErrInventoryChanged) || result.RecoverySHA256 != "" || calls != 0 {
					t.Fatal("former policy-dependent binder did not reproduce target drift", result, err)
				}
				legacy = false
			}
			startup.CommandSHA256 = strings.Repeat("e", 64)
			if _, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
				deps.run, deps.checkParser, bind, sshPublicationDefaults()); !errors.Is(err, ErrInventoryChanged) || calls != 0 {
				t.Fatal("changed startup resumed saved recovery authority", err)
			}
			startup.CommandSHA256 = strings.Repeat("a", 64)
			if again := runtimeRecoveryPlan(t, journal, plan, deps, bind); again != approved || calls != 0 {
				t.Fatal("valid inverse phase changed the saved recovery digest")
			}
			after, err := observeSSHRuntimeRecoveryRecords(journal)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("resume inspection or refused drift changed history", err)
			}
			result, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, approved,
				deps.run, deps.checkParser, bind, sshPublicationDefaults())
			if err != nil || !result.RequestReturned || !result.ConfigurationRestored || !result.RecoveryRequired || calls != 1 {
				t.Fatal("policy-bound recovery did not resume exactly once", result, err)
			}
		})
	}
}

func TestSSHRecoveryCurrentPhaseIsVerifiedBeforeRuntimeBinding(t *testing.T) {
	for _, scenario := range []string{"global-policy", "context-policy", "syntax", "changed-parser", "changed-history"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, deps, journal := runtimeRecoveryFixture(t, false, false)
			before, err := observeSSHRuntimeRecoveryRecords(journal)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "changed-parser" {
				deps.parserDigest = strings.Repeat("e", 64)
			}
			if scenario == "changed-history" {
				f.write(sshJournalDirectory+"/"+sshActivationIntentName, "{}")
				before, err = observeSSHRuntimeRecoveryRecords(journal)
				if err != nil {
					t.Fatal(err)
				}
			}
			run := func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
				wire, err := deps.run(ctx, image, mode, access)
				if image == nil && scenario == "syntax" && mode == "syntax" {
					return nil, unix.EIO
				}
				if image == nil && mode == "effective" && (scenario == "global-policy" || scenario == "context-policy" && access != "") {
					wire = bytes.ReplaceAll(wire, []byte("allowtcpforwarding no"), []byte("allowtcpforwarding yes"))
				}
				return wire, err
			}
			binds := 0
			bind := func(context.Context, func() error, *sshRecoveryPolicyAnchor) (sshActivationLease, error) {
				binds++
				return nil, unix.EIO
			}
			if _, err := recoverSSHActivatedConfiguration(t.Context(), journal, plan.summary.PlanSHA256, deps.parserDigest, "",
				run, deps.checkParser, bind, sshPublicationDefaults()); err == nil || binds != 0 {
				t.Fatal("unverified history or live phase reached the runtime binder", binds, err)
			}
			after, err := observeSSHRuntimeRecoveryRecords(journal)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("rejected pre-bind verification changed history", err)
			}
		})
	}
}
