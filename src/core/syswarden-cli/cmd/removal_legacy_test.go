package cmd

import (
	"errors"
	"reflect"
	"strconv"
	"testing"

	"syswarden-cli/pkg/integration"

	"github.com/spf13/cobra"
)

func TestRemovalEntryPointsPreserveAdministratorPolicyBeforeServiceStop(t *testing.T) {
	oldPreflight, oldBegin := preflightAdministratorPolicyForRemoval, beginRemoval
	oldPrepare, oldCleanup, oldUninstall := prepareFirewallStateForRemoval, cleanupFirewallStateForRemoval, uninstallHostSystem
	t.Cleanup(func() {
		preflightAdministratorPolicyForRemoval, beginRemoval = oldPreflight, oldBegin
		prepareFirewallStateForRemoval, cleanupFirewallStateForRemoval, uninstallHostSystem = oldPrepare, oldCleanup, oldUninstall
	})
	for _, entry := range []string{"standalone", "native-package-preparation"} {
		for _, refusal := range []int{1, 2} {
			t.Run(entry+strconv.Itoa(refusal), func(t *testing.T) {
				var order []string
				checks := 0
				sentinel := errors.New("synthetic administrator policy")
				preflightAdministratorPolicyForRemoval = func() error {
					checks++
					order = append(order, "policy-inspection")
					if checks == refusal {
						return sentinel
					}
					return nil
				}
				beginRemoval = func() error { order = append(order, "barrier"); return nil }
				forbidden := func() error { t.Fatal("administrator protection crossed the service or deletion boundary"); return nil }
				prepareFirewallStateForRemoval, cleanupFirewallStateForRemoval, uninstallHostSystem = forbidden, forbidden, forbidden
				var err error
				if entry == "standalone" {
					err = uninstallCmd.RunE(uninstallCmd, nil)
				} else {
					err = preparePackageRemovalCmd.RunE(preparePackageRemovalCmd, nil)
				}
				if !errors.Is(err, sentinel) {
					t.Fatal("administrator policy refusal lost", err)
				}
				want := []string{"policy-inspection"}
				if refusal == 2 {
					want = append(want, "barrier", "policy-inspection")
				}
				if !reflect.DeepEqual(order, want) {
					t.Fatal("unexpected removal ordering", order)
				}
			})
		}
	}
}

func TestRemovalEntryPointsKeepResourcesUntilPersistentFirewallRecovery(t *testing.T) {
	oldPersistence, oldBegin := preflightKnownNFTPersistenceForRemoval, beginRemoval
	oldPrepare, oldCleanup := prepareFirewallStateForRemoval, cleanupFirewallStateForRemoval
	oldIntegration := removeOwnedIntegrationArtifactsForRemoval
	oldCron, oldWG := removeOwnedCronStateForRemoval, removeOwnedWireGuardStateForRemoval
	oldBarrier, oldCIS := requireRemovalTombstoneForCISPolicyRemoval, removeExactCISHardeningPoliciesForRemoval
	oldServices, oldLock, oldUninstall := removePreparedServiceArtifacts, removePreparedFirewallRuntimeLock, uninstallHostSystem
	t.Cleanup(func() {
		preflightKnownNFTPersistenceForRemoval, beginRemoval = oldPersistence, oldBegin
		prepareFirewallStateForRemoval, cleanupFirewallStateForRemoval = oldPrepare, oldCleanup
		removeOwnedIntegrationArtifactsForRemoval = oldIntegration
		removeOwnedCronStateForRemoval, removeOwnedWireGuardStateForRemoval = oldCron, oldWG
		requireRemovalTombstoneForCISPolicyRemoval, removeExactCISHardeningPoliciesForRemoval = oldBarrier, oldCIS
		removePreparedServiceArtifacts, removePreparedFirewallRuntimeLock, uninstallHostSystem = oldServices, oldLock, oldUninstall
	})
	noChange := func() error { return nil }
	removeOwnedCronStateForRemoval, removeOwnedWireGuardStateForRemoval = noChange, noChange
	requireRemovalTombstoneForCISPolicyRemoval, removeExactCISHardeningPoliciesForRemoval = noChange, noChange
	for _, entry := range []string{"standalone", "native-package-preparation"} {
		for _, refusal := range []int{1, 2, 3} {
			t.Run(entry+strconv.Itoa(refusal), func(t *testing.T) {
				checks, stops, cleanups, barriers := 0, 0, 0, 0
				sentinel := errors.New("synthetic persistent product reference")
				preflightKnownNFTPersistenceForRemoval = func() error {
					checks++
					if checks == refusal {
						return sentinel
					}
					return nil
				}
				beginRemoval = func() error { barriers++; return nil }
				prepareFirewallStateForRemoval = func() error { stops++; return nil }
				cleanupFirewallStateForRemoval = func() error { cleanups++; return nil }
				removeOwnedIntegrationArtifactsForRemoval = func() (integration.RsyslogPackageRemovalOutcome, error) {
					return integration.RsyslogPackageRemovalOfflineAlreadyComplete, nil
				}
				forbidden := func() error { t.Fatal("persistent recovery lost its service, lock or product resources"); return nil }
				removePreparedServiceArtifacts, removePreparedFirewallRuntimeLock, uninstallHostSystem = forbidden, forbidden, forbidden
				var err error
				if entry == "standalone" {
					err = uninstallCmd.RunE(uninstallCmd, nil)
				} else {
					err = preparePackageRemovalCmd.RunE(preparePackageRemovalCmd, nil)
				}
				if !errors.Is(err, sentinel) || checks != refusal {
					t.Fatal("persistence refusal lost", err)
				}
				wantBarriers, wantChanges := 0, 0
				if refusal >= 2 {
					wantBarriers = 1
				}
				if refusal == 3 {
					wantChanges = 1
				}
				if barriers != wantBarriers || stops != wantChanges || cleanups != wantChanges {
					t.Fatal("persistent recovery crossed its mutation boundary", barriers, stops, cleanups)
				}
			})
		}
	}
}

func TestRemovalEntryPointsRetainEvidenceBeforeHistoricalFail2banRecovery(t *testing.T) {
	oldBegin, oldPreflight := beginRemoval, preflightHistoricalFail2banForRemoval
	oldPrepare, oldCron := prepareFirewallStateForRemoval, removeOwnedCronStateForRemoval
	oldWG, oldCleanup := removeOwnedWireGuardStateForRemoval, cleanupFirewallStateForRemoval
	oldUninstall := uninstallHostSystem
	t.Cleanup(func() {
		beginRemoval, preflightHistoricalFail2banForRemoval = oldBegin, oldPreflight
		prepareFirewallStateForRemoval, removeOwnedCronStateForRemoval = oldPrepare, oldCron
		removeOwnedWireGuardStateForRemoval, cleanupFirewallStateForRemoval = oldWG, oldCleanup
		uninstallHostSystem = oldUninstall
	})
	for _, entry := range []string{"standalone", "native-package-preparation"} {
		for _, refusal := range []int{1, 2, 3} {
			t.Run(entry+strconv.Itoa(refusal), func(t *testing.T) {
				var order []string
				checks := 0
				sentinel := errors.New("synthetic unresolved historical producer")
				beginRemoval = func() error { order = append(order, "barrier"); return nil }
				preflightHistoricalFail2banForRemoval = func() error {
					checks++
					order = append(order, "historical-preflight")
					if checks == refusal {
						return sentinel
					}
					return nil
				}
				prepareFirewallStateForRemoval = func() error { order = append(order, "service-stop"); return nil }
				removeOwnedCronStateForRemoval = func() error { order = append(order, "cron"); return nil }
				removeOwnedWireGuardStateForRemoval = func() error { order = append(order, "wireguard"); return nil }
				cleanupFirewallStateForRemoval = func() error { order = append(order, "forbidden-kernel-cleanup"); return nil }
				uninstallHostSystem = func() error { order = append(order, "forbidden-product-deletion"); return nil }
				var err error
				if entry == "standalone" {
					err = uninstallCmd.RunE(uninstallCmd, nil)
				} else {
					err = preparePackageRemovalCmd.RunE(preparePackageRemovalCmd, nil)
				}
				if !errors.Is(err, sentinel) {
					t.Fatal("recovery refusal lost", err)
				}
				expected := []string{"historical-preflight"}
				if refusal >= 2 {
					expected = append(expected, "barrier", "historical-preflight")
				}
				if refusal == 3 {
					expected = append(expected, "service-stop", "cron", "wireguard", "historical-preflight")
				}
				if !reflect.DeepEqual(order, expected) {
					t.Fatal("removal crossed unresolved historical evidence", order)
				}
			})
		}
	}
}

func TestRemovalEntryPointsKeepRecoveryResourcesUntilHistoricalHostAbsence(t *testing.T) {
	oldEarly, oldFinal := preflightHistoricalHostForRemoval, attestHistoricalHostRemovalComplete
	oldF2B, oldBegin := preflightHistoricalFail2banForRemoval, beginRemoval
	oldPrepare, oldCron := prepareFirewallStateForRemoval, removeOwnedCronStateForRemoval
	oldWG, oldCleanup := removeOwnedWireGuardStateForRemoval, cleanupFirewallStateForRemoval
	oldIntegration := removeOwnedIntegrationArtifactsForRemoval
	oldBarrier, oldCIS := requireRemovalTombstoneForCISPolicyRemoval, removeExactCISHardeningPoliciesForRemoval
	oldServices, oldLock, oldUninstall := removePreparedServiceArtifacts, removePreparedFirewallRuntimeLock, uninstallHostSystem
	t.Cleanup(func() {
		preflightHistoricalHostForRemoval, attestHistoricalHostRemovalComplete = oldEarly, oldFinal
		preflightHistoricalFail2banForRemoval, beginRemoval = oldF2B, oldBegin
		prepareFirewallStateForRemoval, removeOwnedCronStateForRemoval = oldPrepare, oldCron
		removeOwnedWireGuardStateForRemoval, cleanupFirewallStateForRemoval = oldWG, oldCleanup
		removeOwnedIntegrationArtifactsForRemoval = oldIntegration
		requireRemovalTombstoneForCISPolicyRemoval, removeExactCISHardeningPoliciesForRemoval = oldBarrier, oldCIS
		removePreparedServiceArtifacts, removePreparedFirewallRuntimeLock, uninstallHostSystem = oldServices, oldLock, oldUninstall
	})
	for _, entry := range []string{"standalone", "native-package-preparation"} {
		for _, refusal := range []int{1, 2, 3} {
			t.Run(entry+strconv.Itoa(refusal), func(t *testing.T) {
				checks := 0
				var calls []string
				sentinel := errors.New("synthetic unresolved host source")
				check := func() error {
					checks++
					calls = append(calls, "host-inspection")
					if checks == refusal {
						return sentinel
					}
					return nil
				}
				preflightHistoricalHostForRemoval, attestHistoricalHostRemovalComplete = check, check
				preflightHistoricalFail2banForRemoval = func() error { return nil }
				step := func(name string) func() error { return func() error { calls = append(calls, name); return nil } }
				beginRemoval = step("barrier")
				prepareFirewallStateForRemoval = step("stop-services")
				removeOwnedCronStateForRemoval = step("cron")
				removeOwnedWireGuardStateForRemoval = step("wireguard")
				cleanupFirewallStateForRemoval = step("firewall")
				removeOwnedIntegrationArtifactsForRemoval = func() (integration.RsyslogPackageRemovalOutcome, error) {
					calls = append(calls, "existing-exact-integration-cleanup")
					return integration.RsyslogPackageRemovalOfflineAlreadyComplete, nil
				}
				requireRemovalTombstoneForCISPolicyRemoval = step("barrier-reattest")
				removeExactCISHardeningPoliciesForRemoval = step("existing-exact-cis-cleanup")
				removePreparedServiceArtifacts = step("forbidden-service-deletion")
				removePreparedFirewallRuntimeLock = step("forbidden-lock-deletion")
				uninstallHostSystem = step("forbidden-product-deletion")
				var err error
				if entry == "standalone" {
					err = uninstallCmd.RunE(uninstallCmd, nil)
				} else {
					err = preparePackageRemovalCmd.RunE(preparePackageRemovalCmd, nil)
				}
				if !errors.Is(err, sentinel) {
					t.Fatal("host refusal lost", err)
				}
				expected := []string{"host-inspection"}
				if refusal >= 2 {
					expected = append(expected, "barrier", "host-inspection")
				}
				if refusal == 3 {
					expected = append(expected, "stop-services", "cron", "wireguard", "firewall", "existing-exact-integration-cleanup", "barrier-reattest", "existing-exact-cis-cleanup", "host-inspection")
				}
				if !reflect.DeepEqual(calls, expected) {
					t.Fatal("recovery resources were discarded or exact cleanup was bypassed", calls)
				}
			})
		}
	}
}

func TestPackageRemovalRefusesNativeEraseUntilRuntimeFileRetirement(t *testing.T) {
	steps := []*func() error{
		&beginRemoval, &prepareFirewallStateForRemoval, &removeOwnedCronStateForRemoval,
		&removeOwnedWireGuardStateForRemoval, &cleanupFirewallStateForRemoval,
		&requireRemovalTombstoneForCISPolicyRemoval, &removeExactCISHardeningPoliciesForRemoval,
		&removePreparedServiceArtifacts, &removePreparedFirewallRuntimeLock,
	}
	for _, step := range steps {
		previous := *step
		t.Cleanup(func() { *step = previous })
		*step = func() error { return nil }
	}
	oldIntegration := removeOwnedIntegrationArtifactsForRemoval
	oldReadiness := attestRuntimeRetirementBeforeNativeErase
	t.Cleanup(func() {
		removeOwnedIntegrationArtifactsForRemoval = oldIntegration
		attestRuntimeRetirementBeforeNativeErase = oldReadiness
	})
	removeOwnedIntegrationArtifactsForRemoval = func() (integration.RsyslogPackageRemovalOutcome, error) {
		return integration.RsyslogPackageRemovalOfflineAlreadyComplete, nil
	}
	sentinel := errors.New("synthetic retained administrator configuration")
	checks := 0
	attestRuntimeRetirementBeforeNativeErase = func() error {
		checks++
		return sentinel
	}
	if err := preparePackageRemovalCmd.RunE(preparePackageRemovalCmd, nil); !errors.Is(err, sentinel) {
		t.Fatal("incomplete file retirement was reported ready for native erase", err)
	}
	if checks != 1 {
		t.Fatal("native erase readiness did not use its independent final check", checks)
	}
	oldDefaults := removePristineDefaultConfigurationForRemoval
	t.Cleanup(func() { removePristineDefaultConfigurationForRemoval = oldDefaults })
	removePristineDefaultConfigurationForRemoval = func() error { return sentinel }
	checks = 0
	for _, command := range []*cobra.Command{uninstallCmd, preparePackageRemovalCmd} {
		if err := command.RunE(command, nil); !errors.Is(err, sentinel) {
			t.Fatal("configuration retirement refusal was lost", command.Name(), err)
		}
	}
	if checks != 0 {
		t.Fatal("native erase was inspected after configuration retirement failed")
	}
}

func TestRemovalEntryPointsKeepServicesUntilRuntimeHistoryRetirement(t *testing.T) {
	steps := []*func() error{&beginRemoval, &prepareFirewallStateForRemoval, &removeOwnedCronStateForRemoval, &removeOwnedWireGuardStateForRemoval, &cleanupFirewallStateForRemoval, &requireRemovalTombstoneForCISPolicyRemoval, &removeExactCISHardeningPoliciesForRemoval}
	for _, step := range steps {
		previous := *step
		t.Cleanup(func() { *step = previous })
		*step = func() error { return nil }
	}
	priorIntegration := removeOwnedIntegrationArtifactsForRemoval
	priorLists := retireGeneratedListsForRemoval
	t.Cleanup(func() { retireGeneratedListsForRemoval = priorLists })
	priorLogs := retireCreatedProductLogsForRemoval
	t.Cleanup(func() { retireCreatedProductLogsForRemoval = priorLogs })
	priorUI := retireCreatedUISnapshotsForRemoval
	t.Cleanup(func() { retireCreatedUISnapshotsForRemoval = priorUI })
	priorHistory, priorServices, priorErase := retireRuntimeHistoryForRemoval, removePreparedServiceArtifacts, attestRuntimeRetirementBeforeNativeErase
	t.Cleanup(func() {
		removeOwnedIntegrationArtifactsForRemoval = priorIntegration
		retireRuntimeHistoryForRemoval, removePreparedServiceArtifacts, attestRuntimeRetirementBeforeNativeErase = priorHistory, priorServices, priorErase
	})
	removeOwnedIntegrationArtifactsForRemoval = func() (integration.RsyslogPackageRemovalOutcome, error) {
		return integration.RsyslogPackageRemovalOfflineAlreadyComplete, nil
	}
	sentinel := errors.New("synthetic unresolved runtime history")
	retireRuntimeHistoryForRemoval = func() error { return sentinel }
	retireCreatedProductLogsForRemoval = func() error { return nil }
	forbidden := func() error { t.Fatal("runtime history lost its recovery resources"); return nil }
	removePreparedServiceArtifacts, attestRuntimeRetirementBeforeNativeErase = forbidden, forbidden
	for _, stage := range []string{"history", "ui", "logs", "lists"} {
		if stage == "ui" {
			retireRuntimeHistoryForRemoval = func() error { t.Fatal("snapshot refusal crossed the history boundary"); return nil }
			retireCreatedUISnapshotsForRemoval = func() error { return sentinel }
		}
		if stage == "logs" {
			retireCreatedUISnapshotsForRemoval = func() error { t.Fatal("log refusal crossed the snapshot boundary"); return nil }
			retireRuntimeHistoryForRemoval = func() error { t.Fatal("log refusal crossed the runtime history boundary"); return nil }
			retireCreatedProductLogsForRemoval = func() error { return sentinel }
		}
		if stage == "lists" {
			retireGeneratedListsForRemoval = func() error { return sentinel }
			retireCreatedProductLogsForRemoval = func() error { t.Fatal("list refusal crossed the log retirement boundary"); return nil }
		}
		for _, command := range []*cobra.Command{uninstallCmd, preparePackageRemovalCmd} {
			if err := command.RunE(command, nil); !errors.Is(err, sentinel) {
				t.Fatal("retirement refusal was lost", stage, err)
			}
		}
	}

}
