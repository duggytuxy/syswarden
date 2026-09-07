package cmd

import (
	"errors"
	"strings"
	"testing"
)

func setQualificationUpdateFlags(t *testing.T, bundle, candidate string) {
	t.Helper()
	bundleFlag := updateCmd.Flags().Lookup("qualification-bundle")
	candidateFlag := updateCmd.Flags().Lookup("candidate-version")
	previousBundle := bundleFlag.Value.String()
	previousBundleChanged := bundleFlag.Changed
	previousCandidate := candidateFlag.Value.String()
	previousCandidateChanged := candidateFlag.Changed
	if err := updateCmd.Flags().Set("qualification-bundle", bundle); err != nil {
		t.Fatal(err)
	}
	if err := updateCmd.Flags().Set("candidate-version", candidate); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = bundleFlag.Value.Set(previousBundle)
		bundleFlag.Changed = previousBundleChanged
		_ = candidateFlag.Value.Set(previousCandidate)
		candidateFlag.Changed = previousCandidateChanged
	})
}

func TestUpdateCommandPropagatesUpgradeFailure(t *testing.T) {
	setQualificationUpdateFlags(t, "", "")
	original := runSystemUpgrade
	runSystemUpgrade = func() error { return errors.New("verified package activation failed") }
	t.Cleanup(func() { runSystemUpgrade = original })

	err := updateCmd.RunE(updateCmd, nil)
	if err == nil {
		t.Fatal("update command returned success after the upgrade failed")
	}
	if !strings.Contains(err.Error(), "verified package activation failed") {
		t.Fatalf("update error = %q", err)
	}
}

func TestUpdateCommandReturnsSuccessAfterVerifiedUpgrade(t *testing.T) {
	setQualificationUpdateFlags(t, "", "")
	original := runSystemUpgrade
	runSystemUpgrade = func() error { return nil }
	t.Cleanup(func() { runSystemUpgrade = original })

	if err := updateCmd.RunE(updateCmd, nil); err != nil {
		t.Fatalf("update command error = %v", err)
	}
}

func TestUpdateCommandRoutesExplicitOfflineQualificationWithoutProductionFallback(t *testing.T) {
	setQualificationUpdateFlags(t, "/root/syswarden-v4.10.0-qualification", "v4.10.0")
	originalProduction := runSystemUpgrade
	originalQualification := runQualificationBundleUpgrade
	productionCalls := 0
	qualificationCalls := 0
	runSystemUpgrade = func() error {
		productionCalls++
		return errors.New("production updater must not run")
	}
	runQualificationBundleUpgrade = func(bundle, candidate string) error {
		qualificationCalls++
		if bundle != "/root/syswarden-v4.10.0-qualification" || candidate != "v4.10.0" {
			t.Fatalf("qualification request = %q %q", bundle, candidate)
		}
		return nil
	}
	t.Cleanup(func() {
		runSystemUpgrade = originalProduction
		runQualificationBundleUpgrade = originalQualification
	})

	if err := updateCmd.RunE(updateCmd, nil); err != nil {
		t.Fatal(err)
	}
	if qualificationCalls != 1 || productionCalls != 0 {
		t.Fatalf("qualification calls=%d production calls=%d", qualificationCalls, productionCalls)
	}
}

func TestUpdateCommandRejectsIncompleteQualificationFlagsBeforeEitherUpdater(t *testing.T) {
	for _, values := range [][2]string{
		{"/root/bundle", ""},
		{"", "v4.10.0"},
	} {
		t.Run(values[0]+values[1], func(t *testing.T) {
			setQualificationUpdateFlags(t, values[0], values[1])
			originalProduction := runSystemUpgrade
			originalQualification := runQualificationBundleUpgrade
			calls := 0
			runSystemUpgrade = func() error { calls++; return nil }
			runQualificationBundleUpgrade = func(string, string) error { calls++; return nil }
			t.Cleanup(func() {
				runSystemUpgrade = originalProduction
				runQualificationBundleUpgrade = originalQualification
			})

			err := updateCmd.RunE(updateCmd, nil)
			if err == nil || !strings.Contains(err.Error(), "must be provided together") {
				t.Fatalf("incomplete flag error = %v", err)
			}
			if calls != 0 {
				t.Fatalf("updater called %d times", calls)
			}
		})
	}
}

func TestUpdateCommandRejectsPositionalArguments(t *testing.T) {
	if err := updateCmd.Args(updateCmd, []string{"v4.10.0"}); err == nil {
		t.Fatal("update accepted a positional candidate argument")
	}
}

func TestQualificationPreflightSkipsMutationHooksButKeepsRemovalGuard(t *testing.T) {
	setQualificationUpdateFlags(t, "/root/bundle", "v4.10.0")
	originalRecovery := recoverPendingFirewallTransactionHook
	originalInit := initConfigHook
	originalRemoval := inspectRemovalTombstone
	recoveryCalls := 0
	configLoads := 0
	removalChecks := 0
	recoverPendingFirewallTransactionHook = func() error { recoveryCalls++; return nil }
	initConfigHook = func() { configLoads++ }
	inspectRemovalTombstone = func() (bool, error) { removalChecks++; return false, nil }
	t.Cleanup(func() {
		recoverPendingFirewallTransactionHook = originalRecovery
		initConfigHook = originalInit
		inspectRemovalTombstone = originalRemoval
	})

	if err := rootCmd.PersistentPreRunE(updateCmd, nil); err != nil {
		t.Fatal(err)
	}
	if recoveryCalls != 0 || configLoads != 0 || removalChecks != 1 {
		t.Fatalf("recovery=%d config=%d removal=%d", recoveryCalls, configLoads, removalChecks)
	}
}

func TestIncompleteQualificationPreflightFailsBeforeAllHooks(t *testing.T) {
	setQualificationUpdateFlags(t, "/root/bundle", "")
	originalRecovery := recoverPendingFirewallTransactionHook
	originalInit := initConfigHook
	originalRemoval := inspectRemovalTombstone
	calls := 0
	recoverPendingFirewallTransactionHook = func() error { calls++; return nil }
	initConfigHook = func() { calls++ }
	inspectRemovalTombstone = func() (bool, error) { calls++; return false, nil }
	t.Cleanup(func() {
		recoverPendingFirewallTransactionHook = originalRecovery
		initConfigHook = originalInit
		inspectRemovalTombstone = originalRemoval
	})

	err := rootCmd.PersistentPreRunE(updateCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "must be provided together") {
		t.Fatalf("incomplete preflight error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("preflight hook called %d times", calls)
	}
}

func TestProductionUpdatePreflightRetainsRecoveryAndConfigurationHooks(t *testing.T) {
	setQualificationUpdateFlags(t, "", "")
	originalRecovery := recoverPendingFirewallTransactionHook
	originalInit := initConfigHook
	originalRemoval := inspectRemovalTombstone
	recoveryCalls := 0
	configLoads := 0
	removalChecks := 0
	recoverPendingFirewallTransactionHook = func() error { recoveryCalls++; return nil }
	initConfigHook = func() { configLoads++ }
	inspectRemovalTombstone = func() (bool, error) { removalChecks++; return false, nil }
	t.Cleanup(func() {
		recoverPendingFirewallTransactionHook = originalRecovery
		initConfigHook = originalInit
		inspectRemovalTombstone = originalRemoval
	})

	_ = rootCmd.PersistentPreRunE(updateCmd, nil)
	if recoveryCalls != 1 || configLoads != 1 || removalChecks != 1 {
		t.Fatalf("production recovery=%d config=%d removal=%d", recoveryCalls, configLoads, removalChecks)
	}
}

func TestOfflineQualificationPackageStagePreflightSkipsMutationHooks(t *testing.T) {
	setQualificationUpdateFlags(t, "", "")
	t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "1")
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	originalRecovery := recoverPendingFirewallTransactionHook
	originalInit := initConfigHook
	originalRemoval := inspectRemovalTombstone
	recoveryCalls := 0
	configLoads := 0
	removalChecks := 0
	recoverPendingFirewallTransactionHook = func() error { recoveryCalls++; return nil }
	initConfigHook = func() { configLoads++ }
	inspectRemovalTombstone = func() (bool, error) { removalChecks++; return false, nil }
	t.Cleanup(func() {
		recoverPendingFirewallTransactionHook = originalRecovery
		initConfigHook = originalInit
		inspectRemovalTombstone = originalRemoval
	})

	if err := rootCmd.PersistentPreRunE(installCmd, nil); err != nil {
		t.Fatal(err)
	}
	if recoveryCalls != 0 || configLoads != 0 || removalChecks != 1 {
		t.Fatalf("package-stage recovery=%d config=%d removal=%d", recoveryCalls, configLoads, removalChecks)
	}
}
