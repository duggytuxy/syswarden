package cmd

import (
	"errors"
	"testing"

	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

func TestNativeInstallDefersBeforeConfigurationOrFirewallRecovery(t *testing.T) {
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	t.Setenv("SYSWARDEN_NATIVE_INSTALL_PHASE", "unknown")
	t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "")
	previousInspect := inspectRemovalTombstone
	previousConfig := initConfigHook
	previousRecovery := recoverPendingFirewallTransactionHook
	previousLegacy := preflightLegacyWireGuardForInstall
	previousDependencies := installDependenciesForInstall
	t.Cleanup(func() {
		inspectRemovalTombstone = previousInspect
		initConfigHook = previousConfig
		recoverPendingFirewallTransactionHook = previousRecovery
		preflightLegacyWireGuardForInstall = previousLegacy
		installDependenciesForInstall = previousDependencies
	})
	inspectRemovalTombstone = func() (bool, error) { return false, nil }
	initConfigHook = func() { t.Fatal("deferred installation loaded configuration") }
	unexpected := func() error { t.Fatal("deferred installation entered the mutation pipeline"); return nil }
	recoverPendingFirewallTransactionHook = unexpected
	preflightLegacyWireGuardForInstall = unexpected
	installDependenciesForInstall = unexpected
	command := &cobra.Command{Use: "install"}
	parent := &cobra.Command{Use: "syswarden"}
	parent.AddCommand(command)
	if err := rootCmd.PersistentPreRunE(command, nil); err != nil {
		t.Fatal(err)
	}
	if !nativeServicePlanForInstall(command).Deferred() {
		t.Fatal("missing deferred disposition")
	}
	if err := installCmd.RunE(command, nil); err != nil {
		t.Fatal(err)
	}
}

func TestNativeInstallObservationFailureStopsCommandPreparation(t *testing.T) {
	t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "")
	previousInspect := inspectRemovalTombstone
	previousPrepare := prepareNativeServicesForInstall
	previousConfig := initConfigHook
	previousRecovery := recoverPendingFirewallTransactionHook
	t.Cleanup(func() {
		inspectRemovalTombstone = previousInspect
		prepareNativeServicesForInstall = previousPrepare
		initConfigHook = previousConfig
		recoverPendingFirewallTransactionHook = previousRecovery
	})
	failure := errors.New("unreadable service state")
	inspectRemovalTombstone = func() (bool, error) { return false, nil }
	prepareNativeServicesForInstall = func() (*system.NativeServiceInstallation, error) { return nil, failure }
	initConfigHook = func() { t.Fatal("failed observation reached configuration") }
	recoverPendingFirewallTransactionHook = func() error { t.Fatal("failed observation reached recovery"); return nil }
	command := &cobra.Command{Use: "install"}
	parent := &cobra.Command{Use: "syswarden"}
	parent.AddCommand(command)
	if err := rootCmd.PersistentPreRunE(command, nil); !errors.Is(err, failure) {
		t.Fatalf("failure was lost: %v", err)
	}
}

func TestLegacyBanRecoveryUsesGuardedRestartAfterQuarantine(t *testing.T) {
	previousQuarantine := quarantineLegacyDynamicBanIntervals
	previousRestart := restartCoreServiceForInstall
	t.Cleanup(func() {
		quarantineLegacyDynamicBanIntervals = previousQuarantine
		restartCoreServiceForInstall = previousRestart
	})
	quarantines := 0
	quarantineLegacyDynamicBanIntervals = func() (bool, error) {
		quarantines++
		return true, nil
	}
	restartCoreServiceForInstall = func() error { t.Fatal("unconditional restart called"); return nil }
	failure := errors.New("administrator stopped core during quarantine")
	err := preparePackagedLegacyDynamicBanUpgradeWithRestart(func() error {
		if quarantines != 1 {
			t.Fatal("restart observation preceded quarantine")
		}
		return failure
	})
	if !errors.Is(err, failure) || quarantines != 1 {
		t.Fatalf("guarded restart failure lost: %v, %d", err, quarantines)
	}
}
