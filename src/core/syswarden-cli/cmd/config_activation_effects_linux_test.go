//go:build linux

package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

func fixtureActivationExecution(t *testing.T, command *cobra.Command, authority, host func(context.Context) error) *activationExecution {
	t.Helper()
	previous := command.Context()
	t.Cleanup(func() { command.SetContext(previous) })
	execution := &activationExecution{command: command, operation: activationOperation(command), verifyAuthority: authority, reviewedHost: host, phase: activationPrepared}
	command.SetContext(context.WithValue(context.Background(), activationExecutionKey{}, execution))
	return execution
}

func TestActivationEffectsRefuseHostOrAuthorityDriftBeforeRecovery(t *testing.T) {
	for _, change := range []string{"host", "authority-before-host", "authority-during-host", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			failure := errors.New("reviewed state changed")
			var authorityFailure error
			if change == "authority-before-host" {
				authorityFailure = failure
			}
			execution := fixtureActivationExecution(t, reloadCmd, func(ctx context.Context) error {
				return errors.Join(authorityFailure, ctx.Err())
			}, func(context.Context) error {
				if change == "host" {
					return failure
				}
				if change == "authority-during-host" {
					authorityFailure = failure
				}
				return nil
			})
			if change == "cancelled" {
				ctx, cancel := context.WithCancel(reloadCmd.Context())
				cancel()
				reloadCmd.SetContext(ctx)
				failure = context.Canceled
			}
			recoveries := 0
			recoverHost := func() error { recoveries++; return nil }
			if err := recoverConfigurationActivation(reloadCmd, recoverHost); !errors.Is(err, failure) {
				t.Fatalf("guard refusal lost: %v", err)
			}
			if recoveries != 0 || execution.phase != activationFailed {
				t.Fatalf("drift reached recovery or left reusable authority: calls=%d phase=%d", recoveries, execution.phase)
			}
			authorityFailure = nil
			if err := recoverConfigurationActivation(reloadCmd, recoverHost); err == nil || recoveries != 0 {
				t.Fatal("failed command execution replayed recovery")
			}
			if err := beginConfigurationActivationApplication(reloadCmd); err == nil {
				t.Fatal("refused recovery reached application")
			}
		})
	}
}

func TestActivationEffectsRecoveryConsumesOriginalHostObservation(t *testing.T) {
	for _, reviewed := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing-exact-authority", true: "new-reviewed-plan"}[reviewed], func(t *testing.T) {
			hostChanged := false
			hostChecks, authorityChecks := 0, 0
			var host func(context.Context) error
			if reviewed {
				host = func(context.Context) error {
					hostChecks++
					if hostChanged {
						return errors.New("original host was intentionally changed by recovery")
					}
					return nil
				}
			}
			execution := fixtureActivationExecution(t, reloadCmd, func(context.Context) error { authorityChecks++; return nil }, host)
			if err := recoverConfigurationActivation(reloadCmd, func() error { hostChanged = true; return nil }); err != nil {
				t.Fatal(err)
			}
			if err := beginConfigurationActivationApplication(reloadCmd); err != nil {
				t.Fatal("intended recovery changes invalidated their own original observation", err)
			}
			if authorityChecks < 4 || execution.reviewedHost != nil || execution.phase != activationApplying {
				t.Fatal("authority checks or deliberate mutation phase were lost")
			}
			if reviewed && hostChecks != 1 || !reviewed && hostChecks != 0 {
				t.Fatalf("original host observation was reused or invented: %d", hostChecks)
			}
			if err := beginConfigurationActivationApplication(reloadCmd); err == nil {
				t.Fatal("application phase replayed")
			}
		})
	}
}

func TestActivationEffectsRecoveryFailureAndAuthorityDriftBlockApplication(t *testing.T) {
	for _, change := range []string{"recovery-failure", "authority-during-recovery"} {
		t.Run(change, func(t *testing.T) {
			failure := errors.New("recovery cannot continue")
			var authorityFailure error
			execution := fixtureActivationExecution(t, installCmd, func(context.Context) error { return authorityFailure }, nil)
			if err := recoverConfigurationActivation(installCmd, func() error {
				if change == "recovery-failure" {
					return failure
				}
				authorityFailure = failure
				return nil
			}); !errors.Is(err, failure) {
				t.Fatal("recovery failure lost", err)
			}
			if execution.phase != activationFailed {
				t.Fatal("recovery failure left a reusable phase")
			}
			authorityFailure = nil
			if err := beginConfigurationActivationApplication(installCmd); err == nil {
				t.Fatal("failed recovery authorized installation")
			}
			if err := markConfigurationActivationApplied(installCmd); err == nil {
				t.Fatal("failed recovery reported application")
			}
		})
	}
}

func TestActivationEffectsCommandRunERefusesAuthorityDriftBeforeEffects(t *testing.T) {
	oldWireGuard, oldCron, oldDependencies := preflightWireGuardPolicyTransition, hostCronSchedulingPreflight, installDependenciesForInstall
	t.Cleanup(func() {
		preflightWireGuardPolicyTransition, hostCronSchedulingPreflight, installDependenciesForInstall = oldWireGuard, oldCron, oldDependencies
	})
	t.Setenv("SYSWARDEN_PKG_INSTALL", "")
	t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "")
	preflightWireGuardPolicyTransition = func() error { return nil }
	hostCronSchedulingPreflight = func(bool) error { t.Fatal("changed authority reached scheduler provider commands"); return nil }
	installDependenciesForInstall = func() error { t.Fatal("changed authority reached dependency mutation"); return nil }
	for _, command := range []*cobra.Command{installCmd, reloadCmd, configActivateCmd} {
		t.Run(command.CommandPath(), func(t *testing.T) {
			failure := errors.New("approval replaced after recovery")
			var authorityFailure error
			execution := fixtureActivationExecution(t, command, func(context.Context) error { return authorityFailure }, nil)
			if err := recoverConfigurationActivation(command, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			authorityFailure = failure
			if err := command.RunE(command, nil); !errors.Is(err, failure) {
				t.Fatalf("command did not preserve the authority refusal: %v", err)
			}
			if execution.phase != activationFailed {
				t.Fatal("failed application entry remained reusable")
			}
		})
	}
}

func TestActivationEffectsRefuseMissingRecoveryAndChangedOperation(t *testing.T) {
	for _, change := range []string{"missing-recovery", "changed-operation", "missing-authority"} {
		t.Run(change, func(t *testing.T) {
			execution := fixtureActivationExecution(t, installCmd, func(context.Context) error { return nil }, nil)
			switch change {
			case "changed-operation":
				execution.command = reloadCmd
			case "missing-authority":
				execution.verifyAuthority = nil
			}
			if err := beginConfigurationActivationApplication(installCmd); err == nil {
				t.Fatal("application bypassed its exact recovery phase")
			}
			if change != "missing-recovery" {
				if err := recoverConfigurationActivation(installCmd, func() error { t.Fatal("invalid authority reached recovery"); return nil }); err == nil {
					t.Fatal("recovery ignored invalid authority")
				}
			}
		})
	}
}

func TestActivationEffectsRootRechecksPublishedAuthorityBeforeRecovery(t *testing.T) {
	previousPrepare, previousRecovery := prepareConfigurationActivationHook, recoverPendingFirewallTransactionHook
	previousRemoval, previousModule, previousWireGuard := inspectRemovalTombstone, refusePendingModuleEditHook, preflightWireGuardPolicyTransition
	t.Cleanup(func() {
		prepareConfigurationActivationHook, recoverPendingFirewallTransactionHook = previousPrepare, previousRecovery
		inspectRemovalTombstone, refusePendingModuleEditHook, preflightWireGuardPolicyTransition = previousRemoval, previousModule, previousWireGuard
	})
	t.Setenv("SYSWARDEN_PKG_INSTALL", "")
	t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "")
	inspectRemovalTombstone = func() (bool, error) { return false, nil }
	refusePendingModuleEditHook = func() error { return nil }
	preflightWireGuardPolicyTransition = func() error { return nil }
	recoverPendingFirewallTransactionHook = func() error { t.Fatal("late drift reached root recovery"); return nil }
	for _, change := range []string{"host", "approval"} {
		t.Run(change, func(t *testing.T) {
			failure := errors.New("published plan became stale before root recovery")
			prepareConfigurationActivationHook = func(command *cobra.Command) error {
				fixtureActivationExecution(t, command, func(context.Context) error {
					if change == "approval" {
						return failure
					}
					return nil
				}, func(context.Context) error {
					if change == "host" {
						return failure
					}
					return nil
				})
				return nil
			}
			if err := rootCmd.PersistentPreRunE(reloadCmd, nil); !errors.Is(err, failure) {
				t.Fatalf("root lost the late approval guard: %v", err)
			}
		})
	}
}

func TestActivationEffectsApplicationFailureCannotReplay(t *testing.T) {
	previousWireGuard, previousCron := preflightWireGuardPolicyTransition, hostCronSchedulingPreflight
	t.Cleanup(func() {
		preflightWireGuardPolicyTransition, hostCronSchedulingPreflight = previousWireGuard, previousCron
	})
	preflightWireGuardPolicyTransition = func() error { return nil }
	failure := errors.New("scheduler preflight refused")
	calls := 0
	hostCronSchedulingPreflight = func(bool) error { calls++; return failure }
	execution := fixtureActivationExecution(t, reloadCmd, func(context.Context) error { return nil }, nil)
	if err := recoverConfigurationActivation(reloadCmd, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := reloadCmd.RunE(reloadCmd, nil); !errors.Is(err, failure) {
		t.Fatal("application failure lost", err)
	}
	if calls != 1 || execution.phase != activationFailed {
		t.Fatal("application failure did not retain its failed phase")
	}
	if err := reloadCmd.RunE(reloadCmd, nil); err == nil || calls != 1 {
		t.Fatal("failed application repeated provider or mutation work")
	}
}

func TestActivationEffectsRemovalLauncherRefusalPrecedesRecoveryAndConfiguration(t *testing.T) {
	previousLaunchers, previousUninstall := preflightAPKLaunchersForRemoval, preflightUninstall
	previousModule, previousWireGuard := refusePendingModuleEditHook, preflightWireGuardPolicyTransition
	previousLoad, previousRecovery, previousRetain := initConfigHook, recoverPendingFirewallTransactionHook, retainAPKPayload
	t.Cleanup(func() {
		preflightAPKLaunchersForRemoval, preflightUninstall = previousLaunchers, previousUninstall
		refusePendingModuleEditHook, preflightWireGuardPolicyTransition = previousModule, previousWireGuard
		initConfigHook, recoverPendingFirewallTransactionHook, retainAPKPayload = previousLoad, previousRecovery, previousRetain
	})
	t.Setenv("SYSWARDEN_PKG_INSTALL", "")
	t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "")
	refusePendingModuleEditHook = func() error { return nil }
	preflightWireGuardPolicyTransition = func() error { return nil }
	preflightUninstall = func() error { t.Fatal("unresolved launcher behavior reached uninstall preparation"); return nil }
	initConfigHook = func() { t.Fatal("unresolved launcher behavior reached configuration loading") }
	recoverPendingFirewallTransactionHook = func() error { t.Fatal("unresolved launcher behavior reached firewall recovery"); return nil }
	failure := errors.New("retained launcher behavior remains unresolved")
	calls := 0
	preflightAPKLaunchersForRemoval = func() error { calls++; return failure }
	retainAPKPayload = false
	for _, command := range []*cobra.Command{uninstallCmd, preparePackageRemovalCmd} {
		t.Run(command.CommandPath(), func(t *testing.T) {
			before := calls
			if err := rootCmd.PersistentPreRunE(command, nil); !errors.Is(err, failure) || calls != before+1 {
				t.Fatalf("root did not preserve the launcher removal refusal: calls=%d error=%v", calls-before, err)
			}
		})
	}
	retainAPKPayload = true
	before := calls
	if err := rootCmd.PersistentPreRunE(preparePackageRemovalCmd, nil); err != nil || calls != before {
		t.Fatal("evidence-only APK retention entered complete removal preflight", err)
	}
}
