//go:build linux

package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"syswarden-cli/pkg/system"
)

func TestActivationOperationScopeCannotPromoteReloadToInstall(t *testing.T) {
	for _, test := range []struct {
		approved, requested string
		allowed             bool
	}{
		{"install", "install", true}, {"install", "reload", true}, {"reload", "reload", true},
		{"reload", "install", false}, {"", "install", false}, {"profile", "reload", false}, {"install", "ssh", false},
	} {
		if got := activationOperationAllowed(test.approved, test.requested); got != test.allowed {
			t.Fatalf("%q -> %q: %t", test.approved, test.requested, got)
		}
	}
	if activationOperation(&cobra.Command{Use: "install"}) != "" {
		t.Fatal("name-only lookalike acquired activation authority")
	}
}

func TestActivationApprovalPrecedesEveryRootMutation(t *testing.T) {
	previousPrepare := prepareConfigurationActivationHook
	previousServices := prepareNativeServicesForInstall
	previousRemoval := inspectRemovalTombstone
	previousModule := refusePendingModuleEditHook
	previousWireGuard := preflightWireGuardPolicyTransition
	previousRecover := recoverPendingFirewallTransactionHook
	previousConfig := initConfigHook
	previousLegacy := preflightLegacyWireGuardForInstall
	t.Cleanup(func() {
		prepareConfigurationActivationHook = previousPrepare
		prepareNativeServicesForInstall = previousServices
		inspectRemovalTombstone = previousRemoval
		refusePendingModuleEditHook = previousModule
		preflightWireGuardPolicyTransition = previousWireGuard
		recoverPendingFirewallTransactionHook = previousRecover
		initConfigHook = previousConfig
		preflightLegacyWireGuardForInstall = previousLegacy
	})
	t.Setenv("SYSWARDEN_PKG_INSTALL", "")
	t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "")
	inspectRemovalTombstone = func() (bool, error) { return false, nil }
	refusePendingModuleEditHook = func() error { return nil }
	preflightWireGuardPolicyTransition = func() error { return nil }
	preflightLegacyWireGuardForInstall = func() error { return nil }
	prepareNativeServicesForInstall = func() (*system.NativeServiceInstallation, error) { return nil, nil }
	recoverPendingFirewallTransactionHook = func() error { t.Fatal("unapproved policy reached automatic recovery"); return nil }
	initConfigHook = func() { t.Fatal("unapproved policy reached normalizing parser") }
	refusal := errors.New("explicit approval is absent")
	prepareConfigurationActivationHook = func(*cobra.Command) error { return refusal }
	for _, command := range []*cobra.Command{installCmd, reloadCmd, configActivateCmd} {
		command.SetContext(context.Background())
		if err := rootCmd.PersistentPreRunE(command, nil); !errors.Is(err, refusal) {
			t.Fatalf("%s: %v", command.CommandPath(), err)
		}
	}
}

func TestRuntimeCommandsCannotConsumeUnapprovedEditedTOML(t *testing.T) {
	previousConsume := consumeApprovedOperationalConfigurationHook
	previousRecovery := recoverPendingFirewallTransactionHook
	previousRemoval := inspectRemovalTombstone
	previousModule := refusePendingModuleEditHook
	previousWireGuard := preflightWireGuardPolicyTransition
	t.Cleanup(func() {
		consumeApprovedOperationalConfigurationHook = previousConsume
		recoverPendingFirewallTransactionHook = previousRecovery
		inspectRemovalTombstone = previousRemoval
		refusePendingModuleEditHook = previousModule
		preflightWireGuardPolicyTransition = previousWireGuard
	})
	inspectRemovalTombstone = func() (bool, error) { return false, nil }
	refusePendingModuleEditHook = func() error { return nil }
	preflightWireGuardPolicyTransition = func() error { return nil }
	refusal := errors.New("changed policy requires explicit approval")
	consumeApprovedOperationalConfigurationHook = func(*cobra.Command) error { return refusal }
	recoverPendingFirewallTransactionHook = func() error { t.Fatal("unapproved runtime command recovered firewall"); return nil }
	for _, name := range []string{"update-feeds", "ha-sync", "block", "unblock", "whitelist", "tui"} {
		command, _, err := rootCmd.Find([]string{name})
		if err != nil {
			t.Fatal(err)
		}
		command.SetContext(context.Background())
		if err := rootCmd.PersistentPreRunE(command, nil); !errors.Is(err, refusal) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestActivationPlanBindsOperationAndAdministratorContext(t *testing.T) {
	plan := configurationActivationPlan{Schema: "syswarden-command-activation-plan-v1", Operation: "install", PolicySHA256: "policy", PreviousApprovalSHA256: "previous", HostSHA256: "host", ObservationSHA256: "observed", SSHConnectionSHA256: "ssh"}
	original, err := activationPlanDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(*configurationActivationPlan){
		func(p *configurationActivationPlan) { p.Operation = "reload" }, func(p *configurationActivationPlan) { p.NoRestart = true },
		func(p *configurationActivationPlan) { p.PolicySHA256 = "changed" }, func(p *configurationActivationPlan) { p.PreviousApprovalSHA256 = "changed" },
		func(p *configurationActivationPlan) { p.HostSHA256 = "changed" }, func(p *configurationActivationPlan) { p.ObservationSHA256 = "changed" },
		func(p *configurationActivationPlan) { p.SSHConnectionSHA256 = "changed" }, func(p *configurationActivationPlan) { p.SSHClientSHA256 = "changed" },
	} {
		copy := plan
		mutation(&copy)
		digest, err := activationPlanDigest(copy)
		if err != nil || digest == original {
			t.Fatalf("plan binding lost: %v", err)
		}
	}
	t.Setenv("SSH_CONNECTION", "fixture-only-connection")
	before := activationEnvironmentDigest("SSH_CONNECTION")
	t.Setenv("SSH_CONNECTION", "different-fixture-connection")
	if before == activationEnvironmentDigest("SSH_CONNECTION") {
		t.Fatal("changed administrator context accepted")
	}
}

func TestNoRestartCannotMintNarrowApprovalThenBroadenIt(t *testing.T) {
	if err := validateActivationApprovalRestartScope(true, "reviewed-plan"); err == nil {
		t.Fatal("no-restart created a new approval")
	}
	if err := validateActivationApprovalRestartScope(true, ""); err != nil {
		t.Fatal(err)
	}
	if err := validateActivationApprovalRestartScope(false, "reviewed-plan"); err != nil {
		t.Fatal(err)
	}
}

func TestPreviouslyApprovedActivationCanRecoverWithoutNormalization(t *testing.T) {
	previousApproval := prepareConfigurationActivationHook
	previousRecovery := recoverPendingFirewallTransactionHook
	previousRemoval := inspectRemovalTombstone
	previousModule := refusePendingModuleEditHook
	previousWireGuard := preflightWireGuardPolicyTransition
	previousInit := initConfigHook
	t.Cleanup(func() {
		prepareConfigurationActivationHook = previousApproval
		recoverPendingFirewallTransactionHook = previousRecovery
		inspectRemovalTombstone = previousRemoval
		refusePendingModuleEditHook = previousModule
		preflightWireGuardPolicyTransition = previousWireGuard
		initConfigHook = previousInit
	})
	inspectRemovalTombstone = func() (bool, error) { return false, nil }
	refusePendingModuleEditHook = func() error { return nil }
	preflightWireGuardPolicyTransition = func() error { return nil }
	approved := false
	prepareConfigurationActivationHook = func(*cobra.Command) error { approved = true; return nil }
	failure := errors.New("owned recovery failed")
	recoverPendingFirewallTransactionHook = func() error {
		if !approved {
			t.Fatal("recovery ran without authority")
		}
		return failure
	}
	initConfigHook = func() { t.Fatal("approved activation reparsed mutable configuration") }
	if err := rootCmd.PersistentPreRunE(reloadCmd, nil); !errors.Is(err, failure) {
		t.Fatalf("recovery failure lost: %v", err)
	}
}

func TestActiveNativeInstallRefusesBeforeServiceQueries(t *testing.T) {
	oldManager, oldServices, oldRemoval, oldModule, oldWG := inspectActivationServiceManagerState, prepareNativeServicesForInstall, inspectRemovalTombstone, refusePendingModuleEditHook, preflightWireGuardPolicyTransition
	t.Cleanup(func() {
		inspectActivationServiceManagerState, prepareNativeServicesForInstall, inspectRemovalTombstone, refusePendingModuleEditHook, preflightWireGuardPolicyTransition = oldManager, oldServices, oldRemoval, oldModule, oldWG
	})
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	t.Setenv("SYSWARDEN_NATIVE_INSTALL_PHASE", "upgrade")
	t.Setenv("SYSWARDEN_OFFLINE_QUALIFICATION", "")
	inspectActivationServiceManagerState = func() (string, error) { return "ACTIVE", nil }
	prepareNativeServicesForInstall = func() (*system.NativeServiceInstallation, error) {
		t.Fatal("unapproved native hook queried services")
		return nil, nil
	}
	inspectRemovalTombstone = func() (bool, error) { return false, nil }
	refusePendingModuleEditHook = func() error { return nil }
	preflightWireGuardPolicyTransition = func() error { return nil }
	installCmd.SetContext(context.Background())
	if err := rootCmd.PersistentPreRunE(installCmd, nil); err == nil {
		t.Fatal("active package install bypassed explicit candidate review")
	}
	inspectActivationServiceManagerState = func() (string, error) { return "OFFLINE", nil }
	if err := refuseUnapprovedActiveNativeInstall(); err != nil {
		t.Fatalf("offline staging incorrectly refused: %v", err)
	}
	want := errors.New("ambiguous runtime")
	inspectActivationServiceManagerState = func() (string, error) { return "OFFLINE", want }
	if err := refuseUnapprovedActiveNativeInstall(); !errors.Is(err, want) {
		t.Fatalf("runtime error ignored: %v", err)
	}
}
