package cmd

import (
	"errors"
	"github.com/spf13/cobra"
	"testing"
)

func TestWireGuardPolicyTransitionStopsLifecycleBeforePreparation(t *testing.T) {
	oldPolicy, oldInit, oldRecovery := preflightWireGuardPolicyTransition, initConfigHook, recoverPendingFirewallTransactionHook
	oldUninstall := preflightUninstall
	t.Cleanup(func() {
		preflightWireGuardPolicyTransition, initConfigHook, recoverPendingFirewallTransactionHook = oldPolicy, oldInit, oldRecovery
		preflightUninstall = oldUninstall
	})
	failure := errors.New("unaccepted file transition")
	preflightWireGuardPolicyTransition = func() error { return failure }
	initConfigHook = func() { t.Fatal("loaded configuration while policy transaction was pending") }
	recoverPendingFirewallTransactionHook = func() error { t.Fatal("recovered firewall while policy transaction was pending"); return nil }
	preflightUninstall = func() error {
		t.Fatal("started uninstall preparation while policy transaction was pending")
		return nil
	}
	for _, command := range []*cobra.Command{installCmd, reloadCmd, updateCmd, uninstallCmd, preparePackageRemovalCmd} {
		t.Run(command.Name(), func(t *testing.T) {
			if err := rootCmd.PersistentPreRunE(command, nil); !errors.Is(err, failure) {
				t.Fatalf("early policy refusal lost: %v", err)
			}
		})
	}
}

func TestWireGuardPolicyTransitionRetainsReadOnlyAssessment(t *testing.T) {
	old := preflightWireGuardPolicyTransition
	t.Cleanup(func() { preflightWireGuardPolicyTransition = old })
	preflightWireGuardPolicyTransition = func() error { t.Fatal("read-only command queried lifecycle guard"); return nil }
	for _, name := range []string{"help", "audit", "check", "config-get", "list", "recover-wireguard"} {
		if err := enforceWireGuardPolicyTransition(syntheticCommandPath(name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWireGuardPolicyTransitionStopsDirectLifecycleBeforeMutation(t *testing.T) {
	oldPolicy, oldBegin, oldPrepare, oldDeps := preflightWireGuardPolicyTransition, beginRemoval, prepareFirewallStateForRemoval, installDependenciesForInstall
	t.Cleanup(func() {
		preflightWireGuardPolicyTransition, beginRemoval, prepareFirewallStateForRemoval, installDependenciesForInstall = oldPolicy, oldBegin, oldPrepare, oldDeps
	})
	failure := errors.New("policy requires host acceptance")
	preflightWireGuardPolicyTransition = func() error { return failure }
	forbidden := func() error { t.Fatal("lifecycle crossed a pending policy transition"); return nil }
	beginRemoval, prepareFirewallStateForRemoval, installDependenciesForInstall = forbidden, forbidden, forbidden
	for name, run := range map[string]func() error{
		"install":        func() error { return installCmd.RunE(installCmd, nil) },
		"reload":         func() error { return reloadCmd.RunE(reloadCmd, nil) },
		"shared-removal": prepareVerifiedFirewallRemoval,
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(); !errors.Is(err, failure) {
				t.Fatalf("policy refusal lost: %v", err)
			}
		})
	}
}

func TestWireGuardPolicyTransitionStopsRemovalRecoveryApplyOnly(t *testing.T) {
	old := preflightWireGuardPolicyTransition
	t.Cleanup(func() { preflightWireGuardPolicyTransition = old })
	failure := errors.New("pending policy debt")
	calls := 0
	preflightWireGuardPolicyTransition = func() error { calls++; return failure }
	command := newRecoverRemovalCommand()
	root := &cobra.Command{Use: "syswarden"}
	root.AddCommand(command)
	if err := enforceWireGuardPolicyTransition(command); err != nil || calls != 0 {
		t.Fatal("dry-run blocked", err)
	}
	if err := command.Flags().Set("apply", "true"); err != nil {
		t.Fatal(err)
	}
	if err := rootCmd.PersistentPreRunE(command, nil); !errors.Is(err, failure) {
		t.Fatalf("recovery preparation guard lost: %v", err)
	}
	if err := command.RunE(command, nil); !errors.Is(err, failure) {
		t.Fatalf("direct recovery apply guard lost: %v", err)
	}
	if calls != 2 {
		t.Fatalf("unexpected guard calls: %d", calls)
	}
}
