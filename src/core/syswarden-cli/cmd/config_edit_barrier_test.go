package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

func TestPendingConfigEditStopsLifecycleBeforeOtherPreflight(t *testing.T) {
	oldEdit, oldPolicy, oldRecovery, oldLoad := refusePendingModuleEditHook, preflightWireGuardPolicyTransition, recoverPendingFirewallTransactionHook, initConfigHook
	t.Cleanup(func() {
		refusePendingModuleEditHook, preflightWireGuardPolicyTransition, recoverPendingFirewallTransactionHook, initConfigHook = oldEdit, oldPolicy, oldRecovery, oldLoad
	})
	pending := errors.New("unresolved configuration edit")
	refusePendingModuleEditHook = func() error { return pending }
	preflightWireGuardPolicyTransition = func() error { t.Fatal("edit barrier reached WireGuard preflight"); return nil }
	recoverPendingFirewallTransactionHook = func() error { t.Fatal("edit barrier reached firewall recovery"); return nil }
	initConfigHook = func() { t.Fatal("edit barrier loaded or normalized configuration") }
	for _, name := range []string{"install", "reload", "update", "uninstall", "prepare-package-removal", "update-feeds", "whitelist", "block", "ha-sync"} {
		t.Run(name, func(t *testing.T) {
			parent := &cobra.Command{Use: "syswarden"}
			command := &cobra.Command{Use: name}
			parent.AddCommand(command)
			if err := rootCmd.PersistentPreRunE(command, nil); !errors.Is(err, pending) {
				t.Fatalf("missing first edit barrier: %v", err)
			}
		})
	}
	if err := rootCmd.PersistentPreRunE(configCmd, nil); !errors.Is(err, pending) {
		t.Fatalf("menu missed edit barrier: %v", err)
	}
}
