package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootRunsFirewallRecoveryBeforeAutomaticConfigLoad_SW_FW_005(t *testing.T) {
	previousRecovery := recoverPendingFirewallTransactionHook
	previousInit := initConfigHook
	t.Cleanup(func() {
		recoverPendingFirewallTransactionHook = previousRecovery
		initConfigHook = previousInit
	})

	sentinel := errors.New("synthetic early recovery failure")
	recoverPendingFirewallTransactionHook = func() error { return sentinel }
	initCalled := false
	initConfigHook = func() { initCalled = true }

	err := rootCmd.PersistentPreRunE(reloadCmd, nil)
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("early recovery error = %v, want sentinel", err)
	}
	if initCalled {
		t.Fatal("automatic configuration load ran before early firewall recovery")
	}
}

func TestEarlyFirewallRecoveryCommandScope_SW_FW_005(t *testing.T) {
	for _, command := range []string{
		"allow-ssh",
		"block",
		"ha-sync",
		"install",
		"prepare-package-removal",
		"reload",
		"revoke-ssh",
		"tui",
		"unblock",
		"uninstall",
		"unwhitelist",
		"update",
		"update-feeds",
		"whitelist",
		"whitelist-infra",
	} {
		if _, required := earlyFirewallRecoveryCommands[command]; !required {
			t.Errorf("mutating command %q is missing the early firewall recovery barrier", command)
		}
	}
	for _, command := range []string{"audit", "check", "config-get", "list", "manual"} {
		if _, required := earlyFirewallRecoveryCommands[command]; required {
			t.Errorf("read-only command %q unexpectedly requires mutating firewall recovery", command)
		}
	}
}

func TestEarlyFirewallRecoveryDistinguishesConfigurationMutations_SW_FW_005(t *testing.T) {
	if !commandRequiresEarlyFirewallRecovery(configCmd) {
		t.Fatal("interactive configuration mutation is missing the early firewall recovery barrier")
	}
	if commandRequiresEarlyFirewallRecovery(configValidateCmd) {
		t.Fatal("read-only configuration validation unexpectedly requires mutating firewall recovery")
	}

	for _, command := range []*cobra.Command{configMigrateCmd, migrateConfigCmd} {
		flag := command.Flags().Lookup("dry-run")
		if flag == nil {
			t.Fatalf("%s is missing --dry-run", command.CommandPath())
		}
		previous := flag.Value.String()
		t.Cleanup(func() { _ = command.Flags().Set("dry-run", previous) })

		if err := command.Flags().Set("dry-run", "false"); err != nil {
			t.Fatal(err)
		}
		if !commandRequiresEarlyFirewallRecovery(command) {
			t.Errorf("%s mutation is missing the early firewall recovery barrier", command.CommandPath())
		}
		if err := command.Flags().Set("dry-run", "true"); err != nil {
			t.Fatal(err)
		}
		if commandRequiresEarlyFirewallRecovery(command) {
			t.Errorf("%s --dry-run unexpectedly requires mutating firewall recovery", command.CommandPath())
		}
	}
}
