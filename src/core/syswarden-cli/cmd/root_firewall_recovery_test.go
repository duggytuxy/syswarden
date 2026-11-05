package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootRequiresActivationApprovalBeforeRecoveryOrNormalization_SW_FW_005(t *testing.T) {
	previousInspect := inspectRemovalTombstone
	previousRecovery := recoverPendingFirewallTransactionHook
	previousInit := initConfigHook
	previousApproval := prepareConfigurationActivationHook
	t.Cleanup(func() {
		inspectRemovalTombstone = previousInspect
		recoverPendingFirewallTransactionHook = previousRecovery
		initConfigHook = previousInit
		prepareConfigurationActivationHook = previousApproval
	})
	inspectRemovalTombstone = func() (bool, error) { return false, nil }
	sentinel := errors.New("synthetic approval refusal")
	prepareConfigurationActivationHook = func(*cobra.Command) error { return sentinel }
	recoverPendingFirewallTransactionHook = func() error { t.Fatal("recovery preceded activation approval"); return nil }
	initConfigHook = func() { t.Fatal("normalization preceded activation approval") }
	if err := rootCmd.PersistentPreRunE(reloadCmd, nil); !errors.Is(err, sentinel) {
		t.Fatalf("approval refusal=%v", err)
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
		"runtime-unblock",
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
	for _, command := range []string{"audit", "check", "config-get", "list", "manual", "recover-wireguard"} {
		if _, required := earlyFirewallRecoveryCommands[command]; required {
			t.Errorf("read-only command %q unexpectedly requires mutating firewall recovery", command)
		}
	}
}

func TestEarlyFirewallRecoveryDistinguishesConfigurationMutations_SW_FW_005(t *testing.T) {
	if commandRequiresEarlyFirewallRecovery(configCmd) {
		t.Fatal("opening the configuration menu unexpectedly requires mutating firewall recovery")
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
