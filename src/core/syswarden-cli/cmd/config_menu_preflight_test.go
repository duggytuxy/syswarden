package cmd

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"syswarden-cli/config"

	"github.com/spf13/cobra"
)

func preserveConfigMenuPreflightHooks(t *testing.T) {
	t.Helper()
	oldPolicy, oldFirewall := preflightWireGuardPolicyTransition, refusePendingFirewallTransactionHook
	oldRecovery, oldInit := recoverPendingFirewallTransactionHook, initConfigHook
	oldRemoval, oldEditor := inspectRemovalTombstone, launchConfigEditor
	oldRoot := configEditorRoot
	oldInput, oldOutput, oldError := configCmd.InOrStdin(), configCmd.OutOrStdout(), configCmd.ErrOrStderr()
	configCmd.SetOut(nil)
	configCmd.SetErr(nil)
	t.Cleanup(func() {
		preflightWireGuardPolicyTransition, refusePendingFirewallTransactionHook = oldPolicy, oldFirewall
		recoverPendingFirewallTransactionHook, initConfigHook = oldRecovery, oldInit
		inspectRemovalTombstone, launchConfigEditor = oldRemoval, oldEditor
		configEditorRoot = oldRoot
		configCmd.SetIn(oldInput)
		configCmd.SetOut(oldOutput)
		configCmd.SetErr(oldError)
	})
	initConfigHook = func() { t.Fatal("menu preflight loaded or normalized runtime configuration") }
	recoverPendingFirewallTransactionHook = func() error {
		t.Fatal("menu preflight ran mutating firewall recovery")
		return nil
	}
	launchConfigEditor = func(string, string, io.Reader, io.Writer, io.Writer) error {
		t.Fatal("menu opening invoked an editor before a selection")
		return nil
	}
}

func TestConfigMenuCobraLifecyclePreservesHistoricalAndInvalidModules(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		name := "historical"
		if invalid {
			name = "invalid_toml_repair"
		}
		t.Run(name, func(t *testing.T) {
			preserveConfigMenuPreflightHooks(t)
			root := filepath.Join(t.TempDir(), "config")
			if err := config.InitializeDefaults(root); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "modules", "40-integrations.toml"), readV4028CommandFixture(t, "40-integrations.toml"), 0600); err != nil {
				t.Fatal(err)
			}
			if invalid {
				if err := os.WriteFile(filepath.Join(root, "modules", "99-user.toml"), []byte("[network\ninvalid TOML\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			configEditorRoot = root
			configCmd.SetIn(strings.NewReader("0\n"))
			before := snapshotRegularFiles(t, root)
			globalBefore, loadBefore := config.GlobalConfig, config.CurrentLoadState()
			var calls []string
			preflightWireGuardPolicyTransition = func() error { calls = append(calls, "wireguard"); return nil }
			refusePendingFirewallTransactionHook = func() error { calls = append(calls, "firewall"); return nil }
			output, err := executeRootCobraLifecycle(t, []string{"config"}, initConfigHook)
			if err != nil {
				t.Fatalf("repair menu did not open: %v", err)
			}
			if !strings.Contains(output, "Modular Configuration Editor") || !strings.Contains(output, "Exiting Configuration Editor") {
				t.Fatalf("menu was not entered and exited: %q", output)
			}
			if !reflect.DeepEqual(calls, []string{"wireguard", "firewall"}) {
				t.Fatalf("read-only barriers = %v", calls)
			}
			if after := snapshotRegularFiles(t, root); !reflect.DeepEqual(before, after) {
				t.Fatal("opening and exiting the menu changed configuration files")
			}
			if config.GlobalConfig != globalBefore || !reflect.DeepEqual(config.CurrentLoadState(), loadBefore) {
				t.Fatal("menu opening changed process-wide runtime configuration state")
			}
		})
	}
}

func TestConfigMenuPreflightRetainsOrderedRecoveryBarriers(t *testing.T) {
	for _, failureAt := range []string{"none", "wireguard", "removal_present", "removal_error", "firewall"} {
		t.Run(failureAt, func(t *testing.T) {
			preserveConfigMenuPreflightHooks(t)
			failure := errors.New("synthetic unsafe recovery state")
			var calls []string
			preflightWireGuardPolicyTransition = func() error {
				calls = append(calls, "wireguard")
				if failureAt == "wireguard" {
					return failure
				}
				return nil
			}
			inspectRemovalTombstone = func() (bool, error) {
				calls = append(calls, "removal")
				if failureAt == "removal_error" {
					return false, failure
				}
				return failureAt == "removal_present", nil
			}
			refusePendingFirewallTransactionHook = func() error {
				calls = append(calls, "firewall")
				if failureAt == "firewall" {
					return failure
				}
				return nil
			}
			err := rootCmd.PersistentPreRunE(configCmd, nil)
			if failureAt == "none" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unsafe recovery state did not stop menu preparation")
			} else if failureAt != "removal_present" && !errors.Is(err, failure) {
				t.Fatalf("underlying refusal was lost: %v", err)
			}
			want := []string{"wireguard", "removal", "firewall"}
			if failureAt == "wireguard" {
				want = want[:1]
			} else if strings.HasPrefix(failureAt, "removal_") {
				want = want[:2]
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("preflight order = %v, want %v", calls, want)
			}
		})
	}
}

func TestConfigMenuPreflightIsExactAndPreservesChildPolicies(t *testing.T) {
	preserveConfigMenuPreflightHooks(t)
	preflightWireGuardPolicyTransition = func() error { t.Fatal("non-menu command crossed the new menu WireGuard barrier"); return nil }
	refusePendingFirewallTransactionHook = func() error { t.Fatal("non-menu command crossed the new menu firewall barrier"); return nil }
	inspectRemovalTombstone = func() (bool, error) { return false, nil }
	if commandRequiresAutomaticConfigLoad(configCmd) || commandRequiresEarlyFirewallRecovery(configCmd) {
		t.Fatal("exact menu still prepares runtime configuration or recovery")
	}
	if commandAllowedDuringRemoval(configCmd) {
		t.Fatal("menu unexpectedly bypasses incomplete removal")
	}
	for _, command := range []*cobra.Command{configGetCmd, configValidateCmd, configMigrateCmd, migrateConfigCmd} {
		t.Run(command.CommandPath(), func(t *testing.T) {
			if commandRequiresAutomaticConfigLoad(command) {
				t.Fatal("configuration child lost its existing explicit-load policy")
			}
			if err := enforceWireGuardPolicyTransition(command); err != nil {
				t.Fatal(err)
			}
			if command == configMigrateCmd || command == migrateConfigCmd {
				preserveCommandFlags(t, command, "dry-run")
				if err := command.Flags().Set("dry-run", "false"); err != nil {
					t.Fatal(err)
				}
				if !commandRequiresEarlyFirewallRecovery(command) {
					t.Fatal("mutation lost its existing firewall recovery barrier")
				}
				if err := command.Flags().Set("dry-run", "true"); err != nil {
					t.Fatal(err)
				}
			}
			if commandRequiresEarlyFirewallRecovery(command) {
				t.Fatal("read-only child unexpectedly requires firewall recovery")
			}
			if err := rootCmd.PersistentPreRunE(command, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
	lookalike := syntheticCommandPath("config")
	if !commandRequiresAutomaticConfigLoad(lookalike) {
		t.Fatal("a same-named command acquired the exact menu exemption")
	}
	if err := enforceWireGuardPolicyTransition(lookalike); err != nil {
		t.Fatal(err)
	}
}
