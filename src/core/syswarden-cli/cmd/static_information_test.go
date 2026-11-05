package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/spf13/cobra"
	"syswarden-cli/config"
	"syswarden-cli/pkg/system"
)

func TestStaticInformationCobraLifecycleDoesNotNormalizeConfiguration(t *testing.T) {
	cases := [][]string{{}, {"manual"}, {"--help"}, {"help", "install"}, {"completion", "bash"}, {"completion", "zsh"}, {"completion", "fish"}, {"completion", "powershell"}, {"__complete", ""}, {"__completeNoDesc", ""}}
	for _, args := range cases {
		t.Run(fmt.Sprintf("%q", args), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "config")
			if err := config.InitializeDefaults(root); err != nil {
				t.Fatal(err)
			}
			fixture := readV4028CommandFixture(t, "40-integrations.toml")
			if !bytes.Contains(fixture, []byte("[integrations.ha]\nenabled = true")) {
				t.Fatal("fixture no longer exercises historical normalization")
			}
			if err := os.WriteFile(filepath.Join(root, "modules", "40-integrations.toml"), fixture, 0600); err != nil {
				t.Fatal(err)
			}
			before := snapshotRegularFiles(t, root)
			globalBefore, stateBefore := config.GlobalConfig, config.CurrentLoadState()
			initializations := 0
			_, err := executeRootCobraLifecycle(t, args, func() { initializations++; _ = config.ParseConfig(root) })
			if err != nil {
				t.Fatal(err)
			}
			if initializations != 0 {
				t.Fatalf("static information loaded configuration %d times", initializations)
			}
			if after := snapshotRegularFiles(t, root); !reflect.DeepEqual(before, after) {
				t.Fatal("static information changed administrator configuration")
			}
			if config.GlobalConfig != globalBefore || !reflect.DeepEqual(config.CurrentLoadState(), stateBefore) {
				t.Fatal("static information replaced process configuration")
			}
		})
	}
}

func TestStaticInformationSkipsRecoveryAndServicePreparation(t *testing.T) {
	oldInit, oldRemoval, oldPolicy, oldRecovery, oldService := initConfigHook, inspectRemovalTombstone, preflightWireGuardPolicyTransition, recoverPendingFirewallTransactionHook, prepareNativeServicesForInstall
	t.Cleanup(func() {
		initConfigHook, inspectRemovalTombstone, preflightWireGuardPolicyTransition, recoverPendingFirewallTransactionHook, prepareNativeServicesForInstall = oldInit, oldRemoval, oldPolicy, oldRecovery, oldService
	})
	initConfigHook = func() { t.Fatal("static command initialized policy") }
	inspectRemovalTombstone = func() (bool, error) { t.Fatal("static command queried removal state"); return false, nil }
	preflightWireGuardPolicyTransition = func() error { t.Fatal("static command queried WireGuard transition"); return nil }
	recoverPendingFirewallTransactionHook = func() error { t.Fatal("static command recovered firewall state"); return nil }
	prepareNativeServicesForInstall = func() (*system.NativeServiceInstallation, error) {
		t.Fatal("static command prepared service state")
		return nil, nil
	}
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()
	for _, args := range [][]string{{}, {"manual"}, {"help"}, {"completion"}, {"completion", "bash"}} {
		command, _, err := rootCmd.Find(args)
		if err != nil {
			t.Fatal(err)
		}
		if err := rootCmd.PersistentPreRunE(command, nil); err != nil {
			t.Fatal(err)
		}
		if commandRequiresAutomaticConfigLoad(command) {
			t.Fatal("static command still requests automatic config")
		}
	}
}

func TestStaticInformationClassificationDoesNotHideOperationalCommands(t *testing.T) {
	if staticInformationCommand(nil) {
		t.Fatal("nil command is not a static entry")
	}
	for _, name := range []string{"audit", "alerts", "list", "install", "reload", "config"} {
		command, _, err := rootCmd.Find([]string{name})
		if err != nil {
			t.Fatal(err)
		}
		if staticInformationCommand(command) {
			t.Fatalf("operational command %s bypasses preparation", name)
		}
	}
	foreign := &cobra.Command{Use: "foreign"}
	completion := &cobra.Command{Use: "completion"}
	foreign.AddCommand(completion)
	for _, command := range []*cobra.Command{foreign, completion, &cobra.Command{Use: "manual"}, &cobra.Command{Use: "syswarden"}} {
		if staticInformationCommand(command) {
			t.Fatal("foreign static-looking command bypasses preparation")
		}
	}
}
