package cmd

import (
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"reflect"
	"syswarden-cli/config"
	"testing"
)

func TestOperationalInspectionCobraLoadsWithoutPersistentNormalization(t *testing.T) {
	for _, name := range []string{"audit", "alerts", "check", "list"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "config")
			if err := config.InitializeDefaults(root); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "modules", "40-integrations.toml"), readV4028CommandFixture(t, "40-integrations.toml"), 0600); err != nil {
				t.Fatal(err)
			}
			before := snapshotRegularFiles(t, root)
			command, _, err := rootCmd.Find([]string{name})
			if err != nil {
				t.Fatal(err)
			}
			oldRun, oldRunE, oldLoad, oldRecovery, oldGlobal := command.Run, command.RunE, initInspectionConfigHook, recoverPendingFirewallTransactionHook, config.GlobalConfig
			t.Cleanup(func() {
				command.Run, command.RunE = oldRun, oldRunE
				initInspectionConfigHook = oldLoad
				recoverPendingFirewallTransactionHook = oldRecovery
				config.GlobalConfig = oldGlobal
			})
			loads, runs := 0, 0
			initInspectionConfigHook = func() {
				loads++
				if err := config.ParseConfigForInspection(root); err != nil {
					t.Fatal(err)
				}
			}
			recoverPendingFirewallTransactionHook = func() error { t.Fatal("inspection ran firewall recovery"); return nil }
			command.Run = nil
			command.RunE = func(*cobra.Command, []string) error { runs++; return nil }
			args := []string{name}
			if name == "check" {
				args = append(args, "192.0.2.9")
			}
			_, err = executeRootCobraLifecycle(t, args, func() { t.Fatal("inspection selected mutating configuration load") })
			if err != nil {
				t.Fatal(err)
			}
			if loads != 1 || runs != 1 || config.GlobalConfig.HAEnabled {
				t.Fatal("inspection did not reach its reader with validated safe policy")
			}
			if !reflect.DeepEqual(before, snapshotRegularFiles(t, root)) {
				t.Fatal("Cobra inspection changed administrator bytes")
			}
		})
	}
}

func TestOperationalInspectionClassificationIsBounded(t *testing.T) {
	for _, name := range []string{"install", "reload", "update", "uninstall", "block", "manual", "config"} {
		command, _, err := rootCmd.Find([]string{name})
		if err != nil {
			t.Fatal(err)
		}
		if configurationInspectionCommand(command) {
			t.Fatalf("%s was classified as operational inspection", name)
		}
	}
	for _, command := range []*cobra.Command{nil, &cobra.Command{Use: "audit"}, &cobra.Command{Use: "list"}} {
		if configurationInspectionCommand(command) {
			t.Fatal("foreign command acquired inspection classification")
		}
	}
}
