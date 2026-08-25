package cmd

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"syswarden-cli/config"

	"github.com/spf13/cobra"
)

func TestDegradedConfigurationGuardExitsBeforeMutation_SW_CFG_001(t *testing.T) {
	temporary := t.TempDir()
	valid := filepath.Join(temporary, "valid.conf")
	if err := os.WriteFile(valid, []byte("SYSWARDEN_HA_ENABLED=n\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = config.ParseConfig(valid) })
	missing := filepath.Join(temporary, "missing.conf")
	if err := config.ParseConfig(missing); err == nil {
		t.Fatal("missing configuration unexpectedly loaded")
	}

	mutated := false
	probe := &cobra.Command{
		Use: "guard-mutation-probe",
		RunE: func(cmd *cobra.Command, args []string) error {
			mutated = true
			cmd.Println("Installation Complete")
			return nil
		},
	}
	testRoot := &cobra.Command{
		Use: "syswarden",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return enforceValidatedConfiguration(cmd)
		},
	}
	var output bytes.Buffer
	testRoot.SetOut(&output)
	testRoot.SetErr(&output)
	testRoot.AddCommand(probe)
	testRoot.SetArgs([]string{probe.Name()})
	_, err := testRoot.ExecuteC()
	if err == nil {
		t.Fatalf("degraded mutating command returned success:\n%s", output.String())
	}
	if mutated {
		t.Fatal("mutating hook ran before the degraded guard")
	}
	if !strings.Contains(err.Error(), "[ERROR] validated configuration is unavailable") {
		t.Fatalf("guard error was not explicit: %v", err)
	}
	if strings.Contains(output.String(), "Installation Complete") {
		t.Fatalf("degraded command emitted a false completion:\n%s", output.String())
	}
}

func TestDegradedConfigurationGuardHasExplicitRepairAllowlist_SW_CFG_001(t *testing.T) {
	valid := filepath.Join(t.TempDir(), "valid.conf")
	if err := os.WriteFile(valid, []byte("SYSWARDEN_HA_ENABLED=n\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = config.ParseConfig(valid) })
	missing := filepath.Join(t.TempDir(), "missing.conf")
	if err := config.ParseConfig(missing); err == nil {
		t.Fatal("missing configuration unexpectedly loaded")
	}
	testRoot := &cobra.Command{Use: "test-root"}
	for commandName := range degradedConfigAllowlist {
		command := &cobra.Command{Use: commandName}
		testRoot.AddCommand(command)
		if err := enforceValidatedConfiguration(command); err != nil {
			t.Errorf("repair/help command %s was blocked: %v", commandName, err)
		}
	}
	blocked := &cobra.Command{Use: "mutating-command"}
	testRoot.AddCommand(blocked)
	if err := enforceValidatedConfiguration(blocked); err == nil {
		t.Fatal("degraded guard accepted a command outside the repair/help allowlist")
	}
}

func executeRootCobraLifecycle(t *testing.T, args []string, initialize func()) (string, error) {
	t.Helper()
	previousInit := initConfigHook
	previousInspect := inspectRemovalTombstone
	previousSilenceErrors := rootCmd.SilenceErrors
	previousSilenceUsage := rootCmd.SilenceUsage
	initConfigHook = initialize
	inspectRemovalTombstone = func() (bool, error) { return false, nil }
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true
	var output bytes.Buffer
	rootCmd.SetOut(&output)
	rootCmd.SetErr(&output)
	rootCmd.SetArgs(args)
	t.Cleanup(func() {
		initConfigHook = previousInit
		inspectRemovalTombstone = previousInspect
		rootCmd.SilenceErrors = previousSilenceErrors
		rootCmd.SilenceUsage = previousSilenceUsage
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	})

	// ExecuteC deliberately exercises Cobra's complete lifecycle. Calling RunE
	// directly would miss the root PersistentPreRunE initialization policy and
	// would not protect the read-only contract against the original regression.
	_, err := rootCmd.ExecuteC()
	return output.String(), err
}

func preserveCommandFlags(t *testing.T, command *cobra.Command, names ...string) {
	t.Helper()
	for _, name := range names {
		flag := command.Flags().Lookup(name)
		if flag == nil {
			t.Fatalf("command %s is missing --%s", command.CommandPath(), name)
		}
		previousValue := flag.Value.String()
		previousChanged := flag.Changed
		t.Cleanup(func() {
			if err := flag.Value.Set(previousValue); err != nil {
				t.Errorf("restore --%s: %v", name, err)
			}
			flag.Changed = previousChanged
		})
	}
}

func readV4028CommandFixture(t *testing.T, name string) []byte {
	t.Helper()
	fixtureRoot, err := os.OpenRoot(filepath.Join("..", "config", "testdata", "v4.02.8"))
	if err != nil {
		t.Fatal(err)
	}
	content, readErr := fixtureRoot.ReadFile(name)
	closeErr := fixtureRoot.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	return content
}

func snapshotRegularFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	secureRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := secureRoot.Close(); err != nil {
			t.Errorf("close snapshot root: %v", err)
		}
	})
	if err := fs.WalkDir(secureRoot.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		content, err := secureRoot.ReadFile(path)
		if err != nil {
			return err
		}
		snapshot[path] = string(content)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestConfigValidateCobraLifecycleDoesNotNormalizeHistoricalModularFiles_SW_CFG_002(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := config.InitializeDefaults(root); err != nil {
		t.Fatal(err)
	}
	integrationPath := filepath.Join(root, "modules", "40-integrations.toml")
	fixture := readV4028CommandFixture(t, "40-integrations.toml")
	if !bytes.Contains(fixture, []byte("[integrations.ha]\nenabled = true")) ||
		bytes.Contains(fixture, []byte("[integrations.bunkerweb]")) {
		t.Fatal("v4.02.8 modular fixture no longer exercises persistent HA compatibility normalization")
	}
	if err := os.WriteFile(integrationPath, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	before := snapshotRegularFiles(t, root)
	initializations := 0
	var initializationErr error
	preserveCommandFlags(t, configValidateCmd, "path")
	_, err := executeRootCobraLifecycle(
		t,
		[]string{"config", "validate", "--path", root},
		func() {
			initializations++
			initializationErr = config.ParseConfig(root)
		},
	)
	if err != nil {
		t.Fatalf("config validate lifecycle error = %v", err)
	}
	if initializations != 0 {
		t.Fatalf("config validate ran %d automatic configuration initializations (last error: %v)", initializations, initializationErr)
	}
	if after := snapshotRegularFiles(t, root); !reflect.DeepEqual(after, before) {
		t.Fatalf("config validate changed historical modular bytes:\nbefore=%q\nafter=%q", before, after)
	}
}

func TestConfigMigrationDryRunCobraLifecycleDoesNotNormalizeHistoricalFiles_SW_CFG_002(t *testing.T) {
	tests := []struct {
		name               string
		command            *cobra.Command
		arguments          func(source, output string) []string
		withModularRuntime bool
	}{
		{
			name:    "config migrate",
			command: configMigrateCmd,
			arguments: func(source, output string) []string {
				return []string{"config", "migrate", "--source", source, "--output", output, "--dry-run"}
			},
		},
		{
			name:               "migrate-config compatibility alias",
			command:            migrateConfigCmd,
			withModularRuntime: true,
			arguments: func(source, output string) []string {
				return []string{"migrate-config", "--source", source, "--output", output, "--dry-run"}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "syswarden-auto.conf")
			legacyFixture := readV4028CommandFixture(t, "legacy-ha-default.conf")
			if !bytes.Contains(legacyFixture, []byte(`SYSWARDEN_HA_ENABLED="y"`)) ||
				bytes.Contains(legacyFixture, []byte("SYSWARDEN_BUNKERWEB_ENABLED=")) {
				t.Fatal("v4.02.8 legacy fixture no longer exercises persistent HA compatibility normalization")
			}
			if err := os.WriteFile(source, legacyFixture, 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(root, "migrated")
			initializationTarget := source
			var modularBefore map[string]string
			if test.withModularRuntime {
				initializationTarget = filepath.Join(root, "runtime-config")
				if err := config.InitializeDefaults(initializationTarget); err != nil {
					t.Fatal(err)
				}
				integrationPath := filepath.Join(initializationTarget, "modules", "40-integrations.toml")
				if err := os.WriteFile(integrationPath, readV4028CommandFixture(t, "40-integrations.toml"), 0600); err != nil {
					t.Fatal(err)
				}
				modularBefore = snapshotRegularFiles(t, initializationTarget)
			}

			initializations := 0
			var initializationErr error
			preserveCommandFlags(t, test.command, "source", "output", "dry-run")
			_, err := executeRootCobraLifecycle(t, test.arguments(source, output), func() {
				initializations++
				initializationErr = config.ParseConfig(initializationTarget)
			})
			if err != nil {
				t.Fatalf("%s --dry-run lifecycle error = %v", test.name, err)
			}
			if initializations != 0 {
				t.Fatalf("%s --dry-run ran %d automatic configuration initializations (last error: %v)", test.name, initializations, initializationErr)
			}
			afterSource, err := os.ReadFile(source) // #nosec G304 -- source is rooted in t.TempDir
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(afterSource, legacyFixture) {
				t.Fatalf("%s --dry-run changed historical legacy bytes", test.name)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("%s --dry-run created destination state: %v", test.name, err)
			}
			if test.withModularRuntime {
				if modularAfter := snapshotRegularFiles(t, initializationTarget); !reflect.DeepEqual(modularAfter, modularBefore) {
					t.Fatalf("%s --dry-run changed unrelated historical modular runtime bytes", test.name)
				}
			}
		})
	}
}

func TestRootCobraLifecycleStillInitializesNormalCommands_SW_CFG_001(t *testing.T) {
	const commandName = "config-initialization-probe"
	initializations := 0
	ran := false
	probe := &cobra.Command{
		Use: commandName,
		RunE: func(cmd *cobra.Command, args []string) error {
			ran = true
			return nil
		},
	}
	rootCmd.AddCommand(probe)
	degradedConfigAllowlist[commandName] = struct{}{}
	t.Cleanup(func() {
		rootCmd.RemoveCommand(probe)
		delete(degradedConfigAllowlist, commandName)
	})
	_, err := executeRootCobraLifecycle(t, []string{commandName}, func() { initializations++ })
	if err != nil {
		t.Fatalf("normal command lifecycle error = %v", err)
	}
	if initializations != 1 || !ran {
		t.Fatalf("normal lifecycle initialization/run = %d/%t, want 1/true", initializations, ran)
	}
	if !commandRequiresAutomaticConfigLoad(probe) {
		t.Fatal("normal command unexpectedly opted out of automatic configuration loading")
	}
}
