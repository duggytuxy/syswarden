package cmd

import (
	"bytes"
	"os"
	"path/filepath"
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
