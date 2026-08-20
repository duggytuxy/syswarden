package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"syswarden-cli/config"
)

func TestConfigEditorExposesBunkerWebIntegrationModule_SW_CFG_002(t *testing.T) {
	if target := configEditorTarget(5); target != "40-integrations.toml" {
		t.Fatalf("integration editor target = %q, want 40-integrations.toml", target)
	}
}

func TestConfigCommandReturnsErrorWhenModulesAreUnavailable_SW_CFG_001(t *testing.T) {
	previousRoot := configEditorRoot
	configEditorRoot = filepath.Join(t.TempDir(), "missing-config")
	t.Cleanup(func() { configEditorRoot = previousRoot })
	var output bytes.Buffer
	configCmd.SetIn(strings.NewReader("0\n"))
	configCmd.SetOut(&output)
	if err := configCmd.RunE(configCmd, nil); err == nil {
		t.Fatal("config command reported success without a modules directory")
	}
	if strings.Contains(output.String(), "updated successfully") {
		t.Fatalf("missing modules emitted false success: %s", output.String())
	}
}

func TestConfigCommandPropagatesEditorFailureAndUsesExactIntegrationPath_SW_CFG_001(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := os.MkdirAll(filepath.Join(root, "modules"), 0750); err != nil {
		t.Fatal(err)
	}
	previousRoot := configEditorRoot
	previousLauncher := launchConfigEditor
	previousEditor, editorWasSet := os.LookupEnv("EDITOR")
	configEditorRoot = root
	if err := os.Setenv("EDITOR", "/test/failing-editor"); err != nil {
		t.Fatal(err)
	}
	var openedPath string
	launchConfigEditor = func(editor, targetPath string, stdin io.Reader, stdout, stderr io.Writer) error {
		openedPath = targetPath
		return errors.New("injected editor failure")
	}
	t.Cleanup(func() {
		configEditorRoot = previousRoot
		launchConfigEditor = previousLauncher
		if editorWasSet {
			_ = os.Setenv("EDITOR", previousEditor)
		} else {
			_ = os.Unsetenv("EDITOR")
		}
	})
	var output bytes.Buffer
	configCmd.SetIn(strings.NewReader("5\n"))
	configCmd.SetOut(&output)
	configCmd.SetErr(&output)
	err := configCmd.RunE(configCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "injected editor failure") {
		t.Fatalf("config editor error = %v", err)
	}
	want := filepath.Join(root, "modules", "40-integrations.toml")
	if openedPath != want {
		t.Fatalf("integration editor path = %q, want %q", openedPath, want)
	}
	if strings.Contains(output.String(), "updated successfully") {
		t.Fatalf("failed editor emitted false success: %s", output.String())
	}
}

func TestConfigValidateCommandReportsCurrentSchema_SW_CFG_002(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := config.InitializeDefaults(root); err != nil {
		t.Fatal(err)
	}
	flag := configValidateCmd.Flags().Lookup("path")
	previous := flag.Value.String()
	if err := configValidateCmd.Flags().Set("path", root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = configValidateCmd.Flags().Set("path", previous) })
	var output bytes.Buffer
	configValidateCmd.SetOut(&output)
	if err := configValidateCmd.RunE(configValidateCmd, nil); err != nil {
		t.Fatalf("config validate error = %v", err)
	}
	if !strings.Contains(output.String(), "Configuration is valid (schema: 1).") {
		t.Fatalf("config validate output = %q", output.String())
	}
}

func TestConfigMigrateDryRunAliasHasNoFilesystemSideEffects_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy.conf")
	destination := filepath.Join(root, "config")
	if err := os.WriteFile(source, []byte(config.DefaultConfig), 0600); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"source": source, "output": destination, "dry-run": "true"} {
		flag := configMigrateCmd.Flags().Lookup(name)
		previous := flag.Value.String()
		if err := configMigrateCmd.Flags().Set(name, value); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = configMigrateCmd.Flags().Set(name, previous) })
	}
	var output bytes.Buffer
	configMigrateCmd.SetOut(&output)
	if err := configMigrateCmd.RunE(configMigrateCmd, nil); err != nil {
		t.Fatalf("config migrate --dry-run error = %v", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("config migrate --dry-run created destination state: %v", err)
	}
	if _, _, err := rootCmd.Find([]string{"migrate-config"}); err != nil {
		t.Fatalf("legacy migrate-config alias is unavailable: %v", err)
	}
}

func TestConfigGetUsesValidatedDescriptorRootedLoader_SW_CFG_002(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := config.InitializeDefaults(root); err != nil {
		t.Fatal(err)
	}
	previousRoot := configGetRoot
	configGetRoot = root
	t.Cleanup(func() { configGetRoot = previousRoot })
	var output bytes.Buffer
	configGetCmd.SetOut(&output)
	if err := configGetCmd.RunE(configGetCmd, []string{"core.firewall_backend"}); err != nil {
		t.Fatalf("config-get error = %v", err)
	}
	if strings.TrimSpace(output.String()) != "nftables" {
		t.Fatalf("config-get output = %q", output.String())
	}
	if err := configGetCmd.RunE(configGetCmd, []string{"missing.value"}); err == nil {
		t.Fatal("config-get reported success for a missing key")
	}
}
