package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"syswarden-cli/config"

	"github.com/spf13/cobra"
)

func TestInstallCommandReturnsFailureBeforeCompletion_SW_CFG_001(t *testing.T) {
	previous := installConfigPreflight
	installConfigPreflight = func(string) error { return errors.New("adversarial invalid configuration") }
	t.Cleanup(func() { installConfigPreflight = previous })

	err := installCmd.RunE(installCmd, nil)
	if err == nil {
		t.Fatal("install command reported success after configuration preflight failure")
	}
	if !strings.Contains(err.Error(), "[ERROR] configuration preflight failed") {
		t.Fatalf("install error = %q, want explicit configuration failure", err)
	}
	if strings.Contains(err.Error(), "Installation Complete") {
		t.Fatalf("failed install emitted a completion result: %q", err)
	}
}

func TestInstallProcessExitsNonZeroWithoutCompletion_SW_CFG_001(t *testing.T) {
	previousPreflight := installConfigPreflight
	installConfigPreflight = func(string) error { return errors.New("command invalid configuration") }
	t.Cleanup(func() { installConfigPreflight = previousPreflight })
	previousInit := initConfigHook
	initConfigHook = func() {}
	t.Cleanup(func() { initConfigHook = previousInit })

	testRoot := &cobra.Command{Use: "syswarden"}
	testInstall := &cobra.Command{Use: "install", RunE: installCmd.RunE}
	testRoot.AddCommand(testInstall)
	testRoot.SetArgs([]string{"install"})
	_, err := testRoot.ExecuteC()
	if err == nil {
		t.Fatal("install Cobra execution returned success")
	}
	if !strings.Contains(err.Error(), "[ERROR] configuration preflight failed") {
		t.Fatalf("install Cobra execution omitted explicit failure: %v", err)
	}
	if strings.Contains(err.Error(), "Installation Complete") {
		t.Fatalf("failed install Cobra execution emitted completion: %v", err)
	}
}

func TestPrepareInstallConfigurationCompletesPartialConfig_SW_CFG_001(t *testing.T) {
	configRoot := filepath.Join(t.TempDir(), "config")
	modules := filepath.Join(configRoot, "modules")
	if err := os.MkdirAll(modules, 0750); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(modules)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	const userConfig = "# operator-owned\n[user]\nwebtui_password = \"preserve-exactly\"\n"
	if err := root.WriteFile("99-user.toml", []byte(userConfig), 0640); err != nil {
		t.Fatal(err)
	}

	previous := config.GlobalConfig
	t.Cleanup(func() { config.GlobalConfig = previous })
	if err := prepareInstallConfiguration(configRoot); err != nil {
		t.Fatalf("prepareInstallConfiguration() error = %v", err)
	}
	content, err := root.ReadFile("99-user.toml")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != userConfig {
		t.Fatalf("operator module changed: got %q, want %q", content, userConfig)
	}
	info, err := root.Lstat("99-user.toml")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("operator module mode = %#o, want 0640", info.Mode().Perm())
	}
	if config.GlobalConfig == nil || config.GlobalConfig.WebTUIPassword != "preserve-exactly" {
		t.Fatalf("validated config = %#v", config.GlobalConfig)
	}
	if state := config.CurrentLoadState(); state.Degraded || state.Source != configRoot {
		t.Fatalf("load state = %#v, want validated install config", state)
	}
}

func TestPrepareInstallConfigurationRejectsInvalidCandidateBeforeHostMutation_SW_CFG_001(t *testing.T) {
	configRoot := filepath.Join(t.TempDir(), "config")
	if err := os.MkdirAll(configRoot, 0750); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(configRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile("config.toml", []byte("[core\n"), 0600); err != nil {
		t.Fatal(err)
	}

	previous := &config.Config{SSHPort: "2222", FirewallBackend: "keep"}
	config.GlobalConfig = previous
	t.Cleanup(func() { config.GlobalConfig = config.NewFailSafeConfig() })
	if err := prepareInstallConfiguration(configRoot); err == nil {
		t.Fatal("prepareInstallConfiguration() accepted invalid TOML")
	}
	if config.GlobalConfig != previous || config.GlobalConfig.SSHPort != "2222" {
		t.Fatal("invalid install candidate replaced the previous valid configuration")
	}
	if state := config.CurrentLoadState(); !state.Degraded || state.Error == "" {
		t.Fatalf("load state = %#v, want degraded rejection", state)
	}
}
