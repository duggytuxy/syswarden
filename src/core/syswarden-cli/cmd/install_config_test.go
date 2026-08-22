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
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	installConfigPreflight = func(string) error { return errors.New("adversarial invalid configuration") }
	hostFirewallBackendPreflight = func(string) error { return nil }
	hostCronSchedulingPreflight = func(bool) error { return nil }
	t.Cleanup(func() {
		installConfigPreflight = previous
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
	})

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
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	installConfigPreflight = func(string) error { return errors.New("command invalid configuration") }
	hostFirewallBackendPreflight = func(string) error { return nil }
	hostCronSchedulingPreflight = func(bool) error { return nil }
	t.Cleanup(func() {
		installConfigPreflight = previousPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
	})
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

func TestInstallRejectsBackendBeforeConfigurationRepair_SW2_FWBACKEND_009(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	config.GlobalConfig = &config.Config{FirewallBackend: "iptables"}
	installConfigPreflight = func(string) error {
		t.Fatal("configuration repair ran after the backend was rejected")
		return nil
	}
	hostFirewallBackendPreflight = func(backend string) error {
		if backend != "iptables" {
			t.Fatalf("backend = %q, want iptables", backend)
		}
		return errors.New("iptables is not operational")
	}
	hostCronSchedulingPreflight = func(bool) error { return nil }
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
	})

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "before configuration repair") {
		t.Fatalf("install backend refusal = %v", err)
	}
}

func TestInstallRevalidatesBackendAfterConfigurationRepair_SW2_FWBACKEND_009(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	config.GlobalConfig = &config.Config{FirewallBackend: "keep"}
	installConfigPreflight = func(string) error {
		config.GlobalConfig = &config.Config{FirewallBackend: "iptables"}
		return nil
	}
	seen := []string{}
	hostFirewallBackendPreflight = func(backend string) error {
		seen = append(seen, backend)
		if backend == "iptables" {
			return errors.New("iptables is not operational")
		}
		return nil
	}
	hostCronSchedulingPreflight = func(bool) error { return nil }
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
	})

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "firewall backend preflight failed") {
		t.Fatalf("install backend revalidation = %v", err)
	}
	if got := strings.Join(seen, ","); got != "keep,iptables" {
		t.Fatalf("backend preflights = %q, want keep,iptables", got)
	}
}

func TestReloadRejectsBackendBeforeMutation_SW2_FWBACKEND_009(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	config.GlobalConfig = &config.Config{FirewallBackend: "iptables"}
	hostFirewallBackendPreflight = func(backend string) error {
		if backend != "iptables" {
			t.Fatalf("backend = %q, want iptables", backend)
		}
		return errors.New("iptables is not operational")
	}
	hostCronSchedulingPreflight = func(bool) error { return nil }
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
	})

	err := reloadCmd.RunE(reloadCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "before reload mutation") {
		t.Fatalf("reload backend refusal = %v", err)
	}
}

func TestInstallRejectsCronSchedulingBeforeConfigurationRepair_SW2_CRON_001(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	config.GlobalConfig = &config.Config{FirewallBackend: "keep", HAEnabled: true}
	installConfigPreflight = func(string) error {
		t.Fatal("configuration repair ran after cron scheduling was rejected")
		return nil
	}
	hostFirewallBackendPreflight = func(string) error {
		t.Fatal("firewall preflight ran after the earlier cron refusal")
		return nil
	}
	hostCronSchedulingPreflight = func(haEnabled bool) error {
		if !haEnabled {
			t.Fatal("HA-enabled configuration reached cron preflight as disabled")
		}
		return errors.New("cron provider is not proven")
	}
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
	})

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "cron scheduling preflight failed before configuration repair") {
		t.Fatalf("install cron scheduling refusal = %v", err)
	}
}

func TestInstallRevalidatesCronSchedulingAfterConfigurationRepair_SW2_CRON_001(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousConfigPreflight := installConfigPreflight
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	config.GlobalConfig = &config.Config{FirewallBackend: "keep", HAEnabled: false}
	installConfigPreflight = func(string) error {
		config.GlobalConfig = &config.Config{FirewallBackend: "keep", HAEnabled: true}
		return nil
	}
	hostFirewallBackendPreflight = func(string) error { return nil }
	seen := []bool{}
	hostCronSchedulingPreflight = func(haEnabled bool) error {
		seen = append(seen, haEnabled)
		if haEnabled {
			return errors.New("HA schedule is not proven")
		}
		return nil
	}
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		installConfigPreflight = previousConfigPreflight
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
	})

	err := installCmd.RunE(installCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "cron scheduling preflight failed") {
		t.Fatalf("install cron scheduling revalidation = %v", err)
	}
	if len(seen) != 2 || seen[0] || !seen[1] {
		t.Fatalf("cron scheduling preflights = %v, want false,true", seen)
	}
}

func TestReloadRejectsCronSchedulingBeforeMutation_SW2_CRON_001(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousFirewallPreflight := hostFirewallBackendPreflight
	previousCronPreflight := hostCronSchedulingPreflight
	previousApply := applyPoliciesForReload
	config.GlobalConfig = &config.Config{FirewallBackend: "keep", HAEnabled: true}
	hostCronSchedulingPreflight = func(haEnabled bool) error {
		if !haEnabled {
			t.Fatal("HA-enabled reload reached cron preflight as disabled")
		}
		return errors.New("cron provider drift")
	}
	hostFirewallBackendPreflight = func(string) error {
		t.Fatal("firewall preflight ran after the earlier cron refusal")
		return nil
	}
	applyPoliciesForReload = func() error {
		t.Fatal("firewall mutation ran after cron preflight refusal")
		return nil
	}
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		hostFirewallBackendPreflight = previousFirewallPreflight
		hostCronSchedulingPreflight = previousCronPreflight
		applyPoliciesForReload = previousApply
	})

	err := reloadCmd.RunE(reloadCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "cron scheduling preflight failed before reload mutation") {
		t.Fatalf("reload cron scheduling refusal = %v", err)
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
	const userConfig = "# operator-owned\n[user]\nwebtui_password = \"remove-this-secret\"\nprofile_name = \"preserve-exactly\"\n"
	const cleanedUserConfig = "# operator-owned\n[user]\nprofile_name = \"preserve-exactly\"\n"
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
	if string(content) != cleanedUserConfig {
		t.Fatalf("retired secret cleanup = %q, want %q", content, cleanedUserConfig)
	}
	info, err := root.Lstat("99-user.toml")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("operator module mode = %#o, want 0640", info.Mode().Perm())
	}
	if config.GlobalConfig == nil {
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
