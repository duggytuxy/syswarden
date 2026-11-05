package cmd

import (
	"errors"
	"strings"
	"syswarden-cli/config"
	"testing"
)

func TestSelectedModulePrerequisiteRefusalPrecedesNativeInstallAndReloadPolicy(t *testing.T) {
	for _, operation := range []string{"install", "reload"} {
		t.Run(operation, func(t *testing.T) {
			stubInstallFirewallCompatibility(t)
			savedConfig := config.GlobalConfig
			savedConfigPreflight, savedDependencies := installConfigPreflight, installDependenciesForInstall
			savedBackend, savedCron := hostFirewallBackendPreflight, hostCronSchedulingPreflight
			savedIF, savedIR, savedIP := recoverPendingWireGuardForwardingForInstall, recoverPendingWireGuardForInstall, preflightWireGuardForInstall
			savedRF, savedRR, savedRP := recoverPendingWireGuardForwardingForReload, recoverPendingWireGuardForReload, preflightWireGuardForReload
			savedModule, savedApplyI, savedApplyR := preflightModuleDependencies, applyPoliciesForInstall, applyPoliciesForReload
			savedQuarantine := quarantineLegacyDynamicBanIntervals
			savedBlocklist, savedWhitelist := ensurePersistentBlocklistPairForReload, ensurePersistentWhitelistPairForReload
			t.Cleanup(func() {
				config.GlobalConfig = savedConfig
				installConfigPreflight, installDependenciesForInstall = savedConfigPreflight, savedDependencies
				hostFirewallBackendPreflight, hostCronSchedulingPreflight = savedBackend, savedCron
				recoverPendingWireGuardForwardingForInstall, recoverPendingWireGuardForInstall, preflightWireGuardForInstall = savedIF, savedIR, savedIP
				recoverPendingWireGuardForwardingForReload, recoverPendingWireGuardForReload, preflightWireGuardForReload = savedRF, savedRR, savedRP
				preflightModuleDependencies, applyPoliciesForInstall, applyPoliciesForReload = savedModule, savedApplyI, savedApplyR
				quarantineLegacyDynamicBanIntervals = savedQuarantine
				ensurePersistentBlocklistPairForReload, ensurePersistentWhitelistPairForReload = savedBlocklist, savedWhitelist
			})
			t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
			config.GlobalConfig = &config.Config{FirewallBackend: "keep", EnableWazuh: true}
			installConfigPreflight = func(string) error { return nil }
			installDependenciesForInstall = func() error { return nil }
			hostFirewallBackendPreflight = func(string) error { return nil }
			hostCronSchedulingPreflight = func(bool) error { return nil }
			recoverPendingWireGuardForwardingForInstall = func() error { return nil }
			recoverPendingWireGuardForInstall = func() error { return nil }
			preflightWireGuardForInstall = func() error { return nil }
			recoverPendingWireGuardForwardingForReload = func() error { return nil }
			recoverPendingWireGuardForReload = func() error { return nil }
			preflightWireGuardForReload = func() error { return nil }
			quarantineLegacyDynamicBanIntervals = func() (bool, error) {
				t.Fatal("install changed legacy firewall before prerequisite success")
				return false, nil
			}
			ensurePersistentBlocklistPairForReload = func() error { t.Fatal("reload changed blocklist before prerequisite success"); return nil }
			ensurePersistentWhitelistPairForReload = func() error { t.Fatal("reload changed whitelist before prerequisite success"); return nil }
			refused := errors.New("selected agent missing")
			preflightModuleDependencies = func() error { return refused }
			applyPoliciesForInstall = func() error { t.Fatal("install changed firewall after missing prerequisite"); return nil }
			applyPoliciesForReload = func() error { t.Fatal("reload changed firewall after missing prerequisite"); return nil }
			var err error
			if operation == "install" {
				err = installCmd.RunE(installCmd, nil)
			} else {
				err = reloadCmd.RunE(reloadCmd, nil)
			}
			if !errors.Is(err, refused) || !strings.Contains(err.Error(), "selected module prerequisite failed") {
				t.Fatalf("prerequisite result: %v", err)
			}
			if !config.GlobalConfig.EnableWazuh {
				t.Fatal("missing prerequisite silently disabled existing selection")
			}
		})
	}
}
