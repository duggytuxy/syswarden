package cmd

import (
	"errors"
	"fmt"
	"os"
	"syswarden-cli/config"
	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/integration"
	"syswarden-cli/pkg/network"
	"syswarden-cli/pkg/security"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install SYSWARDEN and configure security modules",
	Long:  "Runs the host-mutating installation pipeline for dependencies, SSH configuration, firewall policy, integrations, hardening, services, and scheduled jobs.",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("[SYSWARDEN] Starting %s Installation Pipeline...\n", system.Version)

		if err := preflightConfiguredCronScheduling(); err != nil {
			return installStageError("cron scheduling preflight failed before configuration repair", err)
		}
		initialFirewallBackend := configuredFirewallBackend()
		initialFirewallErr := hostFirewallBackendPreflight(initialFirewallBackend)
		if initialFirewallErr != nil {
			compatibilityClass, compatibilityEligible := classifyInstallFirewallCompatibilityError(initialFirewallErr)
			if initialFirewallBackend != "nftables" || !compatibilityEligible {
				return installStageError("firewall backend preflight failed before configuration repair", initialFirewallErr)
			}
			compatibility, err := inspectInstallFirewallCompatibility("/etc/syswarden/config")
			if err != nil {
				return installStageError("historical default firewall compatibility inspection failed before configuration repair", err)
			}
			if compatibility == nil {
				return installStageError("firewall backend preflight failed before configuration repair", initialFirewallErr)
			}
			if err := hostFirewallBackendPreflight("keep"); err != nil {
				return installStageError(
					"historical default keep-mode preflight failed before configuration repair",
					errors.Join(initialFirewallErr, err),
				)
			}
			if err := applyInstallFirewallCompatibility(
				compatibility,
				func() error {
					return revalidateInstallFirewallCompatibilityHost(compatibilityClass)
				},
			); err != nil {
				return installStageError("firewall compatibility migration failed before configuration repair", err)
			}
			fmt.Println("[INFO] Migrated the historical default firewall byte family from nftables to keep after typed host-state attestation.")
		}

		if err := installConfigPreflight("/etc/syswarden/config"); err != nil {
			return installStageError("configuration preflight failed before host mutation", err)
		}
		if err := preflightConfiguredCronScheduling(); err != nil {
			return installStageError("cron scheduling preflight failed", err)
		}
		if err := preflightConfiguredFirewallBackend(); err != nil {
			return installStageError("firewall backend preflight failed", err)
		}

		if err := system.InstallDependencies(); err != nil {
			return installStageError("dependency installation failed", err)
		}
		if os.Getenv("SYSWARDEN_PKG_INSTALL") == "1" {
			if err := preparePackagedLegacyDynamicBanUpgrade(); err != nil {
				return installStageError("legacy dynamic firewall recovery failed", err)
			}
		}

		if err := system.ConfigureSSH(); err != nil {
			return installStageError("SSH configuration failed", err)
		}

		if _, err := system.SelectFastestMirror(); err != nil {
			return installStageError("mirror benchmarking failed", err)
		}

		// Phase 2: Network Intelligence
		fmt.Println("[SYSWARDEN] Starting Network Intelligence Downloader...")
		mirrorURL := config.GlobalConfig.CustomURL
		if mirrorURL == "" && config.GlobalConfig.ListChoice != "3" {
			mirrorURL = "https://codeberg.org/"
		}
		if err := network.DownloadFeedsForInstall(mirrorURL, config.GlobalConfig.CustomURLIPv6, config.GlobalConfig.CustomHash, config.GlobalConfig.CustomHashIPv6, config.GlobalConfig.ListChoice, config.GlobalConfig.GeoCodes, config.GlobalConfig.ASNList, config.GlobalConfig.GeoAllowed, config.GlobalConfig.ASNAllowed, config.GlobalConfig.LANMode, config.GlobalConfig.UseSpamhaus); err != nil {
			return installStageError("failed to download threat intelligence feeds", err)
		}

		if err := network.SetupFeedsCron(); err != nil {
			return installStageError("failed to configure threat feeds cron job", err)
		}

		// Phase 2: Firewall Orchestration
		fmt.Println("[SYSWARDEN] Starting Firewall Engine...")

		if err := system.OptimizeHostFirewall(); err != nil {
			return installStageError("host firewall optimization failed", err)
		}

		if err := firewall.AutoWhitelistAdminAndInfra(); err != nil {
			return installStageError("auto-whitelisting failed", err)
		}

		if err := firewall.ApplyPolicies(); err != nil {
			return installStageError("failed to apply SYSWARDEN overlay rules", err)
		}

		// Phase 3: External Integrations & Log Bridges
		fmt.Println("[SYSWARDEN] Starting Integrations & Log Bridges...")
		if err := integration.SetupWAFLogForwarder(); err != nil {
			return installStageError("WAF log bridge failed", err)
		}
		if err := integration.SetupWebhooks(); err != nil {
			return installStageError("webhook configuration failed", err)
		}
		if err := integration.SetupSIEM(); err != nil {
			return installStageError("SIEM configuration failed", err)
		}
		if err := integration.SetupWazuh(); err != nil {
			return installStageError("Wazuh configuration failed", err)
		}
		if err := integration.SetupAbuseIPDB(); err != nil {
			return installStageError("AbuseIPDB configuration failed", err)
		}

		// Phase 4: Security Hardening (Wave 1 of Grand Purge)
		fmt.Println("[SYSWARDEN] Starting OS & CIS Hardening...")
		if err := security.ApplyCISHardening(); err != nil {
			return installStageError("CIS hardening failed", err)
		}
		if err := security.ApplyOSHardening(); err != nil {
			return installStageError("OS hardening failed", err)
		}

		// Phase 2.5: Private Network & HA (Wave 2 of Grand Purge)
		fmt.Println("[SYSWARDEN] Starting Private Network & HA Cluster...")
		if err := network.SetupWireguard(); err != nil {
			return installStageError("WireGuard setup failed", err)
		}
		if err := network.SetupHACluster(); err != nil {
			return installStageError("HA cluster setup failed", err)
		}

		// Phase 5: Deployment Orchestration
		fmt.Println("[SYSWARDEN] Starting Systemd Orchestration...")
		if err := system.SetupService(); err != nil {
			return installStageError("service setup failed", err)
		}
		if err := removeExactLegacyCompletionAfterInstall(); err != nil {
			return installStageError("legacy shell completion reconciliation failed", err)
		}

		fmt.Println("[SYSWARDEN] v4.03.3 native installation complete.")
		return nil
	},
}

var installConfigPreflight = prepareInstallConfiguration
var removeExactLegacyCompletionAfterInstall = integration.RemoveExactLegacyBashCompletion
var quarantineLegacyDynamicBanIntervals = firewall.QuarantineLegacyDynamicBanIntervals
var restartCoreServiceForInstall = restartCoreService
var hostFirewallBackendPreflight = system.PreflightHostFirewallBackend
var inspectInstallFirewallCompatibility = config.InspectHistoricalDefaultFirewallCompatibility
var applyInstallFirewallCompatibility = config.ApplyHistoricalDefaultFirewallCompatibility
var hostCronSchedulingPreflight = func(haEnabled bool) error {
	_, err := system.PreflightRuntimeCronScheduling(haEnabled)
	return err
}

func preflightConfiguredCronScheduling() error {
	haEnabled := config.GlobalConfig != nil && config.GlobalConfig.HAEnabled
	return hostCronSchedulingPreflight(haEnabled)
}

func preflightConfiguredFirewallBackend() error {
	return hostFirewallBackendPreflight(configuredFirewallBackend())
}

func preparePackagedLegacyDynamicBanUpgrade() error {
	repaired, err := quarantineLegacyDynamicBanIntervals()
	if err != nil {
		return err
	}
	if !repaired {
		return nil
	}
	if err := restartCoreServiceForInstall(); err != nil {
		return fmt.Errorf("restart the packaged core after legacy dynamic-ban quarantine: %w", err)
	}
	// A final pass closes the narrow race in which the historical process had
	// already queued one last mutation before the service restart completed.
	if _, err := quarantineLegacyDynamicBanIntervals(); err != nil {
		return fmt.Errorf("verify legacy dynamic-ban quarantine after core restart: %w", err)
	}
	return nil
}

func configuredFirewallBackend() string {
	backend := "keep"
	if config.GlobalConfig != nil && config.GlobalConfig.FirewallBackend != "" {
		backend = config.GlobalConfig.FirewallBackend
	}
	return backend
}

type installFirewallCompatibilityClass string

const (
	installFirewallCompatibilitySystemd installFirewallCompatibilityClass = "systemd"
	installFirewallCompatibilityOpenRC  installFirewallCompatibilityClass = "openrc"
)

var installSystemdFirewallCompatibilityEligible = system.IsHistoricalDefaultSystemdFirewallCompatibilityEligible
var installOpenRCFirewallCompatibilityEligible = system.IsHistoricalDefaultOpenRCFirewallCompatibilityEligible
var classifyInstallFirewallCompatibilityError = classifyInstallFirewallCompatibility

func classifyInstallFirewallCompatibility(err error) (installFirewallCompatibilityClass, bool) {
	systemdEligible := installSystemdFirewallCompatibilityEligible(err)
	openRCEligible := installOpenRCFirewallCompatibilityEligible(err)
	if systemdEligible == openRCEligible {
		return "", false
	}
	if systemdEligible {
		return installFirewallCompatibilitySystemd, true
	}
	return installFirewallCompatibilityOpenRC, true
}

func revalidateInstallFirewallCompatibilityHost(wantClass installFirewallCompatibilityClass) error {
	err := hostFirewallBackendPreflight("nftables")
	if err == nil {
		return fmt.Errorf("historical default firewall host state became strict-nftables ready during compatibility publication")
	}
	gotClass, eligible := classifyInstallFirewallCompatibilityError(err)
	if !eligible {
		return fmt.Errorf("historical default firewall host state changed during compatibility publication: %w", err)
	}
	if gotClass != wantClass {
		return fmt.Errorf(
			"historical default firewall service-manager class changed during compatibility publication from %s to %s: %w",
			wantClass,
			gotClass,
			err,
		)
	}
	return nil
}

func installStageError(stage string, err error) error {
	return fmt.Errorf("[ERROR] %s: %w", stage, err)
}

func prepareInstallConfiguration(configRoot string) error {
	if err := config.RemoveRetiredWebTUIConfiguration(configRoot); err != nil {
		return fmt.Errorf("remove retired Web-TUI configuration: %w", err)
	}
	if err := config.EnsureDefaults(configRoot); err != nil {
		return fmt.Errorf("complete missing modular defaults: %w", err)
	}
	if err := config.ParseConfig(configRoot); err != nil {
		return fmt.Errorf("validate modular configuration: %w", err)
	}
	if config.GlobalConfig == nil {
		return fmt.Errorf("validated configuration is unavailable")
	}
	state := config.CurrentLoadState()
	if state.Degraded {
		return fmt.Errorf("configuration remains degraded: %s", state.Error)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(installCmd)
}
