package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
		if err := preflightSystemdFirewallOrderingForInstall(); err != nil {
			return installStageError("systemd firewall ordering preflight failed before host mutation", err)
		}
		if system.OfflineQualificationPackageInstall() {
			if err := installDependenciesForInstall(); err != nil {
				return installStageError("offline package dependency attestation failed", err)
			}
			fmt.Println("[INFO] Candidate package staged without host activation; the qualification updater must attest it before activation.")
			return nil
		}
		if system.OfflineQualificationActivation() {
			if err := prepareOfflineQualificationActivationConfiguration(
				"/opt/syswarden/syswarden-auto.conf",
				"/etc/syswarden/config",
			); err != nil {
				return installStageError("deferred package configuration migration failed", err)
			}
		}

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

		if err := installDependenciesForInstall(); err != nil {
			return installStageError("dependency installation failed", err)
		}
		if err := recoverPendingWireGuardForwardingForInstall(); err != nil {
			return installStageError("WireGuard forwarding persistence recovery failed before SSH or firewall mutation", err)
		}
		if err := recoverPendingWireGuardForInstall(); err != nil {
			return installStageError("WireGuard transaction recovery failed before SSH or firewall mutation", err)
		}
		if err := preflightWireGuardForInstall(); err != nil {
			return installStageError("WireGuard preflight failed before SSH or firewall mutation", err)
		}
		if os.Getenv("SYSWARDEN_PKG_INSTALL") == "1" {
			if err := preparePackagedLegacyDynamicBanUpgrade(); err != nil {
				return installStageError("legacy dynamic firewall recovery failed", err)
			}
		}

		if err := configureSSHForInstall(); err != nil {
			return installStageError("SSH configuration failed", err)
		}

		if err := prepareNetworkIntelligenceForInstall(); err != nil {
			return err
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
		if err := ensurePersistentBlocklistPairForInstall(); err != nil {
			return installStageError("persistent blocklist initialization failed", err)
		}

		if err := applyPoliciesForInstall(); err != nil {
			return installStageError("failed to apply SYSWARDEN overlay rules", err)
		}

		// Phase 3: External Integrations & Log Bridges
		fmt.Println("[SYSWARDEN] Starting Integrations & Log Bridges...")
		if err := setupRsyslogIntegrationsForInstall(); err != nil {
			return err
		}
		if err := setupWebhooksWithoutQualificationEgress(); err != nil {
			return installStageError("webhook configuration failed", err)
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
		if err := setupWireGuardWithoutQualificationEgress(); err != nil {
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

		fmt.Println("[SYSWARDEN] v4.10.0 native installation complete.")
		return nil
	},
}

var installConfigPreflight = prepareInstallConfiguration
var preflightSystemdFirewallOrderingForInstall = system.PreflightSystemdFirewallOrdering
var installDependenciesForInstall = system.InstallDependencies
var removeExactLegacyCompletionAfterInstall = integration.RemoveExactLegacyBashCompletion
var quarantineLegacyDynamicBanIntervals = firewall.QuarantineLegacyDynamicBanIntervals
var restartCoreServiceForInstall = restartCoreService
var setupSIEMForInstall = integration.SetupSIEM
var setupWAFForInstall = integration.SetupWAFLogForwarder
var ensurePersistentBlocklistPairForInstall = firewall.EnsurePersistentBlocklistPair
var hostFirewallBackendPreflight = system.PreflightHostFirewallBackend
var inspectInstallFirewallCompatibility = config.InspectHistoricalDefaultFirewallCompatibility
var applyInstallFirewallCompatibility = config.ApplyHistoricalDefaultFirewallCompatibility
var selectFastestMirrorForInstall = system.SelectFastestMirror
var downloadFeedsForInstall = network.DownloadFeedsForInstall
var attestOfflineQualificationFeedsForInstall = network.AttestOfflineQualificationFeeds
var setupWebhooksForInstall = integration.SetupWebhooks
var recoverPendingWireGuardForwardingForInstall = network.RecoverPendingWireGuardForwardingState
var recoverPendingWireGuardForInstall = network.RecoverPendingWireguardState
var preflightWireGuardForInstall = network.PreflightWireguard
var setupWireGuardForInstall = network.SetupWireguard
var configureSSHForInstall = system.ConfigureSSH
var applyPoliciesForInstall = firewall.ApplyPolicies
var hostCronSchedulingPreflight = func(haEnabled bool) error {
	_, err := system.PreflightRuntimeCronScheduling(haEnabled)
	return err
}

func prepareOfflineQualificationActivationConfiguration(legacyPath, configRoot string) error {
	if legacyPath == "" || configRoot == "" || !filepath.IsAbs(legacyPath) || !filepath.IsAbs(configRoot) ||
		filepath.Clean(legacyPath) != legacyPath || filepath.Clean(configRoot) != configRoot {
		return errors.New("offline qualification activation paths must be canonical and absolute")
	}
	legacyCandidates := []string{legacyPath, legacyPath + ".migration_backup"}
	retainedCandidates := []string{legacyPath + ".migrated", legacyPath + ".migration_backup.migrated"}
	archivePath := legacyPath + ".bak"
	for _, path := range append(append([]string{}, legacyCandidates...), append(retainedCandidates, archivePath)...) {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect deferred legacy configuration path %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("deferred legacy configuration path %s is not a regular non-symlink file", path)
		}
	}
	markerPath := filepath.Join(configRoot, ".migration-in-progress")
	if marker, err := os.Lstat(markerPath); err == nil {
		if marker.Mode()&os.ModeSymlink != 0 || !marker.Mode().IsRegular() {
			return errors.New("offline qualification found an unsafe configuration migration marker")
		}
		return errors.New("offline qualification requires the existing configuration migration transaction to be completed first")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect configuration migration marker: %w", err)
	}
	complete, err := config.ModularConfigurationComplete(configRoot)
	if err != nil {
		return err
	}
	if complete {
		return nil
	}
	selected := ""
	for _, candidate := range legacyCandidates {
		if _, err := os.Lstat(candidate); err == nil {
			if selected != "" {
				return errors.New("offline qualification found ambiguous legacy configuration sources")
			}
			selected = candidate
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect legacy configuration source: %w", err)
		}
	}
	if selected == "" {
		for _, retained := range retainedCandidates {
			if _, err := os.Lstat(retained); err == nil {
				return errors.New("offline qualification found retained legacy configuration without a complete modular configuration")
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("inspect retained legacy configuration: %w", err)
			}
		}
		return nil
	}
	if err := (&config.Migrator{SourcePath: selected, OutputDir: configRoot}).Run(); err != nil {
		return fmt.Errorf("migrate deferred legacy configuration: %w", err)
	}
	retained := selected + ".migrated"
	if _, err := os.Lstat(retained); err == nil {
		if err := config.ArchiveMigratedLegacySource(retained, archivePath); err != nil {
			return fmt.Errorf("archive deferred legacy configuration: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect retained migrated legacy configuration: %w", err)
	}
	complete, err = config.ModularConfigurationComplete(configRoot)
	if err != nil {
		return err
	}
	if !complete {
		return errors.New("deferred legacy migration did not publish a complete modular configuration")
	}
	return nil
}

func setupRsyslogIntegrationsForInstall() error {
	if err := setupSIEMForInstall(); err != nil {
		return installStageError("SIEM configuration failed", err)
	}
	if err := setupWAFForInstall(); err != nil {
		return installStageError("WAF log bridge failed", err)
	}
	return nil
}

func setupWebhooksWithoutQualificationEgress() error {
	if system.OfflineQualificationOperation() {
		fmt.Println("[INFO] Preserving webhook configuration without an install-time connectivity probe during offline qualification.")
		return nil
	}
	return setupWebhooksForInstall()
}

func setupWireGuardWithoutQualificationEgress() error {
	if system.OfflineQualificationOperation() {
		fmt.Println("[INFO] Preserving attested WireGuard state without endpoint discovery or interface activation during offline qualification.")
		return nil
	}
	return setupWireGuardForInstall()
}

func prepareNetworkIntelligenceForInstall() error {
	if config.GlobalConfig == nil {
		return installStageError("network intelligence configuration is unavailable", errors.New("global configuration is nil"))
	}
	mirrorURL := config.GlobalConfig.CustomURL
	if mirrorURL == "" && config.GlobalConfig.ListChoice != "3" {
		mirrorURL = "https://codeberg.org/"
	}
	if system.OfflineQualificationOperation() {
		fmt.Println("[SYSWARDEN] Attesting existing Network Intelligence feeds without network access...")
		if err := attestOfflineQualificationFeedsForInstall(
			mirrorURL,
			config.GlobalConfig.CustomURLIPv6,
			config.GlobalConfig.CustomHash,
			config.GlobalConfig.CustomHashIPv6,
			config.GlobalConfig.ListChoice,
			config.GlobalConfig.GeoCodes,
			config.GlobalConfig.GeoAllowed,
			config.GlobalConfig.LANMode,
		); err != nil {
			return installStageError("offline last-known-good feed attestation failed", err)
		}
		return nil
	}
	if _, err := selectFastestMirrorForInstall(); err != nil {
		return installStageError("mirror benchmarking failed", err)
	}
	// Phase 2: Network Intelligence
	fmt.Println("[SYSWARDEN] Starting Network Intelligence Downloader...")
	if err := downloadFeedsForInstall(
		mirrorURL,
		config.GlobalConfig.CustomURLIPv6,
		config.GlobalConfig.CustomHash,
		config.GlobalConfig.CustomHashIPv6,
		config.GlobalConfig.ListChoice,
		config.GlobalConfig.GeoCodes,
		config.GlobalConfig.ASNList,
		config.GlobalConfig.GeoAllowed,
		config.GlobalConfig.ASNAllowed,
		config.GlobalConfig.LANMode,
		config.GlobalConfig.UseSpamhaus,
	); err != nil {
		return installStageError("failed to download threat intelligence feeds", err)
	}
	return nil
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
