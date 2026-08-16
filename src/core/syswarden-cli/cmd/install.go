package cmd

import (
	"fmt"
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

		if err := installConfigPreflight("/etc/syswarden/config"); err != nil {
			return installStageError("configuration preflight failed before host mutation", err)
		}

		if err := system.InstallDependencies(); err != nil {
			return installStageError("dependency installation failed", err)
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
		if mirrorURL == "" {
			mirrorURL = "https://codeberg.org/"
		}
		if err := network.DownloadFeeds(mirrorURL, config.GlobalConfig.CustomURLIPv6, config.GlobalConfig.CustomHash, config.GlobalConfig.CustomHashIPv6, config.GlobalConfig.ListChoice, config.GlobalConfig.GeoCodes, config.GlobalConfig.ASNList, config.GlobalConfig.GeoAllowed, config.GlobalConfig.ASNAllowed, config.GlobalConfig.LANMode, config.GlobalConfig.UseSpamhaus); err != nil {
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

		// Web-TUI Initialization (Must run before Phase 5 to prevent Web-TUI crashes on minimal OS)
		token := readConfigToken()
		if token == "" {
			token = generateSecureToken(32)
			if err := updateConfigToken(token); err != nil {
				return installStageError("failed to save Web-TUI token", err)
			}
		}

		// Phase 5: Deployment Orchestration
		fmt.Println("[SYSWARDEN] Starting Systemd Orchestration...")
		if err := system.SetupService(); err != nil {
			return installStageError("service setup failed", err)
		}

		ip := getPublicIP()
		fmt.Printf("\n======================================================\n")
		fmt.Printf("[+] Web-TUI Client Access URL: https://%s:%s/\n", ip, webtuiPort)
		fmt.Printf("    Username: admin\n")
		fmt.Printf("    Password: %s\n", token)
		fmt.Printf("======================================================\n\n")

		fmt.Println("[SYSWARDEN] v4.02.13 Native Installation Complete.")
		return nil
	},
}

var installConfigPreflight = prepareInstallConfiguration

func installStageError(stage string, err error) error {
	return fmt.Errorf("[ERROR] %s: %w", stage, err)
}

func prepareInstallConfiguration(configRoot string) error {
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
