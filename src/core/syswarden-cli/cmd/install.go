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
	Long:  `Executes the fully automated SYSWARDEN installation pipeline.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("[SYSWARDEN] Starting %s Installation Pipeline...\n", system.Version)

		if err := system.InstallDependencies(); err != nil {
			fmt.Printf("[ERROR] Dependency installation failed: %v\n", err)
			return
		}

		if err := system.ConfigureSSH(); err != nil {
			fmt.Printf("[ERROR] SSH configuration failed: %v\n", err)
			return
		}

		if _, err := system.SelectFastestMirror(); err != nil {
			fmt.Printf("[ERROR] Mirror benchmarking failed: %v\n", err)
			return
		}

		// Phase 2: Network Intelligence
		fmt.Println("[SYSWARDEN] Starting Network Intelligence Downloader...")
		mirrorURL := config.GlobalConfig.CustomURL
		if mirrorURL == "" {
			mirrorURL = "https://codeberg.org/"
		}
		if err := network.DownloadFeeds(mirrorURL, config.GlobalConfig.CustomURLIPv6, config.GlobalConfig.ListChoice, config.GlobalConfig.GeoCodes, config.GlobalConfig.ASNList, config.GlobalConfig.GeoAllowed, config.GlobalConfig.ASNAllowed, config.GlobalConfig.LANMode, config.GlobalConfig.UseSpamhaus); err != nil {
			fmt.Printf("[ERROR] Failed to download threat intelligence feeds: %v\n", err)
			return
		}

		if err := network.SetupFeedsCron(); err != nil {
			fmt.Printf("[ERROR] Failed to configure threat feeds cron job: %v\n", err)
		}

		// Phase 2: Firewall Orchestration
		fmt.Println("[SYSWARDEN] Starting Firewall Engine...")

		if err := system.OptimizeHostFirewall(); err != nil {
			fmt.Printf("[ERROR] Host firewall optimization failed: %v\n", err)
		}

		if err := firewall.AutoWhitelistAdminAndInfra(); err != nil {
			fmt.Printf("[ERROR] Auto-Whitelisting failed: %v\n", err)
		}

		if err := firewall.ApplyPolicies(); err != nil {
			fmt.Printf("[ERROR] Failed to apply SYSWARDEN Overlay rules: %v\n", err)
			return
		}

		// Phase 3: External Integrations & Log Bridges
		fmt.Println("[SYSWARDEN] Starting Integrations & Log Bridges...")
		if err := integration.SetupWAFLogForwarder(); err != nil {
			fmt.Printf("[ERROR] WAF Log Bridge failed: %v\n", err)
		}
		if err := integration.SetupWebhooks(); err != nil {
			fmt.Printf("[ERROR] Webhook configuration failed: %v\n", err)
		}
		if err := integration.SetupSIEM(); err != nil {
			fmt.Printf("[ERROR] SIEM configuration failed: %v\n", err)
		}
		if err := integration.SetupWazuh(); err != nil {
			fmt.Printf("[ERROR] Wazuh configuration failed: %v\n", err)
		}
		if err := integration.SetupAbuseIPDB(); err != nil {
			fmt.Printf("[ERROR] AbuseIPDB configuration failed: %v\n", err)
		}

		// Phase 4: Security Hardening (Wave 1 of Grand Purge)
		fmt.Println("[SYSWARDEN] Starting OS & CIS Hardening...")
		if err := security.ApplyCISHardening(); err != nil {
			fmt.Printf("[ERROR] CIS Hardening failed: %v\n", err)
		}
		if err := security.ApplyOSHardening(); err != nil {
			fmt.Printf("[ERROR] OS Hardening failed: %v\n", err)
		}

		// Phase 2.5: Private Network & HA (Wave 2 of Grand Purge)
		fmt.Println("[SYSWARDEN] Starting Private Network & HA Cluster...")
		if err := network.SetupWireguard(); err != nil {
			fmt.Printf("[ERROR] WireGuard setup failed: %v\n", err)
		}
		if err := network.SetupHACluster(); err != nil {
			fmt.Printf("[ERROR] HA Cluster setup failed: %v\n", err)
		}

		// Phase 5: Deployment Orchestration
		fmt.Println("[SYSWARDEN] Starting Systemd Orchestration...")
		if err := system.SetupService(); err != nil {
			fmt.Printf("[ERROR] Systemd setup failed: %v\n", err)
		}

		// Web-TUI Initialization
		token := readConfigToken()
		if token == "" {
			token = generateSecureToken(32)
			if err := updateConfigToken(token); err != nil {
				fmt.Printf("[ERROR] Failed to save Web-TUI token: %v\n", err)
			}
		}
		ip := getPublicIP()
		fmt.Printf("\n======================================================\n")
		fmt.Printf("[+] Web-TUI Client Access URL: https://%s:%s/?token=%s\n", ip, webtuiPort, token)
		fmt.Printf("======================================================\n\n")

		fmt.Println("[SYSWARDEN] v3.74.11 Native Installation Complete.")
	},
}

func init() {
	rootCmd.AddCommand(installCmd)
}
