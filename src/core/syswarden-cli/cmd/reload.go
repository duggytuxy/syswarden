package cmd

import (
	"fmt"
	"os/exec"
	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/integration"
	"syswarden-cli/pkg/network"

	"github.com/spf13/cobra"
)

var noRestart bool

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reapply policy and normally restart syswarden-core",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[*] Reloading SYSWARDEN configuration from memory...")
		hadReportedError := false

		// Re-apply Firewall and Whitelists based on new config
		if err := firewall.ApplyPolicies(); err != nil {
			fmt.Printf("[ERROR] Firewall reload failed: %v\n", err)
			hadReportedError = true
		}

		// Re-apply Wireguard if changed
		if err := network.SetupWireguard(); err != nil {
			fmt.Printf("[ERROR] Wireguard reload failed: %v\n", err)
			hadReportedError = true
		}

		// Re-apply WAF Log Bridge (Rsyslog)
		if err := integration.SetupWAFLogForwarder(); err != nil {
			fmt.Printf("[ERROR] WAF Log Bridge reload failed: %v\n", err)
			hadReportedError = true
		}

		// Re-apply AbuseIPDB / Telemetry configuration
		if err := integration.SetupAbuseIPDB(); err != nil {
			fmt.Printf("[ERROR] AbuseIPDB reload failed: %v\n", err)
			hadReportedError = true
		}

		// Re-apply Background Cron Orchestration (Repairs missing jobs)
		fmt.Println("[*] Verifying background orchestration...")
		if err := network.SetupFeedsCron(); err != nil {
			fmt.Printf("[WARN] Threat feeds cron repair failed: %v\n", err)
			hadReportedError = true
		}
		if err := network.SetupHACluster(); err != nil {
			fmt.Printf("[WARN] HA cluster cron repair failed: %v\n", err)
			hadReportedError = true
		}

		// Restart Daemons gracefully
		if !noRestart {
			fmt.Println("[*] Restarting background engines...")
			if err := exec.Command("systemctl", "restart", "syswarden-core.service").Run(); err != nil {
				fmt.Printf("[WARN] syswarden-core restart failed: %v\n", err)
				hadReportedError = true
			}
		}

		fmt.Println(reloadCompletionMessage(hadReportedError))
	},
}

func reloadCompletionMessage(hadReportedError bool) string {
	if hadReportedError {
		return "[WARNING] Reload sequence completed with reported errors; review the messages above and verify the resulting system state."
	}
	return "[INFO] Reload sequence completed; verify the resulting service and kernel state."
}

func init() {
	reloadCmd.Flags().BoolVar(&noRestart, "no-restart", false, "Do not restart syswarden-core.service (used by systemd)")
	rootCmd.AddCommand(reloadCmd)
}
