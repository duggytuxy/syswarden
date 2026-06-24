package cmd

import (
	"fmt"
	"os/exec"
	"github.com/spf13/cobra"
	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/integration"
	"syswarden-cli/pkg/network"
)

var noRestart bool

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload configuration and restart security engines",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[*] Reloading SysWarden configuration from memory...")

		// Re-apply Firewall and Whitelists based on new config
		if err := firewall.ApplyNftables(); err != nil {
			fmt.Printf("[ERROR] Firewall reload failed: %v\n", err)
		}

		// Re-apply Wireguard if changed
		if err := network.SetupWireguard(); err != nil {
			fmt.Printf("[ERROR] Wireguard reload failed: %v\n", err)
		}

		// Re-apply WAF Log Bridge (Rsyslog)
		if err := integration.SetupWAFLogForwarder(); err != nil {
			fmt.Printf("[ERROR] WAF Log Bridge reload failed: %v\n", err)
		}

		// Re-apply Background Cron Orchestration (Repairs missing jobs)
		fmt.Println("[*] Verifying background orchestration...")
		if err := network.SetupFeedsCron(); err != nil {
			fmt.Printf("[WARN] Threat feeds cron repair failed: %v\n", err)
		}
		if err := network.SetupHACluster(); err != nil {
			fmt.Printf("[WARN] HA cluster cron repair failed: %v\n", err)
		}

		// Restart Daemons gracefully
		if !noRestart {
			fmt.Println("[*] Restarting background engines...")
   _ = exec.Command("systemctl", "restart", "syswarden-core.service").Run()
		}

		fmt.Println("[SUCCESS] SysWarden configuration reloaded natively.")
	},
}

func init() {
	reloadCmd.Flags().BoolVar(&noRestart, "no-restart", false, "Do not restart syswarden-core.service (used by systemd)")
	rootCmd.AddCommand(reloadCmd)
}
