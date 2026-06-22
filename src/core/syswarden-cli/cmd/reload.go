package cmd

import (
	"fmt"
	"os/exec"
	"github.com/spf13/cobra"
	"syswarden-cli/pkg/firewall"
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
