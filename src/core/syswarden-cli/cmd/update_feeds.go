package cmd

import (
	"fmt"
	"syswarden-cli/config"
	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/network"

	"github.com/spf13/cobra"
)

var updateFeedsCmd = &cobra.Command{
	Use:   "update-feeds",
	Short: "Silently update Threat Intelligence feeds and reload firewall",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[*] Updating Threat Intelligence Feeds...")

		mirrorURL := config.GlobalConfig.CustomURL
		if mirrorURL == "" {
			mirrorURL = "https://codeberg.org/"
		}

		if err := network.DownloadFeeds(mirrorURL, config.GlobalConfig.CustomURL6, config.GlobalConfig.ListChoice, config.GlobalConfig.GeoCodes, config.GlobalConfig.ASNList, config.GlobalConfig.GeoAllowed, config.GlobalConfig.ASNAllowed, config.GlobalConfig.LANMode, config.GlobalConfig.UseSpamhaus); err != nil {
			fmt.Printf("[ERROR] Failed to download threat intelligence feeds: %v\n", err)
			return
		}

		fmt.Println("[*] Feeds downloaded successfully. Reloading SysWarden firewall engine in memory...")
		if err := firewall.ApplyPolicies(); err != nil {
			fmt.Printf("[ERROR] Firewall reload failed: %v\n", err)
		} else {
			fmt.Println("[SUCCESS] Threat Intelligence successfully updated and applied.")
		}
	},
}

func init() {
	rootCmd.AddCommand(updateFeedsCmd)
}
