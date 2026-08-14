package cmd

import (
	"fmt"

	"syswarden-cli/pkg/firewall"

	"github.com/spf13/cobra"
)

var unwhitelistCmd = &cobra.Command{
	Use:   "unwhitelist <IP>...",
	Short: "Remove addresses or CIDRs from the persistent whitelist",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		for _, ip := range args {
			if err := firewall.RemoveFromWhitelist(ip); err != nil {
				fmt.Printf("[ERROR] %s: %v\n", ip, err)
			}
		}
	},
}

func init() { rootCmd.AddCommand(unwhitelistCmd) }
