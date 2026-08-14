package cmd

import (
	"fmt"

	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/integration"

	"github.com/spf13/cobra"
)

var blockCmd = &cobra.Command{
	Use:   "block <IP>...",
	Short: "Add addresses or CIDRs to the persistent blocklist",
	Long:  "Records each entry in the persistent blocklist and reapplies firewall policy; success does not independently prove final kernel state.",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		for _, ip := range args {
			if err := firewall.AddToBlocklist(ip); err != nil {
				fmt.Printf("[ERROR] %s: %v\n", ip, err)
			} else {
				// Send Discord/Teams Notification for Manual Block
				integration.SendBanAlert(ip)
			}
		}
	},
}

func init() { rootCmd.AddCommand(blockCmd) }
