package cmd

import (
	"fmt"
	"os"

	"syswarden-cli/pkg/firewall"

	"github.com/spf13/cobra"
)

var allowSSHCmd = &cobra.Command{
	Use:   "allow-ssh <IP> [PORT]",
	Short: "Add an address to the SSH exception registry",
	Long:  "Records one address or CIDR in the SSH exception registry and reapplies firewall policy. Verify the resulting kernel rule before relying on it for access.",
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		port := ""
		if len(args) == 2 {
			port = args[1]
		}
		if err := firewall.AllowSSH(args[0], port); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func init() { rootCmd.AddCommand(allowSSHCmd) }
