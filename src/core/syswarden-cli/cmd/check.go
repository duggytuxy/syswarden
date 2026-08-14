package cmd

import (
	"syswarden-cli/pkg/firewall"

	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check <IP>",
	Short: "Inspect recorded firewall state for an address or CIDR",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		firewall.CheckIP(args[0])
	},
}

func init() { rootCmd.AddCommand(checkCmd) }
