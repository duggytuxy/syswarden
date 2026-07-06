package cmd

import (
	"fmt"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check and install SYSWARDEN updates",
	Run: func(cmd *cobra.Command, args []string) {
		if err := system.UpgradeSystem(); err != nil {
			fmt.Printf("[ERROR] %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
