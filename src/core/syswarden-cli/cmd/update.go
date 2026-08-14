package cmd

import (
	"fmt"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Run the legacy in-place package updater",
	Long:  "Downloads and installs a release package without currently verifying its checksum or signature. Use a separately verified package-upgrade procedure instead.",
	Run: func(cmd *cobra.Command, args []string) {
		if err := system.UpgradeSystem(); err != nil {
			fmt.Printf("[ERROR] %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
