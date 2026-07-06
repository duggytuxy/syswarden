package cmd

import (
	"fmt"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Completely remove SYSWARDEN from the system",
	Run: func(cmd *cobra.Command, args []string) {
		if err := system.UninstallSystem(); err != nil {
			fmt.Printf("[ERROR] %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(uninstallCmd)
}
