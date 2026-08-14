package cmd

import (
	"fmt"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Delete SysWarden services, rules, configuration, data, and logs",
	Long:  "This destructive operation removes SysWarden state and does not restore every prior host setting.",
	Run: func(cmd *cobra.Command, args []string) {
		if err := system.UninstallSystem(); err != nil {
			fmt.Printf("[ERROR] %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(uninstallCmd)
}
