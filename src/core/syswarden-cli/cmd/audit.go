package cmd

import (
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run a local SYSWARDEN operational diagnostic",
	Long:  "Checks selected local services, files, firewall state, and configuration. Its output is not a compliance certification.",
	Run: func(cmd *cobra.Command, args []string) {
		system.RunAudit()
	},
}

func init() { rootCmd.AddCommand(auditCmd) }
