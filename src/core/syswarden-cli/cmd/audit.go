package cmd

import (
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Performs a full Enterprise SYSWARDEN Audit",
	Run: func(cmd *cobra.Command, args []string) {
		system.RunAudit()
	},
}

func init() { rootCmd.AddCommand(auditCmd) }
