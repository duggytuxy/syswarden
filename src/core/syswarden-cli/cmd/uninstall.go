package cmd

import (
	"fmt"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var uninstallHostSystem = system.UninstallSystem
var preflightStandaloneUninstall = system.PreflightStandaloneUninstall

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Delete SysWarden services, rules, configuration, data, and logs",
	Long:  "Removes a standalone installation after verified cleanup. Native package installations must be removed through their package manager to preserve package database consistency. This destructive operation does not restore every prior host setting.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := preflightStandaloneUninstall(); err != nil {
			return err
		}
		if err := prepareVerifiedFirewallRemoval(); err != nil {
			return err
		}
		if err := uninstallHostSystem(); err != nil {
			return fmt.Errorf("uninstall SysWarden host state: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(uninstallCmd)
}
