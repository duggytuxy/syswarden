package cmd

import (
	"bytes"
	"fmt"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var uninstallHostSystem = func() error {
	completion, err := renderStandaloneCompletionPayload()
	if err != nil {
		return err
	}
	if err := system.RemoveUninstallCompletionPayload(completion); err != nil {
		return err
	}
	return system.UninstallSystem()
}

func renderStandaloneCompletionPayload() (string, error) {
	var completion bytes.Buffer
	if err := rootCmd.GenBashCompletionV2(&completion, !rootCmd.CompletionOptions.DisableDescriptions); err != nil {
		return "", fmt.Errorf("render exact standalone completion payload: %w", err)
	}
	return completion.String(), nil
}

var preflightUninstall = system.PreflightUninstall

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Delete SysWarden services, rules, configuration, data, and logs",
	Long:  "Removes a standalone installation after verified cleanup. Standard native packages require their package manager. An exactly attested optional RHEL package-owned profile permits runtime preparation only; RPM then removes its preserved payload. This operation does not restore every prior host setting.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := preflightUninstall(); err != nil {
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
