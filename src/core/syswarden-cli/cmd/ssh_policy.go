package cmd

import (
	"encoding/json"
	"syswarden-cli/pkg/sshpolicy"

	"github.com/spf13/cobra"
)

func newSSHPolicyCommand(inspect func() (sshpolicy.PlanSummary, error)) *cobra.Command {
	command := &cobra.Command{
		Use:   "ssh-policy",
		Short: "Inspect the dedicated SSH policy migration",
		Long:  "Inspect protected administrator intent and the current SSH configuration. This development command is read-only; migration application is not available yet.",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	command.AddCommand(&cobra.Command{
		Use:   "plan",
		Short: "Print a read-only SSH policy plan without configuration contents",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			plan, err := inspect()
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(plan)
		},
	})
	return command
}

func init() { rootCmd.AddCommand(newSSHPolicyCommand(sshpolicy.InspectPlan)) }

func readOnlySSHPolicyCommand(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	path := cmd.CommandPath()
	return path == "syswarden ssh-policy" || path == "syswarden ssh-policy plan"
}
