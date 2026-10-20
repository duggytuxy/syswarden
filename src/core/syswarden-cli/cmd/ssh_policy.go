package cmd

import (
	"encoding/json"
	"syswarden-cli/pkg/sshpolicy"

	"github.com/spf13/cobra"
)

func newSSHPolicyCommand(inspect func() (sshpolicy.PlanSummary, error), verify func() (sshpolicy.VerificationSummary, error), ports func() (sshpolicy.PortSummary, error)) *cobra.Command {
	command := &cobra.Command{
		Use:   "ssh-policy",
		Short: "Inspect the dedicated SSH policy migration",
		Long:  "Inspect configured SSH ports independently of hardening intent, or verify a declared candidate or an independently owned publication with the installed parser. These development commands are read-only; migration application is not available yet.",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	command.AddCommand(&cobra.Command{
		Use:   "ports",
		Short: "Inspect configured SSH ports without hardening or runtime access claims",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			summary, err := ports()
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(summary)
		},
	})
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
	command.AddCommand(&cobra.Command{
		Use:   "verify",
		Short: "Verify the SSH candidate with the installed parser without activation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			summary, err := verify()
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(summary)
		},
	})
	return command
}

func init() {
	command := newSSHPolicyCommand(sshpolicy.InspectPlan, sshpolicy.VerifyPlan, sshpolicy.InspectPorts)
	command.AddCommand(newSSHOwnedCommand(sshpolicy.VerifyOwned))
	rootCmd.AddCommand(command)
}

func newSSHOwnedCommand(verify func(string) (sshpolicy.OwnedSummary, error)) *cobra.Command {
	var approved string
	command := &cobra.Command{
		Use:   "verify-owned",
		Short: "Verify an existing owned SSH publication without activation or recovery",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			summary, err := verify(approved)
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(summary)
		},
	}
	command.Flags().StringVar(&approved, "plan-sha256", "", "Original independently approved migration plan SHA-256")
	_ = command.MarkFlagRequired("plan-sha256")
	return command
}

func readOnlySSHPolicyCommand(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	path := cmd.CommandPath()
	return path == "syswarden ssh-policy" || path == "syswarden ssh-policy plan" ||
		path == "syswarden ssh-policy verify" || path == "syswarden ssh-policy ports" ||
		path == "syswarden ssh-policy verify-owned"
}
