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
		Long:  "Inspect SSH policy and interrupted activation, or explicitly restore retained original configuration with a separately approved recovery plan. Forward migration application and completed recovery acceptance are not available yet.",
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
	command.AddCommand(newSSHActivationAssessmentCommand(sshpolicy.AssessSystemdActivation))
	command.AddCommand(newSSHRestoreOriginalCommand(sshpolicy.InspectSystemdRecovery, sshpolicy.RestoreOriginalSystemd))
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

func newSSHActivationAssessmentCommand(assess func(string) (sshpolicy.ActivationAssessment, error)) *cobra.Command {
	var approved string
	command := &cobra.Command{
		Use:   "assess-activation",
		Short: "Inspect an interrupted SSH activation without recovering or retrying it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			summary, err := assess(approved)
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
	if sshRestoreOriginalCommand(cmd) {
		apply, err := cmd.Flags().GetBool("apply")
		return err == nil && !apply
	}
	path := cmd.CommandPath()
	return path == "syswarden ssh-policy" || path == "syswarden ssh-policy plan" ||
		path == "syswarden ssh-policy verify" || path == "syswarden ssh-policy ports" ||
		path == "syswarden ssh-policy verify-owned" || path == "syswarden ssh-policy assess-activation"
}
