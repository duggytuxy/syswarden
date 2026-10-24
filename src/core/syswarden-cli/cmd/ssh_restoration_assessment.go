package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"syswarden-cli/pkg/sshpolicy"

	"github.com/spf13/cobra"
)

func newSSHRestorationAssessmentCommand(assess func(context.Context, string, string) (sshpolicy.RecoveryAssessment, error)) *cobra.Command {
	var original, recovery string
	command := &cobra.Command{
		Use:   "assess-restoration",
		Short: "Inspect restored SSH configuration and current endpoints without replaying reload",
		Long: "Read existing original-restoration history using the original plan and separately approved recovery digests. " +
			"Verify the retained original configuration, installed parser and current systemd endpoints without modifying or repairing state. " +
			"A reload intent is not proof of signal delivery, consumed policy or authenticated access. Recovery remains required.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !sshRecoveryDigest.MatchString(original) || !sshRecoveryDigest.MatchString(recovery) {
				return fmt.Errorf("SSH restoration assessment requires lowercase --plan-sha256 and --recovery-sha256 from the independently approved plans")
			}
			if flag := cmd.Flag("config"); flag != nil && flag.Changed {
				return fmt.Errorf("SSH restoration assessment uses fixed protected SSH paths and does not accept --config")
			}
			summary, err := assess(cmd.Context(), original, recovery)
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(summary)
		},
	}
	command.Flags().StringVar(&original, "plan-sha256", "", "Original independently approved migration plan SHA-256")
	command.Flags().StringVar(&recovery, "recovery-sha256", "", "Original separately approved restore-original plan SHA-256")
	_ = command.MarkFlagRequired("plan-sha256")
	_ = command.MarkFlagRequired("recovery-sha256")
	return command
}
