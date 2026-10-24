package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"syswarden-cli/pkg/sshpolicy"

	"github.com/spf13/cobra"
)

var sshRecoveryDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func newSSHRestoreOriginalCommand(
	inspect func(context.Context, string) (sshpolicy.RuntimeRecoverySummary, error),
	restore func(context.Context, string, string) (sshpolicy.RuntimeRecoverySummary, error),
) *cobra.Command {
	var original, recovery string
	var apply bool
	command := &cobra.Command{
		Use:   "restore-original",
		Short: "Inspect or explicitly restore retained SSH configuration after an activation attempt",
		Long: "Inspect a separately approved restore-original plan without changing files or signalling SSH. " +
			"Application requires --apply and the exact --recovery-sha256 from inspection. " +
			"It restores retained original configuration and requests one systemd SSH reload. " +
			"Recovery remains required until policy consumption and fresh authenticated access are independently verified. " +
			"This does not enable forward migration or accept a completed recovery.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !sshRecoveryDigest.MatchString(original) || (apply && !sshRecoveryDigest.MatchString(recovery)) || (!apply && recovery != "") {
				return fmt.Errorf("inspection requires --plan-sha256; application additionally requires --apply and a separate lowercase --recovery-sha256 from the reviewed inspection")
			}
			if flag := cmd.Flag("config"); flag != nil && flag.Changed {
				return fmt.Errorf("SSH recovery uses fixed protected SSH paths and does not accept --config")
			}
			var summary sshpolicy.RuntimeRecoverySummary
			var err error
			if apply {
				summary, err = restore(cmd.Context(), original, recovery)
			} else {
				summary, err = inspect(cmd.Context(), original)
			}
			if err == nil {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				err = encoder.Encode(summary)
			}
			if err != nil {
				if apply && summary.RecoveryRequired {
					return fmt.Errorf("SSH restoration remains unverified (configuration_restored=%t, request_returned=%t, recovery_required=true); preserve the journal and do not retry a recorded reload: %w",
						summary.ConfigurationRestored, summary.RequestReturned, err)
				}
				return err
			}
			return nil
		},
	}
	command.Flags().StringVar(&original, "plan-sha256", "", "Original independently approved migration plan SHA-256")
	command.Flags().BoolVar(&apply, "apply", false, "Apply only the separately approved original-configuration restoration")
	command.Flags().StringVar(&recovery, "recovery-sha256", "", "Exact lowercase SHA-256 of the independently reviewed recovery plan")
	_ = command.MarkFlagRequired("plan-sha256")
	return command
}

func sshRestoreOriginalCommand(cmd *cobra.Command) bool {
	return cmd != nil && cmd.CommandPath() == "syswarden ssh-policy restore-original"
}

// Input isolation is not read-only authority. Application still passes the
// removal barrier; both modes validate their own exact protected SSH inputs.
func isolatedSSHPolicyCommand(cmd *cobra.Command) bool {
	return readOnlySSHPolicyCommand(cmd) || sshRestoreOriginalCommand(cmd)
}
