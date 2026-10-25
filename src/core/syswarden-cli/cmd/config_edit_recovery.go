package cmd

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"syswarden-cli/config"

	"github.com/spf13/cobra"
)

var configEditRecoveryCmd = &cobra.Command{
	Use:   "recover-edit",
	Short: "Review and recover an interrupted TOML file publication",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		observed, err := config.ObserveModuleEdit(cmd.Context(), configEditorRoot)
		if err != nil {
			return err
		}
		if observed.State == "none" {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No pending TOML file publication requires recovery.")
			return nil
		}
		plan, err := config.PrepareModuleEditRecovery(cmd.Context(), configEditorRoot)
		if err != nil {
			return err
		}
		return reviewModuleEditRecovery(cmd, plan)
	},
}

type reviewedModuleEditRecovery interface {
	Review() config.ModuleEditRecoveryReview
	Apply(context.Context, string, func() error) error
}

func reviewModuleEditRecovery(cmd *cobra.Command, plan reviewedModuleEditRecovery) error {
	review := plan.Review()
	output := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(output, "Interrupted configuration publication: %s.\n", review.Target)
	switch review.Action {
	case "discard_unpublished_candidate":
		_, _ = fmt.Fprintln(output, "Proposed recovery: discard the unpublished candidate and preserve the original file.")
	case "restore_original_file":
		_, _ = fmt.Fprintln(output, "Proposed recovery: restore the recorded original file, or its original absence.")
	case "finish_committed_cleanup":
		_, _ = fmt.Fprintln(output, "Proposed recovery: keep the committed file and finish removal of its recorded temporary copy.")
	case "finish_rollback_cleanup":
		_, _ = fmt.Fprintln(output, "Proposed recovery: keep the restored original and finish removal of the recorded candidate.")
	default:
		return fmt.Errorf("unsupported configuration recovery action")
	}
	if review.InputsChanged {
		_, _ = fmt.Fprintln(output, "Other configuration files changed since publication began. Their current reviewed state will be preserved.")
	}
	for _, line := range review.ModulePlan {
		_, _ = fmt.Fprintln(output, line)
	}
	if len(review.ModulePlan) != 0 {
		_, _ = fmt.Fprintf(output, "Unknown keys: %d. Deprecated entries: %d. Review the current TOML values before approving cleanup.\n", review.UnknownKeyCount, review.DeprecatedKeyCount)
	}
	_, _ = fmt.Fprintln(output, "Recovery only changes the recorded file pair and journal. It does not activate policy or reload services.")
	_, _ = fmt.Fprintf(output, "Approval expires at %s.\n", review.ExpiresAt.Format("15:04:05 MST"))
	expected := "recover " + review.ApprovalID
	_, _ = fmt.Fprintf(output, "Type '%s' to recover, or press Enter to cancel: ", expected)
	reader := bufio.NewReader(cmd.InOrStdin())
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read recovery approval; no recovery was applied: %w", err)
	}
	if strings.TrimSpace(input) != expected {
		_, _ = fmt.Fprintln(output, "Recovery cancelled. Configuration and retained evidence were preserved.")
		return nil
	}
	if err := plan.Apply(cmd.Context(), review.ApprovalID, func() error { return readonlyConfigurationLifecyclePreflight(cmd) }); err != nil {
		return fmt.Errorf("configuration recovery refused; preserve remaining evidence: %w", err)
	}
	_, _ = fmt.Fprintln(output, "Recorded file recovery completed. Run 'syswarden config validate' and review the resulting policy before any activation.")
	return nil
}

func readonlyConfigurationLifecyclePreflight(cmd *cobra.Command) error {
	if err := preflightWireGuardPolicyTransition(); err != nil {
		return err
	}
	if err := enforceRemovalState(cmd); err != nil {
		return err
	}
	return refusePendingFirewallTransactionHook()
}

func init() { configCmd.AddCommand(configEditRecoveryCmd) }
