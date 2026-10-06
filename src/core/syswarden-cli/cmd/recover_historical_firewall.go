package cmd

import (
	"encoding/json"
	"fmt"
	"syswarden-cli/pkg/firewall"

	"github.com/spf13/cobra"
)

var inspectHistoricalFirewallPersistence = firewall.InspectHistoricalFirewallPersistence
var applyHistoricalFirewallPersistence = firewall.ApplyHistoricalFirewallPersistence

func runHistoricalFirewallPersistenceRecovery(cmd *cobra.Command, inputPath, digest string, apply, confirmed bool) error {
	var plan firewall.HistoricalFirewallPersistenceSummary
	var err error
	if apply {
		plan, err = applyHistoricalFirewallPersistence(cmd.Context(), inputPath, digest, confirmed, prepareLegacyFail2banRemoval)
	} else {
		plan, err = inspectHistoricalFirewallPersistence(cmd.Context(), inputPath)
	}
	if err != nil {
		return err
	}
	wire, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\n\nPlan SHA-256: %s\n", wire, plan.PlanSHA256); err != nil {
		return err
	}
	if apply {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "Reviewed historical persistent source retired. Original source and shared-file backups remain private. No live firewall rules were deleted. Retry the original removal command for the remaining product state.")
		return err
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), "Dry run only. Independently confirm that the supplied capture describes the original v4.02.8 configuration and host inputs, not values reconstructed from this firewall source or a live ruleset. File hashes bind this review but do not authenticate that historical origin. Applying stops managed product services and retires only the exact recognized source and its bounded includes, keeping private originals. It requires absent product tables and never changes live rules or reloads the shared firewall. After this review, repeat the command with --apply --confirm-historical-inputs and --plan-sha256 followed by the exact digest above.")
	return err
}
