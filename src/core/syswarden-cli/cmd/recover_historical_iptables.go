package cmd

import (
	"encoding/json"
	"fmt"

	"syswarden-cli/pkg/firewall"

	"github.com/spf13/cobra"
)

var inspectHistoricalIPTables = firewall.InspectLegacyIPTablesRecovery
var applyHistoricalIPTables = firewall.ApplyLegacyIPTablesRecovery

func runHistoricalIPTablesRecovery(cmd *cobra.Command, inputPath, digest string, apply, confirmed bool) error {
	var plan firewall.LegacyIPTablesRecoverySummary
	var err error
	if apply {
		plan, err = applyHistoricalIPTables(cmd.Context(), inputPath, digest, confirmed, prepareLegacyFail2banRemoval)
	} else {
		plan, err = inspectHistoricalIPTables(cmd.Context(), inputPath)
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
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "Reviewed historical iptables rules retired. The shared table and exact administrator remainder are preserved. Original captures and recovery intent remain private. Retry the original removal command to finish the remaining product state.")
		return err
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), "Dry run only. Independently verify the original configuration, the before/after generation captures from this boot and network namespace, and that SysWarden was the only writer during that generation interval. Review the current iptables and nftables observations locally and confirm that every retained rule belongs to the administrator or another application. Do not reconstruct missing original evidence from matching current rules. Hashes bind this review but do not authenticate its origin. Applying stops managed product services and deletes only the reviewed handles in one generation-bound transaction; it never flushes or deletes the shared table. Repeat with --apply --confirm-historical-inputs and --plan-sha256 followed by the exact digest above only after this review.")
	return err
}
