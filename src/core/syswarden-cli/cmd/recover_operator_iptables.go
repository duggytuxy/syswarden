package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
	"syswarden-cli/pkg/firewall"
)

var inspectOperatorIPTablesPreservation = firewall.InspectOperatorIPTablesPreservation
var applyOperatorIPTablesPreservation = firewall.ApplyOperatorIPTablesPreservation

func runOperatorIPTablesPreservation(cmd *cobra.Command, apply bool, digest string, confirmed bool) error {
	var plan firewall.OperatorIPTablesPreservationSummary
	var err error
	if apply {
		plan, err = applyOperatorIPTablesPreservation(cmd.Context(), digest, confirmed)
	} else {
		plan, err = inspectOperatorIPTablesPreservation(cmd.Context())
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
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "Administrator iptables preservation decision recorded privately. No rule, service or active configuration was changed. Resume the original removal command. A reboot, reload that changes rule identities, or policy change requires a fresh review.")
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Dry run only. Independently verify every rule in 'sudo iptables-save -t filter' and 'sudo nft -a list table ip filter', including persistence managed by the administrator. Use this route only after historical product rules have been removed and every remaining rule belongs to the administrator. It grants no deletion authority and cannot override a product ownership manifest. Do not publish the rule inventory. Apply the exact reviewed decision with: sudo syswarden recover-removal --preserve-operator-iptables --confirm-operator-iptables --apply --plan-sha256 %s\n", plan.PlanSHA256)
	return err
}
