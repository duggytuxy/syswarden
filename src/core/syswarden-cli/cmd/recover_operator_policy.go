package cmd

import (
	"encoding/json"
	"fmt"
	"syswarden-cli/pkg/firewall"

	"github.com/spf13/cobra"
)

var inspectOperatorPolicyPreservation = firewall.InspectOperatorPolicyPreservation
var applyOperatorPolicyPreservation = firewall.ApplyOperatorPolicyPreservation
var exportOperatorPolicyReceiver = firewall.ExportOperatorPolicyReceiver

func runOperatorPolicyPreservation(cmd *cobra.Command, apply bool, digest string) error {
	var plan firewall.OperatorPolicyPreservationSummary
	var err error
	if apply {
		plan, err = applyOperatorPolicyPreservation(cmd.Context(), digest)
	} else {
		plan, err = inspectOperatorPolicyPreservation(cmd.Context())
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
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "Independent administrator policy preservation recorded privately. Active configuration and live rules were not changed. Resume the original uninstall, remove or purge command; every removal boundary will recheck the original source, enabled shared loader and exact receiver.")
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Dry run only. Review the independently installed receiver and enabled shared-loader configuration before acknowledging this exact plan. Ingress accepts do not override drops in other base chains. The private decision keeps original counter observations; it does not claim a continuous counter epoch. This decision grants no ownership of administrator policy and changes no active file or live rule. Apply with: sudo syswarden recover-removal --preserve-operator-policy --apply --plan-sha256 %s\n", plan.PlanSHA256)
	return err
}

func runOperatorPolicyExport(cmd *cobra.Command) error {
	receiver, err := exportOperatorPolicyReceiver()
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Preparation only. Standard output contains private administrator rule predicates. Save it privately and review it before installation with mode 0600 at %s. Include that exact file once in the active, boot-enabled shared nftables loader and verify traffic independently. Then inspect --preserve-operator-policy. Exporting changes no configuration and grants no removal authority.\n", receiver.Path); err != nil {
		return err
	}
	_, err = cmd.OutOrStdout().Write(receiver.Source)
	return err
}
