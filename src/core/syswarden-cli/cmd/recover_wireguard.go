package cmd

import (
	"fmt"
	"strings"
	"syswarden-cli/pkg/network"

	"github.com/spf13/cobra"
)

var inspectLegacyWireGuardRecovery = network.InspectLegacyWireGuardRecovery
var applyLegacyWireGuardRecovery = network.ApplyLegacyWireGuardRecovery
var inspectLegacyWireGuardRetirement = network.InspectLegacyWireGuardRetirement
var applyLegacyWireGuardRetirement = network.ApplyLegacyWireGuardRetirement

func newRecoverWireGuardCommand() *cobra.Command {
	var apply bool
	var retireLegacyWG0 bool
	var planSHA256 string
	command := &cobra.Command{
		Use:   "recover-wireguard",
		Short: "Inspect and explicitly recover exact historical WireGuard nftables state",
		Long: "Inspects supported historical SysWarden WireGuard state without changing the host. " +
			"Use --retire-legacy-wg0 to explicitly retire the exact historical wg0 configuration, including coexistence with manifest-owned wg-syswarden. " +
			"Recovery is fail-closed and requires a second invocation with --apply and the exact SHA-256 digest printed by the dry run.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !apply && planSHA256 != "" {
				return fmt.Errorf("--plan-sha256 is accepted only with --apply")
			}
			if apply && planSHA256 == "" {
				return fmt.Errorf("--apply requires --plan-sha256 from a reviewed dry run")
			}
			if retireLegacyWG0 {
				return runLegacyWireGuardRetirement(cmd, apply, planSHA256)
			}

			var (
				plan network.LegacyWireGuardRecoveryPlan
				err  error
			)
			if apply {
				plan, err = applyLegacyWireGuardRecovery(planSHA256)
			} else {
				plan, err = inspectLegacyWireGuardRecovery()
			}
			if err != nil {
				return err
			}
			wire, err := network.RenderLegacyWireGuardRecoveryPlan(plan)
			if err != nil {
				return fmt.Errorf("render legacy WireGuard recovery plan: %w", err)
			}
			digest, err := network.LegacyWireGuardRecoveryPlanSHA256(plan)
			if err != nil {
				return fmt.Errorf("digest legacy WireGuard recovery plan: %w", err)
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\n\nPlan SHA-256: %s\n", wire, digest); err != nil {
				return err
			}
			if apply {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "Recovery applied and the exact historical nftables state is absent.")
				return err
			}
			if !plan.SafeToApply {
				_, err = fmt.Fprintf(
					cmd.OutOrStdout(),
					"Dry run only. Recovery is blocked: %s\n",
					strings.Join(plan.Blockers, "; "),
				)
				return err
			}
			_, err = fmt.Fprintf(
				cmd.OutOrStdout(),
				"Dry run only. After reviewing the plan, apply exactly with: sudo syswarden recover-wireguard --apply --plan-sha256 %s\n",
				digest,
			)
			return err
		},
	}
	command.Flags().BoolVar(&apply, "apply", false, "Apply the exact reviewed recovery plan")
	command.Flags().BoolVar(&retireLegacyWG0, "retire-legacy-wg0", false, "Inspect explicit historical wg0 retirement with a private backup, including coexistence with manifest-owned wg-syswarden")
	command.Flags().StringVar(
		&planSHA256,
		"plan-sha256",
		"",
		"Authorize only the exact lowercase SHA-256 digest printed by the dry run",
	)
	return command
}

func runLegacyWireGuardRetirement(cmd *cobra.Command, apply bool, planSHA256 string) error {
	var plan network.LegacyWireGuardRetirementPlan
	var err error
	if apply {
		plan, err = applyLegacyWireGuardRetirement(planSHA256)
	} else {
		plan, err = inspectLegacyWireGuardRetirement()
	}
	if err != nil {
		return err
	}
	wire, err := network.RenderLegacyWireGuardRetirementPlan(plan)
	if err != nil {
		return err
	}
	digest, err := network.LegacyWireGuardRetirementPlanSHA256(plan)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\n\nPlan SHA-256: %s\n", wire, digest); err != nil {
		return err
	}
	if apply {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "Historical wg0 retirement verified. The configuration is preserved in the private archive and its original path is absent. Current ownership evidence is retained. Resume removal through the native package manager, or standalone uninstall when applicable; otherwise reconcile the current installation.")
		return err
	}
	if !plan.SafeToApply {
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Dry run only. Retirement is blocked: %s\nConfirm independent administration access before stopping any VPN. Stop and disable the affected services, then repeat this dry run. Preserve both configurations, the ownership manifest and any removal barrier.\n", strings.Join(plan.Blockers, "; "))
		return err
	}
	if plan.State == "retired" {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "Dry run only. Historical wg0 is already retired; no change is required.")
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Dry run only. After reviewing the plan and confirming retirement of the historical VPN, apply exactly with: sudo syswarden recover-wireguard --retire-legacy-wg0 --apply --plan-sha256 %s\n", digest)
	return err
}

var recoverWireGuardCmd = newRecoverWireGuardCommand()

func init() {
	rootCmd.AddCommand(recoverWireGuardCmd)
}
