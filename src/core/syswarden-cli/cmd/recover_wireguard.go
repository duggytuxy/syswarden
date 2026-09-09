package cmd

import (
	"fmt"
	"strings"
	"syswarden-cli/pkg/network"

	"github.com/spf13/cobra"
)

var inspectLegacyWireGuardRecovery = network.InspectLegacyWireGuardRecovery
var applyLegacyWireGuardRecovery = network.ApplyLegacyWireGuardRecovery

func newRecoverWireGuardCommand() *cobra.Command {
	var apply bool
	var planSHA256 string
	command := &cobra.Command{
		Use:   "recover-wireguard",
		Short: "Inspect and explicitly recover exact historical WireGuard nftables state",
		Long: "Inspects one of the two supported historical SysWarden WireGuard generations without changing the host. " +
			"Recovery is fail-closed and requires a second invocation with --apply and the exact SHA-256 digest printed by the dry run.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !apply && planSHA256 != "" {
				return fmt.Errorf("--plan-sha256 is accepted only with --apply")
			}
			if apply && planSHA256 == "" {
				return fmt.Errorf("--apply requires --plan-sha256 from a reviewed dry run")
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
	command.Flags().StringVar(
		&planSHA256,
		"plan-sha256",
		"",
		"Authorize only the exact lowercase SHA-256 digest printed by the dry run",
	)
	return command
}

var recoverWireGuardCmd = newRecoverWireGuardCommand()

func init() {
	rootCmd.AddCommand(recoverWireGuardCmd)
}
