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
var inspectLegacyWireGuardMigration = network.InspectLegacyWireGuardMigration
var applyLegacyWireGuardMigration = network.ApplyLegacyWireGuardMigration

func newRecoverWireGuardCommand() *cobra.Command {
	var apply bool
	var retireLegacyWG0 bool
	var migrateLegacyCurrent bool
	var planSHA256 string
	command := &cobra.Command{
		Use:   "recover-wireguard",
		Short: "Inspect and explicitly recover exact historical WireGuard nftables state",
		Long: "Inspects supported historical SysWarden WireGuard state without changing the host. " +
			"Use --retire-legacy-wg0 to explicitly retire the exact historical wg0 configuration, including proven unmanifested historical wg-syswarden. Use --migrate-legacy-wg-syswarden to preserve that VPN and migrate its exact generated hooks after historical wg0 retirement. " +
			"Recovery is fail-closed and requires a second invocation with --apply and the exact SHA-256 digest printed by the dry run.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !apply && planSHA256 != "" {
				return fmt.Errorf("--plan-sha256 is accepted only with --apply")
			}
			if apply && planSHA256 == "" {
				return fmt.Errorf("--apply requires --plan-sha256 from a reviewed dry run")
			}
			if retireLegacyWG0 && migrateLegacyCurrent {
				return fmt.Errorf("retirement and migration require separate reviewed plans")
			}
			if migrateLegacyCurrent {
				return runLegacyWireGuardMigration(cmd, apply, planSHA256)
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
	command.Flags().BoolVar(&retireLegacyWG0, "retire-legacy-wg0", false, "Inspect explicit historical wg0 retirement with a private backup, including proven historical wg-syswarden without a manifest")
	command.Flags().BoolVar(&migrateLegacyCurrent, "migrate-legacy-wg-syswarden", false, "Inspect preservation of the exact historical wg-syswarden VPN, with private backups and manifest-bound hooks")
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
	if len(plan.LegacyGenerated) != 0 {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), "The historical wg-syswarden files are preserved without claiming ownership. After retiring wg0, inspect recover-wireguard --migrate-legacy-wg-syswarden before resuming package configuration or removal."); err != nil {
			return err
		}
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

func runLegacyWireGuardMigration(cmd *cobra.Command, apply bool, digest string) error {
	var plan network.LegacyWireGuardMigrationPlan
	var err error
	if apply {
		plan, err = applyLegacyWireGuardMigration(digest)
	} else {
		plan, err = inspectLegacyWireGuardMigration()
	}
	if err != nil {
		return err
	}
	wire, err := network.RenderLegacyWireGuardMigrationPlan(plan)
	if err != nil {
		return err
	}
	planDigest, err := network.LegacyWireGuardMigrationPlanSHA256(plan)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\n\nPlan SHA-256: %s\n", wire, planDigest); err != nil {
		return err
	}
	if apply && plan.State == "complete" {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "Historical VPN migration was already complete. This invocation changed no service, configuration or runtime state.")
		return err
	}
	if apply {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "Historical wg-syswarden migration verified. Private backups retain the original files. Keys, client configuration, VPN addresses and port are preserved. Services remain stopped. Install or resume the verified v4.10.3 native package. These hooks require v4.10.3; do not configure the older half-configured v4.10.2 package. Preserve any removal barrier and resume native removal when that was the intended operation.")
		return err
	}
	if !plan.SafeToApply {
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Dry run only. Migration is blocked: %s\nConfirm independent administration access and the intent to preserve this VPN before stopping and disabling its service. Repeat this inspection afterward. Do not publish the plan or private backups.\n", strings.Join(plan.Blockers, "; "))
		return err
	}
	if plan.State == "complete" {
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "Dry run only. The historical VPN migration is already complete; no change is required.")
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Dry run only. To preserve the existing VPN and replace its exact historical hooks after reviewing this plan: sudo syswarden recover-wireguard --migrate-legacy-wg-syswarden --apply --plan-sha256 %s\n", planDigest)
	return err
}
