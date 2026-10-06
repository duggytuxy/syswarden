package cmd

import (
	"encoding/json"
	"fmt"
	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var inspectOperatorConfigurationRetention = system.InspectOperatorConfigurationRetention
var applyOperatorConfigurationRetention = system.ApplyOperatorConfigurationRetention

var inspectLegacyLogRetention = system.InspectLegacyLogRetention
var applyLegacyLogRetention = system.ApplyLegacyLogRetention
var inspectLegacyDataRetention = system.InspectLegacyDataRetention
var applyLegacyDataRetention = system.ApplyLegacyDataRetention
var inspectLegacyFail2banRecovery = firewall.InspectLegacyFail2banRecovery
var applyLegacyFail2banRecovery = firewall.ApplyLegacyFail2banRecovery
var inspectLegacyFail2banPersistence = firewall.InspectLegacyFail2banPersistence
var applyLegacyFail2banPersistence = firewall.ApplyLegacyFail2banPersistence
var inspectUnusedLegacyFail2banResume = firewall.InspectUnusedLegacyFail2banResume
var applyUnusedLegacyFail2banResume = firewall.ApplyUnusedLegacyFail2banResume
var inspectLegacyCronRetirement = system.InspectLegacyCronRetirement
var applyLegacyCronRetirement = system.ApplyLegacyCronRetirement

func newRecoverRemovalCommand() *cobra.Command {
	var retainLegacyLogs, retainLegacyLists, retainLegacyUI, retireLegacyCron, retireLegacyFail2ban, retireFail2banPersistence, resumeUnusedFail2ban, retainOperatorConfig, retireHistoricalFirewall, confirmHistoricalInputs, preserveOperatorPolicy, exportOperatorPolicy, apply bool
	var digest, fileDigest, historicalInputs string
	command := &cobra.Command{
		Use:   "recover-removal",
		Short: "Inspect bounded recovery for complete product removal",
		Long:  "Inspect one bounded recovery inventory without changing the host. Review its metadata, exact digest and declared effects before applying. Legacy data archival requires stopped product services and explicit confirmation that the files have no other producer. Administrator configuration retention preserves reviewed files at their original paths. Cron and Fail2ban retirement stop managed product services, preserve unrelated protections and retain original files privately. This command does not infer ownership from a filename or create new ownership markers.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			selection := ""
			for _, candidate := range []struct {
				selected bool
				kind     string
			}{{retainLegacyLogs, "logs"}, {retainLegacyLists, "lists"}, {retainLegacyUI, "ui"}, {retireLegacyCron, "cron"}, {retireLegacyFail2ban, "fail2ban"}, {retireFail2banPersistence, "fail2ban-persistence"}, {resumeUnusedFail2ban, "unused-fail2ban-resume"}, {retainOperatorConfig, "operator-config"}, {retireHistoricalFirewall, "historical-firewall-persistence"}, {preserveOperatorPolicy, "operator-policy"}, {exportOperatorPolicy, "operator-policy-export"}} {
				if candidate.selected {
					if selection != "" {
						return fmt.Errorf("select exactly one legacy retention inventory")
					}
					selection = candidate.kind
				}
			}
			if selection == "" {
				return fmt.Errorf("select a bounded legacy recovery inventory")
			}
			if !apply && digest != "" {
				return fmt.Errorf("--plan-sha256 is accepted only with --apply")
			}
			if apply && digest == "" {
				return fmt.Errorf("--apply requires --plan-sha256 from a reviewed dry run")
			}
			if selection == "historical-firewall-persistence" {
				if historicalInputs == "" || fileDigest != "" || confirmHistoricalInputs != apply {
					return fmt.Errorf("historical persistence requires --historical-inputs, and applying additionally requires --confirm-historical-inputs; Fail2ban file-plan approval does not apply")
				}
				return runHistoricalFirewallPersistenceRecovery(cmd, historicalInputs, digest, apply, confirmHistoricalInputs)
			}
			if historicalInputs != "" || confirmHistoricalInputs {
				return fmt.Errorf("historical input flags apply only to --retire-legacy-firewall-persistence")
			}
			if selection == "unused-fail2ban-resume" {
				if fileDigest == "" {
					return fmt.Errorf("unused Fail2ban resumption requires --file-plan-sha256 from its original recovery")
				}
				return runLegacyFail2banRecoveryMode(cmd, apply, fileDigest, digest, true)
			}
			if selection == "fail2ban" || selection == "fail2ban-persistence" {
				if apply != (fileDigest != "") {
					return fmt.Errorf("Fail2ban apply requires --file-plan-sha256 from its reviewed dry run")
				}
				if selection == "fail2ban-persistence" {
					return runLegacyFail2banPersistenceRecovery(cmd, apply, fileDigest, digest)
				}
				return runLegacyFail2banRecovery(cmd, apply, fileDigest, digest)
			}
			if fileDigest != "" {
				return fmt.Errorf("--file-plan-sha256 applies only to historical Fail2ban recovery")
			}
			if selection == "operator-policy-export" {
				if apply {
					return fmt.Errorf("operator policy export is read-only and cannot be applied")
				}
				return runOperatorPolicyExport(cmd)
			}
			if selection == "operator-policy" {
				return runOperatorPolicyPreservation(cmd, apply, digest)
			}
			if selection == "operator-config" {
				return runOperatorConfigurationRetention(cmd, apply, digest)
			}
			if selection == "cron" {
				return runLegacyCronRecovery(cmd, apply, digest)
			}
			var plan system.LegacyLogRetentionPlan
			var backup string
			var err error
			if apply {
				if selection == "logs" {
					plan, backup, err = applyLegacyLogRetention(digest)
				} else {
					plan, backup, err = applyLegacyDataRetention(selection, digest)
				}
			} else {
				if selection == "logs" {
					plan, err = inspectLegacyLogRetention()
				} else {
					plan, err = inspectLegacyDataRetention(selection)
				}
			}
			if err != nil {
				return err
			}
			wire, err := json.MarshalIndent(plan, "", "  ")
			if err != nil {
				return err
			}
			actual, err := system.LegacyLogRetentionPlanSHA256(plan)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\n\nPlan SHA-256: %s\n", wire, actual); err != nil {
				return err
			}
			if apply {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Legacy data retention completed. Private backup: %s\nResume the original native remove/purge or standalone uninstall command to finish remaining cleanup.\n", backup)
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Dry run only. Confirm that every listed file is legacy SysWarden data with no other producer. All original bytes will be retained privately. After reviewing this exact inventory, apply with: sudo syswarden recover-removal --retain-legacy-%s --apply --plan-sha256 %s\n", selection, actual)
			return err
		},
	}
	command.Flags().BoolVar(&preserveOperatorPolicy, "preserve-operator-policy", false, "Review exact independent administrator policy preservation before product removal")
	command.Flags().BoolVar(&exportOperatorPolicy, "export-operator-policy", false, "Export private typed administrator receiver rules for separate operator review and installation")
	command.Flags().BoolVar(&retireHistoricalFirewall, "retire-legacy-firewall-persistence", false, "Review an exact historical persistent source after product tables are absent")
	command.Flags().StringVar(&historicalInputs, "historical-inputs", "", "Private original generation input capture for historical persistence review")
	command.Flags().BoolVar(&confirmHistoricalInputs, "confirm-historical-inputs", false, "Explicitly confirm original independent generation inputs when applying historical persistence recovery")
	command.Flags().BoolVar(&retainOperatorConfig, "retain-operator-config", false, "Review administrator configuration retention at its original paths across uninstall, remove and purge")
	command.Flags().BoolVar(&retainLegacyLogs, "retain-legacy-logs", false, "Inspect exact private retention of operator-confirmed legacy product logs")
	command.Flags().BoolVar(&retainLegacyLists, "retain-legacy-lists", false, "Inspect exact private retention of operator-confirmed legacy lists")
	command.Flags().BoolVar(&retainLegacyUI, "retain-legacy-ui", false, "Inspect exact private retention of operator-confirmed legacy UI snapshots")
	command.Flags().BoolVar(&retireLegacyCron, "retire-legacy-cron", false, "Inspect exact historical root cron retirement with an original private backup and product service shutdown")
	command.Flags().BoolVar(&retireLegacyFail2ban, "retire-legacy-fail2ban", false, "Inspect verified historical Fail2ban retirement while preserving unrelated jails and the shared service")
	command.Flags().BoolVar(&retireFail2banPersistence, "retire-legacy-fail2ban-persistence", false, "Inspect exact historical Fail2ban entries in shared persistent rules with private original backups")
	command.Flags().BoolVar(&resumeUnusedFail2ban, "resume-unused-fail2ban", false, "Review current protection before resuming only the remaining proven unused definitions; preserve original evidence")
	command.Flags().StringVar(&fileDigest, "file-plan-sha256", "", "Bind historical Fail2ban recovery to the exact reviewed configuration inventory")
	command.Flags().BoolVar(&apply, "apply", false, "Apply the exact reviewed recovery plan")
	command.Flags().StringVar(&digest, "plan-sha256", "", "Authorize only the exact lowercase SHA-256 digest printed by the dry run")
	return command
}

var recoverRemovalCmd = newRecoverRemovalCommand()

func init() { rootCmd.AddCommand(recoverRemovalCmd) }

func runLegacyCronRecovery(cmd *cobra.Command, apply bool, digest string) error {
	var plan system.LegacyCronRetirementPlan
	var backup string
	var err error
	if apply {
		plan, backup, err = applyLegacyCronRetirement(digest)
	} else {
		plan, err = inspectLegacyCronRetirement()
	}
	if err != nil {
		return err
	}
	wire, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	actual, err := system.LegacyCronRetirementPlanSHA256(plan)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\n\nPlan SHA-256: %s\n", wire, actual); err != nil {
		return err
	}
	if apply {
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Exact historical root cron records retired. Original private backup: %s\nResume the original removal command.\n", backup)
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Dry run only. Review the selected line numbers in your root crontab. Applying this plan publishes the removal barrier and stops managed product services. Other records remain byte-for-byte unchanged. Apply with: sudo syswarden recover-removal --retire-legacy-cron --apply --plan-sha256 %s\n", actual)
	return err
}

func runLegacyFail2banRecovery(cmd *cobra.Command, apply bool, fileDigest, digest string) error {
	return runLegacyFail2banRecoveryMode(cmd, apply, fileDigest, digest, false)
}

func prepareLegacyFail2banRemoval() error {
	if err := beginRemoval(); err != nil {
		return err
	}
	if err := prepareFirewallStateForRemoval(); err != nil {
		return err
	}
	return removeOwnedCronStateForRemoval()
}

func runLegacyFail2banPersistenceRecovery(cmd *cobra.Command, apply bool, fileDigest, digest string) error {
	var plan firewall.LegacyFail2banPersistenceSummary
	var err error
	if apply {
		plan, err = applyLegacyFail2banPersistence(cmd.Context(), fileDigest, digest, prepareLegacyFail2banRemoval)
	} else {
		plan, err = inspectLegacyFail2banPersistence(cmd.Context())
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
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Exact historical Fail2ban persistent entries retired. Original shared files remain in the private backup. Inspect 'sudo syswarden recover-removal --retire-legacy-fail2ban' to finish target jail and runtime retirement.\n")
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Dry run only. This plan edits only independently verified historical entries in the listed shared files and keeps their originals privately. Administrator entries remain byte-for-byte unchanged. Applying stops managed product services; it does not stop the shared Fail2ban service, change live rules or reload the firewall. Review both digests, then apply with: sudo syswarden recover-removal --retire-legacy-fail2ban-persistence --apply --file-plan-sha256 %s --plan-sha256 %s\n", plan.FilePlanSHA256, plan.PlanSHA256)
	return err
}

func runLegacyFail2banRecoveryMode(cmd *cobra.Command, apply bool, fileDigest, digest string, resume bool) error {
	var plan firewall.LegacyFail2banRecoverySummary
	var err error
	if apply {
		if resume {
			plan, err = applyUnusedLegacyFail2banResume(cmd.Context(), fileDigest, digest, prepareLegacyFail2banRemoval)
		} else {
			plan, err = applyLegacyFail2banRecovery(cmd.Context(), fileDigest, digest, prepareLegacyFail2banRemoval)
		}
	} else {
		if resume {
			plan, err = inspectUnusedLegacyFail2banResume(cmd.Context(), fileDigest)
		} else {
			plan, err = inspectLegacyFail2banRecovery(cmd.Context())
		}
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
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Reviewed historical Fail2ban retirement completed. Original files remain in the private backup. Resume the original removal command.\n")
		return err
	}
	if resume {
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Dry run only. Independently review the current unrelated Fail2ban protections before approving this new runtime fingerprint. This review covers only the remaining unused file moves, not protection continuity between separate attempts. Original files and earlier runtime evidence remain unchanged. Applying this plan stops managed product services; the shared Fail2ban service remains active. Apply with: sudo syswarden recover-removal --resume-unused-fail2ban --file-plan-sha256 %s --apply --plan-sha256 %s\n", plan.FilePlanSHA256, plan.PlanSHA256)
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Dry run only. Applying this plan stops managed product services and only the listed historical jails. The shared Fail2ban service and unrelated protections remain active. Review both digests, then apply with: sudo syswarden recover-removal --retire-legacy-fail2ban --apply --file-plan-sha256 %s --plan-sha256 %s\n", plan.FilePlanSHA256, plan.PlanSHA256)
	return err
}
