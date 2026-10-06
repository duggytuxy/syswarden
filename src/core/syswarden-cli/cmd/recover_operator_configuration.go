package cmd

import (
	"encoding/json"
	"fmt"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

func runOperatorConfigurationRetention(cmd *cobra.Command, apply bool, digest string) error {
	var plan system.OperatorConfigurationRetentionPlan
	var decision string
	var err error
	if apply {
		plan, decision, err = applyOperatorConfigurationRetention(digest)
	} else {
		plan, err = inspectOperatorConfigurationRetention()
	}
	if err != nil {
		return err
	}
	wire, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	actual, err := system.OperatorConfigurationRetentionPlanSHA256(plan)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\n\nPlan SHA-256: %s\n", wire, actual); err != nil {
		return err
	}
	if apply {
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Administrator configuration remains unchanged at its original paths. Private retention decision: %s\nResume the original uninstall, remove or purge command. Later administrator edits remain protected; new unreviewed paths require a separate decision.\n", decision)
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Dry run only. Confirm that every listed file is administrator-owned configuration to preserve at its original path. This decision grants no deletion authority and publishes no file content. Apply this exact inventory with: sudo syswarden recover-removal --retain-operator-config --apply --plan-sha256 %s\n", actual)
	return err
}
