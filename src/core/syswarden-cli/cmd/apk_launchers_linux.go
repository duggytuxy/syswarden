//go:build linux

package cmd

import (
	"errors"
	"os"

	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var stageFreshPackageLaunchers = system.StageFreshAPKLaunchers

var completeFreshPackageLaunchers = system.CompleteFreshAPKLaunchers

// This exact command bypasses the normal policy loader and firewall recovery.
// Its flag selects a fixed intent consumer, never permission to adopt aliases.
var internalAPKLaunchersCmd = &cobra.Command{
	Use:    "internal-apk-launchers",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return errors.New("APK launcher completion requires root")
		}
		complete, completeErr := cmd.Flags().GetBool("complete-fresh")
		stage, stageErr := cmd.Flags().GetBool("stage-fresh")
		if completeErr != nil || stageErr != nil || complete == stage ||
			cmd.Flags().Changed("complete-fresh") != complete || cmd.Flags().Changed("stage-fresh") != stage {
			return errors.New("APK launcher ingress requires exactly one explicit fresh operation")
		}
		if err := enforceRemovalState(cmd); err != nil {
			return err
		}
		if stage {
			return stageFreshPackageLaunchers(cmd.Context())
		}
		return completeFreshPackageLaunchers(cmd.Context())
	},
}

func init() {
	internalAPKLaunchersCmd.Flags().Bool("complete-fresh", false, "complete only the exact pending fresh APK launcher intent after native commit")
	internalAPKLaunchersCmd.Flags().Bool("stage-fresh", false, "stage exact fresh APK launcher intent before native commit without creating aliases")
	rootCmd.AddCommand(internalAPKLaunchersCmd)
}
