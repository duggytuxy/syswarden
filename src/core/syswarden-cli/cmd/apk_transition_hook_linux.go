//go:build linux

package cmd

import (
	"errors"
	"github.com/spf13/cobra"
	"syswarden-cli/pkg/system"
)

var runInternalAPKTransitionHook = system.RunAPKTransitionHook

var internalAPKTransitionHookCmd = &cobra.Command{
	Use:    "internal-apk-transition-hook",
	Short:  "Consume an authenticated live APK transaction handshake",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Context() == nil {
			return errors.New("APK hook requires a bounded live context")
		}
		if err := cmd.Context().Err(); err != nil {
			return err
		}
		plan, err := cmd.Flags().GetString("execution-plan")
		if err != nil {
			return err
		}
		phase, err := cmd.Flags().GetString("phase")
		if err != nil {
			return err
		}
		if len(plan) != 64 {
			return errors.New("APK hook requires an exact execution plan digest")
		}
		for _, value := range []byte(plan) {
			if !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f') {
				return errors.New("APK hook requires a lowercase execution plan digest")
			}
		}
		if phase != "pre-commit" && phase != "pre-upgrade" && phase != "post-upgrade" && phase != "post-commit" {
			return errors.New("APK hook phase is not supported")
		}
		// Plan strings and command selection grant no authority. The system handler
		// authenticates the retained helper and actual live native coordinator.
		return runInternalAPKTransitionHook(cmd.Context(), plan, phase)
	},
}

func init() {
	internalAPKTransitionHookCmd.Flags().String("execution-plan", "", "Exact retained native execution proposal SHA-256")
	internalAPKTransitionHookCmd.Flags().String("phase", "", "Exact native pre/post-commit or pre/post-upgrade phase")
	rootCmd.AddCommand(internalAPKTransitionHookCmd)
}
