package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"syswarden-cli/config"
)

var configPreviewCmd = &cobra.Command{
	Use:   "preview",
	Short: "Review configured host effects without activating them",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		preview, err := config.PreviewConfiguration(cmd.Context(), configEditorRoot)
		if err != nil {
			return fmt.Errorf("configuration preview failed: %w", err)
		}
		if err := readonlyConfigurationLifecyclePreflight(cmd); err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		_, _ = fmt.Fprintf(out, "Validated configuration preview (%d TOML inputs).\n", preview.InputCount)
		for _, line := range preview.ModulePlan {
			_, _ = fmt.Fprintln(out, line)
		}
		printConfigurationEffects(out, preview.Effects)
		_, _ = fmt.Fprintf(out, "Unknown keys: %d. Deprecated entries: %d. Review the TOML values and validation diagnostics before activation.\n", preview.UnknownKeyCount, preview.DeprecatedKeyCount)
		_, _ = fmt.Fprintln(out, "No host change was applied. This preview grants no activation approval and does not prove runtime state or access.")
		return nil
	},
}

func printConfigurationEffects(out io.Writer, effects []config.ConfigurationEffect) {
	if len(effects) == 0 {
		return
	}
	_, _ = fmt.Fprintln(out, "Effects to review before activation (runtime not inspected):")
	for _, effect := range effects {
		_, _ = fmt.Fprintf(out, "- %s: %s\n", effect.Area, effect.Detail)
	}
}

func init() { configCmd.AddCommand(configPreviewCmd) }
