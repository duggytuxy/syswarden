package cmd

import (
	"fmt"

	"syswarden-cli/config"

	"github.com/spf13/cobra"
)

var configGetCmd = &cobra.Command{
	Use:   "config-get <key>",
	Short: "Get a configuration value by key",
	Long: `Get a configuration value by key (e.g., core.firewall_backend).
Useful for shell scripts that need to read the modular configuration.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		value, found, err := config.GetValidatedModularValue(configGetRoot, args[0])
		if err != nil {
			return fmt.Errorf("read validated configuration: %w", err)
		}
		if !found {
			return fmt.Errorf("configuration key %q is not set", args[0])
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), value)
		return nil
	},
}

var configGetRoot = "/etc/syswarden/config"

func init() {
	rootCmd.AddCommand(configGetCmd)
}
