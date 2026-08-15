package cmd

import (
	"fmt"

	"syswarden-cli/config"

	"github.com/spf13/cobra"
)

var migrateConfigCmd = &cobra.Command{
	Use:   "migrate-config",
	Short: "Migrate from old config format to modular TOML format",
	Long: `Migrate your existing syswarden-auto.conf configuration file
to the new modular TOML format. This creates a new directory structure
with separated configuration files for each domain.

With --dry-run, migrated file contents are not written and the source is not
renamed or wiped, but the output directory and modules subdirectory may be created.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		source, err := cmd.Flags().GetString("source")
		if err != nil {
			return err
		}
		output, err := cmd.Flags().GetString("output")
		if err != nil {
			return err
		}
		dryRun, err := cmd.Flags().GetBool("dry-run")
		if err != nil {
			return err
		}

		if source == "" {
			source = "/opt/syswarden/syswarden-auto.conf"
		}
		if output == "" {
			output = "/etc/syswarden/config"
		}

		migrator := &config.Migrator{
			SourcePath: source,
			OutputDir:  output,
			DryRun:     dryRun,
		}

		if dryRun {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "[DRY RUN] Migrated file contents will not be written and the source will not be renamed or wiped; the output directory and modules subdirectory may be created.")
		}

		if err := migrator.Run(); err != nil {
			return fmt.Errorf("[ERROR] migration failed: %w", err)
		}

		if !dryRun {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nConfiguration migrated successfully.")
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "New configuration: %s\n", output)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(migrateConfigCmd)
	migrateConfigCmd.Flags().StringP("source", "s", "", "Source config file path")
	migrateConfigCmd.Flags().StringP("output", "o", "", "Output directory")
	migrateConfigCmd.Flags().Bool("dry-run", false, "Do not write migrated file contents; output directories may be created")
}
