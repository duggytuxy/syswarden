package cmd

import (
	"fmt"

	"syswarden-cli/config"
	"syswarden-cli/pkg/platformpaths"

	"github.com/spf13/cobra"
)

var migrateConfigCmd = &cobra.Command{
	Use:   "migrate-config",
	Short: "Migrate from old config format to modular TOML format",
	Long: `Migrate your existing syswarden-auto.conf configuration file
to the new modular TOML format. This creates a new directory structure
with separated configuration files for each domain.

With --dry-run, migrated file contents are not written and the source and
destination filesystem are not modified.`,
	RunE: runConfigMigration,
	Args: cobra.NoArgs,
}

var configMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate the historical configuration to modular TOML",
	Long:  "Migrate the historical configuration to modular TOML. With --dry-run, neither the source nor destination filesystem is modified.",
	RunE:  runConfigMigration,
	Args:  cobra.NoArgs,
}

func runConfigMigration(cmd *cobra.Command, args []string) error {
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
		source = platformpaths.LegacyConfig
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
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "[DRY RUN] Validating migration without filesystem changes.")
	}

	if err := migrator.Run(); err != nil {
		return fmt.Errorf("[ERROR] migration failed: %w", err)
	}

	if !dryRun {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nConfiguration migrated successfully.")
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "New configuration: %s\n", output)
	} else {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "[DRY RUN] Migration is valid; no source or destination file was modified.")
	}
	return nil
}

func init() {
	rootCmd.AddCommand(migrateConfigCmd)
	configCmd.AddCommand(configMigrateCmd)
	for _, command := range []*cobra.Command{migrateConfigCmd, configMigrateCmd} {
		command.Flags().StringP("source", "s", "", "Source config file path")
		command.Flags().StringP("output", "o", "", "Output directory")
		command.Flags().Bool("dry-run", false, "Validate migration without modifying source or destination files")
	}
}
