package cmd

import (
	"fmt"
	"os"

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
	Run: func(cmd *cobra.Command, args []string) {
		source, _ := cmd.Flags().GetString("source")
		output, _ := cmd.Flags().GetString("output")
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		if source == "" {
			source = "/opt/syswarden/syswarden-auto.conf"
		}
		if output == "" {
			output = "/etc/syswarden/config"
		}

		if _, err := os.Stat(source); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[ERROR] Source config file not found: %s\n", source)
			os.Exit(1)
		}

		migrator := &config.Migrator{
			SourcePath: source,
			OutputDir:  output,
			DryRun:     dryRun,
		}

		if dryRun {
			fmt.Println("[DRY RUN] Migrated file contents will not be written and the source will not be renamed or wiped; the output directory and modules subdirectory may be created.")
		}

		if err := migrator.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Migration failed: %v\n", err)
			os.Exit(1)
		}

		if !dryRun {
			fmt.Println("\n✅ Configuration migrated successfully!")
			fmt.Printf("New configuration: %s\n", output)
		}
	},
}

func init() {
	rootCmd.AddCommand(migrateConfigCmd)
	migrateConfigCmd.Flags().StringP("source", "s", "", "Source config file path")
	migrateConfigCmd.Flags().StringP("output", "o", "", "Output directory")
	migrateConfigCmd.Flags().Bool("dry-run", false, "Do not write migrated file contents; output directories may be created")
}
