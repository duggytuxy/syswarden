package cmd

import (
	"fmt"
	"os"

	"syswarden-cli/config"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "syswarden",
	Short: "SYSWARDEN Security Orchestrator",
	Long:  fmt.Sprintf(`SYSWARDEN %s is a Next-Gen Host-based WAF and Security Orchestrator.`, system.Version),
	Run: func(cmd *cobra.Command, args []string) {
		// Default behavior when no subcommand is given
		fmt.Printf("SYSWARDEN %s CLI\n", system.Version)
		fmt.Println("Use 'syswarden manual' for the comprehensive SysAdmin documentation, or 'syswarden --help' for standard commands.")
	},
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd:   false,
		DisableDescriptions: true,
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "/opt/syswarden/syswarden-auto.conf", "config file")
}

func initConfig() {
	// Only parse config if the file exists
	if _, err := os.Stat(cfgFile); err == nil {
		if err := config.ParseConfig(cfgFile); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to load config: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Ensure config is not nil and vital defaults are maintained even if file is missing (e.g. during fresh install)
		config.GlobalConfig = &config.Config{
			WhitelistInfra: true,
		}
	}
}
