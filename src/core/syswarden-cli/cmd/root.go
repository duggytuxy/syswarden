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
	Long:  "SYSWARDEN is a host firewall orchestrator and out-of-band security-log analysis toolkit; it is not an inline WAF.",
	Run: func(cmd *cobra.Command, args []string) {
		// Default behavior when no subcommand is given
		fmt.Printf("SYSWARDEN %s CLI\n", system.Version)
		fmt.Println("Use 'syswarden manual' for the built-in operator reference, or 'syswarden --help' for command help.")
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
	// Parse config if TOML directory exists, or if legacy conf file exists
	tomlExists := false
	if _, err := os.Stat("/etc/syswarden/config/modules"); err == nil {
		tomlExists = true
	}

	if tomlExists {
		if err := config.ParseConfig("/etc/syswarden/config"); err != nil {
			fmt.Fprintf(os.Stderr, "[WARNING] Failed to load modular config: %v\n", err)
			fmt.Fprintf(os.Stderr, "[WARNING] Continuing in degraded mode. Please fix using 'syswarden config'\n")
		}
	} else if _, err := os.Stat(cfgFile); err == nil {
		if err := config.ParseConfig(cfgFile); err != nil {
			fmt.Fprintf(os.Stderr, "[WARNING] Failed to load config: %v\n", err)
			fmt.Fprintf(os.Stderr, "[WARNING] Continuing in degraded mode. Please fix using 'syswarden config'\n")
		}
	} else {
		// Ensure config is not nil and vital defaults are maintained even if file is missing (e.g. during fresh install)
		config.GlobalConfig = &config.Config{
			WhitelistInfra: true,
		}
	}
}
