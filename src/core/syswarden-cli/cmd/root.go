package cmd

import (
	"fmt"
	"os"

	"syswarden-cli/config"
	"syswarden-cli/pkg/platformpaths"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "syswarden",
	Short: "SYSWARDEN Security Orchestrator",
	Long:  "SYSWARDEN is a host firewall orchestrator and out-of-band security-log analysis toolkit; it is not an inline WAF.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return enforceValidatedConfiguration(cmd)
	},
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
	cobra.OnInitialize(func() { initConfigHook() })
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", platformpaths.LegacyConfig, "config file")
}

var initConfigHook = initConfig

var degradedConfigAllowlist = map[string]struct{}{
	"completion":     {},
	"config":         {},
	"ha-fence":       {},
	"help":           {},
	"install":        {},
	"manual":         {},
	"migrate-config": {},
}

func enforceValidatedConfiguration(cmd *cobra.Command) error {
	if cmd == nil || cmd.Parent() == nil {
		return nil
	}
	topLevel := cmd
	for topLevel.Parent() != nil && topLevel.Parent().Parent() != nil {
		topLevel = topLevel.Parent()
	}
	if _, allowed := degradedConfigAllowlist[topLevel.Name()]; allowed {
		return nil
	}
	state := config.CurrentLoadState()
	if !state.Degraded {
		return nil
	}
	return fmt.Errorf(
		"[ERROR] validated configuration is unavailable from %s: %s; repair it with 'syswarden config' or 'syswarden migrate-config'",
		state.Source,
		state.Error,
	)
}

func initConfig() {
	// Parse config if TOML directory exists, or if legacy conf file exists
	tomlExists := false
	if _, err := os.Stat("/etc/syswarden/config/modules"); err == nil {
		tomlExists = true
	}

	if tomlExists {
		_ = config.ParseConfig("/etc/syswarden/config")
		return
	}

	// ParseConfig records a failed source in CurrentLoadState. Keep startup
	// silent here so root, help, and repair commands retain their process
	// contract; mutating commands surface the recorded failure through the
	// fail-closed PersistentPreRunE guard above.
	_ = config.ParseConfig(cfgFile)
}
