package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configGetCmd = &cobra.Command{
	Use:   "config-get <key>",
	Short: "Get a configuration value by key",
	Long: `Get a configuration value by key (e.g., core.firewall_backend).
Useful for shell scripts that need to read the modular configuration.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]

		// Load the configuration without fully parsing into structs
		// just enough to let Viper read the files and environment variables.
		v := viper.New()
		v.SetConfigType("toml")
		v.AutomaticEnv()
		v.SetEnvPrefix("SYSWARDEN")
		v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

		// Load master config
		masterConfig := "/etc/syswarden/config/config.toml"
		if _, err := os.Stat(masterConfig); err == nil {
			v.SetConfigFile(masterConfig)
			_ = v.MergeInConfig()
		}

		// Load modules
		modulesDir := "/etc/syswarden/config/modules"
		if _, err := os.Stat(modulesDir); err == nil {
			files, _ := filepath.Glob(filepath.Join(modulesDir, "*.toml"))
			for _, file := range files {
				v.SetConfigFile(file)
				_ = v.MergeInConfig()
			}
		}

		if !v.IsSet(key) {
			os.Exit(1)
		}

		fmt.Println(v.GetString(key))
	},
}

func init() {
	rootCmd.AddCommand(configGetCmd)
}
