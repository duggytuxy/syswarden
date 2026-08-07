package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/viper"
)

func LoadConfig() error {
	v := viper.GetViper()
	v.SetConfigType("toml")
	v.AutomaticEnv()
	v.SetEnvPrefix("SYSWARDEN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	configPath := "/etc/syswarden/config"

	// Load master config
	masterConfig := filepath.Join(configPath, "config.toml")
	if _, err := os.Stat(masterConfig); err == nil {
		v.SetConfigFile(masterConfig)
		if err := v.MergeInConfig(); err != nil {
			return fmt.Errorf("failed to load master config: %w", err)
		}
	}

	// Load modules in priority order
	modulesDir := filepath.Join(configPath, "modules")
	if _, err := os.Stat(modulesDir); err == nil {
		files, err := filepath.Glob(filepath.Join(modulesDir, "*.toml"))
		if err != nil {
			return err
		}
		sort.Slice(files, func(i, j int) bool {
			return filepath.Base(files[i]) < filepath.Base(files[j])
		})
		for _, file := range files {
			v.SetConfigFile(file)
			if err := v.MergeInConfig(); err != nil {
				return fmt.Errorf("failed to load module %s: %w", file, err)
			}
		}
	}

	return nil
}
