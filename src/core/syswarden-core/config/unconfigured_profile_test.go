package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func unconfiguredRuntimeFixture(t *testing.T) string {
	t.Helper()
	master := strings.Replace(validMaster("schema_version = 1"), "[core]\n", "[core]\ninstall_profile='unconfigured-v1'\n", 1)
	return writeConfigFixture(t, master, map[string]string{
		"00-core.toml":         "[core]\ninstall_profile='unconfigured-v1'\n",
		"10-network.toml":      "[network.blocklists]\nlist_choice='2'\n",
		"20-security.toml":     "# Synthetic security module\n",
		"30-waap.toml":         "[waap]\nenabled=true\n",
		"40-integrations.toml": "# Synthetic integrations module\n",
		"99-user.toml":         "# Administrator override slot\n",
	})
}

func TestUnconfiguredRuntimeRequiresCompletePublicationWithoutChangingLastSnapshot(t *testing.T) {
	t.Cleanup(viper.Reset)
	for _, missing := range []string{"config.toml", "modules/00-core.toml", "modules/10-network.toml", "modules/20-security.toml", "modules/30-waap.toml", "modules/40-integrations.toml", "modules/99-user.toml"} {
		t.Run(missing, func(t *testing.T) {
			root := unconfiguredRuntimeFixture(t)
			if _, err := LoadConfigDirectory(root); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(root, missing)); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfigDirectory(root); err == nil || !strings.Contains(err.Error(), "incomplete unconfigured-v1 publication") {
				t.Fatal("incomplete runtime publication accepted", err)
			}
			if viper.GetString("network.blocklists.list_choice") != "2" || !viper.GetBool("waap.enabled") || viper.GetString("core.install_profile") != UnconfiguredInstallProfile {
				t.Fatal("failed load changed prior selected policy")
			}
		})
	}
}

func TestUnconfiguredRuntimeRejectsUnsafeReplacementAndProfileShadowing(t *testing.T) {
	t.Cleanup(viper.Reset)
	for _, mutation := range []string{"symlink", "directory", "missing-marker", "truncated", "shadow-standard", "shadow-historical"} {
		t.Run(mutation, func(t *testing.T) {
			root := unconfiguredRuntimeFixture(t)
			path := filepath.Join(root, "modules/00-core.toml")
			switch mutation {
			case "symlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, "config.toml"), path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "missing-marker", "truncated":
				content := "[core]\nlog_level='INFO'\n"
				if mutation == "truncated" {
					content = "[core\n"
				}
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			default:
				profile := StandardInstallProfile
				if mutation == "shadow-historical" {
					profile = ""
				}
				if err := os.WriteFile(filepath.Join(root, "modules/99-user.toml"), []byte("[core]\ninstall_profile='"+profile+"'\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := LoadConfigDirectory(root); err == nil {
				t.Fatal("unsafe or contradictory runtime publication accepted")
			}
		})
	}
}

func TestHistoricalRuntimeLayoutsRemainIndependentOfUnconfiguredCompleteness(t *testing.T) {
	t.Cleanup(viper.Reset)
	for _, profile := range []string{"", StandardInstallProfile} {
		master := strings.Replace(validMaster("schema_version = 1"), "[core]\n", "[core]\ninstall_profile='"+profile+"'\n", 1)
		if _, err := LoadConfigDirectory(writeConfigFixture(t, master, nil)); err != nil {
			t.Fatal("historical layout changed", profile, err)
		}
	}
}
