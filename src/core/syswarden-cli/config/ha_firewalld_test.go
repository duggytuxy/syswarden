package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestHAFirewalldScopeValidatedAndMappedIndependently(t *testing.T) {
	old, state := GlobalConfig, CurrentLoadState()
	t.Cleanup(func() { GlobalConfig = old; loadStateMu.Lock(); loadState = state; loadStateMu.Unlock() })
	for _, test := range []struct {
		value   string
		invalid bool
	}{
		{"", false}, {"br-api0", false}, {"br-api0,br-api1", false},
		{" br-api0", true}, {"br-api0 ", true}, {"br-api0,", true},
		{"br-api0,br-api0", true}, {"br-api0;id", true}, {"abcdefghijklmnop", true},
	} {
		t.Run(fmt.Sprintf("%q", test.value), func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "config")
			if err := InitializeDefaults(root); err != nil {
				t.Fatal(err)
			}
			content := "[network]\ninterfaces = \"eth0\"\n[integrations.ha]\nfirewalld_interfaces = " + fmt.Sprintf("%q", test.value) + "\n"
			if err := os.WriteFile(filepath.Join(root, "modules", "99-scope.toml"), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			err := loadModularConfig(root)
			if test.invalid {
				if err == nil {
					t.Fatal("invalid scope accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if GlobalConfig.HAFirewalldInterfaces != test.value || GlobalConfig.Interfaces != "eth0" {
				t.Fatal("API scope and protected ingress were conflated")
			}
			value, found, err := GetValidatedModularValue(root, "integrations.ha.firewalld_interfaces")
			if err != nil || !found || value != test.value {
				t.Fatalf("scope diagnostic lost validated value: %v %v %v", value, found, err)
			}
		})
	}
}

func TestHAFirewalldScopeLegacyMigrationPreservesIndependentIntent(t *testing.T) {
	old, state := GlobalConfig, CurrentLoadState()
	t.Cleanup(func() { GlobalConfig = old; loadStateMu.Lock(); loadState = state; loadStateMu.Unlock() })
	for _, scope := range []string{"", "br-api0", "br-api0,br-api1"} {
		t.Run(scope, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "legacy.conf")
			content := "SYSWARDEN_INTERFACES=\"eth0\"\nSYSWARDEN_HA_FIREWALLD_INTERFACES=" + fmt.Sprintf("%q", scope) + "\n"
			if err := os.WriteFile(source, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if err := ParseConfig(source); err != nil {
				t.Fatal(err)
			}
			if GlobalConfig.HAFirewalldInterfaces != scope {
				t.Fatal("legacy scope was discarded")
			}
			output := filepath.Join(root, "config")
			if err := (&Migrator{SourcePath: source, OutputDir: output}).Run(); err != nil {
				t.Fatal(err)
			}
			if err := ParseConfig(output); err != nil {
				t.Fatal(err)
			}
			if GlobalConfig.HAFirewalldInterfaces != scope || GlobalConfig.Interfaces != "eth0" || GlobalConfig.HAEnabled {
				t.Fatal("migration changed interface intent or enabled HA")
			}
		})
	}
}
