package config

import (
	"fmt"
	"github.com/spf13/viper"
	"testing"
)

func TestHAFirewalldScopeCoreValidationParity(t *testing.T) {
	t.Cleanup(viper.Reset)
	for _, test := range []struct {
		value   string
		invalid bool
	}{
		{"", false}, {"br-api0", false}, {"br-api0,br-api1", false},
		{" br-api0", true}, {"br-api0 ", true}, {"br-api0,", true},
		{"br-api0,br-api0", true}, {"br-api0;id", true}, {"abcdefghijklmnop", true},
	} {
		t.Run(fmt.Sprintf("%q", test.value), func(t *testing.T) {
			module := "[network]\ninterfaces = \"eth0\"\n[integrations.ha]\nfirewalld_interfaces = " + fmt.Sprintf("%q", test.value) + "\n"
			root := writeConfigFixture(t, validMaster("schema_version = 1"), map[string]string{"99-scope.toml": module})
			_, err := LoadConfigDirectory(root)
			if test.invalid {
				if err == nil {
					t.Fatal("invalid API scope accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if viper.GetString("integrations.ha.firewalld_interfaces") != test.value || viper.GetString("network.interfaces") != "eth0" {
				t.Fatal("independent scopes were lost")
			}
		})
	}
}
