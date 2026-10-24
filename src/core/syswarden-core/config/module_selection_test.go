package config

import (
	"bytes"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/viper"
	"strings"
	"testing"
)

func TestOptionalModuleSelections(t *testing.T) {
	for _, test := range []struct {
		name, document                                 string
		wantOSINT, wantWAAP, wantBridge, wantDetection bool
	}{
		{name: "legacy absence", wantOSINT: true, wantWAAP: true, wantBridge: true, wantDetection: true},
		{name: "fresh absence", document: "[core]\ninstall_profile='standard-v1'\n"},
		{name: "independent fresh opt-ins", document: "[core]\ninstall_profile='standard-v1'\n[network.blocklists]\nosint_enabled=true\n[waap]\nenabled=true\n", wantOSINT: true, wantWAAP: true},
		{name: "legacy explicit withdrawal", document: "[waap]\nenabled=false\nlog_bridge_enabled=false\n", wantOSINT: true, wantDetection: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("toml")
			if test.document != "" {
				if err := v.ReadConfig(bytes.NewBufferString(test.document)); err != nil {
					t.Fatal(err)
				}
			}
			if err := resolveOptionalModules(v); err != nil {
				t.Fatal(err)
			}
			for i, want := range []bool{test.wantOSINT, test.wantWAAP, test.wantBridge, test.wantDetection} {
				if got := v.GetBool(optionalModuleKeys[i]); got != want {
					t.Fatalf("%s = %v, want %v", optionalModuleKeys[i], got, want)
				}
			}
		})
	}
}

func TestOptionalModuleRejectsCoercionAndUnknownProfiles(t *testing.T) {
	for _, document := range []string{
		"[waap]\nenabled='true'\n", "[waap]\nenabled=1\n", "[waap]\nEnabled=true\n",
		"[WAAP]\nenabled=true\n", "[security]\ndetection_enabled=[]\n",
		"[network.blocklists]\nosint_enabled='false'\n", "[core]\ninstall_profile='future'\n", "[core]\ninstall_profile=1\n",
	} {
		t.Run(document, func(t *testing.T) {
			var m map[string]any
			if err := toml.Unmarshal([]byte(document), &m); err != nil {
				t.Fatal(err)
			}
			if err := validateOptionalModuleDocument("modules/99-user.toml", m); err == nil {
				t.Fatal("accepted ambiguous selection")
			}
		})
	}
}

func TestOptionalModuleRejectsEnvironmentConsent(t *testing.T) {
	for _, env := range []string{"SYSWARDEN_CORE_INSTALL_PROFILE", "SYSWARDEN_WAAP_ENABLED", "SYSWARDEN_WAAP_LOG_BRIDGE_ENABLED", "SYSWARDEN_NETWORK_BLOCKLISTS_OSINT_ENABLED", "SYSWARDEN_SECURITY_DETECTION_ENABLED"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "true")
			if err := resolveOptionalModules(viper.New()); err == nil {
				t.Fatal("environment granted selection")
			}
		})
	}
}

func TestFreshProfileNeverEnablesMissingOrEnvironmentModules(t *testing.T) {
	for _, key := range freshModuleKeys {
		t.Run(key, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("toml")
			v.SetDefault(key, true)
			if err := v.ReadConfig(bytes.NewBufferString("[core]\ninstall_profile='standard-v1'\n")); err != nil {
				t.Fatal(err)
			}
			if err := resolveOptionalModules(v); err != nil {
				t.Fatal(err)
			}
			if v.GetBool(key) {
				t.Fatal("historical default enabled a fresh module")
			}
			env := "SYSWARDEN_" + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
			t.Setenv(env, "true")
			if err := resolveOptionalModules(v); err == nil {
				t.Fatal("environment enabled a fresh module")
			}
		})
	}
}

func TestLogBridgeRequiresExplicitWAAPWithoutGrantingOtherModules(t *testing.T) {
	for _, profile := range []string{"", "[core]\ninstall_profile='standard-v1'\n"} {
		for _, c := range []struct {
			name, selection       string
			blocked, waap, bridge bool
		}{
			{name: "bridge without engine", selection: "enabled=false\nlog_bridge_enabled=true\n", blocked: true, bridge: true},
			{name: "both explicitly selected", selection: "enabled=true\nlog_bridge_enabled=true\n", waap: true, bridge: true},
			{name: "engine without bridge", selection: "enabled=true\nlog_bridge_enabled=false\n", waap: true},
			{name: "both disabled", selection: "enabled=false\nlog_bridge_enabled=false\n"},
		} {
			t.Run(profile+c.name, func(t *testing.T) {
				v := viper.New()
				v.SetConfigType("toml")
				document := profile + "[waap]\n" + c.selection + "[network.wireguard]\nenabled=false\n[integrations.bunkerweb]\nenabled=false\n"
				if err := v.ReadConfig(strings.NewReader(document)); err != nil {
					t.Fatal(err)
				}
				err := resolveOptionalModules(v)
				if (err != nil) != c.blocked {
					t.Fatal("incorrect producer/consumer selection", err)
				}
				if c.blocked && !strings.Contains(err.Error(), "waap.log_bridge_enabled requires explicit waap.enabled=true") {
					t.Fatal(err)
				}
				if v.GetBool("waap.enabled") != c.waap || v.GetBool("waap.log_bridge_enabled") != c.bridge || v.GetBool("network.wireguard.enabled") || v.GetBool("integrations.bunkerweb.enabled") {
					t.Fatal("validation implicitly changed a module choice")
				}
			})
		}
	}
}
