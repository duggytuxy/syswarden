package telemetry

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestAbuseReportingSelectionRequiresOptInOutsideEnterpriseMode(t *testing.T) {
	key := strings.Repeat("a1", 40)
	cases := []struct {
		name                 string
		enterprise, selected any
		key                  string
		want                 bool
	}{
		{"selected", false, true, key, true},
		{"enterprise dominates", true, true, key, false},
		{"disabled", false, false, key, false},
		{"both disabled", true, false, key, false},
		{"unknown enterprise", nil, true, key, false},
		{"unknown selection", false, nil, key, false},
		{"invalid enterprise", "unknown", true, key, false},
		{"invalid selection", false, "unknown", key, false},
		{"numeric enterprise", 0, true, key, false},
		{"numeric selection", false, 1, key, false},
		{"environment spellings", "false", "true", key, true},
		{"string enterprise dominates", "true", "true", key, false},
		{"blank key", false, true, "", false},
		{"short key", false, true, strings.Repeat("a", 79), false},
		{"long key", false, true, strings.Repeat("a", 81), false},
		{"uppercase key", false, true, strings.Repeat("A", 80), false},
		{"whitespace key", false, true, " " + key[1:], false},
		{"header injection", false, true, key[:79] + "\n", false},
		{"binary key", false, true, key[:79] + "\x00", false},
		{"unicode key", false, true, key[:78] + "é", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := viper.New()
			if tc.enterprise != nil {
				v.Set("core.enterprise_mode", tc.enterprise)
			}
			if tc.selected != nil {
				v.Set("integrations.abuseipdb.enabled", tc.selected)
			}
			v.Set("integrations.abuseipdb.api_key", tc.key)
			before := v.AllSettings()
			enabled, retained := abuseReportingSelection(v)
			if enabled != tc.want || (!enabled && retained != "") || (enabled && retained != key) {
				t.Fatal("external reporting selection or credential retention violated policy")
			}
			if !reflect.DeepEqual(before, v.AllSettings()) {
				t.Fatal("selection modified configured values")
			}
		})
	}
	if enabled, key := abuseReportingSelection(nil); enabled || key != "" {
		t.Fatal("nil policy allowed reporting")
	}
}

func TestAbuseReportingSelectionHonorsEffectiveEnvironmentAndSecureDefault(t *testing.T) {
	v := viper.New()
	v.SetEnvPrefix("SYSWARDEN_ABUSE_SELECTION_TEST")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	v.SetDefault("core.enterprise_mode", true)
	v.SetDefault("integrations.abuseipdb.enabled", false)
	v.SetDefault("integrations.abuseipdb.api_key", strings.Repeat("a1", 40))
	t.Setenv("SYSWARDEN_ABUSE_SELECTION_TEST_INTEGRATIONS_ABUSEIPDB_ENABLED", "true")
	if enabled, key := abuseReportingSelection(v); enabled || key != "" {
		t.Fatal("opt-in bypassed default enterprise mode")
	}
	t.Setenv("SYSWARDEN_ABUSE_SELECTION_TEST_CORE_ENTERPRISE_MODE", "false")
	if enabled, key := abuseReportingSelection(v); !enabled || key == "" {
		t.Fatal("valid effective selection refused")
	}
	t.Setenv("SYSWARDEN_ABUSE_SELECTION_TEST_CORE_ENTERPRISE_MODE", "invalid")
	if enabled, key := abuseReportingSelection(v); enabled || key != "" {
		t.Fatal("invalid environment became permission")
	}
}

func TestAbuseInitializerUsesEnterprisePolicyAndClearsPreviousKey(t *testing.T) {
	oldEnabled, oldKey := abuseEnabled, abuseAPIKey
	t.Cleanup(func() { abuseEnabled, abuseAPIKey = oldEnabled, oldKey; viper.Reset() })
	viper.Reset()
	viper.Set("core.enterprise_mode", false)
	viper.Set("integrations.abuseipdb.enabled", true)
	viper.Set("integrations.abuseipdb.api_key", strings.Repeat("a1", 40))
	initAbuse()
	if !abuseEnabled || abuseAPIKey == "" {
		t.Fatal("valid opt-in not initialized")
	}
	viper.Set("core.enterprise_mode", true)
	initAbuse()
	if abuseEnabled || abuseAPIKey != "" {
		t.Fatal("enterprise mode retained reporting authority or credentials")
	}
	viper.Reset()
	initAbuse()
	if abuseEnabled || abuseAPIKey != "" {
		t.Fatal("missing configuration initialized reporting")
	}
}
