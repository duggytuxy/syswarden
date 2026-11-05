package integration

import (
	"reflect"
	"strings"
	"testing"

	"syswarden-cli/config"
)

func TestAbuseIPDBSelectionValidationHasNoCredentialOutput(t *testing.T) {
	key := strings.Repeat("a1", 40)
	cases := []struct {
		name                string
		enterprise, enabled bool
		key                 string
		wantError           bool
		message             string
	}{
		{"selected", false, true, key, false, "core reads its key from TOML"},
		{"enterprise", true, true, key, false, "Enterprise mode disables"},
		{"enterprise invalid key", true, true, "invalid-private-value", false, "Enterprise mode disables"},
		{"disabled", false, false, key, false, "disabled by configuration"},
		{"disabled invalid key", false, false, "invalid-private-value", false, "disabled by configuration"},
		{"missing key", false, true, "", false, "core will not report"},
		{"short", false, true, key[:79], true, ""},
		{"long", false, true, key + "a", true, ""},
		{"uppercase", false, true, strings.Repeat("A", 80), true, ""},
		{"newline", false, true, key[:79] + "\n", true, ""},
		{"zero", false, true, key[:79] + "\x00", true, ""},
		{"unicode", false, true, key[:78] + "é", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := config.Config{EnterpriseMode: tc.enterprise, EnableAbuse: tc.enabled, AbuseAPIKey: tc.key}
			before := c
			message, err := abuseIPDBSelectionMessage(&c)
			if (err != nil) != tc.wantError {
				t.Fatal("selection validation result differs")
			}
			text := message
			if err != nil {
				text += err.Error()
			}
			if tc.key != "" && strings.Contains(text, tc.key) {
				t.Fatal("selection output disclosed credentials")
			}
			if tc.message != "" && !strings.Contains(message, tc.message) {
				t.Fatal("selection message omitted its boundary")
			}
			if !reflect.DeepEqual(before, c) {
				t.Fatal("selection validation modified configuration")
			}
		})
	}
}

func TestAbuseIPDBSetupRefusesUnknownConfiguration(t *testing.T) {
	original := config.GlobalConfig
	t.Cleanup(func() { config.GlobalConfig = original })
	config.GlobalConfig = nil
	if err := SetupAbuseIPDB(); err == nil {
		t.Fatal("unknown configuration was accepted")
	}
}
