package telemetry

import (
	"strconv"

	"github.com/spf13/viper"
)

// abuseReportingSelection gives enterprise mode priority over an opt-in. Missing
// or malformed switches never become permission to send an external report.
// The returned key is empty unless reporting is permitted. No legacy credential
// file is consulted and no values are logged or modified.
func abuseReportingSelection(v *viper.Viper) (bool, string) {
	if v == nil {
		return false, ""
	}
	enterprise, knownEnterprise := abuseReportingBool(v, "core.enterprise_mode")
	selected, knownSelection := abuseReportingBool(v, "integrations.abuseipdb.enabled")
	if !knownEnterprise || enterprise || !knownSelection || !selected {
		return false, ""
	}
	key := v.GetString("integrations.abuseipdb.api_key")
	if len(key) != 80 {
		return false, ""
	}
	for i := 0; i < len(key); i++ {
		b := key[i]
		if !(b >= 'a' && b <= 'z') && !(b >= '0' && b <= '9') {
			return false, ""
		}
	}
	return true, key
}

func abuseReportingBool(v *viper.Viper, key string) (bool, bool) {
	if !v.IsSet(key) {
		return false, false
	}
	switch value := v.Get(key).(type) {
	case bool:
		return value, true
	case string:
		// Viper environment values are strings; retain canonical boolean
		// environment choices while refusing errors and numeric TOML values.
		parsed, err := strconv.ParseBool(value)
		return parsed, err == nil
	default:
		return false, false
	}
}
