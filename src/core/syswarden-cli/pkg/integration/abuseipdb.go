package integration

import (
	"fmt"
	"syswarden-cli/config"
)

// SetupAbuseIPDB validates the selected TOML integration only. The core reads
// the same TOML directly. The obsolete secrets.env copy is neither created,
// overwritten nor deleted; its ownership and any external consumers are unknown.
func SetupAbuseIPDB() error {
	message, err := abuseIPDBSelectionMessage(config.GlobalConfig)
	if err != nil {
		return err
	}
	fmt.Println(message)
	return nil
}

func abuseIPDBSelectionMessage(c *config.Config) (string, error) {
	if c == nil {
		return "", fmt.Errorf("AbuseIPDB selection requires validated configuration")
	}
	if c.EnterpriseMode {
		return "[INFO] Enterprise mode disables AbuseIPDB reporting. No credential file was changed.", nil
	}
	if !c.EnableAbuse {
		return "[INFO] AbuseIPDB reporting is disabled by configuration. No credential file was changed.", nil
	}
	if c.AbuseAPIKey == "" {
		return "[WARN] AbuseIPDB is selected without an API key; the core will not report. No credential file was changed.", nil
	}
	if len(c.AbuseAPIKey) != 80 {
		return "", fmt.Errorf("invalid AbuseIPDB API key format")
	}
	for i := 0; i < len(c.AbuseAPIKey); i++ {
		b := c.AbuseAPIKey[i]
		if !(b >= 'a' && b <= 'z') && !(b >= '0' && b <= '9') {
			return "", fmt.Errorf("invalid AbuseIPDB API key format")
		}
	}
	return "[INFO] AbuseIPDB TOML selection is valid. The core reads its key from TOML; runtime activation is not confirmed.", nil
}
