package firewall

import (
	"strings"
	"testing"

	"syswarden-cli/config"
)

func TestUnblockRejectsHAV2BeforeAnyBackendOrListOperation(t *testing.T) {
	previous := config.GlobalConfig
	t.Cleanup(func() { config.GlobalConfig = previous })
	for _, enabled := range []bool{true, false} {
		config.GlobalConfig = &config.Config{
			HAEnabled: enabled, HAV2Enabled: true, FirewallBackend: "iptables",
		}
		err := RemoveFromBlocklist("198.51.100.7")
		if err == nil || !strings.Contains(err.Error(), "HA v2") || strings.Contains(err.Error(), "firewall backend") {
			t.Fatalf("HA enabled=%t: unblock reached backend preflight before the HA v2 refusal: %v", enabled, err)
		}
	}
}
