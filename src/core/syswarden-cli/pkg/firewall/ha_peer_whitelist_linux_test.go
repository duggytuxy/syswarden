//go:build linux

package firewall

import (
	"errors"
	"strings"
	"testing"

	"syswarden-cli/config"
)

func TestHAPeerPortWhitelistDoesNotAcquireLegacyUnbanFence_SW_HA_001(t *testing.T) {
	previousConfig, previousPreflight := config.GlobalConfig, firewallBackendPreflight
	t.Cleanup(func() {
		config.GlobalConfig, firewallBackendPreflight = previousConfig, previousPreflight
	})
	// Stop at the existing backend boundary before any persistent or kernel write.
	// Reaching it proves that scoped peer access does not first open the fence.
	boundary := errors.New("backend boundary reached without legacy unban lease")
	preflights := 0
	firewallBackendPreflight = func(string) error {
		preflights++
		return boundary
	}
	for _, v2 := range []bool{false, true} {
		config.GlobalConfig = &config.Config{HAEnabled: true, HAV2Enabled: v2, FirewallBackend: "nftables"}
		if err := AddToWhitelist("192.0.2.9/32", "62026"); !errors.Is(err, boundary) {
			t.Fatalf("HA v2=%t: scoped peer access entered the legacy unban path: %v", v2, err)
		}
	}
	if preflights != 2 {
		t.Fatalf("scoped preflights = %d, want 2", preflights)
	}
	// The fix must not permit an unscoped whitelist to bypass v2 ownership.
	if err := AddToWhitelist("192.0.2.9/32", ""); err == nil || !strings.Contains(err.Error(), "local unblock is unavailable with HA v2") {
		t.Fatalf("unscoped whitelist lost its HA v2 ownership guard: %v", err)
	}
	if preflights != 2 {
		t.Fatal("unscoped whitelist reached the firewall backend before ownership validation")
	}
}
