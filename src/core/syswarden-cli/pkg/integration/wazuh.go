package integration

import (
	"fmt"
	"syswarden-cli/config"
)

// SetupWazuh registers the node with Wazuh natively
func SetupWazuh() error {
	fmt.Println("[INFO] Configuring Wazuh Agent Integration...")

	if !config.GlobalConfig.EnableWazuh {
		fmt.Println("[INFO] Wazuh integration disabled.")
		return nil
	}

	ip := config.GlobalConfig.WazuhIP
	if ip == "" {
		return fmt.Errorf("wazuh IP is missing in configuration")
	}

	// In a complete implementation, this would interact with the Wazuh API natively.
	// We'll simulate the native registration wrapper for this mockup.
	fmt.Printf("[+] Wazuh Agent theoretically registered to %s\n", ip)

	return nil
}
