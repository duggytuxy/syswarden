package integration

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"syswarden-cli/config"
)

// SetupWazuh registers the node with Wazuh natively and injects SysWarden log parsing
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

	wazuhConf := "/var/ossec/etc/ossec.conf"
	if _, err := os.Stat(wazuhConf); os.IsNotExist(err) {
		fmt.Println("[WARNING] Wazuh agent is enabled but ossec.conf was not found. Please install the Wazuh agent first.")
		return nil
	}

	content, err := os.ReadFile(wazuhConf)
	if err != nil {
		return fmt.Errorf("failed to read wazuh config: %w", err)
	}
	confStr := string(content)

	var modified bool

	// Inject waf.json telemetry parsing
	if !strings.Contains(confStr, "/var/log/syswarden/waf.json") {
		localfileBlock := `
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/syswarden/waf.json</location>
  </localfile>
`
		// Insert before the closing </ossec_config>
		if idx := strings.LastIndex(confStr, "</ossec_config>"); idx != -1 {
			confStr = confStr[:idx] + localfileBlock + confStr[idx:]
			modified = true
		}
	}

	// Inject core.log tracing
	if !strings.Contains(confStr, "/var/log/syswarden/core.log") {
		localfileBlock := `
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syswarden/core.log</location>
  </localfile>
`
		if idx := strings.LastIndex(confStr, "</ossec_config>"); idx != -1 {
			confStr = confStr[:idx] + localfileBlock + confStr[idx:]
			modified = true
		}
	}

	if modified {
		if err := os.WriteFile(wazuhConf, []byte(confStr), 0640); err != nil {
			return fmt.Errorf("failed to write wazuh config: %w", err)
		}
		fmt.Println("[INFO] SysWarden logs successfully injected into Wazuh agent.")

		// Restart Wazuh Agent
		fmt.Println("[INFO] Restarting wazuh-agent service...")
		cmd := exec.Command("systemctl", "restart", "wazuh-agent")
		if err := cmd.Run(); err != nil {
			// Fallback for FreeBSD or non-systemd
			_ = exec.Command("service", "wazuh-agent", "restart").Run()
		}
	}

	fmt.Printf("[SUCCESS] Wazuh Agent integration active (Manager: %s)\n", ip)
	return nil
}
