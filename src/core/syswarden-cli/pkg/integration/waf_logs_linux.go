//go:build linux

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"syswarden-cli/config"
	"syswarden-cli/pkg/system"
)

// SetupWAFLogForwarder configures Rsyslog to bridge local Web/Docker logs into the Go WAF Socket
func SetupWAFLogForwarder() error {
	fmt.Println("[INFO] Configuring WAF Multi-Tenant Log Bridge (Rsyslog -> UDS)...")

	confPath := "/etc/rsyslog.d/99-syswarden-waf-bridge.conf"

	// Base modules
	rsyslogConf := `module(load="imfile")
module(load="omuxsock")
$OMUxSockSocket /var/run/syswarden.sock

# Web Server Logs
input(type="imfile" File="/var/log/nginx/*.log" Tag="syswarden-waf" ruleset="waf_bridge")
input(type="imfile" File="/var/log/apache2/*.log" Tag="syswarden-waf" ruleset="waf_bridge")
input(type="imfile" File="/var/log/httpd/*.log" Tag="syswarden-waf" ruleset="waf_bridge")

# System & Auth Logs (HIDS)
input(type="imfile" File="/var/log/auth.log" Tag="syswarden-waf" ruleset="waf_bridge")
input(type="imfile" File="/var/log/secure" Tag="syswarden-waf" ruleset="waf_bridge")
input(type="imfile" File="/var/log/syslog" Tag="syswarden-waf" ruleset="waf_bridge")
input(type="imfile" File="/var/log/messages" Tag="syswarden-waf" ruleset="waf_bridge")
`

	// Docker Multi-tenant / Traefik / ModSec Logs
	if config.GlobalConfig.ModsecLogs != "" {
		rsyslogConf += fmt.Sprintf("\n# Docker Multi-Tenant Logs\ninput(type=\"imfile\" File=\"%s\" Tag=\"syswarden-waf\" ruleset=\"waf_bridge\")\n", config.GlobalConfig.ModsecLogs)
	}

	// Ruleset to forward everything tagged syswarden-waf to the UDS
	rsyslogConf += `
template(name="SYSWARDENRaw" type="string" string="%msg%\n")

ruleset(name="waf_bridge") {
    # Prevent infinite loops from SYSWARDEN logging its own blocks
    if $programname == "syswarden-core" then stop
    if $msg contains "SYSWARDEN-BLOCK" then stop
    if $msg contains "SYSWARDEN-ALLOWED" then stop

    *.* :omuxsock:;SYSWARDENRaw
}
`

	if err := os.WriteFile(confPath, []byte(rsyslogConf), 0640); err != nil {
		return fmt.Errorf("failed to write WAF bridge config: %w", err)
	}

	// Restart Rsyslog safely
	if system.IsAlpine() {
		if err := exec.Command("rc-service", "rsyslog", "restart").Run(); err != nil {
			fmt.Printf("[WARN] Failed to restart rsyslog for WAF bridge (rc-service): %v\n", err)
		}
	} else {
		if err := exec.Command("systemctl", "restart", "rsyslog").Run(); err != nil {
			fmt.Printf("[WARN] Failed to restart rsyslog for WAF bridge: %v\n", err)
		}
	}

	fmt.Println("[+] WAF Log Bridge successfully configured.")
	return nil
}
