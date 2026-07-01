//go:build freebsd

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"syswarden-cli/config"
)

// SetupWAFLogForwarder configures Rsyslog to bridge local Web/Docker(Jails) logs into the Go WAF Socket
func SetupWAFLogForwarder() error {
	fmt.Println("[INFO] Configuring WAF Multi-Tenant Log Bridge (Rsyslog -> UDS)...")

	_ = os.MkdirAll("/usr/local/etc/rsyslog.d", 0755)
	confPath := "/usr/local/etc/rsyslog.d/99-syswarden-waf-bridge.conf"

	// Base modules
	rsyslogConf := `module(load="imfile")
module(load="omuxsock")
$OMUxSockSocket /var/run/syswarden.sock

# Web Server Logs (FreeBSD typical paths and Jails)
input(type="imfile" File="/var/log/nginx/*.log" Tag="syswarden-waf" ruleset="waf_bridge")
input(type="imfile" File="/var/log/nginx-access.log" Tag="syswarden-waf" ruleset="waf_bridge")
input(type="imfile" File="/var/log/httpd-access.log" Tag="syswarden-waf" ruleset="waf_bridge")

# System & Auth Logs (HIDS)
input(type="imfile" File="/var/log/auth.log" Tag="syswarden-waf" ruleset="waf_bridge")
input(type="imfile" File="/var/log/messages" Tag="syswarden-waf" ruleset="waf_bridge")`

	// Docker Multi-tenant / Traefik / ModSec Logs
	if config.GlobalConfig.ModsecLogs != "" {
		rsyslogConf += fmt.Sprintf("\n# Custom Web Telemetry Logs\ninput(type=\"imfile\" File=\"%s\" Tag=\"syswarden-waf\" ruleset=\"waf_bridge\")\n", config.GlobalConfig.ModsecLogs)
	}

	// Ruleset to forward everything tagged syswarden-waf to the UDS
	rsyslogConf += `
template(name="SysWardenRaw" type="string" string="%msg%\n")

ruleset(name="waf_bridge") {
    # Prevent infinite loops from SysWarden logging its own blocks
    if $programname == "syswarden-core" then stop
    if $msg contains "SysWarden-BLOCK" then stop
    if $msg contains "SysWarden-ALLOWED" then stop

    *.* :omuxsock:;SysWardenRaw
}
`

	if err := os.WriteFile(confPath, []byte(rsyslogConf), 0640); err != nil {
		return fmt.Errorf("failed to write WAF bridge config: %w", err)
	}

	// Restart Rsyslog safely
	if err := exec.Command("service", "rsyslogd", "restart").Run(); err != nil {
		fmt.Printf("[WARN] Failed to restart rsyslogd for WAF bridge: %v\n", err)
	}

	fmt.Println("[+] WAF Log Bridge successfully configured.")
	return nil
}
