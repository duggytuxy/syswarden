//go:build freebsd

package integration

import (
	"fmt"
	"os"
	"syswarden-cli/config"
)

const freeBSDWAFRsyslogFragment = "/usr/local/etc/rsyslog.d/99-syswarden-waf-bridge.conf"

// SetupWAFLogForwarder configures Rsyslog to bridge local Web/Docker(Jails) logs into the Go WAF Socket
func SetupWAFLogForwarder() error {
	fmt.Println("[INFO] Configuring WAF Multi-Tenant Log Bridge (Rsyslog -> UDS)...")

	if err := os.MkdirAll("/usr/local/etc/rsyslog.d", 0750); err != nil {
		return fmt.Errorf("create FreeBSD rsyslog configuration directory: %w", err)
	}
	confPath := freeBSDWAFRsyslogFragment

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
template(name="SYSWARDENRaw" type="string" string="%msg%\n")

ruleset(name="waf_bridge") {
    # Prevent infinite loops from SYSWARDEN logging its own blocks
    if $programname == "syswarden-core" then stop
    if $msg contains "SYSWARDEN-BLOCK" then stop
    if $msg contains "SYSWARDEN-ALLOWED" then stop

    *.* :omuxsock:;SYSWARDENRaw
}
`

	if err := os.WriteFile(confPath, []byte(rsyslogConf), 0600); err != nil {
		return fmt.Errorf("failed to write WAF bridge config: %w", err)
	}

	if err := ensureFreeBSDRsyslogRunning(); err != nil {
		return fmt.Errorf("activate rsyslogd for WAF bridge: %w", err)
	}

	fmt.Println("[+] WAF Log Bridge successfully configured.")
	return nil
}
