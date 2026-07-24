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

    # Do not forward native firewall kernel drops to WAF regex engine to avoid false positives and reduce CPU overhead
    if $msg contains "SYSWARDEN-GEO" then stop
    if $msg contains "SYSWARDEN-ASN" then stop
    if $msg contains "SYSWARDEN-L3" then stop
    if $msg contains "SYSWARDEN-TOR" then stop
    if $msg contains "SYSWARDEN-PROXY" then stop

    *.* :omuxsock:;SYSWARDENRaw
}
`

	_ = os.MkdirAll("/etc/rsyslog.d", 0750)
	if err := os.WriteFile(confPath, []byte(rsyslogConf), 0600); err != nil {
		return fmt.Errorf("failed to write WAF bridge config: %w", err)
	}
	// SELinux Hardening (RHEL/Alma) - Compile and install policy to allow rsyslog -> UDS communication
	if _, err := exec.LookPath("checkmodule"); err == nil {
		fmt.Println("[INFO] Compiling and injecting SELinux policy for Rsyslog UDS bridge...")
		selinuxTE := `module syswarden_rsyslog 1.0;
require {
	type syslogd_t;
	type unconfined_service_t;
	type init_t;
	type var_run_t;
	class sock_file write;
	class unix_dgram_socket sendto;
}
allow syslogd_t unconfined_service_t:unix_dgram_socket sendto;
allow syslogd_t init_t:unix_dgram_socket sendto;
allow syslogd_t var_run_t:sock_file write;
`
		_ = os.WriteFile("/tmp/syswarden_rsyslog.te", []byte(selinuxTE), 0644)
		if err := exec.Command("checkmodule", "-M", "-m", "-o", "/tmp/syswarden_rsyslog.mod", "/tmp/syswarden_rsyslog.te").Run(); err == nil {
			if err := exec.Command("semodule_package", "-o", "/tmp/syswarden_rsyslog.pp", "-m", "/tmp/syswarden_rsyslog.mod").Run(); err == nil {
				_ = exec.Command("semodule", "-i", "/tmp/syswarden_rsyslog.pp").Run()
			}
		}
		// Clean up
		_ = os.Remove("/tmp/syswarden_rsyslog.te")
		_ = os.Remove("/tmp/syswarden_rsyslog.mod")
		_ = os.Remove("/tmp/syswarden_rsyslog.pp")
	}

	// Restart Rsyslog safely
	if system.IsAlpine() {
		if err := exec.Command("rc-service", "rsyslog", "restart").Run(); err != nil { // #nosec
			fmt.Printf("[WARN] Failed to restart rsyslog for WAF bridge (rc-service): %v\n", err)
		}
	} else {
		if err := exec.Command("systemctl", "restart", "rsyslog").Run(); err != nil { // #nosec
			fmt.Printf("[WARN] Failed to restart rsyslog for WAF bridge: %v\n", err)
		}
	}

	fmt.Println("[+] WAF Log Bridge successfully configured.")
	return nil
}
