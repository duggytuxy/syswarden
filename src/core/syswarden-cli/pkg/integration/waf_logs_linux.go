//go:build linux

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syswarden-cli/config"
	"syswarden-cli/pkg/system"
)

const rsyslogSELinuxPolicy = `module syswarden_rsyslog 1.0;
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
		if err := withPrivateSELinuxPolicyWorkspace("", func(workspace string) error {
			compile := exec.Command("checkmodule", "-M", "-m", "-o", "syswarden_rsyslog.mod", "syswarden_rsyslog.te")
			compile.Dir = workspace
			if err := compile.Run(); err != nil {
				return fmt.Errorf("compile SELinux policy: %w", err)
			}
			pack := exec.Command("semodule_package", "-o", "syswarden_rsyslog.pp", "-m", "syswarden_rsyslog.mod")
			pack.Dir = workspace
			if err := pack.Run(); err != nil {
				return fmt.Errorf("package SELinux policy: %w", err)
			}
			install := exec.Command("semodule", "-i", "syswarden_rsyslog.pp")
			install.Dir = workspace
			if err := install.Run(); err != nil {
				return fmt.Errorf("install SELinux policy: %w", err)
			}
			return nil
		}); err != nil {
			fmt.Printf("[WARN] Failed to install Rsyslog SELinux policy: %v\n", err)
		}
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

func withPrivateSELinuxPolicyWorkspace(parent string, action func(workspace string) error) error {
	workspace, err := os.MkdirTemp(parent, "syswarden-rsyslog-")
	if err != nil {
		return fmt.Errorf("create private SELinux policy workspace: %w", err)
	}
	defer func() { _ = os.RemoveAll(workspace) }()

	tePath := filepath.Join(workspace, "syswarden_rsyslog.te")
	if err := os.WriteFile(tePath, []byte(rsyslogSELinuxPolicy), 0600); err != nil {
		return fmt.Errorf("write SELinux policy source: %w", err)
	}
	return action(workspace)
}
