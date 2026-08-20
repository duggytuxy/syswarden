//go:build linux

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

const rsyslogWAFBase = `module(load="imfile")
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

const rsyslogWAFRuleset = `
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

func renderWAFRsyslogConfig(rawPatterns string) (string, int, error) {
	patterns, err := validatedRsyslogLogPatterns(rawPatterns)
	if err != nil {
		return "", 0, err
	}
	var rendered strings.Builder
	rendered.WriteString(rsyslogWAFBase)
	if len(patterns) > 0 {
		rendered.WriteString("\n# Docker Multi-Tenant Logs\n")
	}
	for _, pattern := range patterns {
		quoted, err := quoteRsyslogString(pattern)
		if err != nil {
			return "", 0, fmt.Errorf("encode rsyslog log pattern: %w", err)
		}
		fmt.Fprintf(&rendered, "input(type=\"imfile\" File=%s Tag=\"syswarden-waf\" ruleset=\"waf_bridge\")\n", quoted)
	}
	rendered.WriteString(rsyslogWAFRuleset)
	return rendered.String(), len(patterns), nil
}

// SetupWAFLogForwarder configures Rsyslog to bridge local Web/Docker logs into the Go WAF Socket
func SetupWAFLogForwarder() error {
	fmt.Println("[INFO] Configuring WAF Multi-Tenant Log Bridge (Rsyslog -> UDS)...")

	confPath := "/etc/rsyslog.d/99-syswarden-waf-bridge.conf"

	rsyslogConf, activePatterns, err := renderWAFRsyslogConfig(config.GlobalConfig.ModsecLogs)
	if err != nil {
		return fmt.Errorf("render WAF bridge config: %w", err)
	}
	if config.GlobalConfig.ModsecLogs != "" && activePatterns == 0 {
		fmt.Println("[WARN] Configured ModSecurity log patterns have no real regular-file match; custom rsyslog input was omitted.")
	}

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

	if err := restartManagedService("rsyslog"); err != nil {
		return fmt.Errorf("activate WAF bridge rsyslog configuration: %w", err)
	}

	fmt.Println("[+] WAF Log Bridge successfully configured.")
	return nil
}

func restartManagedService(service string) error {
	state, err := system.ServiceManagerRuntimeState()
	if err != nil {
		return err
	}
	switch state {
	case "OFFLINE":
		fmt.Printf("[INFO] Service-manager runtime is offline; %s restart is deferred to boot.\n", service)
		return nil
	case "ACTIVE":
		if system.IsAlpine() {
			if err := exec.Command("rc-service", service, "restart").Run(); err != nil { // #nosec G204 -- caller passes fixed product integration service constants
				return fmt.Errorf("restart OpenRC service %s: %w", service, err)
			}
			return nil
		}
		if err := exec.Command("systemctl", "restart", service).Run(); err != nil { // #nosec G204 -- caller passes fixed product integration service constants
			return fmt.Errorf("restart systemd service %s: %w", service, err)
		}
		return nil
	default:
		return fmt.Errorf("refusing unrecognized service-manager runtime state %q", state)
	}
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
