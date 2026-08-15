//go:build freebsd

package integration

import (
	"fmt"
	"os"
	"strings"
	"syswarden-cli/config"
)

// SetupSIEM configures Syslog forwarding natively
func SetupSIEM() error {
	fmt.Println("[INFO] Configuring SIEM Logging Integration...")

	if !config.GlobalConfig.SiemEnabled {
		fmt.Println("[INFO] SIEM integration disabled.")
		return nil
	}

	ip := config.GlobalConfig.SiemIP
	port := config.GlobalConfig.SiemPort
	proto := config.GlobalConfig.SiemProto
	tlsCA := config.GlobalConfig.SiemTLSCA

	if ip == "" || port == "" {
		return fmt.Errorf("SIEM IP or Port is missing in configuration")
	}
	wafFragment, err := os.ReadFile(freeBSDWAFRsyslogFragment)
	if err != nil {
		return fmt.Errorf("read required WAF rsyslog module fragment: %w", err)
	}
	if !strings.Contains(string(wafFragment), `module(load="imfile")`) {
		return fmt.Errorf("required WAF rsyslog imfile module declaration is missing")
	}

	// 1. We write the rsyslog configuration natively
	if err := os.MkdirAll("/usr/local/etc/rsyslog.d", 0750); err != nil {
		return fmt.Errorf("create FreeBSD rsyslog configuration directory: %w", err)
	}
	confPath := "/usr/local/etc/rsyslog.d/99-syswarden-siem.conf"

	// Secure formatting (CWE-117)
	var rsyslogConf string
	if proto == "udp" {
		rsyslogConf = fmt.Sprintf("*.* @%s:%s\n", ip, port)
	} else {
		// TCP
		if tlsCA != "" {
			// TLS Configuration using anon mode for robust encryption without domain-match breakage
			rsyslogConf = fmt.Sprintf("$DefaultNetstreamDriverCAFile %s\n", tlsCA)
			rsyslogConf += "$ActionSendStreamDriver gtls\n"
			rsyslogConf += "$ActionSendStreamDriverMode 1\n"
			rsyslogConf += "$ActionSendStreamDriverAuthMode anon\n"
			rsyslogConf += fmt.Sprintf("*.* @@%s:%s\n", ip, port)
		} else {
			// Cleartext TCP
			rsyslogConf = fmt.Sprintf("*.* @@%s:%s\n", ip, port)
		}
	}

	// Add native JSON WAAP telemetry forwarding via imfile
	rsyslogConf += "\n# SYSWARDEN WAAP Native JSON Telemetry\n"
	rsyslogConf += "input(type=\"imfile\"\n"
	rsyslogConf += "      File=\"/var/log/syswarden/waf.json\"\n"
	rsyslogConf += "      Tag=\"syswarden-waf-json\"\n"
	rsyslogConf += "      Severity=\"alert\"\n"
	rsyslogConf += "      Facility=\"local7\")\n"

	if err := os.WriteFile(confPath, []byte(rsyslogConf), 0600); err != nil {
		return fmt.Errorf("failed to write rsyslog SIEM config: %w", err)
	}

	if err := ensureFreeBSDRsyslogRunning(); err != nil {
		return fmt.Errorf("activate rsyslogd for SIEM forwarding: %w", err)
	}

	fmt.Printf("[+] SIEM Forwarder successfully configured (%s:%s/%s)\n", ip, port, proto)
	return nil
}
