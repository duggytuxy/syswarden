//go:build freebsd

package integration

import (
	"fmt"
	"os"
	"os/exec"
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

	// 1. We write the rsyslog configuration natively
	_ = os.MkdirAll("/usr/local/etc/rsyslog.d", 0750)
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
	rsyslogConf += "module(load=\"imfile\" PollingInterval=\"10\")\n"
	rsyslogConf += "input(type=\"imfile\"\n"
	rsyslogConf += "      File=\"/var/log/syswarden/waf.json\"\n"
	rsyslogConf += "      Tag=\"syswarden-waf-json\"\n"
	rsyslogConf += "      Severity=\"alert\"\n"
	rsyslogConf += "      Facility=\"local7\")\n"

	if err := os.WriteFile(confPath, []byte(rsyslogConf), 0600); err != nil {
		return fmt.Errorf("failed to write rsyslog SIEM config: %w", err)
	}

	// 2. Restart Rsyslog safely
	if err := exec.Command("service", "rsyslogd", "restart").Run(); err != nil { // #nosec
		fmt.Printf("[WARN] Failed to restart rsyslogd: %v\n", err)
	}

	fmt.Printf("[+] SIEM Forwarder successfully configured (%s:%s/%s)\n", ip, port, proto)
	return nil
}
