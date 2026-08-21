//go:build linux

package integration

import (
	"fmt"
	"os"
	"strings"
	"syswarden-cli/config"
)

func renderSIEMRsyslogConfig(ip, port, protocol, tlsCA string) (string, error) {
	target, err := rsyslogTarget(ip, port)
	if err != nil {
		return "", err
	}
	var rendered strings.Builder
	switch protocol {
	case "udp":
		fmt.Fprintf(&rendered, "*.* @%s\n", target)
	case "tcp":
		fmt.Fprintf(&rendered, "*.* @@%s\n", target)
	case "tls":
		if tlsCA == "" {
			return "", fmt.Errorf("TLS rsyslog forwarding requires a CA path")
		}
		quotedCA, err := quoteRsyslogString(tlsCA)
		if err != nil {
			return "", fmt.Errorf("encode rsyslog CA path: %w", err)
		}
		fmt.Fprintf(&rendered, "$DefaultNetstreamDriverCAFile %s\n", quotedCA)
		rendered.WriteString("$ActionSendStreamDriver gtls\n")
		rendered.WriteString("$ActionSendStreamDriverMode 1\n")
		rendered.WriteString("$ActionSendStreamDriverAuthMode anon\n")
		fmt.Fprintf(&rendered, "*.* @@%s\n", target)
	default:
		return "", fmt.Errorf("unsupported rsyslog transport %q", protocol)
	}

	rendered.WriteString("\n# SYSWARDEN WAAP Native JSON Telemetry\n")
	rendered.WriteString("module(load=\"imfile\" PollingInterval=\"10\")\n")
	rendered.WriteString("input(type=\"imfile\"\n")
	rendered.WriteString("      File=\"/var/log/syswarden/waf.json\"\n")
	rendered.WriteString("      Tag=\"syswarden-waf-json\"\n")
	rendered.WriteString("      Severity=\"alert\"\n")
	rendered.WriteString("      Facility=\"local7\")\n")
	return rendered.String(), nil
}

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
	confPath := "/etc/rsyslog.d/99-syswarden-siem.conf"

	rsyslogConf, err := renderSIEMRsyslogConfig(ip, port, proto, tlsCA)
	if err != nil {
		return fmt.Errorf("render rsyslog SIEM config: %w", err)
	}

	_ = os.MkdirAll("/etc/rsyslog.d", 0750)
	if err := os.WriteFile(confPath, []byte(rsyslogConf), 0600); err != nil {
		return fmt.Errorf("failed to write rsyslog SIEM config: %w", err)
	}

	if err := restartManagedService("rsyslog"); err != nil {
		return fmt.Errorf("activate SIEM rsyslog configuration: %w", err)
	}

	fmt.Printf("[+] SIEM Forwarder successfully configured (%s:%s/%s)\n", ip, port, proto)
	return nil
}
