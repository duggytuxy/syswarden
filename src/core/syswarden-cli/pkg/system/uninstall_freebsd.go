//go:build freebsd

package system

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// UninstallSystem executes a scorched-earth removal of SYSWARDEN and all its dependencies on FreeBSD
func UninstallSystem() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall must be executed as root")
	}

	fmt.Println("[WARN] Starting Deep Clean Uninstallation (Scorched Earth) on FreeBSD...")

	// 1. Terminate Daemons
	fmt.Println(" -> Stopping and removing SYSWARDEN Core Services...")
	_ = exec.Command("service", "syswarden", "stop").Run() // #nosec
	_ = exec.Command("sysrc", "-x", "syswarden_enable").Run() // #nosec
	_ = os.Remove("/usr/local/etc/rc.d/syswarden")

	// 2. Kill orphan processes
	_ = exec.Command("pkill", "-9", "-f", "syswarden-core").Run() // #nosec

	// 3. Remove WireGuard
	if _, err := os.Stat("/usr/local/etc/wireguard/wg-syswarden.conf"); err == nil {
		fmt.Println(" -> Removing WireGuard VPN configs...")
		_ = exec.Command("sysrc", "-x", "wireguard_interfaces").Run() // #nosec
		_ = exec.Command("service", "wireguard", "stop").Run() // #nosec
		_ = os.Remove("/usr/local/etc/wireguard/wg-syswarden.conf")
		_ = os.RemoveAll("/usr/local/etc/wireguard/clients")
	}

	// 4. Clean Firewall Rules
	fmt.Println(" -> Cleaning Firewall Rules (Packet Filter)...")
	// Flush specific tables
	_ = exec.Command("pfctl", "-t", "syswarden_whitelist", "-T", "kill").Run() // #nosec
	_ = exec.Command("pfctl", "-t", "syswarden_blacklist", "-T", "kill").Run() // #nosec
	_ = exec.Command("pfctl", "-t", "banned_ips", "-T", "kill").Run() // #nosec
	_ = exec.Command("pfctl", "-t", "syswarden_geoip", "-T", "kill").Run() // #nosec
	_ = exec.Command("pfctl", "-t", "syswarden_asn", "-T", "kill").Run() // #nosec

	// 5. Clean up Cron and Syslog
	fmt.Println(" -> Cleaning up background jobs and SIEM...")
	_ = os.Remove("/usr/local/etc/rsyslog.d/99-syswarden-siem.conf")
	_ = os.Remove("/usr/local/etc/rsyslog.d/99-syswarden-waf-bridge.conf")
	_ = exec.Command("service", "rsyslogd", "restart").Run() // #nosec

	// Remove cron natively
	out, _ := exec.Command("crontab", "-l").Output() // #nosec
	lines := strings.Split(string(out), "\n")
	var newLines []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !strings.Contains(line, "syswarden-cli") {
			newLines = append(newLines, line)
		}
	}
	newCron := ""
	if len(newLines) > 0 {
		newCron = strings.Join(newLines, "\n") + "\n"
	}
	cmd := exec.Command("crontab", "-") // #nosec
	cmd.Stdin = strings.NewReader(newCron)
	_ = cmd.Run()

	// 6. Scorched Earth Files
	fmt.Println(" -> Purging remaining files and configurations...")
	_ = os.RemoveAll("/etc/syswarden")
	_ = os.RemoveAll("/var/db/syswarden")
	_ = os.RemoveAll("/var/log/syswarden")
	_ = os.Remove("/var/run/syswarden.sock")
	_ = os.Remove("/usr/local/etc/syswarden-auto.conf")
	_ = os.RemoveAll("/opt/syswarden")
	_ = os.Remove("/usr/local/bin/syswarden")
	_ = os.Remove("/usr/local/bin/syswarden-tui")

	fmt.Println("[SUCCESS] Uninstallation complete. A reboot is recommended.")
	return nil
}
