//go:build linux

package system

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// UninstallSystem executes a scorched-earth removal of SysWarden and all its dependencies
func UninstallSystem() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall must be executed as root")
	}

	fmt.Println("[WARN] Starting Deep Clean Uninstallation (Scorched Earth)...")

	// 1. Terminate Daemons
	fmt.Println(" -> Stopping and removing SysWarden Core Services...")
	if IsAlpine() {
		_ = exec.Command("rc-service", "syswarden-core", "stop").Run()
		_ = exec.Command("rc-update", "del", "syswarden-core", "default").Run()
		_ = os.Remove("/etc/init.d/syswarden-core")

		_ = exec.Command("rc-service", "syswarden-firewall", "stop").Run()
		_ = exec.Command("rc-update", "del", "syswarden-firewall", "default").Run()
		_ = os.Remove("/etc/init.d/syswarden-firewall")
	} else {
		_ = exec.Command("systemctl", "stop", "syswarden-core.service").Run()
		_ = exec.Command("systemctl", "disable", "syswarden-core.service").Run()
		_ = os.Remove("/etc/systemd/system/syswarden-core.service")

		_ = exec.Command("systemctl", "stop", "syswarden-firewall.service").Run()
		_ = exec.Command("systemctl", "disable", "syswarden-firewall.service").Run()
		_ = os.Remove("/etc/systemd/system/syswarden-firewall.service")

		// Legacy cleanups
		_ = exec.Command("systemctl", "stop", "syswarden.service").Run()
		_ = exec.Command("systemctl", "disable", "syswarden.service").Run()
		_ = os.Remove("/etc/systemd/system/syswarden.service")

		_ = exec.Command("systemctl", "stop", "syswarden-reporter").Run()
		_ = exec.Command("systemctl", "disable", "syswarden-reporter").Run()
		_ = os.Remove("/etc/systemd/system/syswarden-reporter.service")

		_ = exec.Command("systemctl", "daemon-reload").Run()
	}

	// 2. Kill orphan processes
	_ = exec.Command("pkill", "-9", "-f", "syswarden-core").Run()

	// 3. Remove WireGuard
	if _, err := os.Stat("/etc/wireguard/wg0.conf"); err == nil {
		fmt.Println(" -> Removing WireGuard VPN configs...")
		_ = exec.Command("systemctl", "disable", "--now", "wg-quick@wg0").Run()
		_ = os.Remove("/etc/wireguard/wg0.conf")
		_ = os.RemoveAll("/etc/wireguard/clients")
		_ = os.Remove("/etc/sysctl.d/99-syswarden-wireguard.conf")
		_ = exec.Command("sysctl", "--system").Run()
	}

	// 4. Clean Firewall Rules
	fmt.Println(" -> Cleaning Firewall Rules (nftables & iptables)...")
	if err := exec.Command("nft", "list", "ruleset").Run(); err == nil {
		_ = exec.Command("nft", "delete", "table", "netdev", "syswarden_hw_drop").Run()
		_ = exec.Command("nft", "delete", "table", "arp", "syswarden_arp").Run()
		_ = exec.Command("nft", "delete", "table", "inet", "syswarden").Run()
		_ = exec.Command("nft", "delete", "table", "inet", "syswarden_wg").Run()
	}
	_ = os.Remove("/etc/syswarden/syswarden.nft")

	// Legacy iptables purge (DOCKER-USER etc)
	_ = exec.Command("sh", "-c", "iptables-save | grep -v SysWarden | iptables-restore").Run()

	// 5. Revert Hardening
	fmt.Println(" -> Reverting CIS Hardening...")
	_ = os.Remove("/etc/modprobe.d/syswarden-cis-fs.conf")
	_ = os.Remove("/etc/modprobe.d/syswarden-cis-net.conf")
	_ = os.Remove("/etc/sysctl.d/99-syswarden-cis-level2.conf")
	_ = os.Remove("/etc/security/limits.d/99-syswarden-cis.conf")
	_ = exec.Command("sysctl", "--system").Run()

	// 5.5 Clean up Cron and Rsyslog
	fmt.Println(" -> Cleaning up background jobs and log bridges...")

	// Remove cron natively
	out, _ := exec.Command("crontab", "-l").Output()
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
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(newCron)
	_ = cmd.Run()
	_ = os.Remove("/etc/rsyslog.d/99-syswarden-waf-bridge.conf")
	_ = os.Remove("/etc/rsyslog.d/99-syswarden-siem.conf")
	_ = exec.Command("systemctl", "restart", "rsyslog").Run()

	// 6. Scorched Earth Files
	fmt.Println(" -> Purging remaining files and configurations...")
	_ = os.RemoveAll("/etc/syswarden")
	_ = os.RemoveAll("/var/lib/syswarden")
	_ = os.RemoveAll("/var/log/syswarden")
	_ = os.Remove("/var/run/syswarden.sock")
	_ = os.Remove("/etc/syswarden.conf")
	_ = os.RemoveAll("/opt/syswarden")
	_ = os.Remove("/usr/local/bin/syswarden")
	_ = os.Remove("/usr/local/bin/syswarden-tui")

	fmt.Println("[SUCCESS] Uninstallation complete. A reboot is recommended.")
	return nil
}
