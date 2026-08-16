//go:build linux

package system

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// UninstallSystem executes a scorched-earth removal of SYSWARDEN and all its dependencies
func UninstallSystem() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall must be executed as root")
	}

	fmt.Println("[WARN] Starting Deep Clean Uninstallation (Scorched Earth)...")

	// 1. Terminate Daemons
	fmt.Println(" -> Stopping and removing SYSWARDEN Core Services...")
	if IsAlpine() {
		_ = exec.Command("rc-service", "syswarden-core", "stop").Run()          // #nosec
		_ = exec.Command("rc-update", "del", "syswarden-core", "default").Run() // #nosec
		_ = os.Remove("/etc/init.d/syswarden-core")

		_ = exec.Command("rc-service", "syswarden-firewall", "stop").Run()          // #nosec
		_ = exec.Command("rc-update", "del", "syswarden-firewall", "default").Run() // #nosec
		_ = os.Remove("/etc/init.d/syswarden-firewall")
	} else {
		_ = exec.Command("systemctl", "stop", "syswarden-core.service").Run()    // #nosec
		_ = exec.Command("systemctl", "disable", "syswarden-core.service").Run() // #nosec
		_ = os.Remove("/etc/systemd/system/syswarden-core.service")

		_ = exec.Command("systemctl", "stop", "syswarden-firewall.service").Run()    // #nosec
		_ = exec.Command("systemctl", "disable", "syswarden-firewall.service").Run() // #nosec
		_ = os.Remove("/etc/systemd/system/syswarden-firewall.service")

		// Legacy cleanups
		_ = exec.Command("systemctl", "stop", "syswarden.service").Run()    // #nosec
		_ = exec.Command("systemctl", "disable", "syswarden.service").Run() // #nosec
		_ = os.Remove("/etc/systemd/system/syswarden.service")

		_ = exec.Command("systemctl", "stop", "syswarden-reporter").Run()    // #nosec
		_ = exec.Command("systemctl", "disable", "syswarden-reporter").Run() // #nosec
		_ = os.Remove("/etc/systemd/system/syswarden-reporter.service")

		_ = exec.Command("systemctl", "stop", "syswarden-webtui.service").Run()    // #nosec
		_ = exec.Command("systemctl", "disable", "syswarden-webtui.service").Run() // #nosec
		_ = os.Remove("/etc/systemd/system/syswarden-webtui.service")

		_ = exec.Command("systemctl", "daemon-reload").Run() // #nosec
	}

	// 2. Kill orphan processes
	_ = exec.Command("pkill", "-9", "-f", "syswarden-core").Run()   // #nosec
	_ = exec.Command("pkill", "-9", "-f", "syswarden-webtui").Run() // #nosec

	// 3. Remove WireGuard
	if _, err := os.Stat("/etc/wireguard/wg-syswarden.conf"); err == nil {
		fmt.Println(" -> Disabling and removing WireGuard Configuration")
		_ = exec.Command("systemctl", "disable", "--now", "wg-quick@wg-syswarden").Run() // #nosec
		_ = os.Remove("/etc/wireguard/wg-syswarden.conf")
		_ = os.RemoveAll("/etc/wireguard/clients")
		_ = os.Remove("/etc/sysctl.d/99-syswarden-wireguard.conf")
		_ = exec.Command("sysctl", "--system").Run() // #nosec
	}

	// 4. Clean Firewall Rules
	fmt.Println(" -> Cleaning Firewall Rules (nftables & iptables)...")
	if err := exec.Command("nft", "list", "ruleset").Run(); err == nil { // #nosec
		_ = exec.Command("nft", "delete", "table", "netdev", "syswarden_hw_drop").Run() // #nosec
		_ = exec.Command("nft", "delete", "table", "arp", "syswarden_arp").Run()        // #nosec
		_ = exec.Command("nft", "delete", "table", "inet", "syswarden").Run()           // #nosec
		_ = exec.Command("nft", "delete", "table", "inet", "syswarden_wg").Run()        // #nosec
	}
	_ = os.Remove("/etc/syswarden/syswarden.nft")

	// Safe targeted iptables purge
	if _, err := exec.LookPath("iptables"); err == nil {
		out, _ := exec.Command("iptables", "-S").Output() // #nosec
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.Contains(line, "SYSWARDEN") {
				parts := strings.Fields(line)
				if len(parts) > 2 && (parts[0] == "-A" || parts[0] == "-I") {
					parts[0] = "-D"
					_ = exec.Command("iptables", parts...).Run() // #nosec
				}
			}
		}
	}
	// 5. Revert Hardening
	fmt.Println(" -> Reverting CIS Hardening...")
	_ = os.Remove("/etc/modprobe.d/syswarden-cis-fs.conf")
	_ = os.Remove("/etc/modprobe.d/syswarden-cis-net.conf")
	_ = os.Remove("/etc/sysctl.d/99-syswarden-cis-level2.conf")
	_ = os.Remove("/etc/security/limits.d/99-syswarden-cis.conf")
	_ = os.Remove("/etc/cron.allow")
	_ = exec.Command("sysctl", "--system").Run() // #nosec

	// Unlock user profiles
	if dirs, err := os.ReadDir("/home"); err == nil {
		for _, d := range dirs {
			if d.IsDir() {
				profiles := []string{".profile", ".bashrc", ".bash_profile"}
				for _, p := range profiles {
					pPath := "/home/" + d.Name() + "/" + p
					if _, err := os.Stat(pPath); err == nil {
						_ = exec.Command("chattr", "-i", pPath).Run() // #nosec
					}
				}
			}
		}
	}

	// 5.5 Clean up Cron and Rsyslog
	fmt.Println(" -> Cleaning up background jobs and log bridges...")

	// Remove only canonical SysWarden cron entries and fail before any write if
	// the operator crontab cannot be read exactly.
	if err := removeManagedRootCron(
		exec.Command("crontab", "-l"),
		exec.Command("crontab", "-"),
	); err != nil {
		return fmt.Errorf("clean root crontab: %w", err)
	}
	_ = os.Remove("/etc/rsyslog.d/99-syswarden-waf-bridge.conf")
	_ = os.Remove("/etc/rsyslog.d/99-syswarden-siem.conf")
	_ = exec.Command("systemctl", "restart", "rsyslog").Run() // #nosec

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
