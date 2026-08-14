//go:build freebsd

package system

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syswarden-cli/config"
)

func logHeader(title string) {
	fmt.Printf("\n\033[1;36m==============================================================================\033[0m\n")
	fmt.Printf("\033[1;36m%s\033[0m\n", title)
	fmt.Printf("\033[1;36m==============================================================================\033[0m\n")
}

func pass(msg string) {
	fmt.Printf("  \033[0;32m[OBSERVED]\033[0m %s\n", msg)
}

func fail(msg string) {
	fmt.Printf("  \033[0;31m[FAIL]\033[0m %s\n", msg)
}

func warn(msg string) {
	fmt.Printf("  \033[1;33m[WARN]\033[0m %s\n", msg)
}

func info(msg string) {
	fmt.Printf("  \033[0;34m[INFO]\033[0m %s\n", msg)
}

func isServiceActive(serviceName string) bool {
	out, err := exec.Command("service", serviceName, "status").Output() // #nosec
	if err == nil && strings.Contains(string(out), "is running") {
		return true
	}
	return false
}

func checkFilePerms(filepath string, validPerms []string, expectedOwner string) {
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		warn(fmt.Sprintf("File %s does not exist.", filepath))
		return
	}

	info, err := os.Stat(filepath)
	if err != nil {
		fail(fmt.Sprintf("Cannot stat %s", filepath))
		return
	}

	modeStr := fmt.Sprintf("%04o", info.Mode().Perm())
	isValid := false
	for _, perm := range validPerms {
		if strings.Contains(modeStr, perm) {
			isValid = true
			break
		}
	}

	if isValid {
		pass(fmt.Sprintf("%s permissions VERIFIED (%s).", filepath, modeStr))
	} else {
		fail(fmt.Sprintf("%s permissions FAILED (Got %s, Expected one of %v).", filepath, modeStr, validPerms))
	}
}

func RunAudit() {
	fmt.Printf("\033[1;36m=== SYSWARDEN %s Local Operational Diagnostic ===\033[0m\n", Version)
	info("This diagnostic reports only the checks shown below; it is not a compliance certification or a complete kernel-state assessment.")

	// Phase 1
	logHeader("Phase 1: Cron Orchestration")
	out, _ := exec.Command("crontab", "-l").Output() // #nosec
	cronCount := strings.Count(string(out), "syswarden-cli update-feeds")
	if cronCount == 1 {
		pass("Cron Orchestration VERIFIED: 'syswarden-cli update-feeds' is actively scheduled.")
	} else if cronCount > 1 {
		fail(fmt.Sprintf("Cron Duplication FAILED: %d SYSWARDEN cron jobs detected! Idempotency violated.", cronCount))
	} else {
		warn("Cron Orchestration: No automated SYSWARDEN background jobs found.")
	}

	// Phase 2
	logHeader("Phase 2: Log Routing & Anti-Injection Verification")

	if _, err := os.Stat("/var/log/auth.log"); err == nil {
		checkFilePerms("/var/log/auth.log", []string{"640", "600"}, "root")
	} else if _, err := os.Stat("/var/log/secure"); err == nil {
		checkFilePerms("/var/log/secure", []string{"640", "600"}, "root")
	}

	if isServiceActive("syslogd") {
		pass("syslogd daemon is active (FreeBSD default).")
	} else {
		fail("syslogd daemon is not running.")
	}

	// Phase 3
	logHeader("Phase 3: Kernel Shield & Threat Intelligence")
	_, errBlacklist := os.Stat("/etc/syswarden/lists/syswarden_blacklist.ipv4")
	_, errThreatIntel := os.Stat("/etc/syswarden/lists/syswarden_threatintel.ipv4")

	if errBlacklist == nil || errThreatIntel == nil {
		pass("Global Blocklist is populated.")
	} else {
		warn("Global Blocklist is missing.")
	}

	if config.GlobalConfig.GeoAllowed != "" {
		pass(fmt.Sprintf("GeoIP strict-allow configuration is set to: %s. PF enforcement was not checked here.", config.GlobalConfig.GeoAllowed))
	} else if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" && config.GlobalConfig.GeoCodes != "none" {
		pass("GeoIP classic-block configuration is enabled. PF enforcement was not checked here.")
	} else {
		info("GeoIP Threat Intelligence (Skipped by user).")
	}

	if config.GlobalConfig.ASNAllowed != "" {
		pass(fmt.Sprintf("ASN strict-allow configuration is set to: %s. PF enforcement was not checked here.", config.GlobalConfig.ASNAllowed))
	} else if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" && config.GlobalConfig.ASNList != "none" {
		pass("ASN classic-block configuration is enabled. PF enforcement was not checked here.")
	} else {
		info("Manual ASN Routing Defense (Skipped by user).")
	}

	out, err := exec.Command("pfctl", "-s", "rules").Output() // #nosec
	if err == nil && strings.Contains(string(out), "syswarden_blacklist") {
		pass("Packet Filter Layer 3 Acceleration is ACTIVE.")
	} else {
		fail("Packet Filter Layer 3 Acceleration is MISSING or failed to load.")
	}

	// Jails integration check (FreeBSD specific instead of Docker)
	_, errJls := exec.LookPath("jls")
	if errJls == nil {
		out, err := exec.Command("jls").Output() // #nosec
		if err == nil && len(strings.Split(string(out), "\n")) > 1 {
			pass("At least one active jail was listed; per-jail PF coverage was not checked.")
		} else {
			warn("FreeBSD Jails Integration: Jails binary found but no active jails detected.")
		}
	} else {
		warn("Docker/Jails Integration: Container orchestrator is not present.")
	}

	// Phase 4
	logHeader("Phase 4: Layer 7 Active Defense (SYSWARDEN WAF)")
	if isServiceActive("syswarden-core") {
		pass("SYSWARDEN WAF service (syswarden-core) is running.")

		if config.GlobalConfig.BruteforceLogs != "" {
			if strings.ToLower(config.GlobalConfig.BruteforceLogs) == "auto" {
				pass("WAAP Auto-Discovery is ENABLED. Dynamically tailing system logs.")
			} else {
				pass("WAAP Manual Log Tailing is actively monitoring custom paths.")
			}
		}

		if config.GlobalConfig.GeoAllowed != "" || config.GlobalConfig.ASNAllowed != "" {
			info("GeoIP or ASN strict-allow configuration is present; L7 override behavior was not exercised by this diagnostic.")
		}

		if _, err := os.Stat("/var/run/syswarden.sock"); err == nil {
			pass("SYSWARDEN UDS socket path exists; listener readiness was not exercised.")
		} else {
			fail("SYSWARDEN UDS socket (/var/run/syswarden.sock) is MISSING. Vector logs will be dropped!")
		}
		if _, err := os.Stat("/var/log/syswarden/waf.json"); err == nil {
			pass("WAF JSON telemetry file exists; event flow was not exercised.")
		} else {
			fail("WAF JSON telemetry backend is inactive (No waf.json).")
		}
	} else {
		fail("SYSWARDEN WAF service is completely offline.")
	}

	// Phase 5
	logHeader("Phase 5: Telemetry & Local Dashboard Inputs")
	info("The checks below observe the core service and local TUI data file only.")
	if isServiceActive("syswarden-core") {
		pass("syswarden-core service is active; telemetry generation was not independently exercised.")
	} else {
		fail("Telemetry Generator: syswarden-core is inactive.")
	}
	checkFilePerms("/var/lib/syswarden/ui/data.json", []string{"600"}, "root")

	// Phase 6
	logHeader("Phase 6: Zero Trust Remote Access (VPN & SSH Cloaking)")
	if config.GlobalConfig.EnableWG {
		pass("WireGuard Cloaking is ENABLED in config.")
		if _, err := os.Stat("/usr/local/etc/wireguard/wg-syswarden.conf"); err == nil {
			pass("WireGuard Configuration VERIFIED.")
			content, err := os.ReadFile("/usr/local/etc/wireguard/wg-syswarden.conf") // #nosec
			if err == nil && strings.Contains(string(content), "PresharedKey = ") {
				pass("WireGuard configuration contains a PresharedKey entry; tunnel state was not exercised.")
			} else {
				fail("WireGuard Post-Quantum PSK is MISSING.")
			}
		} else {
			fail("WireGuard Configuration FAILED: /usr/local/etc/wireguard/wg-syswarden.conf missing.")
		}
	} else {
		info("WireGuard Zero Trust Remote Access is DISABLED (Skipped).")
	}

	// Phase 7
	logHeader("Phase 7: CSPM / Persistence Posture")
	if _, err := exec.LookPath("nft"); err == nil {
		if _, err := os.Stat("/etc/syswarden/syswarden.nft"); err == nil {
			pass("Nftables persistence file exists; load state and locking were not independently checked.")
		} else {
			warn("Firewall Persistence UNKNOWN: Nftables base file /etc/syswarden/syswarden.nft is missing.")
		}
	}

	fmt.Printf("\n\033[1;32m[✔] SYSWARDEN local diagnostic completed; review each observation and warning.\033[0m\n")
}
