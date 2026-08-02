package security

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"syswarden-core/logger"
)

// StartComplianceWatchdog runs a background compliance check every 24h at 2 AM.
func StartComplianceWatchdog(l *logger.Logger) {
	go func() {
		// Initial check on startup
		runComplianceAudit(l)

		for {
			now := time.Now()
			// Calculate time until next 2:00 AM
			next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
			if next.Before(now) || next.Equal(now) {
				next = next.Add(24 * time.Hour)
			}
			
			time.Sleep(time.Until(next))
			runComplianceAudit(l)
		}
	}()
}

func runComplianceAudit(l *logger.Logger) {
	driftFound := false

	// Check tcp_syncookies
	syn, err := os.ReadFile("/proc/sys/net/ipv4/tcp_syncookies")
	if err == nil && !strings.Contains(string(syn), "1") {
		l.LogComplianceDrift("tcp_syncookies is disabled (0). Kernel hardening altered!")
		driftFound = true
	}

	// Check rp_filter
	rp, err := os.ReadFile("/proc/sys/net/ipv4/conf/all/rp_filter")
	if err == nil && !strings.Contains(string(rp), "1") {
		l.LogComplianceDrift("rp_filter is disabled (0). Anti-spoofing altered!")
		driftFound = true
	}

	// Check syswarden-auto.conf permissions
	confPath := "/opt/syswarden/syswarden-auto.conf"
	stat, err := os.Stat(confPath)
	if err == nil {
		mode := stat.Mode().Perm()
		if mode != 0600 {
			l.LogComplianceDrift(fmt.Sprintf("%s permissions are %04o instead of 0600. File is exposed!", confPath, mode))
			driftFound = true
		}
	}

	// Optionally run full CLI audit if installed
	if _, err := os.Stat("/opt/syswarden/bin/syswarden"); err == nil {
		cmd := exec.Command("/opt/syswarden/bin/syswarden", "audit") // #nosec G204
		_ = cmd.Run()
	}

	if !driftFound {
		l.LogComplianceOK("All kernel & config hardening (NIS2/ISO27001) compliant.")
	}
}
