package security

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"syswarden-core/internal/runtimepaths"
	"syswarden-core/logger"
)

const localHardeningCheckOK = "The selected local checks found tcp_syncookies and rp_filter enabled when readable, and syswarden-auto.conf mode 0600 when present. Other settings were not evaluated."

// StartComplianceWatchdog runs selected local hardening checks on startup and
// every 24 hours at 2 AM. The result is not a compliance assessment.
func StartComplianceWatchdog(ctx context.Context, wg *sync.WaitGroup, l *logger.Logger) {
	startComplianceWatchdog(ctx, wg, l, runComplianceAudit)
}

func startComplianceWatchdog(ctx context.Context, wg *sync.WaitGroup, l *logger.Logger, audit func(*logger.Logger)) {
	if ctx == nil || wg == nil || l == nil || audit == nil {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Initial check on startup
		audit(l)

		for {
			now := time.Now()
			// Calculate time until next 2:00 AM
			next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
			if next.Before(now) || next.Equal(now) {
				next = next.Add(24 * time.Hour)
			}

			timer := time.NewTimer(time.Until(next))
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
				audit(l)
			}
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
	if err == nil && !rpFilterEnabled(rp) {
		l.LogComplianceDrift("rp_filter is disabled (0). Anti-spoofing altered!")
		driftFound = true
	}

	// Check syswarden-auto.conf permissions
	confPath := runtimepaths.LegacyConfig()
	stat, err := os.Stat(confPath)
	if err == nil {
		mode := stat.Mode().Perm()
		if mode != 0600 {
			l.LogComplianceDrift(fmt.Sprintf("%s permissions are %04o instead of 0600. File is exposed!", confPath, mode))
			driftFound = true
		}
	}

	// Optionally run the full CLI audit through the fixed native package path.
	runtimepaths.RunInstalledComplianceAudit()

	if !driftFound {
		l.LogComplianceOK(localHardeningCheckOK)
	}
}

// rpFilterEnabled accepts Linux strict mode (1) and loose mode (2). Both modes
// perform reverse-path source validation; only mode 0 disables it.
func rpFilterEnabled(raw []byte) bool {
	switch strings.TrimSpace(string(raw)) {
	case "1", "2":
		return true
	default:
		return false
	}
}
