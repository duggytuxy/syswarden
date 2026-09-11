//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
)

const (
	systemdCoreSocketCapabilityDropInPath = "/usr/lib/systemd/system/syswarden-core.service.d/10-syswarden-socket-ownership.conf"
	systemdCoreSocketCapabilityDropIn     = `[Service]
# Assign the socket to the verified private rsyslog producer group.
CapabilityBoundingSet=CAP_CHOWN
`
)

func attestExactSystemdCoreSocketCapabilityDropIn(executor firewallManagerExecutor, path string) (string, error) {
	return attestExactSystemdPackageDropInAt(
		executor, path, systemdCoreSocketCapabilityDropInPath, "/", 0, 0,
		systemdCoreSocketCapabilityDropIn, "socket capability",
	)
}

// Native packages own the capability addition separately so downgrading also
// removes it. The generated base unit remains byte-compatible with v4.04.3.
// Source installations retain the self-contained socket-capable unit.
func selectedSystemdCoreServiceContent(executor firewallManagerExecutor) (string, error) {
	return selectSystemdCoreServiceContentAt(executor, systemdCoreSocketCapabilityDropInPath, "/", 0, 0)
}

func selectSystemdCoreServiceContentAt(executor firewallManagerExecutor, path, trustedRoot string, uid, gid uint32) (string, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return systemdCoreService, nil
	} else if err != nil {
		return "", fmt.Errorf("inspect systemd socket capability policy: %w", err)
	}
	if _, err := attestExactSystemdPackageDropInAt(
		executor, path, path, trustedRoot, uid, gid,
		systemdCoreSocketCapabilityDropIn, "socket capability",
	); err != nil {
		return "", err
	}
	return historicalV4043SystemdCoreService, nil
}

func attestSystemdSocketCapabilityBeforeActivation() error {
	content, err := selectedSystemdCoreServiceContent(hostFirewallExecutor())
	if err != nil {
		return err
	}
	if content == systemdCoreService {
		// The separately attested RHEL package-owned profile uses its existing
		// vendor unit, which already includes the socket ownership capability.
		if present, err := attestInstalledRHELPackageOwnedProfile(); err != nil {
			return err
		} else if present {
			return nil
		}
		// Missing policy is acceptable only for an independently attested source
		// installation. Native packages must not silently change unit layout.
		if err := attestAbsentSystemdFirewallOrderingDropIn(
			hostFirewallExecutor(), systemdCoreSocketCapabilityDropInPath,
			servicePackageEnvironment("SYSWARDEN_PKG_INSTALL") == "1",
		); err != nil {
			return fmt.Errorf("socket capability policy is required for native packages: %w", err)
		}
	}
	return nil
}
