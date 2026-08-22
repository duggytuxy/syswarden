//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func removePreparedServiceEnablement(
	path string,
	servicePath string,
	serviceContent string,
	serviceMode os.FileMode,
	allowedTargets ...string,
) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect service enablement %s: %w", path, err)
	}
	if err := attestExactServiceFile(servicePath, serviceContent, serviceMode); err != nil {
		return fmt.Errorf("attest service definition before enablement removal %s: %w", path, err)
	}
	directory, err := openPinnedServiceDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	target, err := readAttestedServiceEnablement(directory, filepath.Base(path))
	directory.close()
	if err != nil {
		return fmt.Errorf("attest service enablement %s: %w", path, err)
	}
	if !containsExactString(allowedTargets, target) {
		return fmt.Errorf("refusing unexpected service enablement target %q for %s", target, path)
	}
	if err := removeCreatedServiceArtifact(serviceArtifact{path: path, target: target}); err != nil {
		return err
	}
	return nil
}

// RemovePreparedServiceArtifactsForRemoval deletes only exact attributable
// SysWarden service definitions after the durable barrier is present and all
// mutators have been verified inactive and disabled.
func RemovePreparedServiceArtifactsForRemoval() error {
	if err := RequireRemovalTombstone(); err != nil {
		return fmt.Errorf("service artifact removal requires the durable removal tombstone: %w", err)
	}
	if err := ReattestFirewallStatePreparedForRemoval(); err != nil {
		return fmt.Errorf("service artifact removal requires prepared firewall mutators: %w", err)
	}
	if IsAlpine() {
		if err := removePreparedServiceEnablement(
			"/etc/runlevels/default/syswarden-core",
			"/etc/init.d/syswarden-core", openRCCoreService, 0755,
			"/etc/init.d/syswarden-core",
		); err != nil {
			return err
		}
		if err := removePreparedServiceEnablement(
			"/etc/runlevels/default/syswarden-firewall",
			"/etc/init.d/syswarden-firewall", openRCFirewallService, 0755,
			"/etc/init.d/syswarden-firewall",
		); err != nil {
			return err
		}
		if err := removeExactFirewallRemovalFile("/etc/init.d/syswarden-core", openRCCoreService, 0755); err != nil {
			return err
		}
		if err := removeExactFirewallRemovalFile("/etc/init.d/syswarden-firewall", openRCFirewallService, 0755); err != nil {
			return err
		}
	} else {
		if err := removePreparedServiceEnablement(
			"/etc/systemd/system/multi-user.target.wants/syswarden-core.service",
			"/etc/systemd/system/syswarden-core.service", systemdCoreService, 0600,
			"../syswarden-core.service", "/etc/systemd/system/syswarden-core.service",
		); err != nil {
			return err
		}
		if err := removePreparedServiceEnablement(
			"/etc/systemd/system/multi-user.target.wants/syswarden-firewall.service",
			"/etc/systemd/system/syswarden-firewall.service", systemdFirewallService, 0600,
			"../syswarden-firewall.service", "/etc/systemd/system/syswarden-firewall.service",
		); err != nil {
			return err
		}
		if err := removeExactFirewallRemovalFile(
			"/etc/systemd/system/syswarden-core.service", systemdCoreService, 0600,
		); err != nil {
			return err
		}
		if err := removeExactFirewallRemovalFile(
			"/etc/systemd/system/syswarden-firewall.service", systemdFirewallService, 0600,
		); err != nil {
			return err
		}
		managerState, err := classifyServiceManagerRuntime(false)
		if err != nil {
			return err
		}
		switch managerState {
		case serviceManagerActive:
			executor := hostFirewallExecutor()
			systemctlPath, err := resolveFirewallExecutable(executor, "systemctl")
			if err != nil {
				return err
			}
			if _, err := executor.output(systemctlPath, "daemon-reload"); err != nil {
				return fmt.Errorf("reload systemd after exact service removal: %w", err)
			}
		case serviceManagerOffline:
			// The exact unit files and enablement links are absent before the
			// package payload can disappear. No manager process exists to reload.
		default:
			return fmt.Errorf("refusing service artifact removal with manager state %s", managerState)
		}
	}
	if err := ReattestFirewallStatePreparedForRemoval(); err != nil {
		return fmt.Errorf("reattest host after exact service artifact removal: %w", err)
	}
	return nil
}
