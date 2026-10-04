//go:build linux

package system

import (
	"bytes"
	"errors"
	"fmt"
	"os"
)

// A staged recovery CLI may prepare removal of the half-configured v4.10.2
// package. This exception is confined to removal callers. Activation retains
// the normal same-release requirement, and RPM ownership is unchanged.
func parseSystemdRemovalDPKGOwnerWith(
	output []byte,
	requireBarrier func() error,
	readInstalled func() ([]byte, error),
) (string, error) {
	claim, err := parseSysWardenDPKGDropInOwner(output)
	if err == nil {
		return claim, nil
	}
	if !bytes.Equal(output, []byte("4.10.2\tamd64\n")) || requireBarrier == nil || readInstalled == nil {
		return "", err
	}
	if err := requireBarrier(); err != nil {
		return "", fmt.Errorf("historical package removal requires the durable barrier: %w", err)
	}
	installed, err := readInstalled()
	if err != nil {
		return "", fmt.Errorf("inspect historical package removal state: %w", err)
	}
	if !bytes.Equal(installed, []byte("install ok half-configured\tamd64\t4.10.2\n")) {
		return "", fmt.Errorf("historical package removal state is not exact")
	}
	if err := requireBarrier(); err != nil {
		return "", fmt.Errorf("historical package removal barrier changed: %w", err)
	}
	return "syswarden@4.10.2#amd64#dpkg#half-configured-removal", nil
}

func attestExactSystemdRemovalDropIn(executor firewallManagerExecutor, path string) (string, error) {
	content, description := "", ""
	switch path {
	case systemdCoreSocketCapabilityDropInPath:
		content, description = systemdCoreSocketCapabilityDropIn, "socket capability"
	case systemdFirewallWireGuardOrderingDropInPath:
		content, description = systemdFirewallWireGuardOrderingDropIn, "ordering"
	default:
		return "", fmt.Errorf("refusing unexpected systemd removal drop-in %s", path)
	}
	return attestExactSystemdPackageDropInWithDPKGOwner(
		executor, path, path, "/", 0, 0, content, description,
		func(output []byte) (string, error) {
			return parseSystemdRemovalDPKGOwnerWith(output, RequireRemovalTombstone, func() ([]byte, error) {
				dpkgQuery, err := resolveFirewallExecutable(executor, "dpkg-query")
				if err != nil {
					return nil, err
				}
				return executor.output(dpkgQuery, "--show", "--showformat="+syswardenDropInDPKGInstalledFormat, "syswarden")
			})
		},
	)
}

func attestSystemdRemovalDropIns(executor firewallManagerExecutor, dropIns string) (string, error) {
	return attestSystemdServiceDropInsWithPackageAttestor(executor, dropIns, attestExactSystemdRemovalDropIn)
}

func selectedSystemdCoreRemovalContent(executor firewallManagerExecutor) (string, error) {
	if _, err := os.Lstat(systemdCoreSocketCapabilityDropInPath); errors.Is(err, os.ErrNotExist) {
		return systemdCoreService, nil
	} else if err != nil {
		return "", fmt.Errorf("inspect systemd socket capability before removal: %w", err)
	}
	if _, err := attestExactSystemdRemovalDropIn(executor, systemdCoreSocketCapabilityDropInPath); err != nil {
		return "", err
	}
	return historicalV4043SystemdCoreService, nil
}
