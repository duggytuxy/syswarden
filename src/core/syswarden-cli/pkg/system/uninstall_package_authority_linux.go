//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
)

// PreflightStandaloneUninstall prevents removal of package-owned payload while
// the native package database still records the package. Native package hooks
// use prepare-package-removal, which retains their separate verified lifecycle.
func PreflightStandaloneUninstall() error {
	return preflightStandaloneUninstallWith(hostFirewallExecutor(), uninstallAuthorityPathExists)
}

// PreflightUninstall also permits the fully attested opt-in RPM profile's
// runtime-only first phase. Its payload remains under RPM erase authority.
func PreflightUninstall() error {
	return preflightUninstallWithProfile(hostFirewallExecutor(), uninstallAuthorityPathExists, attestInstalledRHELPackageOwnedProfileForRemoval)
}

func uninstallAuthorityPathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func preflightStandaloneUninstallWith(executor firewallManagerExecutor, exists func(string) (bool, error)) error {
	return preflightUninstallWithProfile(executor, exists, nil)
}

func preflightUninstallWithProfile(executor firewallManagerExecutor, exists func(string) (bool, error), attestProfile func() (bool, error)) error {
	claims, err := inspectNativeProductRegistrations(executor, exists)
	if err != nil {
		return fmt.Errorf("cannot establish native package ownership; no direct removal is allowed: %w", err)
	}
	if len(claims) > 1 {
		return fmt.Errorf("multiple native package identities or managers register SysWarden; resolve ownership before removal")
	}
	if len(claims) == 1 {
		if claims[0].manager == "rpm" && claims[0].name == compatibilityNativePackageName && attestProfile != nil {
			present, err := attestProfile()
			if err != nil {
				return fmt.Errorf("attest optional RPM runtime removal authority: %w", err)
			}
			if present {
				return nil
			}
		}
		return fmt.Errorf("SysWarden is registered with a native package manager; direct uninstall would leave package state inconsistent; %s; this command has not removed product state", claims[0].recovery)
	}
	return nil
}
