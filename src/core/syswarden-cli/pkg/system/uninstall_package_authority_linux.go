//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"strings"
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

type standaloneUninstallAuthority struct {
	executable    string
	databasePaths []string
	arguments     []string
	absentOutput  string
	presentOutput string
	recovery      string
}

func preflightStandaloneUninstallWith(executor firewallManagerExecutor, exists func(string) (bool, error)) error {
	return preflightUninstallWithProfile(executor, exists, nil)
}

func preflightUninstallWithProfile(executor firewallManagerExecutor, exists func(string) (bool, error), attestProfile func() (bool, error)) error {
	if exists == nil {
		return fmt.Errorf("native package database inspection is unavailable")
	}
	authorities := []standaloneUninstallAuthority{
		{executable: "dpkg-query", databasePaths: []string{"/var/lib/dpkg/status"},
			arguments:    []string{"--show", "--showformat=${Package}\\t${db:Status-Status}\\n", "syswarden"},
			absentOutput: "dpkg-query: no packages found matching syswarden\n",
			recovery:     "use 'sudo apt-get purge syswarden' or 'sudo apt-get remove syswarden' through verified native package removal"},
		{executable: "rpm", databasePaths: []string{"/usr/lib/sysimage/rpm", "/var/lib/rpm"},
			arguments:    []string{"--query", "--queryformat", "%{NAME}\\n", "syswarden"},
			absentOutput: "package syswarden is not installed\n", presentOutput: "syswarden\n",
			recovery: "use 'sudo dnf remove syswarden' through the native package manager"},
		{executable: "apk", databasePaths: []string{"/lib/apk/db/installed"},
			arguments: []string{"info", "--quiet", "--exists", "syswarden"}, absentOutput: "", presentOutput: "",
			recovery: "use 'sudo apk del syswarden' through the native package manager"},
	}
	var claims []standaloneUninstallAuthority
	for _, authority := range authorities {
		path, present, err := resolveOptionalFirewallRemovalExecutable(executor, authority.executable)
		if err != nil {
			return err
		}
		if !present {
			for _, database := range authority.databasePaths {
				found, err := exists(database)
				if err != nil {
					return fmt.Errorf("inspect native package database before uninstall: %w", err)
				}
				if found {
					return fmt.Errorf("cannot rule out native package ownership: %s database exists but its query tool is unavailable", authority.executable)
				}
			}
			continue
		}
		output, err := executor.output(path, authority.arguments...)
		if err != nil {
			code, known := firewallRemovalExitCode(err)
			if known && code == 1 && string(output) == authority.absentOutput {
				continue
			}
			return fmt.Errorf("cannot establish native package ownership through %s; no direct removal is allowed: %w", authority.executable, err)
		}
		if authority.executable == "dpkg-query" {
			fields := strings.Split(strings.TrimSuffix(string(output), "\n"), "\t")
			if len(fields) != 2 || fields[0] != "syswarden" || strings.Count(string(output), "\n") != 1 {
				return fmt.Errorf("ambiguous dpkg SysWarden package registration; no direct removal is allowed")
			}
			switch fields[1] {
			case "not-installed":
				continue
			case "config-files", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending", "installed":
			default:
				return fmt.Errorf("unknown dpkg SysWarden package state; no direct removal is allowed")
			}
		} else if string(output) != authority.presentOutput {
			return fmt.Errorf("ambiguous %s SysWarden package registration; no direct removal is allowed", authority.executable)
		}
		claims = append(claims, authority)
	}
	if len(claims) > 1 {
		return fmt.Errorf("multiple native package managers register SysWarden; resolve ownership before removal")
	}
	if len(claims) == 1 {
		if claims[0].executable == "rpm" && attestProfile != nil {
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
