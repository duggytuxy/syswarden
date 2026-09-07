package system

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

var offlineQualificationDependencyLookPath = exec.LookPath

// InstallDependencies installs core system prerequisites securely with timeout context
func InstallDependencies() error {
	fmt.Println("[INFO] Checking and installing dependencies securely...")

	if os.Getenv("SYSWARDEN_PKG_INSTALL") == "1" {
		if OfflineQualificationOperation() {
			if err := attestOfflineQualificationDependencies(); err != nil {
				return fmt.Errorf("attest offline package dependencies: %w", err)
			}
		}
		fmt.Println("[INFO] Package manager install detected. Skipping manual dependency resolution.")
		return nil
	}

	// 5-minute timeout for dependency installation
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Detect package manager
	if _, err := exec.LookPath("apt-get"); err == nil {
		fmt.Println(" -> Detected Debian/Ubuntu (APT)")
		_ = exec.CommandContext(ctx, "apt-get", "update").Run()                                                                         // #nosec
		cmd := exec.CommandContext(ctx, "apt-get", "install", "-y", "nftables", "wireguard-tools", "qrencode", "curl", "jq", "rsyslog") // #nosec
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("APT installation failed: %w", err)
		}
	} else if _, err := exec.LookPath("dnf"); err == nil {
		fmt.Println(" -> Detected RHEL/Alma/Rocky/Oracle (DNF)")
		cmd := exec.CommandContext(ctx, "dnf", "install", "-y", "nftables", "wireguard-tools", "curl", "jq", "rsyslog", "checkpolicy", "policycoreutils-python-utils") // #nosec G204 -- executable and package arguments are fixed constants
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("DNF installation failed: %w", err)
		}
		fmt.Println("[INFO] Terminal WireGuard QR rendering is optional on RHEL-family systems and is enabled only when qrencode is already available from an operator-approved repository.")
	} else if _, err := exec.LookPath("yum"); err == nil {
		fmt.Println(" -> Detected CentOS/Legacy RHEL (YUM)")
		cmd := exec.CommandContext(ctx, "yum", "install", "-y", "nftables", "wireguard-tools", "curl", "jq", "rsyslog", "checkpolicy", "policycoreutils-python-utils") // #nosec G204 -- executable and package arguments are fixed constants
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("YUM installation failed: %w", err)
		}
		fmt.Println("[INFO] Terminal WireGuard QR rendering is optional on RHEL-family systems and is enabled only when qrencode is already available from an operator-approved repository.")
	} else if _, err := exec.LookPath("apk"); err == nil {
		fmt.Println(" -> Detected Alpine Linux (APK)")
		cmd := exec.CommandContext(ctx, "apk", "add", "--no-cache", "nftables", "wireguard-tools", "libqrencode-tools", "curl", "jq", "rsyslog", "rsyslog-uxsock") // #nosec
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("APK installation failed: %w", err)
		}
	} else {
		fmt.Println("[WARN] No supported package manager found. Please install dependencies manually.")
	}

	return nil
}

func attestOfflineQualificationDependencies() error {
	return attestOfflineQualificationDependenciesWith(
		offlineQualificationDependencyLookPath,
		func(path string) error {
			return validateOfflineQualificationDependency(path, os.Geteuid())
		},
	)
}

func attestOfflineQualificationDependenciesWith(
	lookPath func(string) (string, error),
	validate func(string) error,
) error {
	if lookPath == nil || validate == nil {
		return errors.New("offline dependency attestation is unavailable")
	}
	type dependencyProfile struct {
		manager string
		paths   []string
	}
	profiles := []dependencyProfile{
		{
			manager: "apt-get",
			paths:   []string{"chattr", "cron", "curl", "ipset", "jq", "nft", "ps", "qrencode", "rsyslogd", "wg", "wget"},
		},
		{
			manager: "dnf",
			paths:   []string{"chattr", "checkpolicy", "crond", "curl", "ipset", "jq", "nft", "ps", "rsyslogd", "semanage", "wg", "wget"},
		},
		{
			manager: "yum",
			paths:   []string{"chattr", "checkpolicy", "crond", "curl", "ipset", "jq", "nft", "ps", "rsyslogd", "semanage", "wg", "wget"},
		},
		{
			manager: "apk",
			paths:   []string{"chattr", "crond", "curl", "jq", "nft", "ps", "qrencode", "rsyslogd", "wg", "wget"},
		},
	}
	for _, profile := range profiles {
		managerPath, err := lookPath(profile.manager)
		if err != nil {
			continue
		}
		if !trustedPackageManagerPath(profile.manager, managerPath) {
			return fmt.Errorf("package manager %q resolved to untrusted path %q", profile.manager, managerPath)
		}
		for _, dependency := range profile.paths {
			resolved, err := lookPath(dependency)
			if err != nil {
				return fmt.Errorf("required dependency %q is unavailable: %w", dependency, err)
			}
			if err := validate(resolved); err != nil {
				return fmt.Errorf("required dependency %q is untrusted: %w", dependency, err)
			}
		}
		return nil
	}
	return errors.New("no supported package manager is available for offline dependency attestation")
}

func validateOfflineQualificationDependency(path string, expectedUID int) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("dependency path is not canonical and absolute: %q", path)
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	trusted := false
	for _, directory := range []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin"} {
		if filepath.Dir(canonical) == directory {
			trusted = true
			break
		}
	}
	if !trusted {
		return fmt.Errorf("dependency resolves outside trusted system directories: %q", canonical)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return err
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 ||
		int(status.Uid) != expectedUID {
		return errors.New("dependency is not an owner-controlled regular executable")
	}
	return nil
}
