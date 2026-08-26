package system

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// InstallDependencies installs core system prerequisites securely with timeout context
func InstallDependencies() error {
	fmt.Println("[INFO] Checking and installing dependencies securely...")

	if os.Getenv("SYSWARDEN_PKG_INSTALL") == "1" {
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
