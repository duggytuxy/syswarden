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
		_ = exec.CommandContext(ctx, "apt-get", "update").Run() // #nosec
		cmd := exec.CommandContext(ctx, "apt-get", "install", "-y", "nftables", "wireguard-tools", "qrencode", "curl", "jq", "rsyslog") // #nosec
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("APT installation failed: %w", err)
		}
	} else if _, err := exec.LookPath("dnf"); err == nil {
		fmt.Println(" -> Detected RHEL/Alma/Rocky/Oracle (DNF)")
		_ = exec.CommandContext(ctx, "dnf", "install", "-y", "epel-release").Run() // #nosec
		cmd := exec.CommandContext(ctx, "dnf", "install", "-y", "nftables", "wireguard-tools", "qrencode", "curl", "jq", "rsyslog") // #nosec
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("DNF installation failed: %w", err)
		}
	} else if _, err := exec.LookPath("yum"); err == nil {
		fmt.Println(" -> Detected CentOS/Legacy RHEL (YUM)")
		_ = exec.CommandContext(ctx, "yum", "install", "-y", "epel-release").Run() // #nosec
		cmd := exec.CommandContext(ctx, "yum", "install", "-y", "nftables", "wireguard-tools", "qrencode", "curl", "jq", "rsyslog") // #nosec
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("YUM installation failed: %w", err)
		}
	} else if _, err := exec.LookPath("pkg"); err == nil {
		fmt.Println(" -> Detected FreeBSD (pkg)")
		cmd := exec.CommandContext(ctx, "pkg", "install", "-y", "pf", "wireguard-tools", "libqrencode", "curl", "jq") // #nosec
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("PKG installation failed: %w", err)
		}
	} else if _, err := exec.LookPath("apk"); err == nil {
		fmt.Println(" -> Detected Alpine Linux (APK)")
		cmd := exec.CommandContext(ctx, "apk", "add", "--no-cache", "nftables", "wireguard-tools", "libqrencode-tools", "curl", "jq", "rsyslog") // #nosec
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("APK installation failed: %w", err)
		}
	} else {
		fmt.Println("[WARN] No supported package manager found. Please install dependencies manually.")
	}

	return nil
}
