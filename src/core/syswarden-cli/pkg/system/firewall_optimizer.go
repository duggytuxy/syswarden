package system

import (
	"fmt"
	"os/exec"
	"syswarden-cli/config"
)

// OptimizeHostFirewall respects the syswarden-auto.conf settings to replace Firewalld on RHEL systems
func OptimizeHostFirewall() error {
	// Detect if Firewalld is installed (typical for RHEL/AlmaLinux/Fedora/CentOS)
	if _, err := exec.LookPath("firewall-cmd"); err != nil {
		// Not a Firewalld system (e.g. Debian/Ubuntu with UFW). Do nothing.
		return nil
	}

	backend := config.GlobalConfig.FirewallBackend
	if backend == "" {
		backend = "keep"
	}

	if backend == "nftables" {
		fmt.Println("[INFO] Auto-Deploy: Bypassing Firewalld for pure Nftables OS Services...")
  _ = exec.Command("systemctl", "disable", "--now", "firewalld").Run()
		
		if _, err := exec.LookPath("nft"); err != nil {
			if _, err := exec.LookPath("dnf"); err == nil {
    _ = exec.Command("dnf", "install", "-y", "nftables").Run()
			} else if _, err := exec.LookPath("yum"); err == nil {
    _ = exec.Command("yum", "install", "-y", "nftables").Run()
			}
		}
  _ = exec.Command("systemctl", "enable", "--now", "nftables").Run()

	} else if backend == "iptables" {
		fmt.Println("[INFO] Auto-Deploy: Bypassing Firewalld for classic Iptables persistence...")
  _ = exec.Command("systemctl", "disable", "--now", "firewalld").Run()
		
		if _, err := exec.LookPath("dnf"); err == nil {
   _ = exec.Command("dnf", "install", "-y", "iptables-services").Run()
		} else if _, err := exec.LookPath("yum"); err == nil {
   _ = exec.Command("yum", "install", "-y", "iptables-services").Run()
		}
  _ = exec.Command("systemctl", "enable", "--now", "iptables").Run()

	} else {
		fmt.Println("[INFO] Auto-Deploy: Keeping Firewalld active.")
	}

	return nil
}
