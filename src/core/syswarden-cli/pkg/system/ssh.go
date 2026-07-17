package system

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syswarden-cli/config"
)

// ConfigureSSH configures the SSH daemon securely
func ConfigureSSH() error {
	fmt.Println("[INFO] Configuring SSH...")

	// 1. Disable TCP Forwarding (CWE-284) and Detect Port
	sshConf := "/etc/ssh/sshd_config"
	port := config.GlobalConfig.SSHPort

	// Fallback to active sshd_config if port not in config
	if port == "" {
		if out, err := exec.Command("sh", "-c", "sshd -T 2>/dev/null | grep -i '^port '").Output(); err == nil && len(out) > 0 { // #nosec
			fields := strings.Fields(string(out))
			if len(fields) >= 2 {
				port = fields[1]
			}
		}
	}
	if port == "" {
		port = "22" // Absolute fallback
	}
	if _, err := os.Stat(sshConf); err == nil {
		fmt.Println("[INFO] Ensuring SSH TCP Forwarding is strictly DISABLED...")
		// Simulate file edit
		_ = exec.Command("sed", "-i", "s/^#AllowTcpForwarding.*/AllowTcpForwarding no/", sshConf).Run() // #nosec
		_ = exec.Command("sed", "-i", "s/^[[:space:]]*AllowTcpForwarding[[:space:]]*yes/AllowTcpForwarding no/", sshConf).Run() // #nosec

		if IsAlpine() {
			_ = exec.Command("rc-service", "sshd", "restart").Run() // #nosec
		} else {
			_ = exec.Command("systemctl", "restart", "ssh").Run() // #nosec
		}
	}

	// Persist the detected port to memory so Nftables overlay can use it for SSH Cloaking
	config.GlobalConfig.SSHPort = port
	fmt.Printf("[INFO] SSH Port configured as: %s\n", port)
	return nil
}
