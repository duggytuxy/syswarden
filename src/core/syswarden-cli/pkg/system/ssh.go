//go:build linux

package system

import (
	"context"
	"fmt"
	"os/exec"
	"syswarden-cli/config"
	"time"
)

const sshCommandTimeout = 30 * time.Second

var sshDaemonSignalPaths = []string{
	"/usr/sbin/sshd",
	"/usr/local/sbin/sshd",
	"/sbin/sshd",
	"/usr/lib/ssh/sshd",
	"/usr/libexec/openssh/sshd",
	"/usr/libexec/sshd",
	"/etc/ssh/sshd_config.d",
	"/etc/default/ssh",
	"/etc/sysconfig/sshd",
	"/etc/pam.d/sshd",
	"/etc/init.d/ssh",
	"/etc/init.d/sshd",
	"/etc/rc.d/init.d/ssh",
	"/etc/rc.d/init.d/sshd",
	"/etc/systemd/system/ssh.service",
	"/etc/systemd/system/sshd.service",
	"/etc/systemd/system/ssh.socket",
	"/etc/systemd/system/sshd.socket",
	"/run/systemd/system/ssh.service",
	"/run/systemd/system/sshd.service",
	"/run/systemd/system/ssh.socket",
	"/run/systemd/system/sshd.socket",
	"/lib/systemd/system/ssh.service",
	"/lib/systemd/system/sshd.service",
	"/lib/systemd/system/ssh.socket",
	"/lib/systemd/system/sshd.socket",
	"/usr/lib/systemd/system/ssh.service",
	"/usr/lib/systemd/system/sshd.service",
	"/usr/lib/systemd/system/ssh.socket",
	"/usr/lib/systemd/system/sshd.socket",
	"/usr/local/lib/systemd/system/ssh.service",
	"/usr/local/lib/systemd/system/sshd.service",
	"/usr/local/lib/systemd/system/ssh.socket",
	"/usr/local/lib/systemd/system/sshd.socket",
	"/etc/systemd/system/ssh.service.d",
	"/etc/systemd/system/sshd.service.d",
	"/etc/systemd/system/ssh.socket.d",
	"/etc/systemd/system/sshd.socket.d",
	"/run/systemd/system/ssh.service.d",
	"/run/systemd/system/sshd.service.d",
	"/run/systemd/system/ssh.socket.d",
	"/run/systemd/system/sshd.socket.d",
	"/etc/systemd/system/multi-user.target.wants/ssh.service",
	"/etc/systemd/system/multi-user.target.wants/sshd.service",
	"/etc/systemd/system/sockets.target.wants/ssh.socket",
	"/etc/systemd/system/sockets.target.wants/sshd.socket",
}

// ConfigureSSH configures the SSH daemon securely
func ConfigureSSH() error {
	fmt.Println("[INFO] Configuring SSH...")
	applicable, err := sshConfigurationApplicable(
		"/etc/ssh/sshd_config",
		config.GlobalConfig.SSHPort,
		sshDaemonSignalPaths,
		exec.LookPath,
		0,
	)
	if err != nil {
		return err
	}
	if !applicable {
		fmt.Println("[INFO] Standard OpenSSH server configuration is absent; SSH hardening is not applicable.")
		return nil
	}
	managerState, err := classifyServiceManagerRuntime(IsAlpine())
	if err != nil {
		return fmt.Errorf("classify service-manager runtime before SSH configuration: %w", err)
	}
	fmt.Println("[INFO] Ensuring SSH TCP Forwarding is strictly DISABLED...")

	executor := sshCommandExecutor{
		run: func(name string, args ...string) error {
			ctx, cancel := context.WithTimeout(context.Background(), sshCommandTimeout)
			defer cancel()
			return exec.CommandContext(ctx, name, args...).Run() // #nosec G204 -- executable and arguments are constrained by configureSSHFile
		},
		output: func(name string, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(context.Background(), sshCommandTimeout)
			defer cancel()
			return exec.CommandContext(ctx, name, args...).Output() // #nosec G204 -- executable and arguments are constrained by configureSSHFile
		},
	}
	port, err := configureSSHFile("/etc/ssh/sshd_config", config.GlobalConfig.SSHPort, 0, IsAlpine(), managerState, executor)
	if err != nil {
		return err
	}

	// Persist the detected port to memory so Nftables overlay can use it for SSH Cloaking
	config.GlobalConfig.SSHPort = port
	if managerState == serviceManagerOffline {
		fmt.Printf("[INFO] SSH Port %s validated and persisted; runtime restart is deferred to boot.\n", port)
	} else {
		fmt.Printf("[INFO] SSH Port configured as: %s\n", port)
	}
	return nil
}
