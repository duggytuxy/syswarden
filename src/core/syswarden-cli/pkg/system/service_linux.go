//go:build linux

package system

import (
	"fmt"
	"os"
	"os/exec"
)

// SetupService generates and enables the syswarden-core systemd service natively
func SetupService() error {
	if IsAlpine() {
		fmt.Println("[INFO] Configuring OpenRC Services (Alpine Linux)...")

		if err := os.MkdirAll("/var/lib/syswarden/ui", 0755); err != nil {
			fmt.Printf("[WARN] Failed to create /var/lib/syswarden/ui: %v\n", err)
		}
		if err := os.MkdirAll("/var/log/syswarden", 0755); err != nil {
			fmt.Printf("[WARN] Failed to create /var/log/syswarden: %v\n", err)
		}

		coreScript := `#!/sbin/openrc-run

name="syswarden-core"
description="SYSWARDEN WAF and Core Engine"
command="/opt/syswarden/bin/syswarden-core"
command_background=true
pidfile="/run/syswarden-core.pid"

depend() {
	need net rsyslog
}
`
		if err := os.WriteFile("/etc/init.d/syswarden-core", []byte(coreScript), 0755); err != nil {
			return fmt.Errorf("failed to write openrc service file: %w", err)
		}

		fmt.Println("[INFO] Enabling and starting SYSWARDEN Core service...")
		if err := exec.Command("rc-update", "add", "syswarden-core", "default").Run(); err != nil {
			fmt.Printf("[WARN] Failed to enable syswarden-core: %v\n", err)
		}
		if err := exec.Command("rc-service", "syswarden-core", "restart").Run(); err != nil {
			fmt.Printf("[WARN] Failed to start syswarden-core: %v\n", err)
		}

		firewallScript := `#!/sbin/openrc-run

name="syswarden-firewall"
description="SYSWARDEN Firewall Persistence & Engine Loader"

depend() {
	before syswarden-core
}

start() {
	ebegin "Loading SYSWARDEN Firewall Persistence"
	/opt/syswarden/bin/syswarden-cli reload --no-restart
	eend $?
}
`
		if err := os.WriteFile("/etc/init.d/syswarden-firewall", []byte(firewallScript), 0755); err != nil {
			return fmt.Errorf("failed to write openrc firewall file: %w", err)
		}

		fmt.Println("[INFO] Enabling SYSWARDEN Firewall Persistence...")
		if err := exec.Command("rc-update", "add", "syswarden-firewall", "default").Run(); err != nil {
			fmt.Printf("[WARN] Failed to enable syswarden-firewall: %v\n", err)
		}
		if err := exec.Command("rc-service", "syswarden-firewall", "start").Run(); err != nil {
			fmt.Printf("[WARN] Failed to start syswarden-firewall: %v\n", err)
		}

		fmt.Println("[+] OpenRC orchestration complete.")
		return nil
	}

	fmt.Println("[INFO] Configuring Systemd Services...")

	// Create required directories before systemd sandboxing to prevent NAMESPACE crashes
	if err := os.MkdirAll("/var/lib/syswarden/ui", 0755); err != nil {
		fmt.Printf("[WARN] Failed to create /var/lib/syswarden/ui: %v\n", err)
	}
	if err := os.MkdirAll("/var/log/syswarden", 0755); err != nil {
		fmt.Printf("[WARN] Failed to create /var/log/syswarden: %v\n", err)
	}

	servicePath := "/etc/systemd/system/syswarden-core.service"

	serviceContent := `[Unit]
Description=SYSWARDEN WAF and Core Engine
After=network.target rsyslog.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/opt/syswarden/bin/syswarden-core
Restart=on-failure
RestartSec=5s

# Security Hardening
ProtectSystem=full
ProtectHome=yes
NoNewPrivileges=true
PrivateTmp=true
ReadWritePaths=/var/lib/syswarden /var/log/syswarden /run /opt/syswarden /etc/syswarden/lists
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_FOWNER

[Install]
WantedBy=multi-user.target
`

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service file: %w", err)
	}

	fmt.Println("[INFO] Reloading systemd daemon...")
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		fmt.Printf("[WARN] Failed to daemon-reload: %v\n", err)
	}

	fmt.Println("[INFO] Enabling and restarting SYSWARDEN Core service...")
	if err := exec.Command("systemctl", "enable", "--now", "syswarden-core.service").Run(); err != nil {
		fmt.Printf("[WARN] Failed to enable syswarden-core.service: %v\n", err)
	}
	_ = exec.Command("systemctl", "restart", "syswarden-core.service").Run()

	firewallServicePath := "/etc/systemd/system/syswarden-firewall.service"
	firewallServiceContent := `[Unit]
Description=SYSWARDEN Firewall Persistence & Engine Loader
After=network-online.target
Wants=network-online.target
Before=syswarden-core.service

[Service]
Type=oneshot
User=root
ExecStart=/opt/syswarden/bin/syswarden-cli reload --no-restart
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile(firewallServicePath, []byte(firewallServiceContent), 0644); err != nil {
		return fmt.Errorf("failed to write syswarden-firewall.service: %w", err)
	}

	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("[INFO] Enabling SYSWARDEN Firewall Persistence...")
	if err := exec.Command("systemctl", "enable", "--now", "syswarden-firewall.service").Run(); err != nil {
		fmt.Printf("[WARN] Failed to enable/start syswarden-firewall.service: %v\n", err)
	}

	fmt.Println("[+] Systemd orchestration complete.")
	return nil
}
