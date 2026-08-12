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

		if err := os.MkdirAll("/var/lib/syswarden/ui", 0750); err != nil {
			fmt.Printf("[WARN] Failed to create /var/lib/syswarden/ui: %v\n", err)
		}
		if err := os.MkdirAll("/var/log/syswarden", 0750); err != nil {
			fmt.Printf("[WARN] Failed to create /var/log/syswarden: %v\n", err)
		}

		coreScript := `#!/sbin/openrc-run

name="syswarden-core"
description="SYSWARDEN WAF and Core Engine"
command="/opt/syswarden/bin/syswarden-core"
command_background=true
pidfile="/run/syswarden-core.pid"
retry="TERM/5/KILL/5"

depend() {
	need net rsyslog
}
`
		if err := os.WriteFile("/etc/init.d/syswarden-core", []byte(coreScript), 0600); err != nil {
			return fmt.Errorf("failed to write openrc service file: %w", err)
		}
		_ = os.Chmod("/etc/init.d/syswarden-core", 0755) // #nosec G302

		fmt.Println("[INFO] Enabling and starting SYSWARDEN Core service...")
		if err := exec.Command("rc-update", "add", "syswarden-core", "default").Run(); err != nil { // #nosec
			fmt.Printf("[WARN] Failed to enable syswarden-core: %v\n", err)
		}
		if err := exec.Command("rc-service", "syswarden-core", "restart").Run(); err != nil { // #nosec
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
		if err := os.WriteFile("/etc/init.d/syswarden-firewall", []byte(firewallScript), 0600); err != nil {
			return fmt.Errorf("failed to write openrc firewall file: %w", err)
		}
		_ = os.Chmod("/etc/init.d/syswarden-firewall", 0755) // #nosec G302

		fmt.Println("[INFO] Enabling SYSWARDEN Firewall Persistence...")
		if err := exec.Command("rc-update", "add", "syswarden-firewall", "default").Run(); err != nil { // #nosec
			fmt.Printf("[WARN] Failed to enable syswarden-firewall: %v\n", err)
		}
		if err := exec.Command("rc-service", "syswarden-firewall", "start").Run(); err != nil { // #nosec
			fmt.Printf("[WARN] Failed to start syswarden-firewall: %v\n", err)
		}

		webtuiScript := `#!/sbin/openrc-run

name="syswarden-webtui"
description="SYSWARDEN Web-TUI (WebTTY)"
command="/opt/syswarden/bin/syswarden-cli"
command_args="web-tui"
command_background=true
pidfile="/run/syswarden-webtui.pid"
retry="TERM/5/KILL/5"

depend() {
	need net
}
`
		if err := os.WriteFile("/etc/init.d/syswarden-webtui", []byte(webtuiScript), 0600); err != nil {
			return fmt.Errorf("failed to write openrc webtui file: %w", err)
		}
		_ = os.Chmod("/etc/init.d/syswarden-webtui", 0755) // #nosec G302

		fmt.Println("[INFO] Enabling SYSWARDEN Web-TUI...")
		if err := exec.Command("rc-update", "add", "syswarden-webtui", "default").Run(); err != nil { // #nosec
			fmt.Printf("[WARN] Failed to enable syswarden-webtui: %v\n", err)
		}
		if err := exec.Command("rc-service", "syswarden-webtui", "start").Run(); err != nil { // #nosec
			fmt.Printf("[WARN] Failed to start syswarden-webtui: %v\n", err)
		}

		fmt.Println("[+] OpenRC orchestration complete.")
		return nil
	}

	fmt.Println("[INFO] Configuring Systemd Services...")

	// Create required directories before systemd sandboxing to prevent NAMESPACE crashes
	if err := os.MkdirAll("/var/lib/syswarden/ui", 0750); err != nil {
		fmt.Printf("[WARN] Failed to create /var/lib/syswarden/ui: %v\n", err)
	}
	if err := os.MkdirAll("/var/log/syswarden", 0750); err != nil {
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
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
NoNewPrivileges=true
PrivateTmp=true
ReadWritePaths=/var/lib/syswarden /var/log/syswarden /run /opt/syswarden /etc/syswarden/lists
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_FOWNER

[Install]
WantedBy=multi-user.target
`

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0600); err != nil {
		return fmt.Errorf("failed to write systemd service file: %w", err)
	}

	fmt.Println("[INFO] Reloading systemd daemon...")
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil { // #nosec
		fmt.Printf("[WARN] Failed to daemon-reload: %v\n", err)
	}

	fmt.Println("[INFO] Enabling and restarting SYSWARDEN Core service...")
	if err := exec.Command("systemctl", "enable", "--now", "syswarden-core.service").Run(); err != nil { // #nosec
		fmt.Printf("[WARN] Failed to enable syswarden-core.service: %v\n", err)
	}
	_ = exec.Command("systemctl", "restart", "syswarden-core.service").Run() // #nosec

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
	if err := os.WriteFile(firewallServicePath, []byte(firewallServiceContent), 0600); err != nil {
		return fmt.Errorf("failed to write syswarden-firewall.service: %w", err)
	}

	_ = exec.Command("systemctl", "daemon-reload").Run() // #nosec
	fmt.Println("[INFO] Enabling SYSWARDEN Firewall Persistence...")
	if err := exec.Command("systemctl", "enable", "--now", "syswarden-firewall.service").Run(); err != nil { // #nosec
		fmt.Printf("[WARN] Failed to enable/start syswarden-firewall.service: %v\n", err)
	}

	webTuiServicePath := "/etc/systemd/system/syswarden-webtui.service"
	webTuiServiceContent := `[Unit]
Description=SYSWARDEN Web-TUI (WebTTY)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/opt/syswarden/bin/syswarden-cli web-tui
Restart=on-failure
RestartSec=5s

# Security Hardening
ProtectSystem=full
ProtectHome=yes
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile(webTuiServicePath, []byte(webTuiServiceContent), 0600); err != nil {
		return fmt.Errorf("failed to write syswarden-webtui.service: %w", err)
	}

	fmt.Println("[INFO] Enabling SYSWARDEN Web-TUI Service...")
	_ = exec.Command("systemctl", "daemon-reload").Run()                                                   // #nosec
	if err := exec.Command("systemctl", "enable", "--now", "syswarden-webtui.service").Run(); err != nil { // #nosec
		fmt.Printf("[WARN] Failed to enable/start syswarden-webtui.service: %v\n", err)
	}

	fmt.Println("[+] Systemd orchestration complete.")
	return nil
}
