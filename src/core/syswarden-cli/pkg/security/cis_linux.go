//go:build linux

package security

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syswarden-cli/config"
)

// ApplyCISHardening applies CIS Level 2 controls natively
func ApplyCISHardening() error {
	if !config.GlobalConfig.CISL2Hardening {
		return nil
	}

	fmt.Println("[INFO] Applying CIS Level 2 System Hardening...")

	if err := disableObscureFilesystems(); err != nil {
		fmt.Printf("[WARN] Failed to disable obscure filesystems: %v\n", err)
	}

	if err := disableUncommonProtocols(); err != nil {
		fmt.Printf("[WARN] Failed to disable uncommon protocols: %v\n", err)
	}

	if err := applySysctl(); err != nil {
		fmt.Printf("[WARN] Failed to apply sysctl parameters: %v\n", err)
	}

	if err := restrictCoreDumps(); err != nil {
		fmt.Printf("[WARN] Failed to restrict core dumps: %v\n", err)
	}

	if err := applySSHHardening(); err != nil {
		fmt.Printf("[WARN] Failed to apply CIS SSH hardening: %v\n", err)
	}

	if err := secureCronPermissions(); err != nil {
		fmt.Printf("[WARN] Failed to secure cron permissions: %v\n", err)
	}

	if err := enableAutomaticSecurityUpdates(); err != nil {
		fmt.Printf("[WARN] Failed to configure automatic security updates: %v\n", err)
	}

	return nil
}

func disableObscureFilesystems() error {
	fmt.Println(" -> Disabling obscure filesystems (CIS 1.1.1.1 - 1.1.1.8)")
	content := `# --- SYSWARDEN: CIS Level 2 Filesystem Hardening ---
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
`
	if err := os.WriteFile("/etc/modprobe.d/syswarden-cis-fs.conf", []byte(content), 0600); err != nil {
		return err
	}

	fsList := []string{"cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf"}
	for _, fs := range fsList {
		_ = exec.Command("rmmod", fs).Run() // #nosec
	}
	return nil
}

func disableUncommonProtocols() error {
	fmt.Println(" -> Disabling uncommon network protocols (CIS 3.3.1 - 3.3.4)")
	content := `# --- SYSWARDEN: CIS Level 2 Network Protocol Hardening ---
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
`
	if err := os.WriteFile("/etc/modprobe.d/syswarden-cis-net.conf", []byte(content), 0600); err != nil {
		return err
	}

	protoList := []string{"dccp", "sctp", "rds", "tipc"}
	for _, proto := range protoList {
		_ = exec.Command("rmmod", proto).Run() // #nosec
	}
	return nil
}

func applySysctl() error {
	fmt.Println(" -> Applying strict kernel parameters (CIS 1.5, 3.2)")
	content := `# --- SYSWARDEN: CIS Level 2 Kernel Hardening ---
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
`
	if err := os.WriteFile("/etc/sysctl.d/99-syswarden-cis-level2.conf", []byte(content), 0600); err != nil {
		return err
	}
	_ = exec.Command("sysctl", "-p", "/etc/sysctl.d/99-syswarden-cis-level2.conf").Run() // #nosec
	return nil
}

func restrictCoreDumps() error {
	fmt.Println(" -> Enforcing hard limits on core dumps (CIS 1.5.1)")
	_ = os.MkdirAll("/etc/security/limits.d", 0750)

	limitsContent := "# --- SYSWARDEN: CIS Level 2 Limits ---\n* hard core 0\n"
	if err := os.WriteFile("/etc/security/limits.d/99-syswarden-cis.conf", []byte(limitsContent), 0600); err != nil {
		return err
	}

	// systemd override
	if _, err := os.Stat("/etc/systemd/coredump.conf"); err == nil {
		_ = exec.Command("sed", "-i", "s/.*Storage=.*/Storage=none/", "/etc/systemd/coredump.conf").Run() // #nosec
		_ = exec.Command("sed", "-i", "s/.*ProcessSizeMax=.*/ProcessSizeMax=0/", "/etc/systemd/coredump.conf").Run() // #nosec
		_ = exec.Command("systemctl", "daemon-reload").Run() // #nosec
	}
	return nil
}

func applySSHHardening() error {
	fmt.Println(" -> Applying CIS Level 2 SSH Hardening (CIS 5.2)")
	sshConf := "/etc/ssh/sshd_config"
	if _, err := os.Stat(sshConf); err != nil {
		return nil
	}

	content, err := os.ReadFile(sshConf) // #nosec
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	configMap := map[string]string{
		"X11Forwarding":       "no",
		"MaxAuthTries":        "4",
		"ClientAliveInterval": "300",
		"ClientAliveCountMax": "3",
	}

	var newLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		skip := false
		for k := range configMap {
			if strings.HasPrefix(trimmed, k) {
				skip = true
				break
			}
		}
		if !skip {
			newLines = append(newLines, line)
		}
	}

	for k, v := range configMap {
		newLines = append(newLines, fmt.Sprintf("%s %s", k, v))
	}

	err = os.WriteFile(sshConf, []byte(strings.Join(newLines, "\n")), 0600)
	if err == nil {
		_ = exec.Command("systemctl", "restart", "sshd").Run() // #nosec
	}
	return err
}

func secureCronPermissions() error {
	fmt.Println(" -> Securing cron directories permissions (CIS 5.1)")
	cronDirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"}
	for _, dir := range cronDirs {
		if _, err := os.Stat(dir); err == nil {
			_ = os.Chmod(dir, 0700)
			_ = os.Chown(dir, 0, 0)
		}
	}
	if _, err := os.Stat("/etc/crontab"); err == nil {
		_ = os.Chmod("/etc/crontab", 0600)
		_ = os.Chown("/etc/crontab", 0, 0)
	}
	return nil
}

func enableAutomaticSecurityUpdates() error {
	fmt.Println(" -> Configuring automatic security updates (Zero-Day defense)")
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		_ = exec.Command("apt-get", "install", "-y", "-q", "unattended-upgrades", "apt-listchanges").Run() // #nosec
		aptConf := "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
		_ = os.WriteFile("/etc/apt/apt.conf.d/20auto-upgrades", []byte(aptConf), 0600)
		_ = exec.Command("systemctl", "enable", "unattended-upgrades").Run() // #nosec
		_ = exec.Command("systemctl", "start", "unattended-upgrades").Run() // #nosec
	} else if _, err := os.Stat("/etc/redhat-release"); err == nil {
		_ = exec.Command("dnf", "install", "-y", "-q", "dnf-automatic").Run() // #nosec
		conf := "/etc/dnf/automatic.conf"
		if _, err := os.Stat(conf); err == nil {
			_ = exec.Command("sed", "-i", "s/^[[:space:]]*upgrade_type[[:space:]]*=.*/upgrade_type = security/", conf).Run() // #nosec
			_ = exec.Command("sed", "-i", "s/^[[:space:]]*download_updates[[:space:]]*=.*/download_updates = yes/", conf).Run() // #nosec
			_ = exec.Command("sed", "-i", "s/^[[:space:]]*apply_updates[[:space:]]*=.*/apply_updates = yes/", conf).Run() // #nosec
		}
		_ = exec.Command("systemctl", "enable", "dnf-automatic.timer").Run() // #nosec
		_ = exec.Command("systemctl", "start", "dnf-automatic.timer").Run() // #nosec
	}
	return nil
}
