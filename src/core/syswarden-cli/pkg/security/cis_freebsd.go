//go:build freebsd

package security

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syswarden-cli/config"
)

// ApplyCISHardening applies CIS Level 2 controls natively for FreeBSD
func ApplyCISHardening() error {
	if !config.GlobalConfig.CISL2Hardening {
		return nil
	}

	fmt.Println("[INFO] Applying CIS Level 2 System Hardening (FreeBSD)...")

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
	fmt.Println(" -> Disabling obscure filesystems and USB storage auto-mount")
	content := `# --- SYSWARDEN: CIS Level 2 Hardware/FS Hardening ---
hw.usb.no_umass="1"
`
	if _, err := os.Stat("/boot/loader.conf.local"); os.IsNotExist(err) {
		_ = os.WriteFile("/boot/loader.conf.local", []byte(content), 0600)
	} else {
		existing, _ := os.ReadFile("/boot/loader.conf.local") // #nosec
		if !strings.Contains(string(existing), "hw.usb.no_umass") {
			f, _ := os.OpenFile("/boot/loader.conf.local", os.O_APPEND|os.O_WRONLY, 0600) // #nosec
			_, _ = f.WriteString("\n" + content)
			f.Close()
		}
	}
	return nil
}

func disableUncommonProtocols() error {
	fmt.Println(" -> Disabling uncommon network protocols")
	_ = exec.Command("sysctl", "net.inet.sctp.blackhole=2").Run() // #nosec
	return nil
}

func applySysctl() error {
	fmt.Println(" -> Applying strict FreeBSD kernel parameters (CIS / Zero-Trust)")
	content := `# --- SYSWARDEN: CIS Level 2 Kernel Hardening (FreeBSD) ---
security.bsd.see_other_uids=0
security.bsd.see_other_gids=0
security.bsd.unprivileged_read_msgbuf=0
security.bsd.hardlink_check_uid=1
security.bsd.hardlink_check_gid=1
net.inet.tcp.blackhole=2
net.inet.udp.blackhole=1
net.inet.icmp.drop_redirect=1
net.inet.ip.redirect=0
net.inet.tcp.syncookies=1
net.inet.tcp.drop_synfin=1
net.inet.tcp.icmp_may_rst=0
net.inet.udp.checksum=1
`
	sysctlPath := "/etc/sysctl.conf"
	existing, _ := os.ReadFile(sysctlPath) // #nosec
	if !strings.Contains(string(existing), "SYSWARDEN: CIS") {
		f, _ := os.OpenFile(sysctlPath, os.O_APPEND|os.O_WRONLY, 0600) // #nosec
		_, _ = f.WriteString("\n" + content)
		f.Close()
	}

	params := []string{
		"security.bsd.see_other_uids=0",
		"security.bsd.see_other_gids=0",
		"security.bsd.unprivileged_read_msgbuf=0",
		"security.bsd.hardlink_check_uid=1",
		"security.bsd.hardlink_check_gid=1",
		"net.inet.tcp.blackhole=2",
		"net.inet.udp.blackhole=1",
		"net.inet.icmp.drop_redirect=1",
		"net.inet.ip.redirect=0",
		"net.inet.tcp.syncookies=1",
		"net.inet.tcp.drop_synfin=1",
		"net.inet.tcp.icmp_may_rst=0",
	}
	for _, p := range params {
		_ = exec.Command("sysctl", p).Run() // #nosec
	}

	return nil
}

func restrictCoreDumps() error {
	fmt.Println(" -> Enforcing hard limits on core dumps")

	_ = exec.Command("sysctl", "kern.coredump=0").Run() // #nosec
	_ = exec.Command("sysctl", "kern.sugid_coredump=0").Run() // #nosec

	sysctlPath := "/etc/sysctl.conf"
	existing, _ := os.ReadFile(sysctlPath) // #nosec
	if !strings.Contains(string(existing), "kern.coredump") {
		f, _ := os.OpenFile(sysctlPath, os.O_APPEND|os.O_WRONLY, 0600) // #nosec
		_, _ = f.WriteString("\nkern.coredump=0\nkern.sugid_coredump=0\n")
		f.Close()
	}

	return nil
}

func applySSHHardening() error {
	fmt.Println(" -> Applying CIS Level 2 SSH Hardening")
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
		_ = exec.Command("service", "sshd", "restart").Run() // #nosec
	}
	return err
}

func secureCronPermissions() error {
	fmt.Println(" -> Securing cron directories permissions")
	cronDirs := []string{"/var/cron/tabs", "/etc/crontab"}
	for _, dir := range cronDirs {
		if _, err := os.Stat(dir); err == nil {
			_ = os.Chmod(dir, 0600)
			_ = exec.Command("chown", "root:wheel", dir).Run() // #nosec
		}
	}
	return nil
}

func enableAutomaticSecurityUpdates() error {
	fmt.Println(" -> Configuring automatic security updates (freebsd-update)")
	crontabPath := "/etc/crontab"
	content, err := os.ReadFile(crontabPath) // #nosec
	if err == nil {
		if !strings.Contains(string(content), "freebsd-update") {
			f, _ := os.OpenFile(crontabPath, os.O_APPEND|os.O_WRONLY, 0600) // #nosec
			_, _ = f.WriteString("\n# SYSWARDEN: Automatic Security Updates\n0 3 * * * root /usr/sbin/freebsd-update cron\n")
			f.Close()
		}
	}
	return nil
}
