//go:build freebsd

package security

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syswarden-cli/config"
	"syswarden-cli/pkg/system"
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
		target, err := securityFileTargetForPath("/boot/loader.conf.local")
		if err != nil {
			return err
		}
		if err := rewriteSecurityTarget(target, []byte(content)); err != nil {
			return err
		}
	} else {
		existing, _ := os.ReadFile("/boot/loader.conf.local")
		if !strings.Contains(string(existing), "hw.usb.no_umass") {
			file, err := os.OpenFile("/boot/loader.conf.local", os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			return appendAndClose(file, "\n"+content)
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
	existing, _ := os.ReadFile("/etc/sysctl.conf")
	if !strings.Contains(string(existing), "SYSWARDEN: CIS") {
		file, err := os.OpenFile("/etc/sysctl.conf", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if err := appendAndClose(file, "\n"+content); err != nil {
			return err
		}
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

	_ = exec.Command("sysctl", "kern.coredump=0").Run()       // #nosec
	_ = exec.Command("sysctl", "kern.sugid_coredump=0").Run() // #nosec

	existing, _ := os.ReadFile("/etc/sysctl.conf")
	if !strings.Contains(string(existing), "kern.coredump") {
		file, err := os.OpenFile("/etc/sysctl.conf", os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if err := appendAndClose(file, "\nkern.coredump=0\nkern.sugid_coredump=0\n"); err != nil {
			return err
		}
	}

	return nil
}

func applySSHHardening() error {
	fmt.Println(" -> Applying CIS Level 2 SSH Hardening")
	return system.ConfigureFreeBSDSSHDirectives(map[string]string{
		"AllowTcpForwarding":  "no",
		"X11Forwarding":       "no",
		"MaxAuthTries":        "4",
		"ClientAliveInterval": "300",
		"ClientAliveCountMax": "3",
	})
}

func secureCronPermissions() error {
	fmt.Println(" -> Securing cron directories permissions")
	if _, err := os.Stat("/var/cron/tabs"); err == nil {
		const ownerTraverse = os.FileMode(0100)
		if err := os.Chmod("/var/cron/tabs", os.FileMode(0600)|ownerTraverse); err != nil {
			return err
		}
		if err := os.Chown("/var/cron/tabs", 0, 0); err != nil {
			return err
		}
	}
	if _, err := os.Stat("/etc/crontab"); err == nil {
		if err := os.Chmod("/etc/crontab", 0600); err != nil {
			return err
		}
		if err := os.Chown("/etc/crontab", 0, 0); err != nil {
			return err
		}
	}
	return nil
}

func enableAutomaticSecurityUpdates() error {
	fmt.Println(" -> Configuring automatic security updates (freebsd-update)")
	content, err := os.ReadFile("/etc/crontab")
	if err == nil {
		if !strings.Contains(string(content), "freebsd-update") {
			file, err := os.OpenFile("/etc/crontab", os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			if err := appendAndClose(file, "\n# SYSWARDEN: Automatic Security Updates\n0 3 * * * root /usr/sbin/freebsd-update cron\n"); err != nil {
				return err
			}
		}
	}
	return nil
}

func appendAndClose(file *os.File, content string) (resultErr error) {
	defer func() {
		if closeErr := file.Close(); resultErr == nil {
			resultErr = closeErr
		}
	}()
	if _, err := file.WriteString(content); err != nil {
		return err
	}
	return file.Sync()
}
