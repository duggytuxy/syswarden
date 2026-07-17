//go:build linux

package security

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syswarden-cli/config"
	"syswarden-cli/pkg/system"
)

// ApplyOSHardening enforces OS-level access and logging restrictions natively
func ApplyOSHardening() error {
	if !config.GlobalConfig.Hardening {
		return nil
	}

	fmt.Println("[INFO] Applying strict OS hardening (Crontab, Sudo/Wheel, Profiles)...")

	lockCrontab()
	purgePrivilegedGroups()
	lockUserProfiles()
	applyLogAntiForging()
	restrictAuthLogs()

	return nil
}

func lockCrontab() {
	fmt.Println(" -> Locking down Crontab to root only")
	_ = os.WriteFile("/etc/cron.allow", []byte("root\n"), 0600)
	_ = os.Remove("/etc/cron.deny")
}

func purgePrivilegedGroups() {
	fmt.Println(" -> Purging non-root users from privileged groups")

	// Try to identify current admin to prevent locking ourselves out
	currentAdmin := os.Getenv("SUDO_USER")
	if currentAdmin == "" {
		if u, err := user.Current(); err == nil {
			currentAdmin = u.Username
		}
	}

	groups := []string{"sudo", "wheel", "adm"}
	for _, grp := range groups {
		out, err := exec.Command("grep", fmt.Sprintf("^%s:", grp), "/etc/group").Output() // #nosec
		if err == nil {
			parts := strings.Split(strings.TrimSpace(string(out)), ":")
			if len(parts) >= 4 {
				members := strings.Split(parts[3], ",")
				for _, member := range members {
					if member != "" && member != "root" {
						if member == currentAdmin {
							fmt.Printf(" [!] SAFEGUARD: Preserving current admin '%s' in '%s' group\n", member, grp)
							continue
						}
						_ = exec.Command("gpasswd", "-d", member, grp).Run() // #nosec
						fmt.Printf(" [-] Removed user '%s' from '%s' group\n", member, grp)
					}
				}
			}
		}
	}
}

func lockUserProfiles() {
	fmt.Println(" -> Locking down profiles for standard users")

	currentAdmin := os.Getenv("SUDO_USER")

	dirs, err := os.ReadDir("/home")
	if err != nil {
		return
	}

	for _, d := range dirs {
		if d.IsDir() {
			userName := d.Name()
			if userName == currentAdmin {
				continue
			}

			profiles := []string{".profile", ".bashrc", ".bash_profile"}
			for _, p := range profiles {
				pPath := filepath.Join("/home", userName, p)
				if _, err := os.Stat(pPath); err == nil {
					_ = exec.Command("chattr", "-i", pPath).Run() // #nosec
					_ = os.Chmod(pPath, 0600)
					_ = exec.Command("chattr", "+i", pPath).Run() // #nosec
				}
			}
		}
	}
}

func applyLogAntiForging() {
	fmt.Println(" -> Applying strict anti-forging rules to system logging daemons")

	// Rsyslog
	if _, err := os.Stat("/etc/rsyslog.d"); err == nil {
		content := `# --- SYSWARDEN: Anti Log Forging & CRLF Mitigation ---
$EscapeControlCharactersOnReceive on
$DropTrailingLFOnReception on
`
		err := os.WriteFile("/etc/rsyslog.d/99-syswarden-antiforging.conf", []byte(content), 0600)
		if err == nil {
			if exec.Command("rsyslogd", "-N1").Run() == nil { // #nosec
				if system.IsAlpine() {
					_ = exec.Command("rc-service", "rsyslog", "restart").Run() // #nosec
				} else {
					_ = exec.Command("systemctl", "restart", "rsyslog").Run() // #nosec
				}
			}
		}
	}

	// Journald
	journalConf := "/etc/systemd/journald.conf"
	if _, err := os.Stat(journalConf); err == nil {
		out, _ := os.ReadFile(journalConf) // #nosec
		if !strings.Contains(string(out), "ForwardToSyslog=yes") {
			_ = exec.Command("sed", "-i", "s/.*ForwardToSyslog.*/ForwardToSyslog=yes/", journalConf).Run() // #nosec
			_ = exec.Command("systemctl", "restart", "systemd-journald").Run() // #nosec
		}
	}
}

func restrictAuthLogs() {
	fmt.Println(" -> Restricting auth log permissions")

	logsToCheck := []string{"/var/log/auth.log", "/var/log/secure"}
	for _, authLog := range logsToCheck {
		if info, err := os.Stat(authLog); err == nil {
			mode := info.Mode().Perm()
			if mode > 0640 {
				_ = os.Chmod(authLog, 0600)
				if authLog == "/var/log/auth.log" {
					_ = exec.Command("chown", "root:adm", authLog).Run() // #nosec
				} else {
					_ = exec.Command("chown", "root:root", authLog).Run() // #nosec
				}
				fmt.Printf("   [+] Hardened %s to 0640\n", authLog)
			} else {
				fmt.Printf("   [✓] %s is already secure (%04o). Preserving user configuration.\n", authLog, mode)
			}
		}
	}

	logrotateConfs := map[string]string{
		"/etc/logrotate.d/rsyslog": "create 640 root adm",
		"/etc/logrotate.d/syslog":  "create 640 root root",
	}

	for conf, newRule := range logrotateConfs {
		if _, err := os.Stat(conf); err == nil {
			out, _ := os.ReadFile(conf) // #nosec
			content := string(out)
			if strings.Contains(content, "create 644") || strings.Contains(content, "create 0644") {
				_ = exec.Command("sed", "-i", fmt.Sprintf("s/create 644.*/%s/g; s/create 0644.*/%s/g", newRule, newRule), conf).Run() // #nosec
				fmt.Printf("   [+] Hardened logrotate configuration %s\n", conf)
			} else {
				fmt.Printf("   [✓] Logrotate config %s is already secure. Preserving user configuration.\n", conf)
			}
		}
	}
}
