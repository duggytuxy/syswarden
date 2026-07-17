//go:build freebsd

package security

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syswarden-cli/config"
)

// ApplyOSHardening enforces OS-level access and logging restrictions natively for FreeBSD
func ApplyOSHardening() error {
	if !config.GlobalConfig.Hardening {
		return nil
	}

	fmt.Println("[INFO] Applying strict OS hardening (Crontab, Wheel, Profiles)...")

	lockCrontab()
	purgePrivilegedGroups()
	lockUserProfiles()
	applyLogAntiForging()
	restrictAuthLogs()

	return nil
}

func lockCrontab() {
	fmt.Println(" -> Locking down Crontab to root only")
	_ = os.WriteFile("/var/cron/allow", []byte("root\n"), 0600)
	_ = os.Remove("/var/cron/deny")
}

func purgePrivilegedGroups() {
	fmt.Println(" -> Purging non-root users from privileged groups")

	currentAdmin := os.Getenv("SUDO_USER")
	if currentAdmin == "" {
		if u, err := user.Current(); err == nil {
			currentAdmin = u.Username
		}
	}

	groups := []string{"wheel"}
	for _, grp := range groups {
		out, err := exec.Command("pw", "group", "show", grp).Output() // #nosec
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
						_ = exec.Command("pw", "groupmod", grp, "-d", member).Run() // #nosec
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

	baseDir := "/home"
	dirs, err := os.ReadDir(baseDir)
	if err != nil {
		baseDir = "/usr/home"
		dirs, err = os.ReadDir(baseDir)
		if err != nil {
			return
		}
	}

	for _, d := range dirs {
		if d.IsDir() {
			userName := d.Name()
			if userName == currentAdmin {
				continue
			}

			profiles := []string{".profile", ".cshrc", ".shrc", ".login", ".bashrc", ".bash_profile"}
			for _, p := range profiles {
				pPath := filepath.Join(baseDir, userName, p)
				if _, err := os.Stat(pPath); err == nil {
					_ = exec.Command("chflags", "noschg", pPath).Run() // #nosec
					_ = os.Chmod(pPath, 0600)
					_ = exec.Command("chflags", "schg", pPath).Run() // #nosec
				}
			}
		}
	}
}

func applyLogAntiForging() {
	fmt.Println(" -> Applying strict anti-forging rules to system logging daemons")

	syslogConf := "/etc/syslog.conf"
	if _, err := os.Stat(syslogConf); err == nil {
		_ = exec.Command("chflags", "schg", syslogConf).Run() // #nosec
	}
}

func restrictAuthLogs() {
	fmt.Println(" -> Restricting auth log permissions")

	logsToCheck := []string{"/var/log/auth.log", "/var/log/messages", "/var/log/security"}
	for _, authLog := range logsToCheck {
		if info, err := os.Stat(authLog); err == nil {
			mode := info.Mode().Perm()
			if mode > 0640 {
				_ = os.Chmod(authLog, 0600)
				_ = exec.Command("chown", "root:wheel", authLog).Run() // #nosec
				fmt.Printf("   [+] Hardened %s to 0640\n", authLog)
			}
		}
	}

	newsyslogConf := "/etc/newsyslog.conf"
	if _, err := os.Stat(newsyslogConf); err == nil {
		out, _ := os.ReadFile(newsyslogConf) // #nosec
		content := string(out)
		if strings.Contains(content, " 644 ") || strings.Contains(content, " 0644 ") {
			newContent := strings.ReplaceAll(content, " 644 ", " 640 ")
			newContent = strings.ReplaceAll(newContent, " 0644 ", " 0640 ")
			_ = os.WriteFile(newsyslogConf, []byte(newContent), 0600)
			fmt.Printf("   [+] Hardened log rotation configuration %s\n", newsyslogConf)
		}
	}
}
