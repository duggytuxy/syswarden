//go:build freebsd

package system

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"syswarden-cli/pkg/platformpaths"
)

const freeBSDSystemImmutableFlag = 0x00020000

func inactiveServiceResult(command *exec.Cmd, label string) error {
	err := command.Run()
	if err == nil {
		return fmt.Errorf("%s remains active", label)
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 1 {
		return nil
	}
	return fmt.Errorf("verify %s is inactive: %w", label, err)
}

func stopFreeBSDService(stopCommand, statusCommand *exec.Cmd, label string) error {
	_ = stopCommand.Run()
	return inactiveServiceResult(statusCommand, label)
}

func removeFreeBSDRCFlag(removeCommand *exec.Cmd, variable, label string) error {
	_ = removeCommand.Run()
	output, err := exec.Command("sysrc", "-a").Output()
	if err != nil {
		return fmt.Errorf("enumerate rc.conf variables while verifying %s removal: %w", label, err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, variable+":") ||
			strings.HasPrefix(trimmed, variable+"=") {
			return fmt.Errorf("%s remains configured", label)
		}
	}
	return nil
}

func clearFreeBSDSystemImmutable(path string) error {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil
	}
	flags := int(stat.Flags &^ freeBSDSystemImmutableFlag)
	if err := unix.Chflags(path, flags); err != nil {
		return fmt.Errorf("clear system immutable flag on %s: %w", path, err)
	}
	return nil
}

func unlockFreeBSDProfiles(baseDirectory string) error {
	entries, err := os.ReadDir(baseDirectory)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var failures []error
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		for _, profile := range []string{
			".profile", ".cshrc", ".shrc", ".login", ".bashrc", ".bash_profile",
		} {
			if err := clearFreeBSDSystemImmutable(filepath.Join(baseDirectory, entry.Name(), profile)); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func removeManagedFreeBSDCron() error {
	output, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) && exitError.ExitCode() == 1 {
			if _, statErr := os.Lstat("/var/cron/tabs/root"); errors.Is(statErr, os.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("crontab reported no entries but the root spool file still exists")
		}
		return fmt.Errorf("read root crontab: %w", err)
	}
	lines := strings.Split(string(output), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !platformpaths.IsManagedCronLine(line) {
			kept = append(kept, line)
		}
	}
	content := ""
	if len(kept) > 0 {
		content = strings.Join(kept, "\n") + "\n"
	}
	command := exec.Command("crontab", "-")
	command.Stdin = strings.NewReader(content)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("write filtered root crontab: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

func removeFreeBSDPath(path string, recursive bool) error {
	var err error
	if recursive {
		err = os.RemoveAll(path)
	} else {
		err = os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}
	if err != nil {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

// UninstallSystem restores the captured PF policy before destructive cleanup.
func UninstallSystem() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall must be executed as root")
	}

	fmt.Println("[WARN] Starting Deep Clean Uninstallation (Scorched Earth) on FreeBSD...")
	var failures []error
	if err := stopFreeBSDService(
		exec.Command("service", "syswarden", "onestop"),
		exec.Command("service", "syswarden", "onestatus"),
		"syswarden service",
	); err != nil {
		failures = append(failures, err)
	}
	if err := stopFreeBSDService(
		exec.Command("service", "syswardenwebtui", "onestop"),
		exec.Command("service", "syswardenwebtui", "onestatus"),
		"syswardenwebtui service",
	); err != nil {
		failures = append(failures, err)
	}
	if len(failures) > 0 {
		return fmt.Errorf("refusing uninstall while services may still be active: %w", errors.Join(failures...))
	}
	for _, path := range []string{
		"/usr/local/etc/rsyslog.d/99-syswarden-siem.conf",
		"/usr/local/etc/rsyslog.d/99-syswarden-waf-bridge.conf",
	} {
		if err := removeFreeBSDPath(path, false); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("refusing uninstall before generated logging fragments are safely removed: %w", errors.Join(failures...))
	}
	if err := RestoreFreeBSDPackageHostState(); err != nil {
		return fmt.Errorf("restore pre-SysWarden host state before uninstall: %w", err)
	}
	if output, err := exec.Command(
		"/usr/local/syswarden/bin/syswarden-cli",
		"package-restore-pf",
	).CombinedOutput(); err != nil {
		return fmt.Errorf("restore captured PF policy before uninstall: %s: %w", strings.TrimSpace(string(output)), err)
	}

	if err := removeFreeBSDRCFlag(
		exec.Command("sysrc", "-x", "syswarden_enable"),
		"syswarden_enable",
		"syswarden_enable",
	); err != nil {
		failures = append(failures, err)
	}
	if err := removeFreeBSDRCFlag(
		exec.Command("sysrc", "-x", "syswardenwebtui_enable"),
		"syswardenwebtui_enable",
		"syswardenwebtui_enable",
	); err != nil {
		failures = append(failures, err)
	}

	for _, baseDirectory := range []string{"/home", "/usr/home"} {
		if err := unlockFreeBSDProfiles(baseDirectory); err != nil {
			failures = append(failures, err)
		}
	}
	if err := clearFreeBSDSystemImmutable("/etc/syslog.conf"); err != nil {
		failures = append(failures, err)
	}
	if err := removeManagedFreeBSDCron(); err != nil {
		failures = append(failures, err)
	}

	for _, path := range []string{
		"/usr/local/etc/rc.d/syswarden",
		"/usr/local/etc/rc.d/syswardenwebtui",
		"/usr/local/etc/rsyslog.d/99-syswarden-siem.conf",
		"/usr/local/etc/rsyslog.d/99-syswarden-waf-bridge.conf",
		"/var/run/syswarden.sock",
		"/usr/local/etc/syswarden-auto.conf",
		"/usr/local/bin/syswarden",
		"/usr/local/bin/syswarden-tui",
	} {
		if err := removeFreeBSDPath(path, false); err != nil {
			failures = append(failures, err)
		}
	}
	for _, path := range []string{
		"/etc/syswarden",
		"/var/db/syswarden",
		"/var/lib/syswarden",
		"/var/log/syswarden",
		"/usr/local/syswarden",
	} {
		if err := removeFreeBSDPath(path, true); err != nil {
			failures = append(failures, err)
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("FreeBSD uninstall completed with unresolved cleanup errors: %w", errors.Join(failures...))
	}
	fmt.Println("[SUCCESS] Uninstallation complete. A reboot is recommended.")
	return nil
}
