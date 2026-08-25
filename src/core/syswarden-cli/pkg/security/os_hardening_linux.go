//go:build linux

package security

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"syswarden-cli/config"

	"golang.org/x/sys/unix"
)

// ApplyOSHardening enforces OS-level access and logging restrictions natively.
func ApplyOSHardening() error {
	if !config.GlobalConfig.Hardening {
		return nil
	}

	fmt.Println("[INFO] Applying strict OS hardening (Crontab, Sudo/Wheel, Profiles)...")
	host := productionHardeningHost()
	return runHardeningStages([]hardeningStage{
		{name: "lock crontab", run: func() error { return lockCrontabOn(host) }},
		{name: "purge privileged groups", run: func() error { return purgePrivilegedGroupsOn(host) }},
		{name: "lock user profiles", run: func() error { return lockUserProfilesOn(host) }},
		{name: "apply log anti-forging", run: func() error { return applyLogAntiForgingOn(host) }},
		{name: "restrict authentication logs", run: func() error { return restrictAuthLogsOn(host) }},
	})
}

func lockCrontabOn(host hardeningHost) error {
	fmt.Println(" -> Locking down Crontab to root only")
	if err := host.write("/etc/cron.allow", []byte("root\n"), 0600); err != nil {
		return err
	}
	if err := host.removeRegular("/etc/cron.deny"); err != nil {
		return fmt.Errorf("remove cron.deny: %w", err)
	}
	return nil
}

func purgePrivilegedGroupsOn(host hardeningHost) error {
	fmt.Println(" -> Purging non-root users from privileged groups")
	currentAdmin := os.Getenv("SUDO_USER")
	if currentAdmin == "" {
		current, err := user.Current()
		if err != nil {
			return fmt.Errorf("identify current administrator: %w", err)
		}
		currentAdmin = current.Username
	}

	snapshot, err := host.snapshot("/etc/group")
	if err != nil {
		return err
	}
	if !snapshot.existed {
		return fmt.Errorf("group database is absent")
	}
	groups, err := parseGroupMembership(snapshot.content)
	if err != nil {
		return err
	}
	for _, group := range []string{"sudo", "wheel", "adm"} {
		for _, member := range groups[group] {
			if member == "" || member == "root" {
				continue
			}
			if member == currentAdmin {
				fmt.Printf(" [!] SAFEGUARD: Preserving current admin '%s' in '%s' group\n", member, group)
				continue
			}
			if err := host.executor.run("gpasswd", "-d", member, group); err != nil {
				return fmt.Errorf("remove %s from %s: %w", member, group, err)
			}
			current, err := host.snapshot("/etc/group")
			if err != nil {
				return fmt.Errorf("reinspect group database: %w", err)
			}
			currentGroups, err := parseGroupMembership(current.content)
			if err != nil {
				return err
			}
			if containsString(currentGroups[group], member) {
				return fmt.Errorf("user %s remains in privileged group %s", member, group)
			}
			fmt.Printf(" [-] Removed user '%s' from '%s' group\n", member, group)
		}
	}
	return nil
}

func parseGroupMembership(content []byte) (map[string][]string, error) {
	groups := make(map[string][]string)
	for lineNumber, raw := range strings.Split(string(content), "\n") {
		if raw == "" {
			continue
		}
		parts := strings.Split(raw, ":")
		if len(parts) != 4 || parts[0] == "" {
			return nil, fmt.Errorf("malformed group database line %d", lineNumber+1)
		}
		if parts[3] == "" {
			groups[parts[0]] = nil
			continue
		}
		members := strings.Split(parts[3], ",")
		for _, member := range members {
			if member == "" || strings.TrimSpace(member) != member {
				return nil, fmt.Errorf("malformed member list for group %s", parts[0])
			}
		}
		groups[parts[0]] = members
	}
	return groups, nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

const linuxImmutableFileFlag = 0x10

const profileFileModeMask = fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky

func productionProfileFlags(file *os.File) (int, error) {
	return unix.IoctlGetInt(int(file.Fd()), unix.FS_IOC_GETFLAGS)
}

func productionSetProfileFlags(file *os.File, flags int) error {
	return unix.IoctlSetPointerInt(int(file.Fd()), unix.FS_IOC_SETFLAGS, flags)
}

type profileFileTransaction struct {
	logical  string
	target   securityFileTarget
	root     *os.Root
	file     *os.File
	identity securityFileIdentity
	mode     fs.FileMode
	uid      int
	gid      int
}

func (host hardeningHost) openProfileFileTransaction(logical string) (*profileFileTransaction, error) {
	target, err := host.target(logical, false)
	if err != nil {
		return nil, err
	}
	root, err := openSecurityDirectory(target)
	if err != nil {
		return nil, err
	}
	pathInfo, err := root.Lstat(target.name)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		_ = root.Close()
		return nil, fmt.Errorf("profile is not a regular file: %s", logical)
	}
	pathStat, ok := pathInfo.Sys().(*syscall.Stat_t)
	if !ok || pathStat.Nlink != 1 {
		_ = root.Close()
		return nil, fmt.Errorf("profile must have exactly one link: %s", logical)
	}
	file, err := root.OpenFile(target.name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("open profile %s: %w", logical, err)
	}
	opened, digest, err := snapshotSecurityFile(file)
	if err != nil || !os.SameFile(pathInfo, opened) {
		_ = file.Close()
		_ = root.Close()
		return nil, fmt.Errorf("profile changed while opening: %s", logical)
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		_ = file.Close()
		_ = root.Close()
		return nil, fmt.Errorf("profile ownership or link count is unavailable: %s", logical)
	}
	identity := securityFileIdentity{
		info:       opened,
		digest:     digest,
		uid:        int(stat.Uid),
		gid:        int(stat.Gid),
		ownerKnown: true,
	}
	return &profileFileTransaction{
		logical: logical, target: target, root: root, file: file, identity: identity,
		mode: opened.Mode() & profileFileModeMask, uid: int(stat.Uid), gid: int(stat.Gid),
	}, nil
}

func (transaction *profileFileTransaction) close() {
	if transaction.file != nil {
		_ = transaction.file.Close()
	}
	if transaction.root != nil {
		_ = transaction.root.Close()
	}
}

func (host hardeningHost) profileFlags(file *os.File) (int, error) {
	if host.profileFlagsProbe == nil {
		return 0, fmt.Errorf("profile attribute probe is unavailable")
	}
	return host.profileFlagsProbe(file)
}

func (host hardeningHost) setProfileFlags(file *os.File, flags int) error {
	if host.profileFlagsSet == nil {
		return fmt.Errorf("profile attribute mutation is unavailable")
	}
	return host.profileFlagsSet(file, flags)
}

func (transaction *profileFileTransaction) attest(host hardeningHost, mode fs.FileMode, flags *int) error {
	opened, err := transaction.file.Stat()
	if err != nil {
		return fmt.Errorf("attest open profile %s: %w", transaction.logical, err)
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || opened.Mode()&profileFileModeMask != mode&profileFileModeMask ||
		int(stat.Uid) != transaction.uid || int(stat.Gid) != transaction.gid {
		return fmt.Errorf("profile mode, ownership, or link attestation failed: %s", transaction.logical)
	}
	current, exists, err := inspectSecurityDestination(transaction.root, transaction.target)
	if err != nil {
		return fmt.Errorf("reinspect profile path %s: %w", transaction.logical, err)
	}
	if !exists || !os.SameFile(transaction.identity.info, current.info) || current.digest != transaction.identity.digest ||
		!current.ownerKnown || current.uid != transaction.uid || current.gid != transaction.gid ||
		current.info.Mode()&profileFileModeMask != mode&profileFileModeMask {
		return fmt.Errorf("profile path or content changed during hardening: %s", transaction.logical)
	}
	currentStat, ok := current.info.Sys().(*syscall.Stat_t)
	if !ok || currentStat.Nlink != 1 {
		return fmt.Errorf("profile link attestation failed: %s", transaction.logical)
	}
	if flags != nil {
		actual, err := host.profileFlags(transaction.file)
		if err != nil {
			return fmt.Errorf("attest profile flags on %s: %w", transaction.logical, err)
		}
		if actual != *flags {
			return fmt.Errorf("profile flag attestation failed for %s", transaction.logical)
		}
	}
	return nil
}

func restoreProfileTransaction(host hardeningHost, transaction *profileFileTransaction, flags *int) error {
	var failures []error
	if flags != nil {
		if err := host.setProfileFlags(transaction.file, *flags&^linuxImmutableFileFlag); err != nil {
			failures = append(failures, fmt.Errorf("clear immutable flag during rollback for %s: %w", transaction.logical, err))
		}
	}
	if err := transaction.file.Chown(transaction.uid, transaction.gid); err != nil {
		failures = append(failures, fmt.Errorf("restore profile ownership for %s: %w", transaction.logical, err))
	}
	if host.profileChmod == nil {
		failures = append(failures, fmt.Errorf("profile chmod operation is unavailable"))
	} else if err := host.profileChmod(transaction.file, transaction.mode); err != nil {
		failures = append(failures, fmt.Errorf("restore profile mode for %s: %w", transaction.logical, err))
	}
	if flags != nil {
		if err := host.setProfileFlags(transaction.file, *flags); err != nil {
			failures = append(failures, fmt.Errorf("restore profile flags for %s: %w", transaction.logical, err))
		}
	}
	if err := transaction.attest(host, transaction.mode, flags); err != nil {
		failures = append(failures, fmt.Errorf("attest profile rollback: %w", err))
	}
	return errors.Join(failures...)
}

func hardenProfileFile(host hardeningHost, logical string, immutableApplicable bool) error {
	transaction, err := host.openProfileFileTransaction(logical)
	if err != nil {
		return err
	}
	defer transaction.close()
	if !immutableApplicable {
		if host.profileChmod == nil {
			return fmt.Errorf("profile chmod operation is unavailable")
		}
		if err := host.profileChmod(transaction.file, 0600); err != nil {
			return errors.Join(fmt.Errorf("restrict profile mode on %s: %w", logical, err), restoreProfileTransaction(host, transaction, nil))
		}
		if err := transaction.attest(host, 0600, nil); err != nil {
			return errors.Join(err, restoreProfileTransaction(host, transaction, nil))
		}
		return nil
	}
	initialFlags, err := host.profileFlags(transaction.file)
	if err != nil {
		return fmt.Errorf("snapshot profile flags on %s: %w", logical, err)
	}
	rollback := func(cause error) error {
		return errors.Join(cause, restoreProfileTransaction(host, transaction, &initialFlags))
	}
	mutableFlags := initialFlags &^ linuxImmutableFileFlag
	if initialFlags&linuxImmutableFileFlag != 0 {
		if err := host.setProfileFlags(transaction.file, mutableFlags); err != nil {
			return rollback(fmt.Errorf("clear immutable profile flag on %s: %w", logical, err))
		}
	}
	if host.profileChmod == nil {
		return rollback(fmt.Errorf("profile chmod operation is unavailable"))
	}
	if err := host.profileChmod(transaction.file, 0600); err != nil {
		return rollback(fmt.Errorf("restrict profile mode on %s: %w", logical, err))
	}
	if err := transaction.attest(host, 0600, &mutableFlags); err != nil {
		return rollback(err)
	}
	hardenedFlags := mutableFlags | linuxImmutableFileFlag
	if err := host.setProfileFlags(transaction.file, hardenedFlags); err != nil {
		return rollback(fmt.Errorf("set immutable profile flag on %s: %w", logical, err))
	}
	if err := transaction.attest(host, 0600, &hardenedFlags); err != nil {
		return rollback(err)
	}
	return nil
}

func lockUserProfilesOn(host hardeningHost) error {
	fmt.Println(" -> Locking down profiles for standard users")
	decision, err := host.executionDecision()
	if err != nil {
		return fmt.Errorf("classify immutable-profile execution context: %w", err)
	}
	immutableNotApplicable := false
	if decision.rootUIDRemapped {
		capable, err := host.hasEffectiveCapability(9) // CAP_LINUX_IMMUTABLE
		if err != nil {
			return err
		}
		immutableNotApplicable = !capable
	}
	homeExists, err := host.directoryExists("/home")
	if err != nil {
		return err
	}
	if !homeExists {
		return nil
	}
	homePath, err := host.path("/home")
	if err != nil {
		return err
	}
	directories, err := os.ReadDir(homePath)
	if err != nil {
		return fmt.Errorf("read home directory: %w", err)
	}
	currentAdmin := os.Getenv("SUDO_USER")
	reportedImmutableNotApplicable := false
	for _, directory := range directories {
		if !directory.IsDir() || directory.Type()&os.ModeSymlink != 0 || directory.Name() == currentAdmin {
			continue
		}
		userHome := filepath.Join("/home", directory.Name())
		realDirectory, err := host.directoryExists(userHome)
		if err != nil {
			return err
		}
		if !realDirectory {
			continue
		}
		for _, profile := range []string{".profile", ".bashrc", ".bash_profile"} {
			logical := filepath.Join(userHome, profile)
			snapshot, err := host.snapshot(logical)
			if err != nil {
				return err
			}
			if !snapshot.existed {
				continue
			}
			if err := hardenProfileFile(host, logical, !immutableNotApplicable); err != nil {
				return err
			}
			if immutableNotApplicable {
				if !reportedImmutableNotApplicable {
					fmt.Println(" -> Immutable profile flags are not applicable: root UID is remapped and CAP_LINUX_IMMUTABLE is absent. Profile modes were written and attested; no immutable flag was claimed.")
					reportedImmutableNotApplicable = true
				}
			}
		}
	}
	return nil
}

func applyLogAntiForgingOn(host hardeningHost) error {
	fmt.Println(" -> Applying strict anti-forging rules to system logging daemons")
	decision, err := host.executionDecision()
	if err != nil {
		return fmt.Errorf("classify logging service execution context: %w", err)
	}
	deferredRestart := decision.state == hardeningExecutionNotApplicable && decision.packageInstall && decision.manager == ""
	if decision.state == hardeningExecutionDeferred {
		return fmt.Errorf("logging service activation cannot be deferred without a verified offline policy path")
	}
	var failures []error
	applied := false
	rsyslog, err := host.directoryExists("/etc/rsyslog.d")
	if err != nil {
		failures = append(failures, err)
	} else if rsyslog {
		applied = true
		content := []byte("# --- SYSWARDEN: Anti Log Forging & CRLF Mitigation ---\n$EscapeControlCharactersOnReceive on\n$DropTrailingLFOnReception on\n")
		logical := "/etc/rsyslog.d/99-syswarden-antiforging.conf"
		reconcile := func() error { return reconcileRsyslogService(host) }
		validate := func() error { return host.executor.run("rsyslogd", "-N1") }
		var applyErr error
		if deferredRestart {
			running, err := host.processNamedRunning("rsyslogd")
			if err != nil {
				applyErr = fmt.Errorf("prove rsyslog is stopped before offline configuration: %w", err)
			} else if running {
				applyErr = fmt.Errorf("rsyslog is running without an attested init manager")
			} else {
				snapshot, err := host.snapshot(logical)
				if err != nil {
					applyErr = err
				} else if err := host.applyManagedFileFromSnapshot(logical, snapshot, content, validate, nil); err != nil {
					applyErr = err
				} else {
					running, probeErr := host.processNamedRunning("rsyslogd")
					if probeErr != nil || running {
						cause := probeErr
						if cause == nil {
							cause = fmt.Errorf("rsyslog started during offline configuration")
						}
						applyErr = errors.Join(cause, host.restore(logical, snapshot, content))
					} else {
						fmt.Println(" -> Rsyslog anti-forging policy was written, validated, and attested. Service activation is deferred until the next rsyslog start; no current activation is claimed.")
					}
				}
			}
		} else {
			applyErr = host.applyManagedFile(logical, content, validate, reconcile)
		}
		if applyErr != nil {
			failures = append(failures, fmt.Errorf("configure rsyslog anti-forging: %w", applyErr))
		}
	}

	systemdInstalled, systemdActive, err := host.systemdPolicyRuntime(decision)
	if err != nil {
		failures = append(failures, fmt.Errorf("classify journald policy surface: %w", err))
	} else if systemdInstalled {
		applied = true
		content := []byte("[Journal]\nForwardToSyslog=yes\n")
		logical := "/etc/systemd/journald.conf.d/99-syswarden.conf"
		validate := func() error {
			output, err := host.executor.output("systemd-analyze", "cat-config", "systemd/journald.conf")
			if err != nil {
				return err
			}
			if value := lastAssignments(string(output), "ForwardToSyslog")["forwardtosyslog"]; !strings.EqualFold(value, "yes") {
				return fmt.Errorf("effective ForwardToSyslog=%q, want yes", value)
			}
			return nil
		}
		var applyErr error
		if !systemdActive {
			running, probeErr := host.processNamedRunning("systemd-journald")
			if probeErr != nil {
				applyErr = fmt.Errorf("prove journald is stopped before offline configuration: %w", probeErr)
			} else if running {
				applyErr = fmt.Errorf("systemd-journald is running without an attested systemd manager")
			} else {
				parentErr := host.ensureHardeningPolicyParent(logical, 0750)
				var snapshot hardeningFileSnapshot
				var snapshotErr error
				if parentErr == nil {
					snapshot, snapshotErr = host.snapshot(logical)
				} else {
					snapshotErr = parentErr
				}
				if snapshotErr != nil {
					applyErr = snapshotErr
				} else if err := host.applyManagedFileFromSnapshot(logical, snapshot, content, validate, nil); err != nil {
					applyErr = err
				} else {
					running, probeErr = host.processNamedRunning("systemd-journald")
					if probeErr != nil || running {
						cause := probeErr
						if cause == nil {
							cause = fmt.Errorf("systemd-journald started during offline configuration")
						}
						applyErr = errors.Join(cause, host.restore(logical, snapshot, content))
					} else {
						fmt.Println(" -> Journald anti-forging policy was written, validated, and attested for the installed consumer. No current runtime activation is claimed.")
					}
				}
			}
		} else {
			applyErr = host.applyManagedFile(logical, content, validate, func() error {
				return host.executor.run("systemctl", "restart", "systemd-journald.service")
			})
		}
		if applyErr != nil {
			failures = append(failures, fmt.Errorf("configure journald anti-forging: %w", applyErr))
		}
	}
	if !applied {
		failures = append(failures, fmt.Errorf("no supported logging daemon configuration was detected"))
	}
	return errors.Join(failures...)
}

func reconcileRsyslogService(host hardeningHost) error {
	alpine, err := host.markerExists("/etc/alpine-release")
	if err != nil {
		return err
	}
	if alpine {
		return host.executor.run("rc-service", "rsyslog", "restart")
	}
	const unit = "rsyslog.service"
	if err := host.executor.run("systemctl", "reload-or-restart", unit); err != nil {
		return fmt.Errorf("reload or start systemd service %s: %w", unit, err)
	}
	if err := host.executor.run("systemctl", "is-active", "--quiet", unit); err != nil {
		return fmt.Errorf("attest reconciled systemd service %s is active: %w", unit, err)
	}
	return nil
}

func restrictAuthLogsOn(host hardeningHost) error {
	fmt.Println(" -> Restricting auth log permissions")
	for _, entry := range []struct {
		path  string
		group string
	}{{path: "/var/log/auth.log", group: "adm"}, {path: "/var/log/secure", group: "root"}} {
		exists, err := host.regularFileExists(entry.path)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		gid, err := lookupGroupID(entry.group)
		if err != nil {
			return fmt.Errorf("resolve group %s: %w", entry.group, err)
		}
		if _, err := host.securePathPermissions(entry.path, false, 0640, 0, gid); err != nil {
			return err
		}
		fmt.Printf("   [+] Hardened %s to 0640\n", entry.path)
	}

	for _, entry := range []struct {
		path string
		rule string
	}{{path: "/etc/logrotate.d/rsyslog", rule: "create 0640 root adm"}, {path: "/etc/logrotate.d/syslog", rule: "create 0640 root root"}} {
		snapshot, err := host.snapshot(entry.path)
		if err != nil {
			return err
		}
		if !snapshot.existed {
			continue
		}
		content, changed, err := hardenLogrotateCreateRules(snapshot.content, entry.rule)
		if err != nil {
			return fmt.Errorf("harden %s: %w", entry.path, err)
		}
		if !changed {
			continue
		}
		if err := host.writeExpected(entry.path, content, 0600, snapshot); err != nil {
			return err
		}
		fmt.Printf("   [+] Hardened logrotate configuration %s\n", entry.path)
	}
	return nil
}

func lookupGroupID(name string) (int, error) {
	group, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return parseNumericID(group.Gid)
}

func hardenLogrotateCreateRules(input []byte, replacement string) ([]byte, bool, error) {
	lines := strings.Split(string(input), "\n")
	changed := false
	for index, raw := range lines {
		fields := strings.Fields(raw)
		if len(fields) < 2 || fields[0] != "create" {
			continue
		}
		mode, err := strconv.ParseUint(fields[1], 8, 12)
		if err != nil {
			return nil, false, fmt.Errorf("invalid logrotate create mode %q", fields[1])
		}
		if mode&0137 == 0 {
			continue
		}
		indent := raw[:len(raw)-len(strings.TrimLeft(raw, " \t"))]
		lines[index] = indent + replacement
		changed = true
	}
	return []byte(strings.Join(lines, "\n")), changed, nil
}
