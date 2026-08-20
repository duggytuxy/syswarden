//go:build linux

package system

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type serviceManagerRunner func(name string, args ...string) error

type serviceManagerState string

const (
	serviceManagerActive    serviceManagerState = "ACTIVE"
	serviceManagerOffline   serviceManagerState = "OFFLINE"
	serviceManagerAmbiguous serviceManagerState = "AMBIGUOUS"

	openRCCoreService = `#!/sbin/openrc-run

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

	openRCFirewallService = `#!/sbin/openrc-run

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

	systemdCoreService = `[Unit]
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

	systemdFirewallService = `[Unit]
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
)

var (
	serviceSystemdRuntimePath = "/run/systemd/system"
	serviceOpenRCRuntimePath  = "/run/openrc"
	servicePackageEnvironment = os.Getenv
	serviceSystemdUnitDir     = "/etc/systemd/system"
	serviceSystemdWantsDir    = "/etc/systemd/system/multi-user.target.wants"
	serviceOpenRCUnitDir      = "/etc/init.d"
	serviceOpenRCRunlevelDir  = "/etc/runlevels/default"
)

func runServiceManagerCommand(name string, args ...string) error {
	return exec.Command(name, args...).Run() // #nosec G204 -- executable, service names and actions are fixed product constants
}

// classifyServiceManagerRuntime returns OFFLINE only for a package transaction
// with a provably absent expected manager runtime. Every malformed, conflicting,
// inaccessible, or non-package state is AMBIGUOUS and must fail closed.
func classifyServiceManagerRuntime(alpine bool) (serviceManagerState, error) {
	return classifyServiceManagerRuntimePaths(
		alpine,
		serviceSystemdRuntimePath,
		serviceOpenRCRuntimePath,
		servicePackageEnvironment,
	)
}

// ServiceManagerRuntimeState exposes the attested host-manager state to
// integration code that must persist configuration while deferring runtime
// actions during offline package installation.
func ServiceManagerRuntimeState() (string, error) {
	state, err := classifyServiceManagerRuntime(IsAlpine())
	return string(state), err
}

func classifyServiceManagerRuntimePaths(
	alpine bool,
	systemdRuntimePath string,
	openRCRuntimePath string,
	getEnvironment func(string) string,
) (serviceManagerState, error) {
	expectedPath := systemdRuntimePath
	competingPath := openRCRuntimePath
	managerName := "systemd"
	if alpine {
		expectedPath = openRCRuntimePath
		competingPath = systemdRuntimePath
		managerName = "OpenRC"
	}

	runtimeRoot := filepath.Dir(openRCRuntimePath)
	if filepath.Dir(filepath.Dir(systemdRuntimePath)) != runtimeRoot {
		return serviceManagerAmbiguous, fmt.Errorf("service-manager runtimes do not share an attested runtime root")
	}
	hostRoot := filepath.Dir(runtimeRoot)
	hostInfo, err := os.Lstat(hostRoot)
	if err != nil {
		return serviceManagerAmbiguous, fmt.Errorf("inspect service-manager host root %s: %w", hostRoot, err)
	}
	if hostInfo.Mode()&os.ModeSymlink != 0 || !hostInfo.IsDir() {
		return serviceManagerAmbiguous, fmt.Errorf("refusing unsafe service-manager host root %s", hostRoot)
	}
	hostStat, ok := hostInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return serviceManagerAmbiguous, fmt.Errorf("service-manager host root ownership is unavailable")
	}
	if err := attestRuntimeParent(runtimeRoot, hostStat.Uid, hostStat.Gid); err != nil {
		return serviceManagerAmbiguous, err
	}
	systemdParent := filepath.Dir(systemdRuntimePath)
	if systemdParent != runtimeRoot {
		if info, err := os.Lstat(systemdParent); err == nil {
			if !safeRuntimeDirectory(info, hostStat.Uid, hostStat.Gid) {
				return serviceManagerAmbiguous, fmt.Errorf("refusing unsafe systemd runtime parent %s", systemdParent)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return serviceManagerAmbiguous, fmt.Errorf("inspect systemd runtime parent %s: %w", systemdParent, err)
		}
	}
	expectedPresent, err := attestRuntimeDirectory(expectedPath, hostStat.Uid, hostStat.Gid)
	if err != nil {
		return serviceManagerAmbiguous, err
	}
	competingPresent, err := attestRuntimeDirectory(competingPath, hostStat.Uid, hostStat.Gid)
	if err != nil {
		return serviceManagerAmbiguous, err
	}
	if competingPresent {
		return serviceManagerAmbiguous, fmt.Errorf("refusing conflicting service-manager runtime %s", competingPath)
	}
	if expectedPresent {
		pid1CommPath := filepath.Join(hostRoot, "proc", "1", "comm")
		if alpine {
			if err := attestOpenRCRuntime(expectedPath, pid1CommPath, hostStat.Uid, hostStat.Gid); err != nil {
				return serviceManagerAmbiguous, err
			}
		} else if err := attestSystemdRuntime(pid1CommPath, filepath.Join(hostRoot, "proc", "1", "exe"), hostStat.Uid, hostStat.Gid); err != nil {
			return serviceManagerAmbiguous, err
		}
		return serviceManagerActive, nil
	}
	if getEnvironment("SYSWARDEN_PKG_INSTALL") == "1" {
		return serviceManagerOffline, nil
	}
	return serviceManagerAmbiguous, fmt.Errorf("%s runtime is absent outside an attested package transaction", managerName)
}

func attestRuntimeParent(path string, expectedUID, expectedGID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect service-manager runtime parent %s: %w", path, err)
	}
	if !safeRuntimeDirectory(info, expectedUID, expectedGID) {
		return fmt.Errorf("refusing unsafe service-manager runtime parent %s", path)
	}
	return nil
}

func safeRuntimeDirectory(info os.FileInfo, expectedUID, expectedGID uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode()&os.ModeSymlink == 0 && info.IsDir() &&
		info.Mode().Perm()&0022 == 0 && stat.Uid == expectedUID && stat.Gid == expectedGID
}

func attestRuntimeDirectory(path string, expectedUID, expectedGID uint32) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect service-manager runtime %s: %w", path, err)
	}
	if !safeRuntimeDirectory(info, expectedUID, expectedGID) {
		return false, fmt.Errorf("refusing unsafe service-manager runtime %s", path)
	}
	return true, nil
}

func readAttestedRuntimeFile(path string, expectedUID, expectedGID uint32, limit int64) (string, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect runtime proof %s: %w", path, err)
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
		before.Mode().Perm()&0022 != 0 || stat.Uid != expectedUID || stat.Gid != expectedGID {
		return "", fmt.Errorf("refusing unsafe runtime proof %s", path)
	}
	file, err := os.Open(path) // #nosec G304 -- fixed runtime proof paths are lstat/fstat identity attested
	if err != nil {
		return "", fmt.Errorf("open runtime proof %s: %w", path, err)
	}
	opened, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !os.SameFile(before, opened) || int64(len(content)) > limit {
		return "", fmt.Errorf("runtime proof %s changed or exceeded its limit", path)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) {
		return "", fmt.Errorf("runtime proof %s changed while reading", path)
	}
	return string(content), nil
}

func attestOpenRCRuntime(runtimePath, pid1CommPath string, expectedUID, expectedGID uint32) error {
	softlevel, err := readAttestedRuntimeFile(filepath.Join(runtimePath, "softlevel"), expectedUID, expectedGID, 64)
	if err != nil {
		return fmt.Errorf("attest OpenRC softlevel: %w", err)
	}
	softlevel = strings.TrimSuffix(softlevel, "\n")
	if softlevel == "" || strings.ContainsAny(softlevel, "\x00\r\n") {
		return fmt.Errorf("refusing invalid OpenRC softlevel")
	}
	for _, character := range softlevel {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("_.-", character) {
			return fmt.Errorf("refusing invalid OpenRC softlevel")
		}
	}
	comm, err := readAttestedRuntimeFile(pid1CommPath, expectedUID, expectedGID, 32)
	if err != nil {
		return fmt.Errorf("attest OpenRC PID 1 identity: %w", err)
	}
	if comm != "init\n" && comm != "openrc-init\n" {
		return fmt.Errorf("PID 1 identity %q is not coherent with OpenRC", strings.TrimSpace(comm))
	}
	return nil
}

func attestSystemdRuntime(pid1CommPath, pid1ExecutablePath string, expectedUID, expectedGID uint32) error {
	comm, err := readAttestedRuntimeFile(pid1CommPath, expectedUID, expectedGID, 32)
	if err != nil {
		return fmt.Errorf("attest systemd PID 1 identity: %w", err)
	}
	if comm != "systemd\n" {
		return fmt.Errorf("PID 1 identity %q is not coherent with systemd", strings.TrimSpace(comm))
	}
	before, err := os.Lstat(pid1ExecutablePath)
	if err != nil {
		return fmt.Errorf("inspect systemd PID 1 executable: %w", err)
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink == 0 || stat.Uid != expectedUID || stat.Gid != expectedGID {
		return fmt.Errorf("refusing unsafe systemd PID 1 executable proof")
	}
	target, err := os.Readlink(pid1ExecutablePath)
	if err != nil || (target != "/usr/lib/systemd/systemd" && target != "/lib/systemd/systemd") {
		return fmt.Errorf("refusing systemd PID 1 executable %q", target)
	}
	after, err := os.Lstat(pid1ExecutablePath)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return fmt.Errorf("systemd PID 1 executable proof changed while reading")
	}
	return nil
}

func activateOpenRCService(run serviceManagerRunner, service, action string) error {
	if err := run("rc-update", "add", service, "default"); err != nil {
		return fmt.Errorf("enable OpenRC service %s: %w", service, err)
	}
	if err := run("rc-service", service, action); err != nil {
		return fmt.Errorf("%s OpenRC service %s: %w", action, service, err)
	}
	return nil
}

func activateSystemdService(run serviceManagerRunner, service string, restart bool) error {
	if err := run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd before activating %s: %w", service, err)
	}
	if err := run("systemctl", "enable", "--now", service); err != nil {
		return fmt.Errorf("enable and start systemd service %s: %w", service, err)
	}
	if restart {
		if err := run("systemctl", "restart", service); err != nil {
			return fmt.Errorf("restart systemd service %s: %w", service, err)
		}
	}
	return nil
}

func ensureServiceDirectory(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("create service directory %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect service directory %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 || !serviceFileOwnedByCurrentUser(info) {
		return fmt.Errorf("refusing unsafe service directory %s", path)
	}
	return nil
}

func serviceFileOwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(stat.Uid) == int64(os.Geteuid()) && int64(stat.Gid) == int64(os.Getegid())
}

type pinnedServiceDirectory struct {
	root *os.Root
	file *os.File
	fd   int
}

func openPinnedServiceDirectory(path string) (*pinnedServiceDirectory, error) {
	if err := ensureServiceDirectory(path, 0755); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect service directory %s: %w", path, err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("pin service directory %s: %w", path, err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0) // #nosec G304 -- fixed production directories and test roots are identity attested
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("open service directory %s without following links: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		_ = root.Close()
		return nil, fmt.Errorf("pin service directory %s", path)
	}
	rootInfo, rootErr := root.Stat(".")
	fdInfo, fdErr := file.Stat()
	after, afterErr := os.Lstat(path)
	if rootErr != nil || fdErr != nil || afterErr != nil || !os.SameFile(before, rootInfo) ||
		!os.SameFile(rootInfo, fdInfo) || !os.SameFile(fdInfo, after) {
		_ = file.Close()
		_ = root.Close()
		return nil, fmt.Errorf("service directory %s changed while pinning", path)
	}
	return &pinnedServiceDirectory{root: root, file: file, fd: fd}, nil
}

func (directory *pinnedServiceDirectory) close() {
	_ = directory.file.Close()
	_ = directory.root.Close()
}

func (directory *pinnedServiceDirectory) sync() error {
	return unix.Fsync(directory.fd)
}

func readAttestedServiceFile(root *os.Root, name string, before os.FileInfo) ([]byte, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("service file changed while reading")
	}
	if len(content) > 64<<10 {
		return nil, fmt.Errorf("service file exceeds the publication limit")
	}
	after, err := root.Lstat(name)
	if err != nil || !os.SameFile(opened, after) {
		return nil, fmt.Errorf("service file changed while reading")
	}
	return content, nil
}

func publishExactServiceFile(path, content string, mode os.FileMode) (bool, error) {
	directory := filepath.Dir(path)
	pinned, err := openPinnedServiceDirectory(directory)
	if err != nil {
		return false, err
	}
	defer pinned.close()
	name := filepath.Base(path)
	if info, err := pinned.root.Lstat(name); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !serviceFileOwnedByCurrentUser(info) || info.Mode().Perm() != mode {
			return false, fmt.Errorf("refusing unsafe existing service file %s", path)
		}
		actual, readErr := readAttestedServiceFile(pinned.root, name, info)
		if readErr != nil {
			return false, fmt.Errorf("read existing service file %s: %w", path, readErr)
		}
		if string(actual) != content {
			return false, fmt.Errorf("refusing modified existing service file %s", path)
		}
		return false, pinned.sync()
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect service file %s: %w", path, err)
	}

	temporary, err := os.CreateTemp(directory, ".syswarden-service-*")
	if err != nil {
		return false, fmt.Errorf("create temporary service file for %s: %w", path, err)
	}
	temporaryPath := temporary.Name()
	keepTemporary := true
	defer func() {
		if keepTemporary {
			_ = temporary.Close()
			_ = pinned.root.Remove(filepath.Base(temporaryPath))
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return false, fmt.Errorf("set service file mode for %s: %w", path, err)
	}
	if _, err := temporary.WriteString(content); err != nil {
		return false, fmt.Errorf("write service file %s: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		return false, fmt.Errorf("sync service file %s: %w", path, err)
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("close service file %s: %w", path, err)
	}
	if err := unix.Renameat2(pinned.fd, filepath.Base(temporaryPath), pinned.fd, name, unix.RENAME_NOREPLACE); err != nil {
		return false, fmt.Errorf("publish service file %s without replacement: %w", path, err)
	}
	keepTemporary = false
	return true, pinned.sync()
}

func publishExactServiceEnablement(path, target string) (bool, error) {
	directory := filepath.Dir(path)
	pinned, err := openPinnedServiceDirectory(directory)
	if err != nil {
		return false, err
	}
	defer pinned.close()
	name := filepath.Base(path)
	if info, err := pinned.root.Lstat(name); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return false, fmt.Errorf("refusing non-symlink service enablement %s", path)
		}
		actualTarget, readErr := pinned.root.Readlink(name)
		if readErr != nil || actualTarget != target {
			return false, fmt.Errorf("refusing modified service enablement %s", path)
		}
		return false, pinned.sync()
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect service enablement %s: %w", path, err)
	}

	temporary, err := os.CreateTemp(directory, ".syswarden-enable-*")
	if err != nil {
		return false, fmt.Errorf("reserve service enablement name for %s: %w", path, err)
	}
	temporaryPath := temporary.Name()
	if closeErr := temporary.Close(); closeErr != nil {
		_ = os.Remove(temporaryPath)
		return false, fmt.Errorf("close service enablement reservation for %s: %w", path, closeErr)
	}
	temporaryName := filepath.Base(temporaryPath)
	if err := pinned.root.Remove(temporaryName); err != nil {
		return false, fmt.Errorf("remove service enablement reservation for %s: %w", path, err)
	}
	if err := pinned.root.Symlink(target, temporaryName); err != nil {
		return false, fmt.Errorf("create temporary service enablement for %s: %w", path, err)
	}
	keepTemporary := true
	defer func() {
		if keepTemporary {
			_ = pinned.root.Remove(temporaryName)
		}
	}()
	if err := unix.Renameat2(pinned.fd, temporaryName, pinned.fd, name, unix.RENAME_NOREPLACE); err != nil {
		return false, fmt.Errorf("publish service enablement %s without replacement: %w", path, err)
	}
	keepTemporary = false
	return true, pinned.sync()
}

type serviceArtifact struct {
	path    string
	content string
	target  string
	mode    os.FileMode
}

func removeCreatedServiceArtifact(artifact serviceArtifact) error {
	directory, err := openPinnedServiceDirectory(filepath.Dir(artifact.path))
	if err != nil {
		return err
	}
	defer directory.close()
	name := filepath.Base(artifact.path)
	info, err := directory.root.Lstat(name)
	if err != nil {
		return fmt.Errorf("inspect created service artifact %s during rollback: %w", artifact.path, err)
	}
	if artifact.target != "" {
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("refusing changed service enablement %s during rollback", artifact.path)
		}
		target, err := directory.root.Readlink(name)
		if err != nil || target != artifact.target {
			return fmt.Errorf("refusing changed service enablement %s during rollback", artifact.path)
		}
	} else {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
			!serviceFileOwnedByCurrentUser(info) || info.Mode().Perm() != artifact.mode {
			return fmt.Errorf("refusing changed service file %s during rollback", artifact.path)
		}
		content, err := readAttestedServiceFile(directory.root, name, info)
		if err != nil || string(content) != artifact.content {
			return fmt.Errorf("refusing changed service file %s during rollback", artifact.path)
		}
	}
	if err := directory.root.Remove(name); err != nil {
		return fmt.Errorf("remove created service artifact %s during rollback: %w", artifact.path, err)
	}
	if err := directory.sync(); err != nil {
		return fmt.Errorf("sync service artifact rollback for %s: %w", artifact.path, err)
	}
	return nil
}

func publishServiceArtifacts(artifacts []serviceArtifact) error {
	created := make([]serviceArtifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		var wasCreated bool
		var err error
		if artifact.target != "" {
			wasCreated, err = publishExactServiceEnablement(artifact.path, artifact.target)
		} else {
			wasCreated, err = publishExactServiceFile(artifact.path, artifact.content, artifact.mode)
		}
		if wasCreated {
			created = append(created, artifact)
		}
		if err == nil {
			continue
		}
		rollbackErrors := []error{err}
		for index := len(created) - 1; index >= 0; index-- {
			if rollbackErr := removeCreatedServiceArtifact(created[index]); rollbackErr != nil {
				rollbackErrors = append(rollbackErrors, rollbackErr)
			}
		}
		return errors.Join(rollbackErrors...)
	}
	return nil
}

func publishOpenRCServices() error {
	return publishServiceArtifacts([]serviceArtifact{
		{path: filepath.Join(serviceOpenRCUnitDir, "syswarden-core"), content: openRCCoreService, mode: 0755},
		{path: filepath.Join(serviceOpenRCUnitDir, "syswarden-firewall"), content: openRCFirewallService, mode: 0755},
		{path: filepath.Join(serviceOpenRCRunlevelDir, "syswarden-core"), target: "/etc/init.d/syswarden-core"},
		{path: filepath.Join(serviceOpenRCRunlevelDir, "syswarden-firewall"), target: "/etc/init.d/syswarden-firewall"},
	})
}

func publishSystemdServices() error {
	return publishServiceArtifacts([]serviceArtifact{
		{path: filepath.Join(serviceSystemdUnitDir, "syswarden-core.service"), content: systemdCoreService, mode: 0600},
		{path: filepath.Join(serviceSystemdUnitDir, "syswarden-firewall.service"), content: systemdFirewallService, mode: 0600},
		{path: filepath.Join(serviceSystemdWantsDir, "syswarden-core.service"), target: "../syswarden-core.service"},
		{path: filepath.Join(serviceSystemdWantsDir, "syswarden-firewall.service"), target: "../syswarden-firewall.service"},
	})
}

// SetupService publishes and enables the two native SysWarden services.
func SetupService() error {
	alpine := IsAlpine()
	managerState, err := classifyServiceManagerRuntime(alpine)
	if err != nil {
		return fmt.Errorf("classify service-manager runtime: %w", err)
	}
	if err := retireLegacyWebTUIService(alpine); err != nil {
		return fmt.Errorf("retire legacy Web-TUI service: %w", err)
	}
	if err := os.MkdirAll("/var/lib/syswarden/ui", 0750); err != nil {
		return fmt.Errorf("create SysWarden UI state directory: %w", err)
	}
	if err := os.MkdirAll("/var/log/syswarden", 0750); err != nil {
		return fmt.Errorf("create SysWarden log directory: %w", err)
	}

	if alpine {
		fmt.Println("[INFO] Configuring OpenRC services (Alpine Linux)...")
		if err := publishOpenRCServices(); err != nil {
			return fmt.Errorf("publish OpenRC services: %w", err)
		}
		if managerState == serviceManagerOffline {
			fmt.Println("[INFO] OpenRC runtime is offline; service start is deferred to boot.")
			return nil
		}
		if err := activateOpenRCService(runServiceManagerCommand, "syswarden-firewall", "start"); err != nil {
			return err
		}
		if err := activateOpenRCService(runServiceManagerCommand, "syswarden-core", "restart"); err != nil {
			return err
		}
		fmt.Println("[+] OpenRC orchestration complete.")
		return nil
	}

	fmt.Println("[INFO] Configuring systemd services...")
	if err := publishSystemdServices(); err != nil {
		return fmt.Errorf("publish systemd services: %w", err)
	}
	if managerState == serviceManagerOffline {
		fmt.Println("[INFO] systemd runtime is offline; service start is deferred to boot.")
		return nil
	}
	if err := activateSystemdService(runServiceManagerCommand, "syswarden-firewall.service", false); err != nil {
		return err
	}
	if err := activateSystemdService(runServiceManagerCommand, "syswarden-core.service", true); err != nil {
		return err
	}
	fmt.Println("[+] systemd orchestration complete.")
	return nil
}
