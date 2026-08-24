//go:build linux

package system

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	need net rsyslog syswarden-firewall
}
`

	historicalV4028OpenRCCoreService = `#!/sbin/openrc-run

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
	historicalV4028OpenRCCoreServiceLength = 242
	historicalV4028OpenRCCoreServiceSHA256 = "89965a9e7d2784bc7e3119966e2564e17c5ec915dc2396986a98fe6ccfcb6247"

	openRCFirewallService = `#!/sbin/openrc-run

name="syswarden-firewall"
description="SYSWARDEN Firewall Persistence & Engine Loader"

depend() {
	need net rsyslog cronie
	before syswarden-core
}

start() {
	ebegin "Loading SYSWARDEN Firewall Persistence"
	/opt/syswarden/bin/syswarden-cli reload --no-restart
	eend $?
}
`
	historicalV4028OpenRCFirewallService = `#!/sbin/openrc-run

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
	historicalV4028OpenRCFirewallServiceLength = 269
	historicalV4028OpenRCFirewallServiceSHA256 = "82a936e4f9ce394d6cc0ffd3978a1842a899570842ab5d283184384e73af5905"

	systemdCoreService = `[Unit]
Description=SYSWARDEN WAF and Core Engine
Requires=syswarden-firewall.service
After=network.target rsyslog.service syswarden-firewall.service
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

	historicalV4028SystemdCoreService = `[Unit]
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
	historicalV4028SystemdCoreServiceLength = 712
	historicalV4028SystemdCoreServiceSHA256 = "0079096c0a92f17e3aafb6c76ad89a0fdac03c2977732a15776be01220d81768"

	systemdFirewallService = `[Unit]
Description=SYSWARDEN Firewall Persistence & Engine Loader
After=network-online.target rsyslog.service cron.service crond.service
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
	historicalV4028SystemdFirewallService = `[Unit]
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
	historicalV4028SystemdFirewallServiceLength = 307
	historicalV4028SystemdFirewallServiceSHA256 = "bc730793c007273a380261155b7602571c42efd93972f45ad2dd440f98251724"
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
	var openRCRuntimeProof *openRCRuntimeDirectoryProof
	var expectedPresent bool
	if alpine {
		openRCRuntimeProof, expectedPresent, err = beginOpenRCRuntimeDirectoryAttestation(
			expectedPath,
			hostStat.Uid,
			hostStat.Gid,
		)
		if openRCRuntimeProof != nil {
			defer func() { _ = openRCRuntimeProof.directory.Close() }()
		}
	} else {
		expectedPresent, err = attestRuntimeDirectory(expectedPath, hostStat.Uid, hostStat.Gid)
	}
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
			if err := attestOpenRCRuntime(
				expectedPath,
				pid1CommPath,
				hostStat.Uid,
				hostStat.Gid,
				openRCRuntimeProof,
			); err != nil {
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

type openRCRuntimeDirectoryProof struct {
	path      string
	directory *os.File
	info      os.FileInfo
}

func safeOpenRCRuntimeDirectory(info os.FileInfo, expectedUID, expectedGID uint32) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	unsafeMode := os.ModeSymlink | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	if !ok || !info.IsDir() || info.Mode()&unsafeMode != 0 ||
		stat.Uid != expectedUID || stat.Gid != expectedGID {
		return false
	}
	return info.Mode().Perm() == 0755 || info.Mode().Perm() == 0775
}

func sameOpenRCRuntimeDirectory(
	first os.FileInfo,
	second os.FileInfo,
	expectedUID uint32,
	expectedGID uint32,
) bool {
	return first != nil && second != nil && os.SameFile(first, second) &&
		first.Mode() == second.Mode() &&
		safeOpenRCRuntimeDirectory(first, expectedUID, expectedGID) &&
		safeOpenRCRuntimeDirectory(second, expectedUID, expectedGID)
}

func beginOpenRCRuntimeDirectoryAttestation(
	path string,
	expectedUID uint32,
	expectedGID uint32,
) (*openRCRuntimeDirectoryProof, bool, error) {
	if filepath.Clean(path) != path {
		return nil, false, fmt.Errorf("refusing non-canonical service-manager runtime %s", path)
	}
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect service-manager runtime %s: %w", path, err)
	}
	if !safeOpenRCRuntimeDirectory(before, expectedUID, expectedGID) {
		return nil, false, fmt.Errorf("refusing unsafe service-manager runtime %s", path)
	}
	directory, err := os.Open(path) // #nosec G304 -- the expected OpenRC runtime is lstat/fstat identity attested
	if err != nil {
		return nil, false, fmt.Errorf("open service-manager runtime %s: %w", path, err)
	}
	opened, statErr := directory.Stat()
	if statErr != nil || !sameOpenRCRuntimeDirectory(
		before,
		opened,
		expectedUID,
		expectedGID,
	) {
		_ = directory.Close()
		return nil, false, fmt.Errorf("service-manager runtime %s changed while opening", path)
	}
	return &openRCRuntimeDirectoryProof{
		path:      path,
		directory: directory,
		info:      opened,
	}, true, nil
}

func (proof *openRCRuntimeDirectoryProof) reattest(expectedUID, expectedGID uint32) error {
	if proof == nil || proof.directory == nil {
		return fmt.Errorf("OpenRC service-manager runtime proof is unavailable")
	}
	opened, openedErr := proof.directory.Stat()
	after, afterErr := os.Lstat(proof.path)
	if openedErr != nil || afterErr != nil ||
		!sameOpenRCRuntimeDirectory(proof.info, opened, expectedUID, expectedGID) ||
		!sameOpenRCRuntimeDirectory(proof.info, after, expectedUID, expectedGID) {
		return fmt.Errorf("OpenRC service-manager runtime %s changed while attesting", proof.path)
	}
	return nil
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

func attestOpenRCRuntime(
	runtimePath string,
	pid1CommPath string,
	expectedUID uint32,
	expectedGID uint32,
	runtimeProof *openRCRuntimeDirectoryProof,
) error {
	if runtimeProof == nil || runtimeProof.path != runtimePath {
		return fmt.Errorf("OpenRC service-manager runtime proof does not match %s", runtimePath)
	}
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
	return runtimeProof.reattest(expectedUID, expectedGID)
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

func publishExactServiceFile(path, content string, mode os.FileMode) (created bool, returnErr error) {
	directory := filepath.Dir(path)
	pinned, err := openPinnedServiceDirectory(directory)
	if err != nil {
		return false, err
	}
	defer pinned.close()
	name := filepath.Base(path)
	if info, err := pinned.root.Lstat(name); err == nil {
		if info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
			!info.Mode().IsRegular() || !serviceFileOwnedByCurrentUser(info) || info.Mode().Perm() != mode {
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

	temporaryName, temporary, temporaryIdentity, err := createTemporaryServiceFile(pinned)
	if err != nil {
		return false, fmt.Errorf("create temporary service file for %s: %w", path, err)
	}
	keepTemporary := true
	defer func() {
		if keepTemporary {
			closeErr := temporary.Close()
			cleanupErr := quarantineAndRemoveServiceArtifact(
				pinned,
				temporaryName,
				true,
				func(directory *pinnedServiceDirectory, name string) (os.FileInfo, error) {
					return inspectServiceArtifactIdentity(directory, name, temporaryIdentity)
				},
			)
			returnErr = errors.Join(returnErr, closeErr, cleanupErr)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return false, fmt.Errorf("set service file mode for %s: %w", path, err)
	}
	temporaryIdentity, err = temporary.Stat()
	if err != nil {
		return false, fmt.Errorf("attest temporary service file for %s: %w", path, err)
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
	if err := unix.Renameat2(pinned.fd, temporaryName, pinned.fd, name, unix.RENAME_NOREPLACE); err != nil {
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
	if _, err := pinned.root.Lstat(name); err == nil {
		actualTarget, readErr := readAttestedServiceEnablement(pinned, name)
		if readErr != nil || actualTarget != target {
			return false, fmt.Errorf("refusing modified service enablement %s", path)
		}
		return false, pinned.sync()
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect service enablement %s: %w", path, err)
	}

	temporaryName, err := createTemporaryServiceEnablement(pinned, target)
	if err != nil {
		return false, fmt.Errorf("prepare service enablement %s: %w", path, err)
	}
	temporary, err := inspectAttestedServiceEnablement(pinned, temporaryName)
	if err != nil {
		return false, fmt.Errorf("attest temporary service enablement %s: %w", path, err)
	}
	if err := unix.Renameat2(pinned.fd, temporaryName, pinned.fd, name, unix.RENAME_NOREPLACE); err != nil {
		cleanupErr := removeAttestedServiceEnablement(pinned, temporaryName, temporary)
		return false, errors.Join(
			fmt.Errorf("publish service enablement %s without replacement: %w", path, err),
			cleanupErr,
		)
	}
	return true, pinned.sync()
}

type attestedServiceEnablement struct {
	identity os.FileInfo
	target   string
}

func inspectAttestedServiceEnablement(directory *pinnedServiceDirectory, name string) (attestedServiceEnablement, error) {
	before, err := directory.root.Lstat(name)
	if err != nil {
		return attestedServiceEnablement{}, err
	}
	if before.Mode()&os.ModeSymlink == 0 {
		return attestedServiceEnablement{identity: before}, fmt.Errorf("service enablement is not a symlink")
	}
	target, err := directory.root.Readlink(name)
	if err != nil {
		return attestedServiceEnablement{identity: before}, err
	}
	after, err := directory.root.Lstat(name)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return attestedServiceEnablement{identity: before, target: target}, fmt.Errorf("service enablement changed while reading")
	}
	return attestedServiceEnablement{identity: after, target: target}, nil
}

func readAttestedServiceEnablement(directory *pinnedServiceDirectory, name string) (string, error) {
	enablement, err := inspectAttestedServiceEnablement(directory, name)
	return enablement.target, err
}

func sameServiceArtifactIdentity(expected os.FileInfo, actual os.FileInfo) bool {
	return expected != nil && actual != nil && os.SameFile(expected, actual) && expected.Mode() == actual.Mode()
}

func randomServiceArtifactName(prefix string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(random), nil
}

func createTemporaryServiceEnablement(directory *pinnedServiceDirectory, target string) (string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		name, err := randomServiceArtifactName(".syswarden-enable-")
		if err != nil {
			return "", fmt.Errorf("generate service enablement reservation: %w", err)
		}
		if err := directory.root.Symlink(target, name); err == nil {
			return name, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("create temporary service enablement: %w", err)
		}
	}
	return "", fmt.Errorf("reserve a unique service enablement name")
}

func createTemporaryServiceFile(
	directory *pinnedServiceDirectory,
) (string, *os.File, os.FileInfo, error) {
	for attempt := 0; attempt < 16; attempt++ {
		name, err := randomServiceArtifactName(".syswarden-service-")
		if err != nil {
			return "", nil, nil, fmt.Errorf("generate service file reservation: %w", err)
		}
		file, err := directory.root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", nil, nil, fmt.Errorf("create temporary service file: %w", err)
		}
		identity, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			return "", nil, nil, fmt.Errorf("attest temporary service file: %w", statErr)
		}
		return name, file, identity, nil
	}
	return "", nil, nil, fmt.Errorf("reserve a unique service file name")
}

type serviceArtifactAttestor func(*pinnedServiceDirectory, string) (os.FileInfo, error)
type serviceArtifactRename func(int, string, int, string, uint) error

func inspectServiceArtifactIdentity(
	directory *pinnedServiceDirectory,
	name string,
	expected os.FileInfo,
) (os.FileInfo, error) {
	current, err := directory.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !sameServiceArtifactIdentity(expected, current) {
		return current, fmt.Errorf("service artifact identity changed")
	}
	return current, nil
}

func restoreQuarantinedServiceArtifact(
	directory *pinnedServiceDirectory,
	name string,
	quarantineName string,
	rename serviceArtifactRename,
) error {
	quarantined, err := directory.root.Lstat(quarantineName)
	if err != nil {
		return fmt.Errorf("inspect quarantined service artifact %s: %w", quarantineName, err)
	}
	for attempt := 0; attempt < 4; attempt++ {
		err = rename(directory.fd, quarantineName, directory.fd, name, unix.RENAME_NOREPLACE)
		if err == nil {
			restored, inspectErr := directory.root.Lstat(name)
			syncErr := directory.sync()
			if inspectErr != nil || !sameServiceArtifactIdentity(quarantined, restored) || syncErr != nil {
				return errors.Join(
					fmt.Errorf("quarantined service artifact %s was not exactly restored", name),
					inspectErr,
					syncErr,
				)
			}
			return nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("restore quarantined service artifact %s without replacement: %w", name, err)
		}
		err = rename(directory.fd, quarantineName, directory.fd, name, unix.RENAME_EXCHANGE)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return fmt.Errorf("restore quarantined service artifact %s by exchange: %w", name, err)
		}
		restored, inspectErr := directory.root.Lstat(name)
		displaced, displacedErr := directory.root.Lstat(quarantineName)
		syncErr := directory.sync()
		if inspectErr != nil || !sameServiceArtifactIdentity(quarantined, restored) || displacedErr != nil ||
			displaced == nil || syncErr != nil {
			return errors.Join(
				fmt.Errorf("quarantined service artifact %s was not exactly restored by exchange", name),
				inspectErr,
				displacedErr,
				syncErr,
			)
		}
		return nil
	}
	return fmt.Errorf("restore quarantined service artifact %s after concurrent changes", name)
}

func quarantineAndRemoveServiceArtifactUsing(
	directory *pinnedServiceDirectory,
	name string,
	missingOK bool,
	attest serviceArtifactAttestor,
	rename serviceArtifactRename,
) error {
	expected, err := attest(directory, name)
	if missingOK && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("attest service artifact %s before quarantine: %w", name, err)
	}

	var quarantineName string
	for attempt := 0; attempt < 16; attempt++ {
		quarantineName, err = randomServiceArtifactName(".syswarden-quarantine-")
		if err != nil {
			return fmt.Errorf("generate service artifact quarantine: %w", err)
		}
		err = rename(directory.fd, name, directory.fd, quarantineName, unix.RENAME_NOREPLACE)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return fmt.Errorf("quarantine service artifact %s atomically: %w", name, err)
		}
		break
	}
	if err != nil {
		return fmt.Errorf("reserve a unique quarantine for service artifact %s", name)
	}

	moved, attestErr := attest(directory, quarantineName)
	syncErr := directory.sync()
	if attestErr != nil || !sameServiceArtifactIdentity(expected, moved) || syncErr != nil {
		restoreErr := restoreQuarantinedServiceArtifact(directory, name, quarantineName, rename)
		return errors.Join(
			fmt.Errorf("service artifact %s changed before atomic quarantine", name),
			attestErr,
			syncErr,
			restoreErr,
		)
	}
	if err := unix.Unlinkat(directory.fd, quarantineName, 0); err != nil {
		restoreErr := restoreQuarantinedServiceArtifact(directory, name, quarantineName, rename)
		return errors.Join(
			fmt.Errorf("remove quarantined service artifact %s: %w", name, err),
			restoreErr,
		)
	}
	if err := directory.sync(); err != nil {
		return fmt.Errorf("sync removal of quarantined service artifact %s: %w", name, err)
	}
	return nil
}

func quarantineAndRemoveServiceArtifact(
	directory *pinnedServiceDirectory,
	name string,
	missingOK bool,
	attest serviceArtifactAttestor,
) error {
	return quarantineAndRemoveServiceArtifactUsing(directory, name, missingOK, attest, unix.Renameat2)
}

func removeAttestedServiceEnablement(
	directory *pinnedServiceDirectory,
	name string,
	expected attestedServiceEnablement,
) error {
	return quarantineAndRemoveServiceArtifact(
		directory,
		name,
		true,
		func(directory *pinnedServiceDirectory, candidate string) (os.FileInfo, error) {
			current, err := inspectAttestedServiceEnablement(directory, candidate)
			if err != nil {
				return current.identity, err
			}
			if !sameServiceArtifactIdentity(expected.identity, current.identity) || current.target != expected.target {
				return current.identity, fmt.Errorf("temporary service enablement changed")
			}
			return current.identity, nil
		},
	)
}

func attestExactServiceFile(path, content string, mode os.FileMode) error {
	directory, err := openPinnedServiceDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.close()
	name := filepath.Base(path)
	_, err = inspectExactServiceFile(directory, name, content, mode)
	if err != nil {
		return fmt.Errorf("attest service file %s: %w", path, err)
	}
	return directory.sync()
}

func inspectExactServiceFile(
	directory *pinnedServiceDirectory,
	name string,
	content string,
	mode os.FileMode,
) (os.FileInfo, error) {
	info, err := directory.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !info.Mode().IsRegular() ||
		!serviceFileOwnedByCurrentUser(info) || info.Mode().Perm() != mode {
		return info, fmt.Errorf("refusing unsafe service file")
	}
	actual, err := readAttestedServiceFile(directory.root, name, info)
	if err != nil {
		return info, err
	}
	if string(actual) != content {
		return info, fmt.Errorf("refusing modified service file")
	}
	return info, nil
}

func serviceFileHasSingleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

func sameServiceFileMetadata(expected, actual os.FileInfo) bool {
	expectedStat, expectedOK := expected.Sys().(*syscall.Stat_t)
	actualStat, actualOK := actual.Sys().(*syscall.Stat_t)
	return expectedOK && actualOK && sameServiceArtifactIdentity(expected, actual) &&
		expectedStat.Uid == actualStat.Uid && expectedStat.Gid == actualStat.Gid &&
		expectedStat.Nlink == actualStat.Nlink
}

func inspectSingleLinkExactServiceFile(
	directory *pinnedServiceDirectory,
	name string,
	content string,
	mode os.FileMode,
) (os.FileInfo, error) {
	before, err := directory.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if before.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !before.Mode().IsRegular() ||
		!serviceFileOwnedByCurrentUser(before) || before.Mode().Perm() != mode ||
		!serviceFileHasSingleLink(before) {
		return before, fmt.Errorf("refusing unsafe single-link service file")
	}
	actual, err := readAttestedServiceFile(directory.root, name, before)
	if err != nil {
		return before, err
	}
	if string(actual) != content {
		return before, fmt.Errorf("refusing modified service file")
	}
	after, err := directory.root.Lstat(name)
	if err != nil || !sameServiceFileMetadata(before, after) ||
		!serviceFileOwnedByCurrentUser(after) || !serviceFileHasSingleLink(after) {
		return before, errors.Join(fmt.Errorf("service file metadata changed while reading"), err)
	}
	return after, nil
}

func inspectAnchoredHistoricalServiceFile(
	directory *pinnedServiceDirectory,
	name string,
	content string,
	contentLength int,
	contentSHA256 string,
	mode os.FileMode,
) (os.FileInfo, error) {
	expected := []byte(content)
	expectedDigest := sha256.Sum256(expected)
	if len(expected) != contentLength || hex.EncodeToString(expectedDigest[:]) != contentSHA256 {
		return nil, fmt.Errorf("historical service file anchor is internally inconsistent")
	}
	info, err := inspectSingleLinkExactServiceFile(directory, name, content, mode)
	if err != nil {
		return info, err
	}
	actual, err := readAttestedServiceFile(directory.root, name, info)
	if err != nil {
		return info, err
	}
	actualDigest := sha256.Sum256(actual)
	if len(actual) != contentLength || hex.EncodeToString(actualDigest[:]) != contentSHA256 {
		return info, fmt.Errorf("historical service file digest is not exact")
	}
	after, err := directory.root.Lstat(name)
	if err != nil || !sameServiceFileMetadata(info, after) {
		return info, errors.Join(fmt.Errorf("historical service file changed while anchoring"), err)
	}
	return after, nil
}

type migratedServiceFile struct {
	artifact            serviceArtifact
	directory           *pinnedServiceDirectory
	name                string
	quarantineName      string
	historicalIdentity  os.FileInfo
	replacementIdentity os.FileInfo
	rename              serviceArtifactRename
	closed              bool
}

func (migration *migratedServiceFile) close() {
	if migration == nil || migration.closed {
		return
	}
	migration.closed = true
	migration.directory.close()
}

func inspectHistoricalServiceArtifact(
	directory *pinnedServiceDirectory,
	name string,
	artifact serviceArtifact,
) (os.FileInfo, error) {
	return inspectAnchoredHistoricalServiceFile(
		directory,
		name,
		artifact.historicalContent,
		artifact.historicalContentLength,
		artifact.historicalContentSHA256,
		artifact.mode,
	)
}

func removePinnedServiceArtifactByIdentity(
	directory *pinnedServiceDirectory,
	name string,
	expected os.FileInfo,
	rename serviceArtifactRename,
) error {
	return quarantineAndRemoveServiceArtifactUsing(
		directory,
		name,
		true,
		func(directory *pinnedServiceDirectory, candidate string) (os.FileInfo, error) {
			return inspectServiceArtifactIdentity(directory, candidate, expected)
		},
		rename,
	)
}

func removePinnedExactServiceFile(
	directory *pinnedServiceDirectory,
	name string,
	content string,
	mode os.FileMode,
	expected os.FileInfo,
	rename serviceArtifactRename,
) error {
	return quarantineAndRemoveServiceArtifactUsing(
		directory,
		name,
		false,
		func(directory *pinnedServiceDirectory, candidate string) (os.FileInfo, error) {
			info, err := inspectSingleLinkExactServiceFile(directory, candidate, content, mode)
			if err != nil {
				return info, err
			}
			if !sameServiceFileMetadata(expected, info) {
				return info, fmt.Errorf("service file identity changed")
			}
			return info, nil
		},
		rename,
	)
}

func renamePinnedServiceArtifactToQuarantine(
	directory *pinnedServiceDirectory,
	name string,
	rename serviceArtifactRename,
) (string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		quarantineName, err := randomServiceArtifactName(".syswarden-quarantine-")
		if err != nil {
			return "", fmt.Errorf("generate service migration quarantine: %w", err)
		}
		err = rename(directory.fd, name, directory.fd, quarantineName, unix.RENAME_NOREPLACE)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("quarantine migrated service file: %w", err)
		}
		return quarantineName, nil
	}
	return "", fmt.Errorf("reserve a unique service migration quarantine")
}

func preserveFailedServiceFileExchange(migration *migratedServiceFile) error {
	directory := migration.directory
	target, targetErr := inspectSingleLinkExactServiceFile(
		directory,
		migration.name,
		migration.artifact.content,
		migration.artifact.mode,
	)
	if targetErr != nil || !sameServiceFileMetadata(migration.replacementIdentity, target) {
		return errors.Join(
			fmt.Errorf("cannot preserve raced service file exchange with a changed replacement target"),
			targetErr,
		)
	}
	displaced, err := directory.root.Lstat(migration.quarantineName)
	if err != nil {
		return fmt.Errorf("inspect displaced service file after raced exchange: %w", err)
	}
	quarantineName, err := renamePinnedServiceArtifactToQuarantine(
		directory,
		migration.quarantineName,
		migration.rename,
	)
	if err != nil {
		return fmt.Errorf("preserve displaced service file after raced exchange: %w", err)
	}
	migration.quarantineName = quarantineName
	preserved, preservedErr := directory.root.Lstat(quarantineName)
	reattestedTarget, reattestErr := inspectSingleLinkExactServiceFile(
		directory,
		migration.name,
		migration.artifact.content,
		migration.artifact.mode,
	)
	syncErr := directory.sync()
	if preservedErr != nil || !sameServiceFileMetadata(displaced, preserved) || reattestErr != nil ||
		!sameServiceFileMetadata(migration.replacementIdentity, reattestedTarget) || syncErr != nil {
		return errors.Join(
			fmt.Errorf("raced service file exchange was not safely preserved"),
			preservedErr,
			reattestErr,
			syncErr,
		)
	}
	return nil
}

func ensureHistoricalServiceQuarantine(migration *migratedServiceFile) error {
	if strings.HasPrefix(migration.quarantineName, ".syswarden-quarantine-") {
		return nil
	}
	directory := migration.directory
	historical, err := inspectHistoricalServiceArtifact(directory, migration.quarantineName, migration.artifact)
	if err != nil || !sameServiceFileMetadata(migration.historicalIdentity, historical) {
		return errors.Join(fmt.Errorf("refusing changed historical service temporary"), err)
	}
	quarantineName, err := renamePinnedServiceArtifactToQuarantine(
		directory,
		migration.quarantineName,
		migration.rename,
	)
	if err != nil {
		return err
	}
	migration.quarantineName = quarantineName
	reattested, reattestErr := inspectHistoricalServiceArtifact(directory, quarantineName, migration.artifact)
	syncErr := directory.sync()
	if reattestErr != nil || !sameServiceFileMetadata(migration.historicalIdentity, reattested) || syncErr != nil {
		return errors.Join(fmt.Errorf("historical service quarantine is not exact"), reattestErr, syncErr)
	}
	return nil
}

func reverseRacedServiceFileRollback(migration *migratedServiceFile, displaced os.FileInfo) error {
	directory := migration.directory
	restoredHistorical, historicalErr := inspectHistoricalServiceArtifact(
		directory,
		migration.name,
		migration.artifact,
	)
	quarantinedConcurrent, concurrentErr := directory.root.Lstat(migration.quarantineName)
	if historicalErr != nil || !sameServiceFileMetadata(migration.historicalIdentity, restoredHistorical) ||
		concurrentErr != nil || !sameServiceFileMetadata(displaced, quarantinedConcurrent) {
		return errors.Join(
			fmt.Errorf("cannot reverse raced service rollback from unattested state"),
			historicalErr,
			concurrentErr,
		)
	}
	if err := migration.rename(
		directory.fd,
		migration.quarantineName,
		directory.fd,
		migration.name,
		unix.RENAME_EXCHANGE,
	); err != nil {
		return fmt.Errorf("reverse raced service rollback exchange: %w", err)
	}
	restoredConcurrent, restoredErr := directory.root.Lstat(migration.name)
	quarantinedHistorical, quarantineErr := inspectHistoricalServiceArtifact(
		directory,
		migration.quarantineName,
		migration.artifact,
	)
	syncErr := directory.sync()
	if restoredErr != nil || !sameServiceFileMetadata(displaced, restoredConcurrent) ||
		quarantineErr != nil || !sameServiceFileMetadata(migration.historicalIdentity, quarantinedHistorical) ||
		syncErr != nil {
		return errors.Join(
			fmt.Errorf("raced service rollback was not exactly reversed"),
			restoredErr,
			quarantineErr,
			syncErr,
		)
	}
	return nil
}

func reverseInvalidHistoricalServiceRollback(migration *migratedServiceFile) error {
	directory := migration.directory
	suspectHistorical, suspectErr := directory.root.Lstat(migration.name)
	quarantinedReplacement, replacementErr := inspectSingleLinkExactServiceFile(
		directory,
		migration.quarantineName,
		migration.artifact.content,
		migration.artifact.mode,
	)
	if suspectErr != nil || replacementErr != nil ||
		!sameServiceFileMetadata(migration.replacementIdentity, quarantinedReplacement) {
		return errors.Join(
			fmt.Errorf("cannot reverse invalid historical service rollback from unattested replacement"),
			suspectErr,
			replacementErr,
		)
	}
	if err := migration.rename(
		directory.fd,
		migration.quarantineName,
		directory.fd,
		migration.name,
		unix.RENAME_EXCHANGE,
	); err != nil {
		return fmt.Errorf("reverse invalid historical service rollback exchange: %w", err)
	}
	restoredReplacement, restoredErr := inspectSingleLinkExactServiceFile(
		directory,
		migration.name,
		migration.artifact.content,
		migration.artifact.mode,
	)
	preservedSuspect, preservedErr := directory.root.Lstat(migration.quarantineName)
	syncErr := directory.sync()
	if restoredErr != nil || !sameServiceFileMetadata(migration.replacementIdentity, restoredReplacement) ||
		preservedErr != nil || !sameServiceFileMetadata(suspectHistorical, preservedSuspect) || syncErr != nil {
		return errors.Join(
			fmt.Errorf("invalid historical service rollback was not exactly reversed"),
			restoredErr,
			preservedErr,
			syncErr,
		)
	}
	return nil
}

func rollbackMigratedServiceFile(migration *migratedServiceFile) error {
	directory := migration.directory
	historical, err := inspectHistoricalServiceArtifact(directory, migration.quarantineName, migration.artifact)
	if err != nil || !sameServiceFileMetadata(migration.historicalIdentity, historical) {
		return errors.Join(fmt.Errorf("refusing changed historical service quarantine"), err)
	}

	target, targetErr := inspectSingleLinkExactServiceFile(
		directory,
		migration.name,
		migration.artifact.content,
		migration.artifact.mode,
	)
	if errors.Is(targetErr, os.ErrNotExist) {
		if err := migration.rename(
			directory.fd,
			migration.quarantineName,
			directory.fd,
			migration.name,
			unix.RENAME_NOREPLACE,
		); err != nil {
			return fmt.Errorf("restore historical service file into missing target: %w", err)
		}
		restored, restoreErr := inspectHistoricalServiceArtifact(directory, migration.name, migration.artifact)
		syncErr := directory.sync()
		if restoreErr != nil || !sameServiceFileMetadata(migration.historicalIdentity, restored) || syncErr != nil {
			return errors.Join(fmt.Errorf("historical service file was not exactly restored"), restoreErr, syncErr)
		}
		return fmt.Errorf("service target disappeared concurrently; historical file restored")
	}
	if targetErr != nil {
		quarantineErr := ensureHistoricalServiceQuarantine(migration)
		return errors.Join(fmt.Errorf("refusing changed service target before rollback: %w", targetErr), quarantineErr)
	}
	if !sameServiceFileMetadata(migration.replacementIdentity, target) {
		quarantineErr := ensureHistoricalServiceQuarantine(migration)
		return errors.Join(fmt.Errorf("refusing substituted service target before rollback"), quarantineErr)
	}
	if err := migration.rename(
		directory.fd,
		migration.quarantineName,
		directory.fd,
		migration.name,
		unix.RENAME_EXCHANGE,
	); err != nil {
		return fmt.Errorf("restore historical service file by exchange: %w", err)
	}
	restored, restoreErr := inspectHistoricalServiceArtifact(directory, migration.name, migration.artifact)
	displaced, displacedErr := directory.root.Lstat(migration.quarantineName)
	syncErr := directory.sync()
	if restoreErr != nil || !sameServiceFileMetadata(migration.historicalIdentity, restored) {
		reverseErr := reverseInvalidHistoricalServiceRollback(migration)
		return errors.Join(
			fmt.Errorf("historical service file changed during rollback exchange"),
			restoreErr,
			syncErr,
			reverseErr,
		)
	}
	if displacedErr != nil {
		return errors.Join(
			fmt.Errorf("historical service file was not exactly restored by exchange"),
			displacedErr,
			syncErr,
		)
	}
	if !sameServiceFileMetadata(target, displaced) {
		reverseErr := reverseRacedServiceFileRollback(migration, displaced)
		return errors.Join(fmt.Errorf("service target changed during rollback exchange"), syncErr, reverseErr)
	}
	if syncErr != nil {
		return fmt.Errorf("sync restored historical service file: %w", syncErr)
	}

	quarantinedReplacement, replacementErr := inspectSingleLinkExactServiceFile(
		directory,
		migration.quarantineName,
		migration.artifact.content,
		migration.artifact.mode,
	)
	if replacementErr != nil || !sameServiceFileMetadata(migration.replacementIdentity, quarantinedReplacement) {
		reverseErr := reverseRacedServiceFileRollback(migration, displaced)
		return errors.Join(fmt.Errorf("service target changed during rollback exchange"), replacementErr, reverseErr)
	}
	return removePinnedExactServiceFile(
		directory,
		migration.quarantineName,
		migration.artifact.content,
		migration.artifact.mode,
		migration.replacementIdentity,
		migration.rename,
	)
}

func commitMigratedServiceFileUsing(
	migration *migratedServiceFile,
	unlink func(int, string, int) error,
	syncDirectory func() error,
) (bool, error) {
	directory := migration.directory
	target, err := inspectSingleLinkExactServiceFile(
		directory,
		migration.name,
		migration.artifact.content,
		migration.artifact.mode,
	)
	if err != nil || !sameServiceFileMetadata(migration.replacementIdentity, target) {
		return false, errors.Join(fmt.Errorf("refusing changed migrated service target"), err)
	}
	historical, err := inspectHistoricalServiceArtifact(directory, migration.quarantineName, migration.artifact)
	if err != nil || !sameServiceFileMetadata(migration.historicalIdentity, historical) {
		return false, errors.Join(fmt.Errorf("refusing changed historical service quarantine"), err)
	}
	quarantineName, err := renamePinnedServiceArtifactToQuarantine(
		directory,
		migration.quarantineName,
		migration.rename,
	)
	if err != nil {
		return false, fmt.Errorf("prepare committed historical service quarantine removal: %w", err)
	}
	migration.quarantineName = quarantineName
	reattestedHistorical, historicalErr := inspectHistoricalServiceArtifact(
		directory,
		quarantineName,
		migration.artifact,
	)
	if historicalErr != nil || !sameServiceFileMetadata(migration.historicalIdentity, reattestedHistorical) {
		return false, errors.Join(fmt.Errorf("historical service quarantine changed before removal"), historicalErr)
	}
	if err := syncDirectory(); err != nil {
		return false, fmt.Errorf("sync historical service quarantine before removal: %w", err)
	}
	reattestedTarget, targetErr := inspectSingleLinkExactServiceFile(
		directory,
		migration.name,
		migration.artifact.content,
		migration.artifact.mode,
	)
	if targetErr != nil || !sameServiceFileMetadata(migration.replacementIdentity, reattestedTarget) {
		return false, errors.Join(fmt.Errorf("migrated service target changed before commit"), targetErr)
	}
	if err := unlink(directory.fd, quarantineName, 0); err != nil {
		return false, fmt.Errorf("remove committed historical service quarantine: %w", err)
	}

	// From this point onward the historical inode has been destroyed. A later
	// durability or reattestation error must be reported without pretending that
	// the transaction can still restore that inode.
	postSyncErr := syncDirectory()
	committedTarget, committedTargetErr := inspectSingleLinkExactServiceFile(
		directory,
		migration.name,
		migration.artifact.content,
		migration.artifact.mode,
	)
	if postSyncErr != nil || committedTargetErr != nil ||
		!sameServiceFileMetadata(migration.replacementIdentity, committedTarget) {
		return true, errors.Join(
			fmt.Errorf("service migration crossed its irreversible commit boundary"),
			postSyncErr,
			committedTargetErr,
		)
	}
	return true, nil
}

func commitMigratedServiceFile(migration *migratedServiceFile) (bool, error) {
	return commitMigratedServiceFileUsing(migration, unix.Unlinkat, migration.directory.sync)
}

func publishMigratableServiceFileUsing(
	artifact serviceArtifact,
	rename serviceArtifactRename,
) (change serviceArtifactChange, returnErr error) {
	directory, err := openPinnedServiceDirectory(filepath.Dir(artifact.path))
	if err != nil {
		return change, err
	}
	releaseDirectory := true
	defer func() {
		if releaseDirectory {
			directory.close()
		}
	}()
	name := filepath.Base(artifact.path)

	if _, err := directory.root.Lstat(name); errors.Is(err, os.ErrNotExist) {
		directory.close()
		releaseDirectory = false
		created, publishErr := publishExactServiceFile(artifact.path, artifact.content, artifact.mode)
		return serviceArtifactChange{artifact: artifact, created: created}, publishErr
	} else if err != nil {
		return change, fmt.Errorf("inspect service file %s: %w", artifact.path, err)
	}
	if _, err := inspectSingleLinkExactServiceFile(directory, name, artifact.content, artifact.mode); err == nil {
		return change, directory.sync()
	}
	historicalIdentity, err := inspectHistoricalServiceArtifact(directory, name, artifact)
	if err != nil {
		return change, fmt.Errorf("refusing non-exact historical service file %s: %w", artifact.path, err)
	}

	temporaryName, temporary, temporaryIdentity, err := createTemporaryServiceFile(directory)
	if err != nil {
		return change, fmt.Errorf("create replacement service file for %s: %w", artifact.path, err)
	}
	temporaryOpen := true
	cleanupTemporary := func() error {
		var closeErr error
		if temporaryOpen {
			closeErr = temporary.Close()
			temporaryOpen = false
		}
		cleanupErr := removePinnedServiceArtifactByIdentity(directory, temporaryName, temporaryIdentity, rename)
		return errors.Join(closeErr, cleanupErr)
	}
	if err := temporary.Chmod(artifact.mode); err != nil {
		return change, errors.Join(
			fmt.Errorf("set replacement service file mode for %s: %w", artifact.path, err),
			cleanupTemporary(),
		)
	}
	temporaryIdentity, err = temporary.Stat()
	if err != nil {
		return change, errors.Join(
			fmt.Errorf("attest replacement service file for %s: %w", artifact.path, err),
			cleanupTemporary(),
		)
	}
	if _, err := temporary.WriteString(artifact.content); err != nil {
		return change, errors.Join(
			fmt.Errorf("write replacement service file %s: %w", artifact.path, err),
			cleanupTemporary(),
		)
	}
	if err := temporary.Sync(); err != nil {
		return change, errors.Join(
			fmt.Errorf("sync replacement service file %s: %w", artifact.path, err),
			cleanupTemporary(),
		)
	}
	if err := temporary.Close(); err != nil {
		temporaryOpen = false
		return change, errors.Join(
			fmt.Errorf("close replacement service file %s: %w", artifact.path, err),
			removePinnedServiceArtifactByIdentity(directory, temporaryName, temporaryIdentity, rename),
		)
	}
	temporaryOpen = false
	replacementIdentity, err := inspectSingleLinkExactServiceFile(
		directory,
		temporaryName,
		artifact.content,
		artifact.mode,
	)
	if err != nil || !sameServiceFileMetadata(temporaryIdentity, replacementIdentity) {
		return change, errors.Join(
			fmt.Errorf("replacement service file %s is not exact", artifact.path),
			err,
			removePinnedServiceArtifactByIdentity(directory, temporaryName, temporaryIdentity, rename),
		)
	}
	revalidatedHistorical, err := inspectHistoricalServiceArtifact(directory, name, artifact)
	if err != nil || !sameServiceFileMetadata(historicalIdentity, revalidatedHistorical) {
		return change, errors.Join(
			fmt.Errorf("historical service file %s changed before exchange", artifact.path),
			err,
			removePinnedExactServiceFile(
				directory, temporaryName, artifact.content, artifact.mode, replacementIdentity, rename,
			),
		)
	}

	if err := rename(directory.fd, temporaryName, directory.fd, name, unix.RENAME_EXCHANGE); err != nil {
		return change, errors.Join(
			fmt.Errorf("exchange historical service file %s atomically: %w", artifact.path, err),
			removePinnedExactServiceFile(
				directory, temporaryName, artifact.content, artifact.mode, replacementIdentity, rename,
			),
		)
	}
	migration := &migratedServiceFile{
		artifact:            artifact,
		directory:           directory,
		name:                name,
		quarantineName:      temporaryName,
		historicalIdentity:  historicalIdentity,
		replacementIdentity: replacementIdentity,
		rename:              rename,
	}
	published, publishErr := inspectSingleLinkExactServiceFile(directory, name, artifact.content, artifact.mode)
	quarantinedHistorical, historicalErr := inspectHistoricalServiceArtifact(directory, temporaryName, artifact)
	if historicalErr != nil || !sameServiceFileMetadata(historicalIdentity, quarantinedHistorical) {
		preserveErr := preserveFailedServiceFileExchange(migration)
		return change, errors.Join(
			fmt.Errorf("historical service file %s changed during atomic exchange", artifact.path),
			historicalErr,
			preserveErr,
		)
	}
	if publishErr != nil || !sameServiceFileMetadata(replacementIdentity, published) {
		rollbackErr := rollbackMigratedServiceFile(migration)
		return change, errors.Join(
			fmt.Errorf("replacement service file %s changed during atomic exchange", artifact.path),
			publishErr,
			rollbackErr,
		)
	}
	if err := directory.sync(); err != nil {
		rollbackErr := rollbackMigratedServiceFile(migration)
		return change, errors.Join(fmt.Errorf("sync migrated service file %s: %w", artifact.path, err), rollbackErr)
	}
	quarantineName, err := renamePinnedServiceArtifactToQuarantine(directory, temporaryName, rename)
	if err != nil {
		rollbackErr := rollbackMigratedServiceFile(migration)
		return change, errors.Join(err, rollbackErr)
	}
	migration.quarantineName = quarantineName
	if err := directory.sync(); err != nil {
		rollbackErr := rollbackMigratedServiceFile(migration)
		return change, errors.Join(fmt.Errorf("sync historical service quarantine: %w", err), rollbackErr)
	}
	revalidatedPublished, publishedErr := inspectSingleLinkExactServiceFile(
		directory, name, artifact.content, artifact.mode,
	)
	revalidatedQuarantine, quarantineErr := inspectHistoricalServiceArtifact(directory, quarantineName, artifact)
	if publishedErr != nil || !sameServiceFileMetadata(replacementIdentity, revalidatedPublished) ||
		quarantineErr != nil || !sameServiceFileMetadata(historicalIdentity, revalidatedQuarantine) {
		rollbackErr := rollbackMigratedServiceFile(migration)
		return change, errors.Join(
			fmt.Errorf("service migration changed during quarantine reattestation"),
			publishedErr,
			quarantineErr,
			rollbackErr,
		)
	}

	releaseDirectory = false
	return serviceArtifactChange{artifact: artifact, migration: migration}, nil
}

func publishMigratableServiceFile(artifact serviceArtifact) (serviceArtifactChange, error) {
	return publishMigratableServiceFileUsing(artifact, unix.Renameat2)
}

func containsExactString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func publishMigratableServiceEnablement(artifact serviceArtifact) (bool, error) {
	directory, err := openPinnedServiceDirectory(filepath.Dir(artifact.path))
	if err != nil {
		return false, err
	}
	defer directory.close()
	name := filepath.Base(artifact.path)
	actualTarget, err := readAttestedServiceEnablement(directory, name)
	if errors.Is(err, os.ErrNotExist) {
		created, publishErr := publishExactServiceEnablement(artifact.path, artifact.target)
		return created, publishErr
	}
	if err != nil {
		return false, fmt.Errorf("inspect service enablement %s: %w", artifact.path, err)
	}
	if actualTarget == artifact.target {
		return false, directory.sync()
	}
	if !containsExactString(artifact.legacyTargets, actualTarget) {
		return false, fmt.Errorf("refusing modified service enablement %s", artifact.path)
	}
	if err := attestExactServiceFile(artifact.attestedFilePath, artifact.attestedFileContent, artifact.attestedFileMode); err != nil {
		return false, fmt.Errorf("attest legacy service enablement %s: %w", artifact.path, err)
	}
	recheckedTarget, err := readAttestedServiceEnablement(directory, name)
	if err != nil || recheckedTarget != actualTarget {
		return false, errors.Join(
			fmt.Errorf("legacy service enablement %s changed while attesting", artifact.path),
			err,
		)
	}
	if err := attestExactServiceFile(artifact.attestedFilePath, artifact.attestedFileContent, artifact.attestedFileMode); err != nil {
		return false, fmt.Errorf("reattest legacy service enablement %s: %w", artifact.path, err)
	}
	return false, directory.sync()
}

type serviceArtifact struct {
	path                    string
	content                 string
	target                  string
	mode                    os.FileMode
	legacyTargets           []string
	attestedFilePath        string
	attestedFileContent     string
	attestedFileMode        os.FileMode
	historicalContent       string
	historicalContentLength int
	historicalContentSHA256 string
}

type serviceArtifactChange struct {
	artifact  serviceArtifact
	created   bool
	migration *migratedServiceFile
}

func removeCreatedServiceArtifactUsing(artifact serviceArtifact, rename serviceArtifactRename) error {
	directory, err := openPinnedServiceDirectory(filepath.Dir(artifact.path))
	if err != nil {
		return err
	}
	defer directory.close()
	name := filepath.Base(artifact.path)
	var attest serviceArtifactAttestor
	if artifact.target != "" {
		attest = func(directory *pinnedServiceDirectory, candidate string) (os.FileInfo, error) {
			enablement, inspectErr := inspectAttestedServiceEnablement(directory, candidate)
			if inspectErr != nil {
				return enablement.identity, inspectErr
			}
			if enablement.target != artifact.target {
				return enablement.identity, fmt.Errorf("refusing changed service enablement")
			}
			return enablement.identity, nil
		}
	} else {
		attest = func(directory *pinnedServiceDirectory, candidate string) (os.FileInfo, error) {
			return inspectExactServiceFile(directory, candidate, artifact.content, artifact.mode)
		}
	}
	if err := quarantineAndRemoveServiceArtifactUsing(directory, name, false, attest, rename); err != nil {
		return fmt.Errorf("remove created service artifact %s during rollback: %w", artifact.path, err)
	}
	return nil
}

func removeCreatedServiceArtifact(artifact serviceArtifact) error {
	return removeCreatedServiceArtifactUsing(artifact, unix.Renameat2)
}

func rollbackServiceArtifactChange(change serviceArtifactChange) error {
	if change.migration != nil {
		defer change.migration.close()
		return rollbackMigratedServiceFile(change.migration)
	}
	if change.created {
		return removeCreatedServiceArtifact(change.artifact)
	}
	return nil
}

type serviceMigrationCommitter func(*migratedServiceFile) (bool, error)

func commitServiceArtifactChange(
	change serviceArtifactChange,
	commit serviceMigrationCommitter,
) (bool, error) {
	if change.migration == nil {
		return false, nil
	}
	irreversible, err := commit(change.migration)
	if err != nil {
		return irreversible, err
	}
	change.migration.close()
	return irreversible, nil
}

func rollbackServiceArtifactChanges(changes []serviceArtifactChange, primary error) error {
	errorsToJoin := []error{primary}
	for index := len(changes) - 1; index >= 0; index-- {
		if rollbackErr := rollbackServiceArtifactChange(changes[index]); rollbackErr != nil {
			errorsToJoin = append(errorsToJoin, rollbackErr)
		}
	}
	return errors.Join(errorsToJoin...)
}

func closeServiceArtifactChanges(changes []serviceArtifactChange) {
	for _, change := range changes {
		change.migration.close()
	}
}

func commitServiceArtifactChangesUsing(
	changes []serviceArtifactChange,
	commit serviceMigrationCommitter,
) error {
	irreversible := false
	for index := len(changes) - 1; index >= 0; index-- {
		crossedBoundary, err := commitServiceArtifactChange(changes[index], commit)
		irreversible = irreversible || crossedBoundary
		if err == nil {
			continue
		}
		if irreversible {
			closeServiceArtifactChanges(changes)
			return fmt.Errorf("service publication cannot roll back after irreversible migration commit: %w", err)
		}
		return rollbackServiceArtifactChanges(changes, err)
	}
	return nil
}

func publishServiceArtifacts(artifacts []serviceArtifact) error {
	changes := make([]serviceArtifactChange, 0, len(artifacts))
	for _, artifact := range artifacts {
		var change serviceArtifactChange
		var err error
		if artifact.target != "" {
			if len(artifact.legacyTargets) == 0 {
				change.created, err = publishExactServiceEnablement(artifact.path, artifact.target)
			} else {
				change.created, err = publishMigratableServiceEnablement(artifact)
			}
			change.artifact = artifact
		} else if artifact.historicalContent != "" {
			change, err = publishMigratableServiceFile(artifact)
		} else {
			change.created, err = publishExactServiceFile(artifact.path, artifact.content, artifact.mode)
			change.artifact = artifact
		}
		if change.created || change.migration != nil {
			changes = append(changes, change)
		}
		if err == nil {
			continue
		}
		return rollbackServiceArtifactChanges(changes, err)
	}
	return commitServiceArtifactChangesUsing(changes, commitMigratedServiceFile)
}

func publishOpenRCServices() error {
	return publishServiceArtifacts([]serviceArtifact{
		{
			path: filepath.Join(serviceOpenRCUnitDir, "syswarden-core"), content: openRCCoreService, mode: 0755,
			historicalContent:       historicalV4028OpenRCCoreService,
			historicalContentLength: historicalV4028OpenRCCoreServiceLength,
			historicalContentSHA256: historicalV4028OpenRCCoreServiceSHA256,
		},
		{
			path: filepath.Join(serviceOpenRCUnitDir, "syswarden-firewall"), content: openRCFirewallService, mode: 0755,
			historicalContent:       historicalV4028OpenRCFirewallService,
			historicalContentLength: historicalV4028OpenRCFirewallServiceLength,
			historicalContentSHA256: historicalV4028OpenRCFirewallServiceSHA256,
		},
		{path: filepath.Join(serviceOpenRCRunlevelDir, "syswarden-core"), target: "/etc/init.d/syswarden-core"},
		{path: filepath.Join(serviceOpenRCRunlevelDir, "syswarden-firewall"), target: "/etc/init.d/syswarden-firewall"},
	})
}

func publishSystemdServices() error {
	coreUnitPath := filepath.Join(serviceSystemdUnitDir, "syswarden-core.service")
	firewallUnitPath := filepath.Join(serviceSystemdUnitDir, "syswarden-firewall.service")
	return publishServiceArtifacts([]serviceArtifact{
		{
			path: coreUnitPath, content: systemdCoreService, mode: 0600,
			historicalContent:       historicalV4028SystemdCoreService,
			historicalContentLength: historicalV4028SystemdCoreServiceLength,
			historicalContentSHA256: historicalV4028SystemdCoreServiceSHA256,
		},
		{
			path: firewallUnitPath, content: systemdFirewallService, mode: 0600,
			historicalContent:       historicalV4028SystemdFirewallService,
			historicalContentLength: historicalV4028SystemdFirewallServiceLength,
			historicalContentSHA256: historicalV4028SystemdFirewallServiceSHA256,
		},
		{
			path: filepath.Join(serviceSystemdWantsDir, "syswarden-core.service"), target: "../syswarden-core.service",
			legacyTargets:    []string{"/etc/systemd/system/syswarden-core.service"},
			attestedFilePath: coreUnitPath, attestedFileContent: systemdCoreService, attestedFileMode: 0600,
		},
		{
			path: filepath.Join(serviceSystemdWantsDir, "syswarden-firewall.service"), target: "../syswarden-firewall.service",
			legacyTargets:    []string{"/etc/systemd/system/syswarden-firewall.service"},
			attestedFilePath: firewallUnitPath, attestedFileContent: systemdFirewallService, attestedFileMode: 0600,
		},
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
