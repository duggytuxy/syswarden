//go:build linux

package system

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	maximumLegacyServiceFileSize = 64 << 10
	maximumLegacyPIDFileSize     = 32
	maximumLegacyCmdlineSize     = 64 << 10
	maximumLegacyProcStatSize    = 4 << 10
	maximumLegacyProcessRounds   = 3
	maximumLegacyManagerOutput   = 4 << 10

	legacySystemdWebTUITemplate = `[Unit]
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

	legacyOpenRCWebTUITemplate = `#!/sbin/openrc-run

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
)

var (
	legacySystemdWebTUIPath           = "/etc/systemd/system/syswarden-webtui.service"
	legacySystemdWebTUIEnablementPath = "/etc/systemd/system/multi-user.target.wants/syswarden-webtui.service"
	legacySystemdWebTUIDropInPath     = "/etc/systemd/system/syswarden-webtui.service.d"
	legacySystemdManagerRuntimePath   = "/run/systemd/system"
	legacySystemdWebTUIRuntimePath    = "/run/systemd/system/syswarden-webtui.service"
	legacySystemdWebTUIRuntimeDropIn  = "/run/systemd/system/syswarden-webtui.service.d"
	legacyOpenRCWebTUIPath            = "/etc/init.d/syswarden-webtui"
	legacyOpenRCWebTUIEnablementPath  = "/etc/runlevels/default/syswarden-webtui"
	legacyOpenRCWebTUIConfPath        = "/etc/conf.d/syswarden-webtui"
	legacyOpenRCManagerRuntimePath    = "/run/openrc"
	legacyWebTUIPIDPath               = "/run/syswarden-webtui.pid"
	legacyWebTUIExecutablePath        = "/opt/syswarden/bin/syswarden-cli"
	legacyWebTUIProcPath              = "/proc"
	legacyWebTUIExpectedOwnerUID      = uint32(0)
	legacyWebTUIExpectedOwnerGID      = uint32(0)
	legacyPackageEnvironment          = os.Getenv
	legacyRetirementManagerExecutor   = hostFirewallExecutor
	runRetirementCommand              = runAllowedRetirementCommand
	readRetirementCommandOutput       = readAllowedRetirementCommandOutput
	probeRetiredService               = probeRetiredServiceActive
	discoverRetiredProcesses          = discoverExactLegacyWebTUIProcesses
	inspectRetiredProcess             = inspectExactLegacyWebTUIProcess
	signalRetiredProcess              = func(pid int, signal syscall.Signal) error { return syscall.Kill(pid, signal) }
	retirementProcessNow              = time.Now
	retirementProcessSleep            = time.Sleep
	legacyWebTUITermGrace             = 5 * time.Second
	legacyWebTUIKillGrace             = 5 * time.Second
	legacyWebTUIPollInterval          = 50 * time.Millisecond
)

type legacyProcessState uint8

const (
	legacyProcessUnrelated legacyProcessState = iota
	legacyProcessExact
	legacyProcessVanished
)

type legacyWebTUIProcess struct {
	pid       int
	startTime string
}

func runAllowedRetirementCommand(name string, args ...string) error {
	_, err := runAllowedRetirementManagerCommand(name, args...)
	return err
}

func runAllowedRetirementManagerCommand(name string, args ...string) ([]byte, error) {
	command := name + "\x00" + strings.Join(args, "\x00")
	switch command {
	case "systemctl\x00is-active\x00--quiet\x00syswarden-webtui.service":
	case "systemctl\x00stop\x00syswarden-webtui.service":
	case "systemctl\x00disable\x00syswarden-webtui.service":
	case "systemctl\x00daemon-reload":
	case "rc-service\x00syswarden-webtui\x00status":
	case "rc-service\x00syswarden-webtui\x00stop":
	case "rc-update\x00del\x00syswarden-webtui\x00default":
	case "systemctl\x00show\x00syswarden-webtui.service\x00--property=LoadState\x00--value":
	case "systemctl\x00show\x00syswarden-webtui.service\x00--property=ActiveState\x00--value":
	case "systemctl\x00show\x00syswarden-webtui.service\x00--property=FragmentPath\x00--value":
	case "systemctl\x00show\x00syswarden-webtui.service\x00--property=DropInPaths\x00--value":
	case "systemctl\x00show\x00syswarden-webtui.service\x00--property=ExecStart\x00--value":
	default:
		return nil, fmt.Errorf("refusing unexpected legacy Web-TUI manager command")
	}
	executor := legacyRetirementManagerExecutor()
	path, err := resolveFirewallExecutable(executor, name)
	if err != nil {
		return nil, fmt.Errorf("resolve trusted legacy Web-TUI manager: %w", err)
	}
	output, err := executor.output(path, args...)
	if err != nil {
		return output, err
	}
	return output, nil
}

func readAllowedRetirementCommandOutput(name string, args ...string) (string, error) {
	command := name + "\x00" + strings.Join(args, "\x00")
	switch command {
	case "systemctl\x00show\x00syswarden-webtui.service\x00--property=LoadState\x00--value":
	case "systemctl\x00show\x00syswarden-webtui.service\x00--property=ActiveState\x00--value":
	case "systemctl\x00show\x00syswarden-webtui.service\x00--property=FragmentPath\x00--value":
	case "systemctl\x00show\x00syswarden-webtui.service\x00--property=DropInPaths\x00--value":
	case "systemctl\x00show\x00syswarden-webtui.service\x00--property=ExecStart\x00--value":
	default:
		return "", fmt.Errorf("refusing unexpected legacy Web-TUI manager query")
	}
	output, err := runAllowedRetirementManagerCommand(name, args...)
	if err != nil {
		return "", err
	}
	if len(output) == 0 || len(output) > maximumLegacyManagerOutput || output[len(output)-1] != '\n' ||
		bytes.Count(output, []byte{'\n'}) != 1 || bytes.IndexByte(output, 0) >= 0 {
		return "", fmt.Errorf("refusing ambiguous legacy Web-TUI manager output")
	}
	return string(output[:len(output)-1]), nil
}

func legacyManagerOverridePaths(alpine bool) []string {
	if alpine {
		return []string{legacyOpenRCWebTUIConfPath}
	}
	return []string{
		legacySystemdWebTUIDropInPath,
		legacySystemdWebTUIRuntimePath,
		legacySystemdWebTUIRuntimeDropIn,
	}
}

func attestNoLegacyManagerOverrides(alpine bool) error {
	for _, path := range legacyManagerOverridePaths(alpine) {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refusing legacy Web-TUI manager override %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect legacy Web-TUI manager override %s: %w", path, err)
		}
	}
	return nil
}

func attestLegacyServiceManagerRuntime(alpine bool) error {
	if err := attestNoLegacyManagerOverrides(alpine); err != nil {
		return err
	}
	if alpine {
		available, err := openRCManagerRuntimeAvailable()
		if err != nil {
			return err
		}
		if !available {
			return fmt.Errorf("OpenRC runtime disappeared during legacy Web-TUI retirement")
		}
		content, err := readOwnedLegacyService(legacyOpenRCWebTUIPath)
		if err != nil {
			return fmt.Errorf("attest legacy Web-TUI OpenRC unit: %w", err)
		}
		if content != legacyOpenRCWebTUITemplate {
			return fmt.Errorf("refusing modified legacy Web-TUI OpenRC unit")
		}
		if err := validateExactLegacyEnablement(legacyOpenRCWebTUIEnablementPath, "openrc"); err != nil {
			return err
		}
		return attestNoLegacyManagerOverrides(true)
	}
	loadState, err := readLegacySystemdLoadState()
	if err != nil {
		return err
	}
	if loadState != "loaded" {
		return fmt.Errorf("refusing legacy Web-TUI unit that is not loaded normally")
	}
	fragment, err := readRetirementCommandOutput(
		"systemctl", "show", "syswarden-webtui.service", "--property=FragmentPath", "--value",
	)
	if err != nil {
		return fmt.Errorf("attest loaded legacy Web-TUI fragment: %w", err)
	}
	if fragment != legacySystemdWebTUIPath {
		return fmt.Errorf("refusing legacy Web-TUI unit loaded from an unexpected fragment")
	}
	dropIns, err := readRetirementCommandOutput(
		"systemctl", "show", "syswarden-webtui.service", "--property=DropInPaths", "--value",
	)
	if err != nil {
		return fmt.Errorf("attest loaded legacy Web-TUI drop-ins: %w", err)
	}
	if dropIns != "" {
		return fmt.Errorf("refusing loaded legacy Web-TUI unit with drop-ins")
	}
	execStart, err := readRetirementCommandOutput(
		"systemctl", "show", "syswarden-webtui.service", "--property=ExecStart", "--value",
	)
	if err != nil {
		return fmt.Errorf("attest loaded legacy Web-TUI ExecStart: %w", err)
	}
	if !exactLegacySystemdExecStart(execStart) {
		return fmt.Errorf("refusing unexpected loaded legacy Web-TUI ExecStart")
	}
	return attestNoLegacyManagerOverrides(false)
}

func readLegacySystemdLoadState() (string, error) {
	loadState, err := readRetirementCommandOutput(
		"systemctl", "show", "syswarden-webtui.service", "--property=LoadState", "--value",
	)
	if err != nil {
		return "", fmt.Errorf("attest loaded legacy Web-TUI state: %w", err)
	}
	return loadState, nil
}

func readLegacySystemdActiveState() (string, error) {
	activeState, err := readRetirementCommandOutput(
		"systemctl", "show", "syswarden-webtui.service", "--property=ActiveState", "--value",
	)
	if err != nil {
		return "", fmt.Errorf("attest loaded legacy Web-TUI active state: %w", err)
	}
	return activeState, nil
}

func openRCManagerRuntimeAvailable() (bool, error) {
	parentPath := filepath.Dir(legacyOpenRCManagerRuntimePath)
	parent, err := os.Lstat(parentPath)
	if err != nil {
		return false, fmt.Errorf("inspect OpenRC runtime parent: %w", err)
	}
	if parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() {
		return false, fmt.Errorf("refusing unsafe OpenRC runtime parent %s", parentPath)
	}
	info, err := os.Lstat(legacyOpenRCManagerRuntimePath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect OpenRC runtime directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf("refusing unsafe OpenRC runtime directory %s", legacyOpenRCManagerRuntimePath)
	}
	return true, nil
}

func retireCachedLegacySystemdService(enablementPath string) error {
	loadState, err := readLegacySystemdLoadState()
	if err != nil {
		return err
	}
	switch loadState {
	case "not-found":
		activeState, activeErr := readLegacySystemdActiveState()
		if activeErr != nil {
			return activeErr
		}
		if activeState != "inactive" {
			return fmt.Errorf("refusing non-inactive legacy Web-TUI service without an attestable loaded unit")
		}
		return removeExactLegacyEnablement(enablementPath, "systemd")
	case "loaded":
		if err := attestLegacyServiceManagerRuntime(false); err != nil {
			return err
		}
	default:
		return fmt.Errorf("refusing ambiguous cached legacy Web-TUI load state %q", loadState)
	}

	if err := attestLegacyServiceManagerRuntime(false); err != nil {
		return err
	}
	if err := runRetirementCommand("systemctl", "stop", "syswarden-webtui.service"); err != nil {
		return fmt.Errorf("stop cached legacy Web-TUI service: %w", err)
	}
	activeState, err := readLegacySystemdActiveState()
	if err != nil {
		return err
	}
	if activeState != "inactive" && activeState != "failed" {
		return fmt.Errorf("cached legacy Web-TUI service remains live after synchronous stop")
	}
	if err := removeExactLegacyEnablement(enablementPath, "systemd"); err != nil {
		return err
	}
	if err := attestNoLegacyManagerOverrides(false); err != nil {
		return err
	}
	if err := runRetirementCommand("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd after cached legacy Web-TUI retirement: %w", err)
	}
	loadState, err = readLegacySystemdLoadState()
	if err != nil {
		return err
	}
	if loadState != "not-found" {
		return fmt.Errorf("cached legacy Web-TUI unit remains loaded after daemon reload")
	}
	activeState, err = readLegacySystemdActiveState()
	if err != nil {
		return err
	}
	if activeState != "inactive" {
		return fmt.Errorf("legacy Web-TUI service resurrected after daemon reload")
	}
	return nil
}

func exactLegacySystemdExecStart(value string) bool {
	if !strings.HasPrefix(value, "{ ") || !strings.HasSuffix(value, " }") {
		return false
	}
	fields := strings.Split(value[2:len(value)-2], " ; ")
	if len(fields) != 8 ||
		fields[0] != "path=/opt/syswarden/bin/syswarden-cli" ||
		fields[1] != "argv[]=/opt/syswarden/bin/syswarden-cli web-tui" ||
		(fields[2] != "ignore_errors=no" && fields[2] != "ignore_errors=yes") ||
		!strings.HasPrefix(fields[3], "start_time=") || len(fields[3]) == len("start_time=") ||
		!strings.HasPrefix(fields[4], "stop_time=") || len(fields[4]) == len("stop_time=") ||
		!strings.HasPrefix(fields[5], "pid=") ||
		!strings.HasPrefix(fields[6], "code=") || len(fields[6]) == len("code=") ||
		!strings.HasPrefix(fields[7], "status=") || len(fields[7]) == len("status=") {
		return false
	}
	pid := strings.TrimPrefix(fields[5], "pid=")
	if pid == "" {
		return false
	}
	for _, character := range pid {
		if character < '0' || character > '9' {
			return false
		}
	}
	for _, field := range fields[3:] {
		if strings.ContainsAny(field, "\x00\r\n{}") {
			return false
		}
	}
	return true
}

func retireLegacyWebTUIService(alpine bool) error {
	managerState, err := classifyServiceManagerRuntimePaths(
		alpine,
		legacySystemdManagerRuntimePath,
		legacyOpenRCManagerRuntimePath,
		legacyPackageEnvironment,
	)
	if err != nil {
		return fmt.Errorf("classify legacy Web-TUI service-manager runtime: %w", err)
	}
	servicePath := legacySystemdWebTUIPath
	enablementPath := legacySystemdWebTUIEnablementPath
	expectedUnit := legacySystemdWebTUITemplate
	enablementKind := "systemd"
	stopCommand := []string{"systemctl", "stop", "syswarden-webtui.service"}
	disableCommand := []string{"systemctl", "disable", "syswarden-webtui.service"}
	if alpine {
		servicePath = legacyOpenRCWebTUIPath
		enablementPath = legacyOpenRCWebTUIEnablementPath
		expectedUnit = legacyOpenRCWebTUITemplate
		enablementKind = "openrc"
		stopCommand = []string{"rc-service", "syswarden-webtui", "stop"}
		disableCommand = []string{"rc-update", "del", "syswarden-webtui", "default"}
	}
	pendingPath := servicePath + ".syswarden-retiring"
	if err := attestNoLegacyManagerOverrides(alpine); err != nil {
		return err
	}

	if err := recoverPendingLegacyService(servicePath, pendingPath, expectedUnit); err != nil {
		return err
	}
	content, err := readOwnedLegacyService(servicePath)
	if errors.Is(err, os.ErrNotExist) {
		managerAvailable := managerState == serviceManagerActive
		if managerAvailable && !alpine {
			if err := retireCachedLegacySystemdService(enablementPath); err != nil {
				return err
			}
		} else {
			if managerState == serviceManagerOffline {
				if err := attestLegacyServiceManagerOffline(alpine); err != nil {
					return err
				}
			}
			if err := removeExactLegacyEnablement(enablementPath, enablementKind); err != nil {
				return err
			}
		}
		if managerState == serviceManagerOffline {
			if err := attestLegacyServiceManagerOffline(alpine); err != nil {
				return err
			}
		}
		if err := retireExactLegacyWebTUIProcesses(); err != nil {
			return err
		}
		if managerState == serviceManagerOffline {
			if err := attestLegacyServiceManagerOffline(alpine); err != nil {
				return err
			}
		}
		if err := removeLegacyWebTUIPID(legacyWebTUIPIDPath); err != nil {
			return err
		}
		if err := verifyLegacyWebTUIRetired(servicePath, pendingPath, enablementPath, legacyWebTUIPIDPath); err != nil {
			return err
		}
		if managerState == serviceManagerOffline {
			return attestLegacyServiceManagerOffline(alpine)
		}
		return attestNoLegacyManagerOverrides(alpine)
	}
	if err != nil {
		return err
	}
	if content != expectedUnit {
		return fmt.Errorf("refusing to remove modified legacy Web-TUI service file %s", servicePath)
	}
	// Validate the known enablement path before any manager command can mutate it.
	if err := validateExactLegacyEnablement(enablementPath, enablementKind); err != nil {
		return err
	}
	managerAvailable := managerState == serviceManagerActive
	if managerAvailable {
		if err := attestLegacyServiceManagerRuntime(alpine); err != nil {
			return err
		}

		active, err := probeRetiredService(alpine)
		if err != nil {
			return fmt.Errorf("verify retired service state: %w", err)
		}
		if active {
			if err := attestLegacyServiceManagerRuntime(alpine); err != nil {
				return err
			}
			if err := runRetirementCommand(stopCommand[0], stopCommand[1:]...); err != nil {
				return fmt.Errorf("stop retired service %s: %w", servicePath, err)
			}
		}
		if err := attestLegacyServiceManagerRuntime(alpine); err != nil {
			return err
		}
		active, err = probeRetiredService(alpine)
		if err != nil {
			return fmt.Errorf("verify retired service inactivity: %w", err)
		}
		if active {
			return fmt.Errorf("retired service remains active after stop")
		}
		enabled, err := exactLegacyEnablementPresent(enablementPath, enablementKind)
		if err != nil {
			return err
		}
		if enabled {
			if err := attestLegacyServiceManagerRuntime(alpine); err != nil {
				return err
			}
			if err := runRetirementCommand(disableCommand[0], disableCommand[1:]...); err != nil {
				return fmt.Errorf("disable retired service %s: %w", servicePath, err)
			}
			if alpine {
				if err := syncParentDirectory(enablementPath); err != nil {
					return fmt.Errorf("sync OpenRC enablement removal: %w", err)
				}
			}
		}
		if err := removeExactLegacyEnablement(enablementPath, enablementKind); err != nil {
			return err
		}
	} else {
		// Without an OpenRC runtime there is no cached manager state. Re-attest
		// both exact owned paths immediately before their fsync-backed removal;
		// the exact /proc inventory below remains the process authority.
		if err := attestLegacyServiceManagerOffline(alpine); err != nil {
			return err
		}
		content, err := readOwnedLegacyService(servicePath)
		if err != nil {
			return err
		}
		if content != expectedUnit {
			return fmt.Errorf("refusing to remove modified legacy Web-TUI service file %s", servicePath)
		}
		if err := removeExactLegacyEnablement(enablementPath, enablementKind); err != nil {
			return err
		}
	}

	if !managerAvailable {
		if err := attestLegacyServiceManagerOffline(alpine); err != nil {
			return err
		}
		if err := removeExactLegacyUnit(servicePath, expectedUnit); err != nil {
			return err
		}
	} else if alpine {
		if err := removeExactLegacyUnit(servicePath, expectedUnit); err != nil {
			return err
		}
	} else {
		if err := moveExactLegacyUnit(servicePath, pendingPath, expectedUnit); err != nil {
			return err
		}
		if err := attestNoLegacyManagerOverrides(false); err != nil {
			restoreErr := restorePendingLegacyUnit(servicePath, pendingPath, expectedUnit)
			if restoreErr != nil {
				return fmt.Errorf("attest systemd overrides before reload: %w (restore failed: %v)", err, restoreErr)
			}
			return fmt.Errorf("attest systemd overrides before reload: %w", err)
		}
		if err := runRetirementCommand("systemctl", "daemon-reload"); err != nil {
			restoreErr := restorePendingLegacyUnit(servicePath, pendingPath, expectedUnit)
			if restoreErr != nil {
				return fmt.Errorf("reload systemd after retired service removal: %w (restore failed: %v)", err, restoreErr)
			}
			return fmt.Errorf("reload systemd after retired service removal: %w", err)
		}
		if err := removeExactLegacyUnit(pendingPath, expectedUnit); err != nil {
			return err
		}
	}
	if managerState == serviceManagerOffline {
		if err := attestLegacyServiceManagerOffline(alpine); err != nil {
			return err
		}
	}
	if err := retireExactLegacyWebTUIProcesses(); err != nil {
		return err
	}
	if managerState == serviceManagerOffline {
		if err := attestLegacyServiceManagerOffline(alpine); err != nil {
			return err
		}
	}
	if err := removeLegacyWebTUIPID(legacyWebTUIPIDPath); err != nil {
		return err
	}
	if err := verifyLegacyWebTUIRetired(servicePath, pendingPath, enablementPath, legacyWebTUIPIDPath); err != nil {
		return err
	}
	if managerState == serviceManagerOffline {
		return attestLegacyServiceManagerOffline(alpine)
	}
	return attestNoLegacyManagerOverrides(alpine)
}

func attestLegacyServiceManagerOffline(alpine bool) error {
	state, err := classifyServiceManagerRuntimePaths(
		alpine,
		legacySystemdManagerRuntimePath,
		legacyOpenRCManagerRuntimePath,
		legacyPackageEnvironment,
	)
	if err != nil {
		return err
	}
	if state != serviceManagerOffline {
		return fmt.Errorf("legacy Web-TUI service-manager runtime is no longer offline")
	}
	return attestNoLegacyManagerOverrides(alpine)
}

func exactLegacyEnablementPresent(path, kind string) (bool, error) {
	if err := validateExactLegacyEnablement(path, kind); err != nil {
		return false, err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("inspect legacy Web-TUI enablement %s: %w", path, err)
	}
	return true, nil
}

func recoverPendingLegacyService(servicePath, pendingPath, expectedUnit string) error {
	pendingInfo, pendingErr := os.Lstat(pendingPath)
	if errors.Is(pendingErr, os.ErrNotExist) {
		return nil
	}
	if pendingErr != nil {
		return fmt.Errorf("inspect pending legacy Web-TUI service file %s: %w", pendingPath, pendingErr)
	}
	if _, serviceErr := os.Lstat(servicePath); serviceErr == nil {
		return fmt.Errorf("both active and pending legacy Web-TUI service files exist")
	} else if !errors.Is(serviceErr, os.ErrNotExist) {
		return fmt.Errorf("inspect legacy Web-TUI service file %s: %w", servicePath, serviceErr)
	}
	if pendingInfo.Mode()&os.ModeSymlink != 0 || !pendingInfo.Mode().IsRegular() {
		return fmt.Errorf("pending legacy Web-TUI service path %s is not a regular file", pendingPath)
	}
	content, err := readOwnedLegacyService(pendingPath)
	if err != nil {
		return err
	}
	if content != expectedUnit {
		return fmt.Errorf("refusing to restore modified pending legacy Web-TUI service file %s", pendingPath)
	}
	return restorePendingLegacyUnit(servicePath, pendingPath, expectedUnit)
}

func restorePendingLegacyUnit(servicePath, pendingPath, expectedUnit string) error {
	content, err := readOwnedLegacyService(pendingPath)
	if err != nil {
		return fmt.Errorf("read pending legacy Web-TUI service file before restore: %w", err)
	}
	if content != expectedUnit {
		return fmt.Errorf("refusing to restore modified pending legacy Web-TUI service file %s", pendingPath)
	}
	if _, err := os.Lstat(servicePath); err == nil {
		return fmt.Errorf("refusing to overwrite active legacy Web-TUI service file %s", servicePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect active legacy Web-TUI service file %s: %w", servicePath, err)
	}
	if err := os.Rename(pendingPath, servicePath); err != nil {
		return fmt.Errorf("restore pending legacy Web-TUI service file: %w", err)
	}
	if err := syncParentDirectory(servicePath); err != nil {
		return fmt.Errorf("sync restored legacy Web-TUI service file: %w", err)
	}
	return nil
}

func moveExactLegacyUnit(servicePath, pendingPath, expectedUnit string) error {
	if _, err := os.Lstat(pendingPath); err == nil {
		return fmt.Errorf("refusing to overwrite pending legacy Web-TUI service file %s", pendingPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect pending legacy Web-TUI service file %s: %w", pendingPath, err)
	}
	content, err := readOwnedLegacyService(servicePath)
	if err != nil {
		return err
	}
	if content != expectedUnit {
		return fmt.Errorf("refusing to move modified legacy Web-TUI service file %s", servicePath)
	}
	if err := os.Rename(servicePath, pendingPath); err != nil {
		return fmt.Errorf("stage legacy Web-TUI service removal: %w", err)
	}
	if err := syncParentDirectory(servicePath); err != nil {
		return fmt.Errorf("sync staged legacy Web-TUI service removal: %w", err)
	}
	return nil
}

func removeExactLegacyUnit(path, expectedUnit string) error {
	content, err := readOwnedLegacyService(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if content != expectedUnit {
		return fmt.Errorf("refusing to remove modified legacy Web-TUI service file %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove legacy Web-TUI service file %s: %w", path, err)
	}
	if err := verifyRetiredPathAbsent(path); err != nil {
		return err
	}
	if err := syncParentDirectory(path); err != nil {
		return fmt.Errorf("sync removed legacy Web-TUI service file %s: %w", path, err)
	}
	return nil
}

func validateExactLegacyEnablement(path, kind string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect legacy Web-TUI enablement path %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("refusing a non-symlink legacy Web-TUI enablement path %s", path)
	}
	target, err := os.Readlink(path)
	if err != nil {
		return fmt.Errorf("read legacy Web-TUI enablement path %s: %w", path, err)
	}
	if !legacyEnablementTargetAllowed(kind, target) {
		return fmt.Errorf("refusing a modified legacy Web-TUI enablement link %s", path)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, after) {
		return fmt.Errorf("legacy Web-TUI enablement path %s changed while reading", path)
	}
	return nil
}

func legacyEnablementTargetAllowed(kind, target string) bool {
	switch kind {
	case "systemd":
		return target == "../syswarden-webtui.service" || target == "/etc/systemd/system/syswarden-webtui.service"
	case "openrc":
		return target == "/etc/init.d/syswarden-webtui" || target == "../../init.d/syswarden-webtui"
	default:
		return false
	}
}

func removeExactLegacyEnablement(path, kind string) error {
	if err := validateExactLegacyEnablement(path, kind); err != nil {
		return err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect legacy Web-TUI enablement path %s before removal: %w", path, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove legacy Web-TUI enablement path %s: %w", path, err)
	}
	if err := verifyRetiredPathAbsent(path); err != nil {
		return err
	}
	if err := syncParentDirectory(path); err != nil {
		return fmt.Errorf("sync removed legacy Web-TUI enablement path %s: %w", path, err)
	}
	return nil
}

func retireExactLegacyWebTUIProcesses() error {
	for round := 0; round < maximumLegacyProcessRounds; round++ {
		processes, err := discoverRetiredProcesses()
		if err != nil {
			return fmt.Errorf("discover exact legacy Web-TUI processes: %w", err)
		}
		if len(processes) == 0 {
			return nil
		}
		for _, process := range processes {
			current, state, err := inspectRetiredProcess(process.pid)
			if err != nil {
				return fmt.Errorf("revalidate legacy Web-TUI process %d before termination: %w", process.pid, err)
			}
			if state != legacyProcessExact || current.startTime != process.startTime {
				// The original process vanished or the PID was recycled. A later
				// complete inventory decides whether the replacement is relevant.
				continue
			}
			if err := signalRetiredProcess(process.pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("terminate exact legacy Web-TUI process %d: %w", process.pid, err)
			}
			stopped, err := waitForLegacyWebTUIProcessExit(process, legacyWebTUITermGrace)
			if err != nil {
				return err
			}
			if stopped {
				continue
			}
			current, state, err = inspectRetiredProcess(process.pid)
			if err != nil {
				return fmt.Errorf("revalidate legacy Web-TUI process %d before forced termination: %w", process.pid, err)
			}
			if state != legacyProcessExact || current.startTime != process.startTime {
				continue
			}
			if err := signalRetiredProcess(process.pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("force terminate exact legacy Web-TUI process %d: %w", process.pid, err)
			}
			stopped, err = waitForLegacyWebTUIProcessExit(process, legacyWebTUIKillGrace)
			if err != nil {
				return err
			}
			if !stopped {
				return fmt.Errorf("exact legacy Web-TUI process %d remains after bounded termination", process.pid)
			}
		}
	}
	processes, err := discoverRetiredProcesses()
	if err != nil {
		return fmt.Errorf("verify exact legacy Web-TUI process retirement: %w", err)
	}
	if len(processes) != 0 {
		return fmt.Errorf("exact legacy Web-TUI process inventory did not converge")
	}
	return nil
}

func waitForLegacyWebTUIProcessExit(process legacyWebTUIProcess, grace time.Duration) (bool, error) {
	deadline := retirementProcessNow().Add(grace)
	for {
		current, state, err := inspectRetiredProcess(process.pid)
		if err != nil {
			return false, fmt.Errorf("verify legacy Web-TUI process %d exit: %w", process.pid, err)
		}
		if state != legacyProcessExact || current.startTime != process.startTime {
			return true, nil
		}
		if !retirementProcessNow().Before(deadline) {
			return false, nil
		}
		retirementProcessSleep(legacyWebTUIPollInterval)
	}
}

func discoverExactLegacyWebTUIProcesses() ([]legacyWebTUIProcess, error) {
	executable, err := attestLegacyWebTUIExecutable()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(legacyWebTUIProcPath)
	if err != nil {
		return nil, fmt.Errorf("read process inventory: %w", err)
	}
	processes := make([]legacyWebTUIProcess, 0)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		process, state, err := inspectLegacyWebTUIProcessWithExecutable(pid, executable)
		if err != nil {
			return nil, err
		}
		if state == legacyProcessExact {
			processes = append(processes, process)
		}
	}
	return processes, nil
}

func inspectExactLegacyWebTUIProcess(pid int) (legacyWebTUIProcess, legacyProcessState, error) {
	executable, err := attestLegacyWebTUIExecutable()
	if err != nil {
		return legacyWebTUIProcess{}, legacyProcessUnrelated, err
	}
	return inspectLegacyWebTUIProcessWithExecutable(pid, executable)
}

func inspectLegacyWebTUIProcessWithExecutable(pid int, executable os.FileInfo) (legacyWebTUIProcess, legacyProcessState, error) {
	processRoot := filepath.Join(legacyWebTUIProcPath, strconv.Itoa(pid))
	startBefore, err := readLegacyProcessStartTime(filepath.Join(processRoot, "stat"))
	if errors.Is(err, os.ErrNotExist) {
		return legacyWebTUIProcess{}, legacyProcessVanished, nil
	}
	if err != nil {
		return legacyWebTUIProcess{}, legacyProcessUnrelated, fmt.Errorf("read process %d start time: %w", pid, err)
	}

	executableInfo, executableErr := os.Stat(filepath.Join(processRoot, "exe"))
	executableStatOK := executableErr == nil
	executableMatches := executableStatOK && os.SameFile(executable, executableInfo)
	executableLink, linkErr := os.Readlink(filepath.Join(processRoot, "exe"))
	linkOK := linkErr == nil
	arguments, argumentsErr := readLegacyProcessArguments(filepath.Join(processRoot, "cmdline"))
	argumentsOK := argumentsErr == nil
	state, err := classifyLegacyWebTUIProcess(
		executableMatches,
		executableStatOK,
		executableLink,
		linkOK,
		arguments,
		argumentsOK,
	)
	if err != nil {
		return legacyWebTUIProcess{}, legacyProcessUnrelated, fmt.Errorf("process %d identity is not attestable: %w", pid, err)
	}

	startAfter, err := readLegacyProcessStartTime(filepath.Join(processRoot, "stat"))
	if errors.Is(err, os.ErrNotExist) {
		return legacyWebTUIProcess{}, legacyProcessVanished, nil
	}
	if err != nil {
		return legacyWebTUIProcess{}, legacyProcessUnrelated, fmt.Errorf("re-read process %d start time: %w", pid, err)
	}
	if startBefore != startAfter {
		return legacyWebTUIProcess{}, legacyProcessVanished, nil
	}
	return legacyWebTUIProcess{pid: pid, startTime: startAfter}, state, nil
}

func classifyLegacyWebTUIProcess(
	executableMatches bool,
	executableStatOK bool,
	executableLink string,
	linkOK bool,
	arguments []string,
	argumentsOK bool,
) (legacyProcessState, error) {
	exactLink := linkOK && (executableLink == legacyWebTUIExecutablePath || executableLink == legacyWebTUIExecutablePath+" (deleted)")
	exactSubcommand := argumentsOK && len(arguments) >= 2 && arguments[1] == "web-tui"
	exactCommandClaim := exactSubcommand && arguments[0] == legacyWebTUIExecutablePath

	if executableMatches {
		if !argumentsOK {
			return legacyProcessUnrelated, fmt.Errorf("cannot read NUL-delimited arguments for the attested executable")
		}
		if exactSubcommand {
			return legacyProcessExact, nil
		}
		return legacyProcessUnrelated, nil
	}
	if exactLink {
		if !executableStatOK {
			return legacyProcessUnrelated, fmt.Errorf("cannot stat an executable with the exact legacy path")
		}
		if !argumentsOK {
			return legacyProcessUnrelated, fmt.Errorf("cannot read NUL-delimited arguments for the exact legacy path")
		}
		if exactSubcommand {
			return legacyProcessExact, nil
		}
		return legacyProcessUnrelated, nil
	}
	if exactCommandClaim {
		return legacyProcessUnrelated, fmt.Errorf("the exact legacy command line belongs to a different executable identity")
	}
	return legacyProcessUnrelated, nil
}

func attestLegacyWebTUIExecutable() (os.FileInfo, error) {
	before, err := os.Lstat(legacyWebTUIExecutablePath)
	if err != nil {
		return nil, fmt.Errorf("inspect legacy Web-TUI executable: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("legacy Web-TUI executable path is not a regular file")
	}
	file, err := openFileWithinParent(legacyWebTUIExecutablePath)
	if err != nil {
		return nil, fmt.Errorf("open legacy Web-TUI executable: %w", err)
	}
	opened, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil || closeErr != nil || !sameLegacyFileSnapshot(before, opened) {
		return nil, fmt.Errorf("legacy Web-TUI executable changed while attesting")
	}
	after, err := os.Lstat(legacyWebTUIExecutablePath)
	if err != nil || !sameLegacyFileSnapshot(opened, after) {
		return nil, fmt.Errorf("legacy Web-TUI executable changed while attesting")
	}
	return after, nil
}

func readLegacyProcessArguments(path string) ([]string, error) {
	file, err := openFileWithinParent(path)
	if err != nil {
		return nil, err
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maximumLegacyCmdlineSize+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(content) > maximumLegacyCmdlineSize {
		return nil, fmt.Errorf("process command line exceeds the cleanup limit")
	}
	if len(content) == 0 {
		return []string{}, nil
	}
	if content[len(content)-1] != 0 {
		return nil, fmt.Errorf("process command line is not NUL terminated")
	}
	parts := bytes.Split(content[:len(content)-1], []byte{0})
	arguments := make([]string, len(parts))
	for index, part := range parts {
		arguments[index] = string(part)
	}
	return arguments, nil
}

func readLegacyProcessStartTime(path string) (string, error) {
	file, err := openFileWithinParent(path)
	if err != nil {
		return "", err
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maximumLegacyProcStatSize+1))
	closeErr := file.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if len(content) > maximumLegacyProcStatSize {
		return "", fmt.Errorf("process stat exceeds the cleanup limit")
	}
	closingParenthesis := bytes.LastIndex(content, []byte(") "))
	if closingParenthesis < 0 {
		return "", fmt.Errorf("process stat has no bounded command terminator")
	}
	fields := strings.Fields(string(content[closingParenthesis+2:]))
	if len(fields) < 20 || fields[19] == "" {
		return "", fmt.Errorf("process stat has no start time")
	}
	return fields[19], nil
}

func probeRetiredServiceActive(alpine bool) (bool, error) {
	name := "systemctl"
	args := []string{"is-active", "--quiet", "syswarden-webtui.service"}
	inactiveExitCode := 3
	if alpine {
		name = "rc-service"
		args = []string{"syswarden-webtui", "status"}
	}
	err := runRetirementCommand(name, args...)
	if err == nil {
		return true, nil
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		return false, err
	}
	if exitError.ExitCode() == inactiveExitCode || (!alpine && exitError.ExitCode() == 4) {
		return false, nil
	}
	return false, fmt.Errorf("status probe exited with code %d", exitError.ExitCode())
}

func removeLegacyWebTUIPID(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect legacy Web-TUI PID file %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maximumLegacyPIDFileSize {
		return fmt.Errorf("refusing an unsafe legacy Web-TUI PID file %s", path)
	}
	file, err := openFileWithinParent(path)
	if err != nil {
		return fmt.Errorf("open legacy Web-TUI PID file %s: %w", path, err)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maximumLegacyPIDFileSize+1))
	opened, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || !os.SameFile(info, opened) || len(content) > maximumLegacyPIDFileSize {
		return fmt.Errorf("legacy Web-TUI PID file %s changed while reading", path)
	}
	pid := strings.TrimRight(string(content), "\n")
	if pid == "" || strings.IndexFunc(pid, func(character rune) bool { return character < '0' || character > '9' }) >= 0 {
		return fmt.Errorf("refusing invalid legacy Web-TUI PID content in %s", path)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) {
		return fmt.Errorf("legacy Web-TUI PID file %s changed while reading", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove legacy Web-TUI PID file %s: %w", path, err)
	}
	if err := verifyRetiredPathAbsent(path); err != nil {
		return err
	}
	if err := syncParentDirectory(path); err != nil {
		return fmt.Errorf("sync removed legacy Web-TUI PID file %s: %w", path, err)
	}
	return nil
}

func verifyLegacyWebTUIRetired(paths ...string) error {
	for _, path := range paths {
		if err := verifyRetiredPathAbsent(path); err != nil {
			return err
		}
	}
	return nil
}

func verifyRetiredPathAbsent(path string) error {
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return fmt.Errorf("retired legacy Web-TUI path %s remains after removal", path)
		}
		return fmt.Errorf("verify retired legacy Web-TUI path %s: %w", path, err)
	}
	return nil
}

func syncParentDirectory(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func readOwnedLegacyService(path string) (string, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return "", fmt.Errorf("legacy service path %s is not a regular file", path)
	}
	if !legacyFileHasExpectedOwner(before) {
		return "", fmt.Errorf("legacy service path %s is not owned by the expected privileged account", path)
	}
	file, err := openFileWithinParent(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !sameLegacyFileSnapshot(before, opened) {
		return "", fmt.Errorf("legacy service path %s changed while opening", path)
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumLegacyServiceFileSize+1))
	if err != nil {
		return "", fmt.Errorf("read legacy service path %s: %w", path, err)
	}
	if len(content) > maximumLegacyServiceFileSize {
		return "", fmt.Errorf("legacy service path %s exceeds the cleanup limit", path)
	}
	openedAfter, err := file.Stat()
	if err != nil || !sameLegacyFileSnapshot(opened, openedAfter) {
		return "", fmt.Errorf("legacy service path %s changed while reading", path)
	}
	after, err := os.Lstat(path)
	if err != nil || !sameLegacyFileSnapshot(openedAfter, after) {
		return "", fmt.Errorf("legacy service path %s changed while reading", path)
	}
	return string(content), nil
}

func sameLegacyFileSnapshot(first, second os.FileInfo) bool {
	firstStat, firstOK := first.Sys().(*syscall.Stat_t)
	secondStat, secondOK := second.Sys().(*syscall.Stat_t)
	return firstOK && secondOK &&
		os.SameFile(first, second) &&
		first.Mode() == second.Mode() &&
		first.Size() == second.Size() &&
		first.ModTime() == second.ModTime() &&
		sameLegacyStatSnapshot(firstStat, secondStat)
}

func sameLegacyStatSnapshot(first, second *syscall.Stat_t) bool {
	return first.Uid == second.Uid &&
		first.Gid == second.Gid &&
		first.Ctim == second.Ctim
}

func legacyFileHasExpectedOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == legacyWebTUIExpectedOwnerUID && stat.Gid == legacyWebTUIExpectedOwnerGID
}

func openFileWithinParent(path string) (*os.File, error) {
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	file, openErr := parent.Open(filepath.Base(path))
	closeErr := parent.Close()
	if openErr != nil {
		return nil, openErr
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, closeErr
	}
	return file, nil
}
