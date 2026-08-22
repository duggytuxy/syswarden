package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"syswarden-cli/config"
	"time"
)

const (
	maximumFirewallPreflightOutput = 64 << 10
	firewallPreflightTimeout       = 15 * time.Second
)

type firewallManagerExecutor struct {
	lookPath func(string) (string, error)
	validate func(string) error
	output   func(string, ...string) ([]byte, error)
}

type firewallUnitSnapshot struct {
	name    string
	loaded  bool
	enabled bool
	active  bool
}

type openRCFirewallUnitSnapshot struct {
	name    string
	loaded  bool
	active  bool
	enabled bool
}

var (
	firewallCommandLookPath   = exec.LookPath
	firewallCommandValidate   = validateResolvedFirewallExecutable
	firewallCommandOutput     = runFirewallPreflightCommand
	firewallRuntimeClassifier = classifyServiceManagerRuntime
	firewallPlatformIsAlpine  = IsAlpine
)

func hostFirewallExecutor() firewallManagerExecutor {
	return firewallManagerExecutor{
		lookPath: firewallCommandLookPath,
		validate: firewallCommandValidate,
		output:   firewallCommandOutput,
	}
}

func resolveFirewallExecutable(executor firewallManagerExecutor, name string) (string, error) {
	path, err := executor.lookPath(name)
	if err != nil {
		return "", fmt.Errorf("resolve required %s executable: %w", name, err)
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("required %s executable did not resolve to a clean absolute path", name)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve required %s executable target: %w", name, err)
	}
	resolved = filepath.Clean(resolved)
	if !filepath.IsAbs(resolved) {
		return "", fmt.Errorf("required %s executable target is not absolute", name)
	}
	if err := executor.validate(resolved); err != nil {
		return "", fmt.Errorf("validate required %s executable: %w", name, err)
	}
	return resolved, nil
}

type boundedFirewallPreflightOutput struct {
	content  bytes.Buffer
	exceeded bool
}

func (output *boundedFirewallPreflightOutput) Write(content []byte) (int, error) {
	remaining := maximumFirewallPreflightOutput - output.content.Len()
	if remaining > 0 {
		written := len(content)
		if written > remaining {
			written = remaining
		}
		_, _ = output.content.Write(content[:written])
	}
	if len(content) > remaining {
		output.exceeded = true
	}
	return len(content), nil
}

func validateResolvedFirewallExecutable(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("firewall preflight executable path %q is not a clean absolute path", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect firewall preflight executable %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 || !ok {
		return fmt.Errorf("firewall preflight executable %s is not a trusted non-writable regular executable", path)
	}
	if stat.Uid != 0 && int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("firewall preflight executable %s is not owned by root or the effective user", path)
	}
	rootInfo, err := os.Lstat(string(filepath.Separator))
	if err != nil {
		return fmt.Errorf("inspect filesystem root for firewall preflight executable: %w", err)
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !rootInfo.IsDir() || !ok {
		return fmt.Errorf("filesystem root is not an attestable directory")
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("inspect firewall preflight executable directory %s: %w", directory, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		writable := info.Mode().Perm()&0022 != 0
		if !info.IsDir() || !ok || writable && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("firewall preflight executable directory %s is not trusted", directory)
		}
		if stat.Uid != 0 && int64(stat.Uid) != int64(os.Geteuid()) && stat.Uid != rootStat.Uid {
			return fmt.Errorf("firewall preflight executable directory %s is not owned by root, the effective user, or the filesystem-root owner", directory)
		}
		if directory == string(filepath.Separator) {
			break
		}
	}
	return nil
}

func runFirewallPreflightCommand(path string, arguments ...string) ([]byte, error) {
	return runFirewallPreflightCommandWithTimeout(path, firewallPreflightTimeout, arguments...)
}

func runFirewallPreflightCommandWithTimeout(path string, timeout time.Duration, arguments ...string) ([]byte, error) {
	if err := validateResolvedFirewallExecutable(path); err != nil {
		return nil, err
	}
	if timeout <= 0 || timeout > firewallPreflightTimeout {
		return nil, fmt.Errorf("invalid firewall preflight command timeout %s", timeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, path, arguments...) // #nosec G204 -- path and arguments are validated before execution
	command.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = time.Second
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	output := &boundedFirewallPreflightOutput{}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if errors.Is(err, exec.ErrWaitDelay) && command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	content := append([]byte(nil), output.content.Bytes()...)
	if output.exceeded {
		return content, fmt.Errorf("firewall preflight command output exceeds %d bytes", maximumFirewallPreflightOutput)
	}
	if ctx.Err() != nil {
		return content, fmt.Errorf("firewall preflight command exceeded %s: %w", timeout, ctx.Err())
	}
	return content, err
}

func queryFirewallProperty(
	executor firewallManagerExecutor,
	systemctlPath string,
	unit string,
	property string,
) (string, error) {
	output, err := executor.output(systemctlPath, "show", "--property="+property, "--value", unit)
	if err != nil {
		return "", fmt.Errorf("query %s for %s: %w", property, unit, err)
	}
	value := strings.TrimSpace(string(output))
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("invalid %s for %s", property, unit)
	}
	return value, nil
}

func queryFirewallUnitActivity(
	executor firewallManagerExecutor,
	systemctlPath string,
	unit string,
) (firewallUnitSnapshot, error) {
	loadState, err := queryFirewallProperty(executor, systemctlPath, unit, "LoadState")
	if err != nil {
		return firewallUnitSnapshot{}, err
	}
	snapshot := firewallUnitSnapshot{name: unit}
	switch loadState {
	case "not-found":
		return snapshot, nil
	case "loaded":
		snapshot.loaded = true
	default:
		return firewallUnitSnapshot{}, fmt.Errorf("refusing ambiguous LoadState %q for %s", loadState, unit)
	}

	activeState, err := queryFirewallProperty(executor, systemctlPath, unit, "ActiveState")
	if err != nil {
		return firewallUnitSnapshot{}, err
	}
	switch activeState {
	case "active":
		snapshot.active = true
	case "inactive":
	default:
		return firewallUnitSnapshot{}, fmt.Errorf("refusing ambiguous ActiveState %q for %s", activeState, unit)
	}
	return snapshot, nil
}

func queryFirewallTargetUnit(
	executor firewallManagerExecutor,
	systemctlPath string,
	unit string,
) (firewallUnitSnapshot, error) {
	snapshot, err := queryFirewallUnitActivity(executor, systemctlPath, unit)
	if err != nil {
		return firewallUnitSnapshot{}, err
	}
	if !snapshot.loaded {
		return snapshot, nil
	}
	unitFileState, err := queryFirewallProperty(executor, systemctlPath, unit, "UnitFileState")
	if err != nil {
		return firewallUnitSnapshot{}, err
	}
	switch unitFileState {
	case "enabled":
		snapshot.enabled = true
	case "disabled":
	default:
		return firewallUnitSnapshot{}, fmt.Errorf("refusing ambiguous UnitFileState %q for %s", unitFileState, unit)
	}
	return snapshot, nil
}

func queryConflictingFirewallUnit(
	executor firewallManagerExecutor,
	systemctlPath string,
	unit string,
) (firewallUnitSnapshot, error) {
	snapshot, err := queryFirewallUnitActivity(executor, systemctlPath, unit)
	if err != nil || !snapshot.loaded {
		return snapshot, err
	}
	unitFileState, err := queryFirewallProperty(executor, systemctlPath, unit, "UnitFileState")
	if err != nil {
		return firewallUnitSnapshot{}, err
	}
	switch unitFileState {
	case "enabled", "enabled-runtime":
		snapshot.enabled = true
	case "disabled", "masked":
	default:
		return firewallUnitSnapshot{}, fmt.Errorf("refusing ambiguous UnitFileState %q for %s", unitFileState, unit)
	}
	return snapshot, nil
}

func inspectFirewallBackendSnapshot(
	executor firewallManagerExecutor,
	systemctlPath string,
) ([6]firewallUnitSnapshot, error) {
	target, err := queryFirewallTargetUnit(executor, systemctlPath, "nftables.service")
	if err != nil {
		return [6]firewallUnitSnapshot{}, fmt.Errorf("inspect nftables target unit: %w", err)
	}
	firewalld, err := queryConflictingFirewallUnit(executor, systemctlPath, "firewalld.service")
	if err != nil {
		return [6]firewallUnitSnapshot{}, fmt.Errorf("inspect firewalld frontend: %w", err)
	}
	ufw, err := queryConflictingFirewallUnit(executor, systemctlPath, "ufw.service")
	if err != nil {
		return [6]firewallUnitSnapshot{}, fmt.Errorf("inspect UFW frontend: %w", err)
	}
	iptables, err := queryConflictingFirewallUnit(executor, systemctlPath, "iptables.service")
	if err != nil {
		return [6]firewallUnitSnapshot{}, fmt.Errorf("inspect iptables-services IPv4 frontend: %w", err)
	}
	ip6tables, err := queryConflictingFirewallUnit(executor, systemctlPath, "ip6tables.service")
	if err != nil {
		return [6]firewallUnitSnapshot{}, fmt.Errorf("inspect iptables-services IPv6 frontend: %w", err)
	}
	netfilterPersistent, err := queryConflictingFirewallUnit(executor, systemctlPath, "netfilter-persistent.service")
	if err != nil {
		return [6]firewallUnitSnapshot{}, fmt.Errorf("inspect netfilter-persistent frontend: %w", err)
	}
	return [6]firewallUnitSnapshot{target, firewalld, ufw, iptables, ip6tables, netfilterPersistent}, nil
}

func validateNftablesSnapshot(snapshot [6]firewallUnitSnapshot) error {
	target := snapshot[0]
	if !target.loaded {
		return fmt.Errorf("required firewall unit %s is not loaded", target.name)
	}
	if !target.enabled || !target.active {
		return fmt.Errorf("required firewall unit %s must already be enabled and active", target.name)
	}
	activeFrontends := make([]string, 0, len(snapshot)-1)
	enabledFrontends := make([]string, 0, len(snapshot)-1)
	for _, frontend := range snapshot[1:] {
		if frontend.active {
			activeFrontends = append(activeFrontends, frontend.name)
		}
		if frontend.enabled {
			enabledFrontends = append(enabledFrontends, frontend.name)
		}
	}
	if len(activeFrontends) > 1 {
		return fmt.Errorf("multiple active firewall frontends detected: %s", strings.Join(activeFrontends, ", "))
	}
	if len(activeFrontends) == 1 {
		return fmt.Errorf("active firewall frontend %s conflicts with the explicit nftables backend", activeFrontends[0])
	}
	if len(enabledFrontends) > 0 {
		return fmt.Errorf("enabled firewall frontend %s conflicts with the explicit nftables backend", strings.Join(enabledFrontends, ", "))
	}
	return nil
}

func validateKeepSystemdSnapshot(snapshot [3]firewallUnitSnapshot) error {
	for _, frontend := range snapshot {
		if frontend.active || frontend.enabled {
			return fmt.Errorf("iptables compatibility service %s must be inactive and disabled before keep-mode policy mutation", frontend.name)
		}
	}
	return nil
}

func inspectKeepSystemdSnapshot(executor firewallManagerExecutor, systemctlPath string) ([3]firewallUnitSnapshot, error) {
	var snapshot [3]firewallUnitSnapshot
	for index, unit := range []string{"iptables.service", "ip6tables.service", "netfilter-persistent.service"} {
		state, err := queryConflictingFirewallUnit(executor, systemctlPath, unit)
		if err != nil {
			return [3]firewallUnitSnapshot{}, fmt.Errorf("inspect keep-mode compatibility service %s: %w", unit, err)
		}
		snapshot[index] = state
	}
	return snapshot, nil
}

func inspectOpenRCRunlevelMembership(output []byte, tracked map[string]bool) (map[string]bool, error) {
	enabled := make(map[string]bool, len(tracked))
	seen := make(map[string]bool, len(tracked))
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 2 {
			return nil, fmt.Errorf("refusing malformed OpenRC runlevel inventory")
		}
		name := strings.TrimSpace(parts[0])
		if !tracked[name] {
			continue
		}
		if seen[name] {
			return nil, fmt.Errorf("refusing duplicate OpenRC runlevel inventory for %s", name)
		}
		seen[name] = true
		runlevels := strings.Fields(parts[1])
		if len(runlevels) == 0 {
			return nil, fmt.Errorf("refusing empty OpenRC runlevel inventory for %s", name)
		}
		enabled[name] = true
	}
	return enabled, nil
}

func inspectKeepOpenRCSnapshot(
	executor firewallManagerExecutor,
	servicePath string,
	runlevelPath string,
) ([2]openRCFirewallUnitSnapshot, error) {
	names := []string{"iptables", "ip6tables"}
	tracked := map[string]bool{"iptables": true, "ip6tables": true}
	runlevelOutput, err := executor.output(runlevelPath, "show")
	if err != nil {
		return [2]openRCFirewallUnitSnapshot{}, fmt.Errorf("inspect OpenRC firewall runlevels: %w", err)
	}
	enabled, err := inspectOpenRCRunlevelMembership(runlevelOutput, tracked)
	if err != nil {
		return [2]openRCFirewallUnitSnapshot{}, err
	}
	var snapshot [2]openRCFirewallUnitSnapshot
	for index, name := range names {
		state := openRCFirewallUnitSnapshot{name: name, enabled: enabled[name]}
		_, existsErr := executor.output(servicePath, "--exists", name)
		if existsErr != nil {
			code, exact := firewallRemovalExitCode(existsErr)
			if !exact || code != 1 {
				return [2]openRCFirewallUnitSnapshot{}, fmt.Errorf("inspect OpenRC firewall service %s: %w", name, existsErr)
			}
			if state.enabled {
				return [2]openRCFirewallUnitSnapshot{}, fmt.Errorf("absent OpenRC firewall service %s remains enabled", name)
			}
			snapshot[index] = state
			continue
		}
		state.loaded = true
		_, statusErr := executor.output(servicePath, name, "status")
		if statusErr == nil {
			state.active = true
		} else {
			code, exact := firewallRemovalExitCode(statusErr)
			if !exact || (code != 3 && code != 16) {
				return [2]openRCFirewallUnitSnapshot{}, fmt.Errorf("inspect OpenRC firewall service status for %s: %w", name, statusErr)
			}
		}
		snapshot[index] = state
	}
	return snapshot, nil
}

func validateKeepOpenRCSnapshot(snapshot [2]openRCFirewallUnitSnapshot) error {
	for _, frontend := range snapshot {
		if frontend.active || frontend.enabled {
			return fmt.Errorf("OpenRC iptables compatibility service %s must be inactive and disabled before keep-mode policy mutation", frontend.name)
		}
	}
	return nil
}

func preflightKeepFirewallBackend(
	executor firewallManagerExecutor,
	alpine bool,
) error {
	if alpine {
		servicePath, err := resolveFirewallExecutable(executor, "rc-service")
		if err != nil {
			return err
		}
		runlevelPath, err := resolveFirewallExecutable(executor, "rc-update")
		if err != nil {
			return err
		}
		initial, err := inspectKeepOpenRCSnapshot(executor, servicePath, runlevelPath)
		if err != nil {
			return err
		}
		if err := validateKeepOpenRCSnapshot(initial); err != nil {
			return err
		}
		confirmed, err := inspectKeepOpenRCSnapshot(executor, servicePath, runlevelPath)
		if err != nil {
			return fmt.Errorf("reinspect OpenRC keep-mode firewall state: %w", err)
		}
		if confirmed != initial {
			return fmt.Errorf("OpenRC keep-mode firewall state changed during preflight")
		}
		return validateKeepOpenRCSnapshot(confirmed)
	}

	systemctlPath, err := resolveFirewallExecutable(executor, "systemctl")
	if err != nil {
		return err
	}
	initial, err := inspectKeepSystemdSnapshot(executor, systemctlPath)
	if err != nil {
		return err
	}
	if err := validateKeepSystemdSnapshot(initial); err != nil {
		return err
	}
	confirmed, err := inspectKeepSystemdSnapshot(executor, systemctlPath)
	if err != nil {
		return fmt.Errorf("reinspect keep-mode firewall state: %w", err)
	}
	if confirmed != initial {
		return fmt.Errorf("keep-mode firewall state changed during preflight")
	}
	return validateKeepSystemdSnapshot(confirmed)
}

func preflightHostFirewallBackend(
	backend string,
	executor firewallManagerExecutor,
	isAlpine func() bool,
	classifyRuntime func(bool) (serviceManagerState, error),
) error {
	switch backend {
	case "", "keep":
		backend = "keep"
	case "iptables":
		return fmt.Errorf("iptables is accepted for configuration compatibility but refused for host-mutating install and reload workflows")
	case "nftables":
	default:
		return fmt.Errorf("unsupported firewall backend %q", backend)
	}

	if executor.lookPath == nil || executor.validate == nil || executor.output == nil || isAlpine == nil || classifyRuntime == nil {
		return fmt.Errorf("firewall backend preflight dependencies are incomplete")
	}
	alpine := isAlpine()
	managerState, err := classifyRuntime(alpine)
	if err != nil {
		return fmt.Errorf("attest service-manager runtime for firewall preflight: %w", err)
	}
	if managerState != serviceManagerActive {
		return fmt.Errorf("firewall policy mutation requires an attestable active service manager, got %s", managerState)
	}
	if backend == "keep" {
		return preflightKeepFirewallBackend(executor, alpine)
	}
	if alpine {
		return fmt.Errorf("the explicit nftables backend requires systemd service attestation; OpenRC is not supported")
	}

	systemctlPath, err := resolveFirewallExecutable(executor, "systemctl")
	if err != nil {
		return err
	}
	if _, err := resolveFirewallExecutable(executor, "nft"); err != nil {
		return err
	}

	initial, err := inspectFirewallBackendSnapshot(executor, systemctlPath)
	if err != nil {
		return err
	}
	if err := validateNftablesSnapshot(initial); err != nil {
		return err
	}
	confirmed, err := inspectFirewallBackendSnapshot(executor, systemctlPath)
	if err != nil {
		return fmt.Errorf("reinspect firewall backend state: %w", err)
	}
	if confirmed != initial {
		return fmt.Errorf("firewall backend state changed during preflight")
	}
	if err := validateNftablesSnapshot(confirmed); err != nil {
		return fmt.Errorf("revalidate firewall backend state: %w", err)
	}
	return nil
}

// PreflightHostFirewallBackend validates a host-mutating install or reload
// before any mutation. It never changes service or kernel firewall state.
func PreflightHostFirewallBackend(backend string) error {
	return preflightHostFirewallBackend(
		backend,
		hostFirewallExecutor(),
		firewallPlatformIsAlpine,
		firewallRuntimeClassifier,
	)
}

// OptimizeHostFirewall is the compatibility wrapper used by the current
// installer. New install and reload entry points must call
// PreflightHostFirewallBackend at the beginning of their mutating transaction.
func OptimizeHostFirewall() error {
	backend := "keep"
	if config.GlobalConfig != nil && config.GlobalConfig.FirewallBackend != "" {
		backend = config.GlobalConfig.FirewallBackend
	}
	if err := PreflightHostFirewallBackend(backend); err != nil {
		return err
	}
	if backend == "keep" {
		fmt.Println("[INFO] Preserving the operator-managed firewall frontend without service-manager changes.")
		return nil
	}
	if backend == "nftables" {
		fmt.Println("[INFO] Validated the preconfigured nftables backend without changing service or kernel firewall state.")
		return nil
	}
	return errors.New("unreachable firewall backend preflight state")
}
