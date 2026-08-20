package system

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syswarden-cli/config"
)

type firewallManagerExecutor struct {
	lookPath func(string) (string, error)
	output   func(string, ...string) ([]byte, error)
	run      func(string, ...string) error
}

type firewallUnitSnapshot struct {
	name    string
	loaded  bool
	enabled bool
	active  bool
}

var (
	firewallCommandLookPath   = exec.LookPath
	firewallCommandLstat      = os.Lstat
	firewallRuntimeClassifier = classifyServiceManagerRuntime
	firewallPlatformIsAlpine  = IsAlpine
	firewallBackendTransition = func(backend string) error {
		return transitionFirewallBackend(backend, hostFirewallExecutor())
	}
)

func firewalldConflictApplicable() (bool, error) {
	if path, err := firewallCommandLookPath("firewall-cmd"); err == nil {
		if path == "" {
			return false, fmt.Errorf("firewall-cmd lookup returned an empty path")
		}
		return true, nil
	} else if !errors.Is(err, exec.ErrNotFound) {
		return false, fmt.Errorf("inspect firewall-cmd applicability: %w", err)
	}
	for _, path := range []string{
		"/usr/bin/firewall-cmd",
		"/usr/sbin/firewall-cmd",
		"/bin/firewall-cmd",
		"/sbin/firewall-cmd",
	} {
		if _, err := firewallCommandLstat(path); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("inspect firewalld command path %s: %w", path, err)
		}
	}
	return false, nil
}

func hostFirewallExecutor() firewallManagerExecutor {
	return firewallManagerExecutor{
		lookPath: exec.LookPath,
		output: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).Output() // #nosec G204 -- executable and arguments are fixed below
		},
		run: func(name string, args ...string) error {
			return exec.Command(name, args...).Run() // #nosec G204 -- executable and arguments are fixed below
		},
	}
}

func queryFirewallUnit(executor firewallManagerExecutor, unit string) (firewallUnitSnapshot, error) {
	query := func(property string) (string, error) {
		output, err := executor.output("systemctl", "show", "--property="+property, "--value", unit)
		if err != nil {
			return "", fmt.Errorf("query %s for %s: %w", property, unit, err)
		}
		value := strings.TrimSpace(string(output))
		if value == "" || strings.ContainsAny(value, "\x00\r\n") {
			return "", fmt.Errorf("invalid %s for %s", property, unit)
		}
		return value, nil
	}
	loadState, err := query("LoadState")
	if err != nil {
		return firewallUnitSnapshot{}, err
	}
	snapshot := firewallUnitSnapshot{name: unit, loaded: loadState == "loaded"}
	if loadState == "not-found" {
		return snapshot, nil
	}
	if !snapshot.loaded {
		return firewallUnitSnapshot{}, fmt.Errorf("refusing ambiguous LoadState %q for %s", loadState, unit)
	}
	unitFileState, err := query("UnitFileState")
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
	activeState, err := query("ActiveState")
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

func restoreFirewallUnit(executor firewallManagerExecutor, snapshot firewallUnitSnapshot) error {
	current, err := queryFirewallUnit(executor, snapshot.name)
	if err != nil {
		return fmt.Errorf("inspect %s before rollback: %w", snapshot.name, err)
	}
	if current == snapshot {
		return nil
	}
	if !snapshot.loaded {
		return fmt.Errorf("unit %s appeared during firewall transaction", snapshot.name)
	}
	if snapshot.enabled {
		if err := executor.run("systemctl", "enable", snapshot.name); err != nil {
			return fmt.Errorf("restore enabled state for %s: %w", snapshot.name, err)
		}
	} else if err := executor.run("systemctl", "disable", snapshot.name); err != nil {
		return fmt.Errorf("restore disabled state for %s: %w", snapshot.name, err)
	}
	if snapshot.active {
		if err := executor.run("systemctl", "start", snapshot.name); err != nil {
			return fmt.Errorf("restore active state for %s: %w", snapshot.name, err)
		}
	} else if err := executor.run("systemctl", "stop", snapshot.name); err != nil {
		return fmt.Errorf("restore inactive state for %s: %w", snapshot.name, err)
	}
	restored, err := queryFirewallUnit(executor, snapshot.name)
	if err != nil {
		return fmt.Errorf("attest rollback for %s: %w", snapshot.name, err)
	}
	if restored != snapshot {
		return fmt.Errorf("rollback attestation failed for %s", snapshot.name)
	}
	return nil
}

func transitionFirewallBackend(backend string, executor firewallManagerExecutor) error {
	if executor.lookPath == nil || executor.output == nil || executor.run == nil {
		return fmt.Errorf("firewall manager executor is incomplete")
	}
	targetTool := "iptables"
	if backend == "nftables" {
		targetTool = "nft"
	}
	if _, err := executor.lookPath(targetTool); err != nil {
		return fmt.Errorf("%s executable is required for the %s backend: %w", targetTool, backend, err)
	}
	targetUnit := backend + ".service"
	firewalld, err := queryFirewallUnit(executor, "firewalld.service")
	if err != nil {
		return err
	}
	target, err := queryFirewallUnit(executor, targetUnit)
	if err != nil {
		return err
	}
	if !target.loaded {
		return fmt.Errorf("required firewall unit %s is not loaded", targetUnit)
	}
	confirmedFirewalld, err := queryFirewallUnit(executor, firewalld.name)
	if err != nil {
		return fmt.Errorf("reinspect firewall unit %s before mutation: %w", firewalld.name, err)
	}
	if confirmedFirewalld != firewalld {
		return fmt.Errorf("firewall unit %s changed before mutation", firewalld.name)
	}
	confirmedTarget, err := queryFirewallUnit(executor, target.name)
	if err != nil {
		return fmt.Errorf("reinspect firewall unit %s before mutation: %w", target.name, err)
	}
	if confirmedTarget != target {
		return fmt.Errorf("firewall unit %s changed before mutation", target.name)
	}
	snapshots := []firewallUnitSnapshot{firewalld, target}
	rollback := func(cause error) error {
		errs := []error{cause}
		for index := len(snapshots) - 1; index >= 0; index-- {
			if restoreErr := restoreFirewallUnit(executor, snapshots[index]); restoreErr != nil {
				errs = append(errs, restoreErr)
			}
		}
		return errors.Join(errs...)
	}
	if firewalld.loaded {
		if err := executor.run("systemctl", "disable", "--now", firewalld.name); err != nil {
			return rollback(fmt.Errorf("disable %s: %w", firewalld.name, err))
		}
	}
	if err := executor.run("systemctl", "enable", "--now", target.name); err != nil {
		return rollback(fmt.Errorf("enable %s: %w", target.name, err))
	}
	attestedFirewalld, err := queryFirewallUnit(executor, firewalld.name)
	if err != nil {
		return rollback(err)
	}
	attestedTarget, err := queryFirewallUnit(executor, target.name)
	if err != nil {
		return rollback(err)
	}
	if firewalld.loaded && (attestedFirewalld.enabled || attestedFirewalld.active) {
		return rollback(fmt.Errorf("%s remains enabled or active", firewalld.name))
	}
	if !attestedTarget.loaded || !attestedTarget.enabled || !attestedTarget.active {
		return rollback(fmt.Errorf("%s did not become enabled and active", target.name))
	}
	return nil
}

// OptimizeHostFirewall respects the configured persistent firewall backend.
func OptimizeHostFirewall() error {
	backend := config.GlobalConfig.FirewallBackend
	if backend == "" || backend == "keep" {
		fmt.Println("[INFO] Preserving the operator-managed firewall backend without service-manager changes.")
		return nil
	}
	applicable, err := firewalldConflictApplicable()
	if err != nil {
		return err
	}
	if !applicable {
		fmt.Println("[INFO] Firewalld is absent; no firewall service transition is required.")
		return nil
	}
	alpine := firewallPlatformIsAlpine()
	managerState, err := firewallRuntimeClassifier(alpine)
	if err != nil {
		return fmt.Errorf("classify service-manager runtime before firewall optimization: %w", err)
	}
	if managerState == serviceManagerOffline {
		return fmt.Errorf("firewall backend %s requires an attestable active service manager; offline transition is refused", backend)
	}
	if alpine {
		return fmt.Errorf("firewall backend transition %s has no exact OpenRC transaction contract", backend)
	}
	if backend != "nftables" && backend != "iptables" {
		return fmt.Errorf("unsupported firewall backend %q", backend)
	}
	return firewallBackendTransition(backend)
}
