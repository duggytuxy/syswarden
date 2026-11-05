package system

import (
	"errors"
	"fmt"
)

const nativeInstallPhaseEnvironment = "SYSWARDEN_NATIVE_INSTALL_PHASE"

type installationServiceState struct {
	name, load, active, enabled string
	runlevels                   string
}

type installationServiceSnapshot [2]installationServiceState

// NativeServiceInstallation holds the observed pair, not permission to repair
// an administrator's stopped, disabled, masked or missing service automatically.
type NativeServiceInstallation struct {
	fresh    bool
	deferred bool
	alpine   bool
	snapshot installationServiceSnapshot
	inspect  func() (installationServiceSnapshot, error)
}

// Deferred reports that only package staging is permitted. A nil plan belongs
// to an explicit non-package install, whose existing behavior is unchanged.
func (plan *NativeServiceInstallation) Deferred() bool {
	return plan != nil && plan.deferred
}

// Revalidate refuses a manager or pair-state change before automatic mutation.
// This is a bounded observation, not a lock against concurrent administrator
// service-manager operations.
func (plan *NativeServiceInstallation) Revalidate() error {
	if plan == nil {
		return nil
	}
	if plan.deferred || plan.inspect == nil {
		return errors.New("native service activation is deferred; administrator review is required")
	}
	current, err := plan.inspect()
	if err != nil {
		return err
	}
	if current != plan.snapshot {
		return errors.New("native service state changed after installation preflight; refusing automatic activation")
	}
	return nil
}

// PrepareNativeServiceInstallation is read-only. Native hooks provide their
// actual operation, and an absent or unknown operation never authorizes first
// activation. Offline qualification staging is handled before this boundary.
func PrepareNativeServiceInstallation() (*NativeServiceInstallation, error) {
	if servicePackageEnvironment("SYSWARDEN_PKG_INSTALL") != "1" {
		return nil, nil
	}
	phase := servicePackageEnvironment(nativeInstallPhaseEnvironment)
	if phase != "fresh" && phase != "upgrade" {
		return &NativeServiceInstallation{deferred: true}, nil
	}
	alpine := IsAlpine()
	managerState, err := classifyServiceManagerRuntime(alpine)
	if err != nil {
		return nil, fmt.Errorf("inspect native service manager before installation: %w", err)
	}
	if managerState != serviceManagerActive {
		return &NativeServiceInstallation{deferred: true}, nil
	}
	executor := hostFirewallExecutor()
	inspect, err := installationServiceInspector(executor, alpine)
	if err != nil {
		return nil, err
	}
	observed := func() (installationServiceSnapshot, error) {
		state, err := classifyServiceManagerRuntime(alpine)
		if err != nil || state != serviceManagerActive {
			return installationServiceSnapshot{}, errors.Join(errors.New("native service manager is no longer active"), err)
		}
		return inspect()
	}
	return prepareNativeServiceInstallation(phase, alpine, observed)
}

func prepareNativeServiceInstallation(phase string, alpine bool, inspect func() (installationServiceSnapshot, error)) (*NativeServiceInstallation, error) {
	plan := &NativeServiceInstallation{alpine: alpine, inspect: inspect}
	if phase != "fresh" && phase != "upgrade" {
		plan.deferred = true
		return plan, nil
	}
	if inspect == nil {
		return nil, errors.New("missing native service observer")
	}
	state, err := inspect()
	if err != nil {
		return nil, fmt.Errorf("inspect native service pair: %w", err)
	}
	plan.snapshot = state
	if phase == "fresh" {
		plan.fresh = true
		for _, service := range state {
			if service.load != "not-found" || service.active != "inactive" || service.enabled != "disabled" || service.runlevels != "" {
				plan.deferred = true
			}
		}
	} else {
		for _, service := range state {
			if service.load != "loaded" || service.active != "active" || service.enabled != "enabled" {
				plan.deferred = true
			}
		}
	}
	if !plan.deferred {
		if err := plan.Revalidate(); err != nil {
			return nil, err
		}
	}
	return plan, nil
}

func installationServiceInspector(executor firewallManagerExecutor, alpine bool) (func() (installationServiceSnapshot, error), error) {
	if !alpine {
		manager, err := resolveFirewallExecutable(executor, "systemctl")
		if err != nil {
			return nil, err
		}
		return func() (installationServiceSnapshot, error) {
			return inspectInstallationSystemdServices(executor, manager)
		}, nil
	}
	return func() (installationServiceSnapshot, error) {
		if err := nativeOpenRCEnvironment(); err != nil {
			return installationServiceSnapshot{}, err
		}
		return inspectNativeOpenRCServices(nativeOpenRCObserver{root: "/", uid: 0, gid: 0}, observeNativeOpenRCCore)
	}, nil
}

func inspectInstallationSystemdServices(executor firewallManagerExecutor, manager string) (installationServiceSnapshot, error) {
	var snapshot installationServiceSnapshot
	for index, name := range []string{"syswarden-firewall.service", "syswarden-core.service"} {
		state := installationServiceState{name: name, active: "inactive", enabled: "disabled"}
		var err error
		state.load, err = queryFirewallProperty(executor, manager, name, "LoadState")
		if err != nil {
			return snapshot, err
		}
		// Unknown or masked load states defer, rather than being treated as absent.
		if state.load == "loaded" || state.load == "masked" || state.load == "not-found" {
			state.active, err = queryFirewallProperty(executor, manager, name, "ActiveState")
			if err != nil {
				return snapshot, err
			}
			if state.load != "not-found" {
				state.enabled, err = queryFirewallProperty(executor, manager, name, "UnitFileState")
				if err != nil {
					return snapshot, err
				}
			}
		}
		snapshot[index] = state
	}
	return snapshot, nil
}

// RestartExistingCore applies the observed upgrade disposition to an earlier
// recovery restart without falling back to unconditional service activation.
func (plan *NativeServiceInstallation) RestartExistingCore() error {
	return plan.activateExisting(runServiceManagerCommand)
}

// activateExisting preserves enablement, including custom OpenRC runlevels.
// The pair is checked again after manager reload and immediately before restart.
func (plan *NativeServiceInstallation) activateExisting(run serviceManagerRunner) error {
	if plan == nil || plan.fresh || plan.deferred {
		return errors.New("existing-service activation requires an observed upgrade")
	}
	if err := plan.Revalidate(); err != nil {
		return err
	}
	if !plan.alpine {
		if err := run("systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("reload systemd before guarded restart: %w", err)
		}
	}
	if err := plan.Revalidate(); err != nil {
		return err
	}
	var err error
	if plan.alpine {
		err = run("rc-service", "--ifstarted", "syswarden-core", "restart")
	} else {
		err = run("systemctl", "try-restart", "syswarden-core.service")
	}
	if err != nil {
		return fmt.Errorf("conditionally restart existing core: %w", err)
	}
	return plan.Revalidate()
}

// Existing installations retain all enablement artifacts byte for byte, even
// when their membership uses a custom runlevel or target. Only explicit fresh
// installation may create the default enablement links.
func publishInstallationServiceArtifacts(enable bool, artifacts []serviceArtifact) error {
	if enable {
		return publishServiceArtifacts(artifacts)
	}
	definitions := make([]serviceArtifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.target == "" {
			definitions = append(definitions, artifact)
		}
	}
	return publishServiceArtifacts(definitions)
}
