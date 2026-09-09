//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

type firewallRemovalService struct {
	name      string
	wireGuard bool
}

type firewallRemovalServiceSnapshot struct {
	service         firewallRemovalService
	loaded          bool
	stopRequired    bool
	failedInitially bool
	enabled         bool
	runtimeEnabled  bool
	runlevels       []string
}

type firewallRemovalPreparationHost struct {
	effectiveUID               int
	alpine                     bool
	classifyRuntime            func(bool) (serviceManagerState, error)
	executor                   firewallManagerExecutor
	processScan                func() error
	postStopProcessScan        func() error
	attestWireGuard            func() (firewallRemovalWireGuardEvidence, error)
	verifyWireGuardStopConfig  func() error
	resolveWireGuardExe        func() (string, error)
	wireGuardInterface         func() (bool, error)
	attestSystemdUnit          func(string) error
	attestRHELPackageOwned     func() (bool, error)
	attestRHELPackageUnit      func(string) error
	attestSystemdDropIns       func(firewallManagerExecutor, string) (string, error)
	attestOpenRCUnit           func(firewallRemovalService) error
	openRCUnitPresent          func(firewallRemovalService) (bool, error)
	attestOpenRCRunlevel       func(firewallRemovalService, string) error
	verifyOpenRCRunlevelAbsent func(firewallRemovalService, string) error
}

type firewallRemovalManager struct {
	alpine                     bool
	servicePath                string
	runlevelPath               string
	executor                   firewallManagerExecutor
	attestSystemdUnit          func(string) error
	rhelPackageOwned           bool
	attestRHELPackageUnit      func(string) error
	attestSystemdDropIns       func(firewallManagerExecutor, string) (string, error)
	attestOpenRCUnit           func(firewallRemovalService) error
	openRCUnitPresent          func(firewallRemovalService) (bool, error)
	attestOpenRCRunlevel       func(firewallRemovalService, string) error
	verifyOpenRCRunlevelAbsent func(firewallRemovalService, string) error
	resolveWireGuardExe        func() (string, error)
	verifyWireGuardStopConfig  func() error
	wireGuardInterface         func() (bool, error)
}

var firewallRemovalServices = []firewallRemovalService{
	{name: "syswarden-core"},
	{name: "syswarden-firewall"},
	{name: "syswarden"},
	{name: "syswarden-reporter"},
	{name: "wg-quick@wg-syswarden", wireGuard: true},
}

func productionFirewallRemovalPreparationHost() firewallRemovalPreparationHost {
	return firewallRemovalPreparationHost{
		effectiveUID:               os.Geteuid(),
		alpine:                     IsAlpine(),
		classifyRuntime:            classifyServiceManagerRuntime,
		executor:                   hostFirewallExecutor(),
		processScan:                scanExactRootSysWardenCLIMutators,
		postStopProcessScan:        scanExactRootSysWardenProcessesAfterServiceStop,
		attestWireGuard:            attestFirewallRemovalWireGuardState,
		verifyWireGuardStopConfig:  verifyWireGuardServerBeforeRemovalStop,
		resolveWireGuardExe:        resolveWireGuardRemovalExecutable,
		wireGuardInterface:         inspectWireGuardRemovalInterface,
		attestSystemdUnit:          attestSystemdFirewallRemovalUnitFile,
		attestRHELPackageOwned:     attestInstalledRHELPackageOwnedProfile,
		attestRHELPackageUnit:      attestRHELPackageOwnedUnit,
		attestSystemdDropIns:       attestApprovedSystemdServiceDropIns,
		attestOpenRCUnit:           attestOpenRCFirewallRemovalUnit,
		openRCUnitPresent:          inspectOpenRCFirewallRemovalUnitPresence,
		attestOpenRCRunlevel:       attestOpenRCFirewallRemovalRunlevelLink,
		verifyOpenRCRunlevelAbsent: verifyOpenRCFirewallRemovalRunlevelLinkAbsent,
	}
}

func (host firewallRemovalPreparationHost) validate() error {
	if host.effectiveUID != 0 {
		return fmt.Errorf("firewall removal preparation must be executed as root")
	}
	if host.classifyRuntime == nil || host.executor.lookPath == nil || host.executor.validate == nil ||
		host.executor.output == nil || host.processScan == nil || host.postStopProcessScan == nil ||
		host.attestWireGuard == nil ||
		host.verifyWireGuardStopConfig == nil || host.resolveWireGuardExe == nil ||
		host.wireGuardInterface == nil || host.attestSystemdUnit == nil ||
		host.attestSystemdDropIns == nil ||
		host.attestOpenRCUnit == nil || host.openRCUnitPresent == nil || host.attestOpenRCRunlevel == nil ||
		host.verifyOpenRCRunlevelAbsent == nil {
		return fmt.Errorf("firewall removal preparation dependencies are incomplete")
	}
	return nil
}

func (host firewallRemovalPreparationHost) resolveManager() (firewallRemovalManager, error) {
	state, err := host.classifyRuntime(host.alpine)
	if err != nil {
		return firewallRemovalManager{}, fmt.Errorf("attest service-manager runtime before firewall removal: %w", err)
	}
	if state != serviceManagerActive {
		return firewallRemovalManager{}, fmt.Errorf("firewall removal requires an attestable active service manager, got %s", state)
	}

	serviceName := "systemctl"
	if host.alpine {
		serviceName = "rc-service"
	}
	servicePath, err := resolveFirewallExecutable(host.executor, serviceName)
	if err != nil {
		return firewallRemovalManager{}, err
	}
	rhelPackageOwned := false
	if !host.alpine && host.attestRHELPackageOwned != nil {
		rhelPackageOwned, err = host.attestRHELPackageOwned()
		if err != nil {
			return firewallRemovalManager{}, fmt.Errorf("attest RHEL package-owned profile: %w", err)
		}
		if rhelPackageOwned && host.attestRHELPackageUnit == nil {
			return firewallRemovalManager{}, fmt.Errorf("RHEL package-owned unit attestation is unavailable")
		}
	}
	manager := firewallRemovalManager{
		alpine:                     host.alpine,
		servicePath:                servicePath,
		executor:                   host.executor,
		attestSystemdUnit:          host.attestSystemdUnit,
		rhelPackageOwned:           rhelPackageOwned,
		attestRHELPackageUnit:      host.attestRHELPackageUnit,
		attestSystemdDropIns:       host.attestSystemdDropIns,
		attestOpenRCUnit:           host.attestOpenRCUnit,
		openRCUnitPresent:          host.openRCUnitPresent,
		attestOpenRCRunlevel:       host.attestOpenRCRunlevel,
		verifyOpenRCRunlevelAbsent: host.verifyOpenRCRunlevelAbsent,
		resolveWireGuardExe:        host.resolveWireGuardExe,
		verifyWireGuardStopConfig:  host.verifyWireGuardStopConfig,
		wireGuardInterface:         host.wireGuardInterface,
	}
	if host.alpine {
		manager.runlevelPath, err = resolveFirewallExecutable(host.executor, "rc-update")
		if err != nil {
			return firewallRemovalManager{}, err
		}
	}
	return manager, nil
}

type firewallRemovalExitStatus interface {
	ExitCode() int
}

func firewallRemovalExitCode(err error) (int, bool) {
	if err == nil {
		return 0, true
	}
	var status firewallRemovalExitStatus
	if !errors.As(err, &status) {
		return 0, false
	}
	return status.ExitCode(), true
}

func systemdFirewallRemovalUnit(service firewallRemovalService) string {
	return service.name + ".service"
}

func queryOptionalFirewallProperty(
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
	if strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("invalid %s for %s", property, unit)
	}
	return value, nil
}

func exactSystemdExecutionProperty(value string, path string, arguments string) bool {
	if !strings.HasPrefix(value, "{ ") || !strings.HasSuffix(value, " }") {
		return false
	}
	fields := strings.Split(value[2:len(value)-2], " ; ")
	if len(fields) != 8 || fields[0] != "path="+path || fields[1] != "argv[]="+arguments ||
		fields[2] != "ignore_errors=no" || !strings.HasPrefix(fields[3], "start_time=") ||
		len(fields[3]) == len("start_time=") || !strings.HasPrefix(fields[4], "stop_time=") ||
		len(fields[4]) == len("stop_time=") || !strings.HasPrefix(fields[5], "pid=") ||
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
	return true
}

func attestSystemdFirewallRemovalService(
	manager firewallRemovalManager,
	service firewallRemovalService,
) error {
	if service.name == "syswarden" || service.name == "syswarden-reporter" {
		return fmt.Errorf("refusing ambiguous legacy systemd unit %s", systemdFirewallRemovalUnit(service))
	}
	unit := systemdFirewallRemovalUnit(service)
	fragment, err := queryFirewallProperty(manager.executor, manager.servicePath, unit, "FragmentPath")
	if err != nil {
		return err
	}
	dropIns, err := queryOptionalFirewallProperty(manager.executor, manager.servicePath, unit, "DropInPaths")
	if err != nil {
		return err
	}
	if _, err := manager.attestSystemdDropIns(manager.executor, dropIns); err != nil {
		return fmt.Errorf("refusing unapproved systemd drop-ins for firewall mutator %s: %w", unit, err)
	}
	execStart, err := queryFirewallProperty(manager.executor, manager.servicePath, unit, "ExecStart")
	if err != nil {
		return err
	}
	execStop, err := queryOptionalFirewallProperty(manager.executor, manager.servicePath, unit, "ExecStop")
	if err != nil {
		return err
	}

	expectedFragment := ""
	expectedStartPath := ""
	expectedStartArguments := ""
	expectedStopPath := ""
	expectedStopArguments := ""
	switch service.name {
	case "syswarden-core":
		expectedFragment = "/etc/systemd/system/syswarden-core.service"
		if manager.rhelPackageOwned {
			expectedFragment = rhelPackageOwnedCoreUnitPath
		}
		expectedStartPath = "/opt/syswarden/bin/syswarden-core"
		expectedStartArguments = expectedStartPath
	case "syswarden-firewall":
		expectedFragment = "/etc/systemd/system/syswarden-firewall.service"
		if manager.rhelPackageOwned {
			expectedFragment = rhelPackageOwnedFirewallUnitPath
		}
		expectedStartPath = "/opt/syswarden/bin/syswarden-cli"
		expectedStartArguments = expectedStartPath + " reload --no-restart"
	case "wg-quick@wg-syswarden":
		if _, err := manager.resolveWireGuardExe(); err != nil {
			return fmt.Errorf("attest WireGuard executable: %w", err)
		}
		if fragment != "/usr/lib/systemd/system/wg-quick@.service" && fragment != "/lib/systemd/system/wg-quick@.service" {
			return fmt.Errorf("refusing unexpected WireGuard unit fragment %s", fragment)
		}
		expectedStartPath = "/usr/bin/wg-quick"
		expectedStartArguments = expectedStartPath + " up wg-syswarden"
		expectedStopPath = expectedStartPath
		expectedStopArguments = expectedStartPath + " down wg-syswarden"
	default:
		return fmt.Errorf("refusing unknown systemd firewall mutator %s", unit)
	}
	if expectedFragment != "" && fragment != expectedFragment {
		return fmt.Errorf("refusing unexpected unit fragment %s for %s", fragment, unit)
	}
	attestUnit := manager.attestSystemdUnit
	if manager.rhelPackageOwned &&
		(fragment == rhelPackageOwnedCoreUnitPath || fragment == rhelPackageOwnedFirewallUnitPath) {
		attestUnit = manager.attestRHELPackageUnit
	}
	if err := attestUnit(fragment); err != nil {
		return fmt.Errorf("attest unit fragment %s: %w", fragment, err)
	}
	if !exactSystemdExecutionProperty(execStart, expectedStartPath, expectedStartArguments) {
		return fmt.Errorf("refusing unexpected ExecStart for %s", unit)
	}
	if expectedStopPath == "" {
		if execStop != "" {
			return fmt.Errorf("refusing unexpected ExecStop for %s", unit)
		}
	} else if !exactSystemdExecutionProperty(execStop, expectedStopPath, expectedStopArguments) {
		return fmt.Errorf("refusing unexpected ExecStop for %s", unit)
	}
	return nil
}

func inspectSystemdFirewallRemovalService(
	manager firewallRemovalManager,
	service firewallRemovalService,
) (firewallRemovalServiceSnapshot, error) {
	unit := systemdFirewallRemovalUnit(service)
	loadState, err := queryFirewallProperty(manager.executor, manager.servicePath, unit, "LoadState")
	if err != nil {
		return firewallRemovalServiceSnapshot{}, err
	}
	snapshot := firewallRemovalServiceSnapshot{service: service}
	switch loadState {
	case "not-found":
		return snapshot, nil
	case "loaded":
		snapshot.loaded = true
	default:
		return firewallRemovalServiceSnapshot{}, fmt.Errorf("refusing ambiguous LoadState %q for %s", loadState, unit)
	}

	activeState, err := queryFirewallProperty(manager.executor, manager.servicePath, unit, "ActiveState")
	if err != nil {
		return firewallRemovalServiceSnapshot{}, err
	}
	switch activeState {
	case "active":
		snapshot.stopRequired = true
	case "failed":
		// A failed unit is not accepted as quiescent. It is an exact terminal
		// systemd state that must still pass unit attestation, be explicitly
		// stopped, and subsequently prove ActiveState=inactive. A bounded
		// reset-failed transition is available only for this initial state.
		snapshot.stopRequired = true
		snapshot.failedInitially = true
	case "inactive":
	default:
		return firewallRemovalServiceSnapshot{}, fmt.Errorf("refusing ambiguous ActiveState %q for %s", activeState, unit)
	}

	unitFileState, err := queryFirewallProperty(manager.executor, manager.servicePath, unit, "UnitFileState")
	if err != nil {
		return firewallRemovalServiceSnapshot{}, err
	}
	switch unitFileState {
	case "enabled":
		snapshot.enabled = true
	case "enabled-runtime":
		snapshot.enabled = true
		snapshot.runtimeEnabled = true
	case "disabled":
	default:
		return firewallRemovalServiceSnapshot{}, fmt.Errorf("refusing ambiguous UnitFileState %q for %s", unitFileState, unit)
	}
	if err := attestSystemdFirewallRemovalService(manager, service); err != nil {
		return firewallRemovalServiceSnapshot{}, err
	}
	return snapshot, nil
}

func validOpenRCRunlevelForRemoval(value string) bool {
	if value == "" || len(value) > 128 || value[0] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("_.-", character) {
			return false
		}
	}
	return true
}

func inspectOpenRCFirewallRemovalEnablement(manager firewallRemovalManager) (map[string][]string, error) {
	output, err := manager.executor.output(manager.runlevelPath, "show")
	if err != nil {
		return nil, fmt.Errorf("inspect OpenRC runlevel enablement: %w", err)
	}
	enabled := make(map[string][]string, len(firewallRemovalServices))
	known := make(map[string]struct{}, len(firewallRemovalServices))
	for _, service := range firewallRemovalServices {
		name := service.name
		if service.wireGuard {
			name = "wg-quick.wg-syswarden"
		}
		known[name] = struct{}{}
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 2 {
			return nil, fmt.Errorf("refusing malformed OpenRC runlevel inventory")
		}
		name := strings.TrimSpace(parts[0])
		if _, tracked := known[name]; !tracked {
			continue
		}
		if _, duplicate := enabled[name]; duplicate {
			return nil, fmt.Errorf("refusing duplicate OpenRC runlevel inventory for %s", name)
		}
		runlevels := strings.Fields(parts[1])
		if len(runlevels) == 0 {
			return nil, fmt.Errorf("refusing empty OpenRC runlevel inventory for %s", name)
		}
		for _, runlevel := range runlevels {
			if !validOpenRCRunlevelForRemoval(runlevel) {
				return nil, fmt.Errorf("refusing invalid OpenRC runlevel %q for %s", runlevel, name)
			}
		}
		enabled[name] = append([]string(nil), runlevels...)
	}
	return enabled, nil
}

func openRCFirewallRemovalServiceName(service firewallRemovalService) string {
	if service.wireGuard {
		return "wg-quick.wg-syswarden"
	}
	return service.name
}

func inspectOpenRCFirewallRemovalService(
	manager firewallRemovalManager,
	service firewallRemovalService,
	enablement map[string][]string,
) (firewallRemovalServiceSnapshot, error) {
	name := openRCFirewallRemovalServiceName(service)
	snapshot := firewallRemovalServiceSnapshot{service: service}
	loaded, err := manager.openRCUnitPresent(service)
	if err != nil {
		return firewallRemovalServiceSnapshot{}, err
	}
	if !loaded {
		if len(enablement[name]) != 0 {
			return firewallRemovalServiceSnapshot{}, fmt.Errorf("absent OpenRC service %s remains enabled", name)
		}
		return snapshot, nil
	}
	snapshot.loaded = true
	snapshot.runlevels = append([]string(nil), enablement[name]...)
	snapshot.enabled = len(snapshot.runlevels) != 0

	if service.name == "syswarden" || service.name == "syswarden-reporter" {
		return firewallRemovalServiceSnapshot{}, fmt.Errorf("refusing ambiguous legacy OpenRC service %s", name)
	}
	if service.wireGuard {
		if _, err := manager.resolveWireGuardExe(); err != nil {
			return firewallRemovalServiceSnapshot{}, fmt.Errorf("attest WireGuard executable: %w", err)
		}
		if err := manager.attestOpenRCUnit(service); err != nil {
			return firewallRemovalServiceSnapshot{}, fmt.Errorf("attest OpenRC service %s: %w", name, err)
		}
		active, err := manager.wireGuardInterface()
		if err != nil {
			return firewallRemovalServiceSnapshot{}, err
		}
		if _, err := manager.resolveWireGuardExe(); err != nil {
			return firewallRemovalServiceSnapshot{}, fmt.Errorf("reattest WireGuard executable: %w", err)
		}
		if err := manager.attestOpenRCUnit(service); err != nil {
			return firewallRemovalServiceSnapshot{}, fmt.Errorf("reattest OpenRC service %s: %w", name, err)
		}
		snapshot.stopRequired = active
		return snapshot, nil
	}
	if err := manager.attestOpenRCUnit(service); err != nil {
		return firewallRemovalServiceSnapshot{}, fmt.Errorf("attest OpenRC service %s: %w", name, err)
	}
	_, statusErr := manager.executor.output(manager.servicePath, name, "status")
	if statusErr == nil {
		snapshot.stopRequired = true
	} else {
		code, exact := firewallRemovalExitCode(statusErr)
		if !exact || (code != 3 && code != 16) {
			return firewallRemovalServiceSnapshot{}, fmt.Errorf("refusing ambiguous OpenRC status for %s: %w", name, statusErr)
		}
	}
	if err := manager.attestOpenRCUnit(service); err != nil {
		return firewallRemovalServiceSnapshot{}, fmt.Errorf("reattest OpenRC service %s: %w", name, err)
	}
	return snapshot, nil
}

func (manager firewallRemovalManager) inspectAll() ([]firewallRemovalServiceSnapshot, error) {
	snapshots := make([]firewallRemovalServiceSnapshot, 0, len(firewallRemovalServices))
	var enablement map[string][]string
	var err error
	if manager.alpine {
		enablement, err = inspectOpenRCFirewallRemovalEnablement(manager)
		if err != nil {
			return nil, err
		}
	}
	for _, service := range firewallRemovalServices {
		var snapshot firewallRemovalServiceSnapshot
		if manager.alpine {
			snapshot, err = inspectOpenRCFirewallRemovalService(manager, service, enablement)
		} else {
			snapshot, err = inspectSystemdFirewallRemovalService(manager, service)
		}
		if err != nil {
			return nil, fmt.Errorf("inspect firewall mutator %s: %w", service.name, err)
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func validateFirewallRemovalSnapshots(
	snapshots []firewallRemovalServiceSnapshot,
	wireGuardConfigurationPresent bool,
) error {
	for _, snapshot := range snapshots {
		if snapshot.service.wireGuard && !wireGuardConfigurationPresent {
			if snapshot.stopRequired || snapshot.enabled {
				return fmt.Errorf("refusing unmanaged WireGuard service state without an attested configuration")
			}
			continue
		}
		if !snapshot.loaded {
			continue
		}
		if snapshot.stopRequired {
			return fmt.Errorf("firewall mutator %s has not reached inactive state", snapshot.service.name)
		}
		if snapshot.enabled {
			return fmt.Errorf("firewall mutator %s is still enabled", snapshot.service.name)
		}
	}
	return nil
}

func (manager firewallRemovalManager) disable(snapshot firewallRemovalServiceSnapshot) error {
	if !snapshot.enabled {
		return nil
	}
	if manager.alpine {
		removedAny := false
		for _, runlevel := range snapshot.runlevels {
			if err := manager.attestOpenRCRunlevel(snapshot.service, runlevel); err != nil {
				return fmt.Errorf("attest OpenRC runlevel enablement for %s: %w", snapshot.service.name, err)
			}
			if _, err := manager.executor.output(
				manager.runlevelPath, "del", openRCFirewallRemovalServiceName(snapshot.service), runlevel,
			); err != nil {
				if removedAny {
					return fmt.Errorf(
						"remove OpenRC runlevel enablement for %s: %w; one or more exact runlevel links may remain removed",
						snapshot.service.name, err,
					)
				}
				return fmt.Errorf("remove OpenRC runlevel enablement for %s: %w", snapshot.service.name, err)
			}
			if err := manager.verifyOpenRCRunlevelAbsent(snapshot.service, runlevel); err != nil {
				return fmt.Errorf("verify OpenRC runlevel disable for %s: %w", snapshot.service.name, err)
			}
			removedAny = true
		}
		return nil
	}
	arguments := []string{"disable", systemdFirewallRemovalUnit(snapshot.service)}
	if snapshot.runtimeEnabled {
		arguments = []string{"disable", "--runtime", systemdFirewallRemovalUnit(snapshot.service)}
	}
	if _, err := manager.executor.output(manager.servicePath, arguments...); err != nil {
		return fmt.Errorf("disable systemd firewall mutator %s: %w", snapshot.service.name, err)
	}
	return nil
}

func (manager firewallRemovalManager) stop(snapshot firewallRemovalServiceSnapshot) error {
	if !snapshot.stopRequired {
		return nil
	}
	if manager.alpine {
		if snapshot.service.wireGuard {
			path, err := manager.resolveWireGuardExe()
			if err != nil {
				return fmt.Errorf("resolve WireGuard executable before stop: %w", err)
			}
			if err := manager.attestOpenRCUnit(snapshot.service); err != nil {
				return fmt.Errorf("reattest OpenRC WireGuard service before stop: %w", err)
			}
			if err := manager.verifyWireGuardStopConfig(); err != nil {
				return fmt.Errorf("verify WireGuard server configuration before stop: %w", err)
			}
			if _, err := manager.executor.output(path, "down", "wg-syswarden"); err != nil {
				return fmt.Errorf("stop OpenRC WireGuard mutator %s: %w", snapshot.service.name, err)
			}
			return nil
		}
		if err := manager.attestOpenRCUnit(snapshot.service); err != nil {
			return fmt.Errorf("reattest OpenRC firewall mutator %s before stop: %w", snapshot.service.name, err)
		}
		if _, err := manager.executor.output(
			manager.servicePath, openRCFirewallRemovalServiceName(snapshot.service), "stop",
		); err != nil {
			return fmt.Errorf("stop OpenRC firewall mutator %s: %w", snapshot.service.name, err)
		}
		return nil
	}
	if snapshot.service.wireGuard {
		if err := attestSystemdFirewallRemovalService(manager, snapshot.service); err != nil {
			return fmt.Errorf("reattest systemd WireGuard service before stop: %w", err)
		}
		if err := manager.verifyWireGuardStopConfig(); err != nil {
			return fmt.Errorf("verify WireGuard server configuration before stop: %w", err)
		}
	}
	if _, err := manager.executor.output(manager.servicePath, "stop", systemdFirewallRemovalUnit(snapshot.service)); err != nil {
		return fmt.Errorf("stop systemd firewall mutator %s: %w", snapshot.service.name, err)
	}
	return nil
}

func (manager firewallRemovalManager) attestFailedSystemdServiceRuntime(
	snapshot firewallRemovalServiceSnapshot,
	wantActiveState string,
) error {
	if manager.alpine || !snapshot.failedInitially {
		return fmt.Errorf("refusing failed-state normalization outside an initially failed systemd unit")
	}
	unit := systemdFirewallRemovalUnit(snapshot.service)
	if err := attestSystemdFirewallRemovalService(manager, snapshot.service); err != nil {
		return fmt.Errorf("reattest initially failed systemd firewall mutator %s: %w", snapshot.service.name, err)
	}
	loadState, err := queryFirewallProperty(manager.executor, manager.servicePath, unit, "LoadState")
	if err != nil {
		return err
	}
	if loadState != "loaded" {
		return fmt.Errorf("initially failed systemd firewall mutator %s changed LoadState to %q", snapshot.service.name, loadState)
	}
	activeState, err := queryFirewallProperty(manager.executor, manager.servicePath, unit, "ActiveState")
	if err != nil {
		return err
	}
	if activeState != wantActiveState {
		return fmt.Errorf(
			"initially failed systemd firewall mutator %s has ActiveState %q, want %q",
			snapshot.service.name, activeState, wantActiveState,
		)
	}
	for _, property := range []string{"MainPID", "ControlPID"} {
		value, err := queryFirewallProperty(manager.executor, manager.servicePath, unit, property)
		if err != nil {
			return err
		}
		if value != "0" {
			return fmt.Errorf(
				"initially failed systemd firewall mutator %s has nonzero %s %q",
				snapshot.service.name, property, value,
			)
		}
	}
	return nil
}

func (manager firewallRemovalManager) normalizeInitiallyFailedSystemdService(
	snapshot firewallRemovalServiceSnapshot,
	preReset func() error,
) error {
	if !snapshot.failedInitially {
		return nil
	}
	if manager.alpine || preReset == nil {
		return fmt.Errorf("failed-state normalization dependencies are incomplete")
	}
	unit := systemdFirewallRemovalUnit(snapshot.service)
	if err := attestSystemdFirewallRemovalService(manager, snapshot.service); err != nil {
		return fmt.Errorf("reattest initially failed systemd firewall mutator %s after stop: %w", snapshot.service.name, err)
	}
	activeState, err := queryFirewallProperty(manager.executor, manager.servicePath, unit, "ActiveState")
	if err != nil {
		return err
	}
	switch activeState {
	case "inactive":
		return nil
	case "failed":
	default:
		return fmt.Errorf(
			"initially failed systemd firewall mutator %s changed to disallowed ActiveState %q after stop",
			snapshot.service.name, activeState,
		)
	}
	if err := manager.attestFailedSystemdServiceRuntime(snapshot, "failed"); err != nil {
		return err
	}
	if err := preReset(); err != nil {
		return err
	}
	// Repeat exact unit and zero-runtime proofs after the global process and
	// interface barrier so reset-failed cannot normalize a raced service.
	if err := manager.attestFailedSystemdServiceRuntime(snapshot, "failed"); err != nil {
		return err
	}
	if _, err := manager.executor.output(manager.servicePath, "reset-failed", unit); err != nil {
		return fmt.Errorf("reset exact failed systemd firewall mutator %s: %w", snapshot.service.name, err)
	}
	if err := manager.attestFailedSystemdServiceRuntime(snapshot, "inactive"); err != nil {
		return fmt.Errorf("verify failed-state normalization for %s: %w", snapshot.service.name, err)
	}
	return nil
}

func (host firewallRemovalPreparationHost) attestBeforeFailedSystemdReset(
	wireGuard firewallRemovalWireGuardEvidence,
) error {
	currentWireGuard, err := host.attestWireGuard()
	if err != nil {
		return fmt.Errorf("reattest WireGuard state before systemd reset-failed: %w", err)
	}
	if !sameFirewallRemovalWireGuardEvidence(currentWireGuard, wireGuard) {
		return fmt.Errorf("WireGuard state changed before systemd reset-failed")
	}
	interfacePresent, err := host.wireGuardInterface()
	if err != nil {
		return err
	}
	if interfacePresent {
		return fmt.Errorf("WireGuard interface wg-syswarden remains active before systemd reset-failed")
	}
	if err := host.postStopProcessScan(); err != nil {
		return fmt.Errorf("scan SysWarden processes before systemd reset-failed: %w", err)
	}
	return nil
}

func (host firewallRemovalPreparationHost) reattestWithManager(
	manager firewallRemovalManager,
	wireGuard firewallRemovalWireGuardEvidence,
) error {
	currentWireGuard, err := host.attestWireGuard()
	if err != nil {
		return err
	}
	if !sameFirewallRemovalWireGuardEvidence(currentWireGuard, wireGuard) {
		return fmt.Errorf("WireGuard state changed during firewall removal preparation")
	}
	snapshots, err := manager.inspectAll()
	if err != nil {
		return err
	}
	if err := validateFirewallRemovalSnapshots(snapshots, wireGuard.present); err != nil {
		return err
	}
	interfacePresent, err := host.wireGuardInterface()
	if err != nil {
		return err
	}
	if interfacePresent {
		return fmt.Errorf("WireGuard interface wg-syswarden remains active after service preparation")
	}
	if err := host.postStopProcessScan(); err != nil {
		return fmt.Errorf("scan concurrent SysWarden CLI mutators: %w", err)
	}
	return nil
}

func (host firewallRemovalPreparationHost) prepare() error {
	if err := host.validate(); err != nil {
		return err
	}
	if err := host.processScan(); err != nil {
		return fmt.Errorf("scan concurrent SysWarden CLI mutators before service preparation: %w", err)
	}
	wireGuard, err := host.attestWireGuard()
	if err != nil {
		return fmt.Errorf("attest WireGuard state before service preparation: %w", err)
	}
	interfacePresent, err := host.wireGuardInterface()
	if err != nil {
		return err
	}
	if interfacePresent && !wireGuard.present {
		return fmt.Errorf("refusing unmanaged WireGuard interface without an attested configuration")
	}
	managerState, err := host.classifyRuntime(host.alpine)
	if err != nil {
		return fmt.Errorf("attest service-manager runtime before firewall removal: %w", err)
	}
	if managerState == serviceManagerOffline {
		if interfacePresent {
			return fmt.Errorf("offline package removal cannot stop the active WireGuard interface")
		}
		confirmedWireGuard, err := host.attestWireGuard()
		if err != nil {
			return fmt.Errorf("reattest WireGuard state during offline removal: %w", err)
		}
		if !sameFirewallRemovalWireGuardEvidence(confirmedWireGuard, wireGuard) {
			return fmt.Errorf("WireGuard state changed during offline removal preparation")
		}
		if err := host.postStopProcessScan(); err != nil {
			return fmt.Errorf("scan concurrent SysWarden CLI mutators during offline removal: %w", err)
		}
		return nil
	}
	if managerState != serviceManagerActive {
		return fmt.Errorf("firewall removal requires an attestable service manager, got %s", managerState)
	}
	manager, err := host.resolveManager()
	if err != nil {
		return err
	}
	snapshots, err := manager.inspectAll()
	if err != nil {
		return err
	}
	for _, snapshot := range snapshots {
		if snapshot.service.wireGuard && !wireGuard.present && (snapshot.stopRequired || snapshot.enabled) {
			return fmt.Errorf("refusing unmanaged WireGuard service state without an attested configuration")
		}
	}

	disabledAny := false
	recoverableFailure := func(cause error) error {
		if !disabledAny {
			return cause
		}
		return fmt.Errorf(
			"%w; one or more exact SysWarden services may remain disabled and can be re-enabled after inspection",
			cause,
		)
	}
	for _, snapshot := range snapshots {
		if snapshot.service.wireGuard && !wireGuard.present {
			continue
		}
		if err := manager.disable(snapshot); err != nil {
			return recoverableFailure(err)
		}
		if snapshot.enabled {
			disabledAny = true
		}
	}
	for _, snapshot := range snapshots {
		if snapshot.service.wireGuard && !wireGuard.present {
			continue
		}
		if err := manager.stop(snapshot); err != nil {
			return recoverableFailure(err)
		}
	}
	for _, snapshot := range snapshots {
		if !snapshot.failedInitially {
			continue
		}
		if err := manager.normalizeInitiallyFailedSystemdService(snapshot, func() error {
			return host.attestBeforeFailedSystemdReset(wireGuard)
		}); err != nil {
			return recoverableFailure(err)
		}
	}
	if err := host.reattestWithManager(manager, wireGuard); err != nil {
		return recoverableFailure(fmt.Errorf("reattest prepared firewall mutators: %w", err))
	}
	if err := host.reattestWithManager(manager, wireGuard); err != nil {
		return recoverableFailure(fmt.Errorf("confirm prepared firewall mutators: %w", err))
	}
	return nil
}

func (host firewallRemovalPreparationHost) reattest() error {
	if err := host.validate(); err != nil {
		return err
	}
	wireGuard, err := host.attestWireGuard()
	if err != nil {
		return fmt.Errorf("attest WireGuard state: %w", err)
	}
	managerState, err := host.classifyRuntime(host.alpine)
	if err != nil {
		return fmt.Errorf("attest service-manager runtime: %w", err)
	}
	if managerState == serviceManagerOffline {
		interfacePresent, interfaceErr := host.wireGuardInterface()
		if interfaceErr != nil {
			return interfaceErr
		}
		if interfacePresent {
			return fmt.Errorf("WireGuard interface wg-syswarden is active during offline removal")
		}
		if err := host.postStopProcessScan(); err != nil {
			return fmt.Errorf("scan concurrent SysWarden CLI mutators during offline removal: %w", err)
		}
		confirmedWireGuard, err := host.attestWireGuard()
		if err != nil {
			return err
		}
		if !sameFirewallRemovalWireGuardEvidence(confirmedWireGuard, wireGuard) {
			return fmt.Errorf("WireGuard state changed during offline removal reattestation")
		}
		return nil
	}
	if managerState != serviceManagerActive {
		return fmt.Errorf("firewall removal requires an attestable service manager, got %s", managerState)
	}
	manager, err := host.resolveManager()
	if err != nil {
		return err
	}
	if err := host.reattestWithManager(manager, wireGuard); err != nil {
		return fmt.Errorf("reattest firewall state prepared for removal: %w", err)
	}
	return nil
}

// PrepareFirewallStateForRemoval stops and disables every exact SysWarden
// firewall mutator, then verifies that none can race the verified firewall
// cleanup. Unit and configuration files are preserved. A successful call
// intentionally leaves owned services disabled; callers must report that
// recoverable state if a later cleanup phase fails.
func PrepareFirewallStateForRemoval() error {
	if err := RequireRemovalTombstone(); err != nil {
		return fmt.Errorf("firewall removal preparation requires the durable removal tombstone: %w", err)
	}
	rhelPackageOwned := false
	if !IsAlpine() {
		var err error
		rhelPackageOwned, err = attestInstalledRHELPackageOwnedProfile()
		if err != nil {
			return fmt.Errorf("attest RHEL package-owned profile before service preparation: %w", err)
		}
	}
	if !IsAlpine() && !rhelPackageOwned {
		if err := productionPreparedSystemdServiceArtifactHost().recoverInterruptedRemoval(); err != nil {
			return fmt.Errorf("recover interrupted systemd service artifact removal: %w", err)
		}
	}
	return productionFirewallRemovalPreparationHost().prepare()
}

// ReattestFirewallStatePreparedForRemoval performs the read-only service-state
// check used immediately before and after verified firewall cleanup.
func ReattestFirewallStatePreparedForRemoval() error {
	return productionFirewallRemovalPreparationHost().reattest()
}

// UninstallSystem removes exact SysWarden-owned host state after the durable
// removal barrier and firewall preparation have completed. Ambiguous legacy
// host artifacts are preserved for explicit operator recovery.
func UninstallSystem() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall must be executed as root")
	}
	if err := RequireRemovalTombstone(); err != nil {
		return fmt.Errorf("host removal requires the durable removal tombstone: %w", err)
	}
	rhelPackageOwned := false
	if !IsAlpine() {
		var err error
		rhelPackageOwned, err = attestInstalledRHELPackageOwnedProfile()
		if err != nil {
			return fmt.Errorf("attest RHEL package-owned profile before host removal: %w", err)
		}
	}
	if err := ReattestFirewallStatePreparedForRemoval(); err != nil {
		return fmt.Errorf("host removal requires prepared firewall mutators: %w", err)
	}
	if err := preflightHostRemovalMountBoundaries(); err != nil {
		return fmt.Errorf("refusing host removal before mount-boundary preflight: %w", err)
	}
	if err := preflightHostProductRemovalArtifacts(); err != nil {
		return fmt.Errorf("refusing host removal before product-root preflight: %w", err)
	}
	if err := retireLegacyWebTUIService(IsAlpine()); err != nil {
		return fmt.Errorf("retire legacy Web-TUI service: %w", err)
	}
	if err := ReattestFirewallStatePreparedForRemoval(); err != nil {
		return fmt.Errorf("reattest prepared firewall mutators before host deletion: %w", err)
	}

	fmt.Println("[WARN] Starting verified SysWarden host removal...")
	if rhelPackageOwned {
		present, err := attestInstalledRHELPackageOwnedProfile()
		if err != nil || !present {
			return errors.Join(
				fmt.Errorf("RHEL package-owned payload changed before runtime cleanup"), err,
			)
		}
		if err := prepareRHELPackageOwnedRuntimeForErase(); err != nil {
			return fmt.Errorf("prepare RHEL package-owned payload for RPM erase: %w", err)
		}
		fmt.Println("[READY] Verified runtime state is removed and the exact RPM payload is preserved.")
		fmt.Println("[ACTION] Complete removal with: rpm -e syswarden-4.10.0-1.rhelpo.x86_64")
		return nil
	}

	// Exact core and firewall service artifacts were already removed by the
	// shared verified preparation while this executable path was available.
	// That preparation also exclusively owns the rsyslog runtime socket and
	// policy sequence: it either removed them after an active restart barrier or
	// attested both already absent without mutation while offline. Do not repeat
	// either teardown in this host-removal tail.

	// Every reserved firewall table and compatibility permission was already
	// removed and verified under the firewall lock before this phase. Exact
	// WireGuard nftables and manifest-attributed artifacts were also removed
	// while their ownership evidence was still available.
	fmt.Fprintln(
		os.Stderr,
		"[WARN] Preserved ambiguous legacy hardening, rsyslog, shell-completion, legacy config, and root-crontab artifacts for manual recovery. Exact legacy SysWarden cron records may remain but cannot execute after the product binary is absent.",
	)

	// Remove the shared-parent log root first while the executable remains
	// available for a retry. The durable tombstone remains until every
	// attributable deletion has succeeded, and the executable root is removed
	// last so deterministic host-layout refusals cannot strand recovery.
	fmt.Println(" -> Removing exact product files and state...")
	if err := removeDedicatedProductLogTree(); err != nil {
		return err
	}
	if err := removeDedicatedRemovalTree("/etc/syswarden"); err != nil {
		return err
	}
	if err := removeExactProductSymlinkAt(
		"/usr/local/bin/syswarden-tui", "/opt/syswarden/bin/syswarden-tui", 0, 0,
	); err != nil {
		return err
	}
	if err := removeExactProductSymlinkAt(
		"/usr/local/bin/syswarden", "/opt/syswarden/bin/syswarden-cli", 0, 0,
	); err != nil {
		return err
	}
	if err := removeDedicatedRemovalTree("/opt/syswarden"); err != nil {
		return err
	}
	if err := removeRemovalStateContents(); err != nil {
		return err
	}
	if err := FinalizeRemovalTombstone(); err != nil {
		return fmt.Errorf("finalize verified host removal: %w", err)
	}

	fmt.Println("[SUCCESS] Verified SysWarden-owned host removal is complete. Preserved legacy artifacts require manual review.")
	return nil
}
