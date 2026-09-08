//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type preparedSystemdServiceArtifact struct {
	path                string
	content             string
	mode                os.FileMode
	allowedTargets      []string
	requiredServicePath string
	packageDropIn       bool
	optionalParent      bool
}

type preparedSystemdServiceArtifactSnapshot struct {
	path           string
	present        bool
	identity       removalArtifactIdentity
	target         string
	proof          string
	parentPath     string
	parentPresent  bool
	parentIdentity removalArtifactIdentity
	anchorPath     string
	anchorIdentity removalArtifactIdentity
}

type preparedSystemdServiceArtifactHost struct {
	artifacts         []preparedSystemdServiceArtifact
	trustedRoot       string
	expectedUID       uint32
	expectedGID       uint32
	classifyRuntime   func(bool) (serviceManagerState, error)
	executor          firewallManagerExecutor
	processScan       func() error
	attestPackageDrop func(firewallManagerExecutor, string) (string, error)
	afterFirstCapture func()
}

func productionPreparedSystemdServiceArtifactHost() preparedSystemdServiceArtifactHost {
	corePath := filepath.Join(serviceSystemdUnitDir, "syswarden-core.service")
	firewallPath := filepath.Join(serviceSystemdUnitDir, "syswarden-firewall.service")
	return preparedSystemdServiceArtifactHost{
		artifacts: []preparedSystemdServiceArtifact{
			{path: corePath, content: systemdCoreService, mode: 0600},
			{path: firewallPath, content: systemdFirewallService, mode: 0600},
			{
				path: filepath.Join(serviceSystemdWantsDir, "syswarden-core.service"),
				allowedTargets: []string{
					"../syswarden-core.service", "/etc/systemd/system/syswarden-core.service",
				},
				requiredServicePath: corePath,
			},
			{
				path: filepath.Join(serviceSystemdWantsDir, "syswarden-firewall.service"),
				allowedTargets: []string{
					"../syswarden-firewall.service", "/etc/systemd/system/syswarden-firewall.service",
				},
				requiredServicePath: firewallPath,
			},
			{
				path: systemdFirewallWireGuardOrderingDropInPath, content: systemdFirewallWireGuardOrderingDropIn,
				mode: 0644, packageDropIn: true, optionalParent: true,
			},
		},
		trustedRoot:     "/",
		expectedUID:     0,
		expectedGID:     0,
		classifyRuntime: classifyServiceManagerRuntime,
		executor:        hostFirewallExecutor(),
		processScan:     scanExactRootSysWardenCLIMutators,
		attestPackageDrop: func(executor firewallManagerExecutor, path string) (string, error) {
			return attestExactSystemdFirewallOrderingDropIn(executor, path)
		},
	}
}

func (host preparedSystemdServiceArtifactHost) validate() error {
	if len(host.artifacts) != 5 || host.classifyRuntime == nil || host.processScan == nil ||
		host.attestPackageDrop == nil || host.executor.lookPath == nil || host.executor.validate == nil ||
		host.executor.output == nil || host.trustedRoot == "" || !filepath.IsAbs(host.trustedRoot) ||
		filepath.Clean(host.trustedRoot) != host.trustedRoot {
		return fmt.Errorf("systemd service artifact recovery dependencies are incomplete")
	}
	seen := make(map[string]struct{}, len(host.artifacts))
	packageDropIns := 0
	for _, artifact := range host.artifacts {
		if artifact.path == "" || !filepath.IsAbs(artifact.path) || filepath.Clean(artifact.path) != artifact.path {
			return fmt.Errorf("systemd service artifact recovery path %q is not clean and absolute", artifact.path)
		}
		if _, duplicate := seen[artifact.path]; duplicate {
			return fmt.Errorf("systemd service artifact recovery path %s is duplicated", artifact.path)
		}
		seen[artifact.path] = struct{}{}
		if artifact.packageDropIn {
			packageDropIns++
		} else if artifact.optionalParent {
			return fmt.Errorf("only the package-owned systemd drop-in may have an optional parent")
		}
		if len(artifact.allowedTargets) == 0 && (artifact.content == "" || artifact.mode == 0) {
			return fmt.Errorf("systemd service file recovery contract is incomplete for %s", artifact.path)
		}
		if len(artifact.allowedTargets) != 0 && artifact.requiredServicePath == "" {
			return fmt.Errorf("systemd enablement recovery contract is incomplete for %s", artifact.path)
		}
	}
	if packageDropIns != 1 {
		return fmt.Errorf("systemd service artifact recovery requires one package drop-in")
	}
	return nil
}

func capturePreparedSystemdServiceDirectory(
	path string,
	trustedRoot string,
	expectedUID uint32,
	expectedGID uint32,
) (removalArtifactIdentity, error) {
	probePath := filepath.Join(path, ".syswarden-removal-parent-attestation")
	if err := attestApprovedSystemdServiceDropInParents(
		probePath, trustedRoot, expectedUID, expectedGID,
	); err != nil {
		return removalArtifactIdentity{}, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return removalArtifactIdentity{}, err
	}
	beforeIdentity, err := exactRemovalArtifactIdentity(before)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() || before.Mode().Perm()&0022 != 0 ||
		beforeIdentity.uid != expectedUID || beforeIdentity.gid != expectedGID {
		return removalArtifactIdentity{}, errors.Join(
			fmt.Errorf("refusing unsafe systemd service artifact directory %s", path), err,
		)
	}
	directory, err := openExistingPinnedServiceDirectory(path)
	if err != nil {
		return removalArtifactIdentity{}, err
	}
	opened, openedErr := directory.root.Stat(".")
	directory.close()
	openedIdentity, identityErr := exactRemovalArtifactIdentity(opened)
	after, afterErr := os.Lstat(path)
	afterIdentity, afterIdentityErr := exactRemovalArtifactIdentity(after)
	if openedErr != nil || identityErr != nil || afterErr != nil || afterIdentityErr != nil ||
		beforeIdentity != openedIdentity || openedIdentity != afterIdentity {
		return removalArtifactIdentity{}, errors.Join(
			fmt.Errorf("systemd service artifact directory %s changed while pinning", path),
			openedErr,
			identityErr,
			afterErr,
			afterIdentityErr,
		)
	}
	return afterIdentity, nil
}

func (host preparedSystemdServiceArtifactHost) captureMissingOptionalParent(
	artifact preparedSystemdServiceArtifact,
	parentPath string,
) (preparedSystemdServiceArtifactSnapshot, error) {
	snapshot := preparedSystemdServiceArtifactSnapshot{
		path: artifact.path, parentPath: parentPath, anchorPath: filepath.Dir(parentPath),
	}
	firstAnchor, err := capturePreparedSystemdServiceDirectory(
		snapshot.anchorPath, host.trustedRoot, host.expectedUID, host.expectedGID,
	)
	if err != nil {
		return snapshot, fmt.Errorf("attest optional systemd artifact anchor %s: %w", snapshot.anchorPath, err)
	}
	if _, err := os.Lstat(parentPath); !errors.Is(err, os.ErrNotExist) {
		return snapshot, errors.Join(fmt.Errorf("optional systemd artifact parent %s is not absent", parentPath), err)
	}
	if _, err := os.Lstat(artifact.path); !errors.Is(err, os.ErrNotExist) {
		return snapshot, errors.Join(fmt.Errorf("systemd artifact %s is not absent with its parent", artifact.path), err)
	}
	secondAnchor, err := capturePreparedSystemdServiceDirectory(
		snapshot.anchorPath, host.trustedRoot, host.expectedUID, host.expectedGID,
	)
	if err != nil || firstAnchor != secondAnchor {
		return snapshot, errors.Join(
			fmt.Errorf("optional systemd artifact anchor %s changed during absence attestation", snapshot.anchorPath), err,
		)
	}
	if _, err := os.Lstat(parentPath); !errors.Is(err, os.ErrNotExist) {
		return snapshot, errors.Join(
			fmt.Errorf("optional systemd artifact parent %s changed during absence attestation", parentPath), err,
		)
	}
	if _, err := os.Lstat(artifact.path); !errors.Is(err, os.ErrNotExist) {
		return snapshot, errors.Join(
			fmt.Errorf("systemd artifact %s changed during parent absence attestation", artifact.path), err,
		)
	}
	snapshot.anchorIdentity = secondAnchor
	return snapshot, nil
}

func (host preparedSystemdServiceArtifactHost) captureArtifact(
	artifact preparedSystemdServiceArtifact,
) (preparedSystemdServiceArtifactSnapshot, error) {
	parentPath := filepath.Dir(artifact.path)
	snapshot := preparedSystemdServiceArtifactSnapshot{
		path: artifact.path, parentPath: parentPath, anchorPath: parentPath,
	}
	parentIdentity, err := capturePreparedSystemdServiceDirectory(
		parentPath, host.trustedRoot, host.expectedUID, host.expectedGID,
	)
	if errors.Is(err, os.ErrNotExist) && artifact.optionalParent {
		return host.captureMissingOptionalParent(artifact, parentPath)
	}
	if err != nil {
		return snapshot, fmt.Errorf("attest systemd service artifact parent for %s: %w", artifact.path, err)
	}
	snapshot.parentPresent = true
	snapshot.parentIdentity = parentIdentity
	snapshot.anchorIdentity = parentIdentity
	if _, err := os.Lstat(artifact.path); errors.Is(err, os.ErrNotExist) {
		return snapshot, nil
	} else if err != nil {
		return snapshot, fmt.Errorf("inspect systemd service artifact %s: %w", artifact.path, err)
	}
	directory, err := openExistingPinnedServiceDirectory(filepath.Dir(artifact.path))
	if err != nil {
		return snapshot, err
	}
	defer directory.close()
	name := filepath.Base(artifact.path)
	var info os.FileInfo
	if len(artifact.allowedTargets) != 0 {
		enablement, inspectErr := inspectAttestedServiceEnablement(directory, name)
		if inspectErr != nil {
			return snapshot, fmt.Errorf("attest systemd service enablement %s: %w", artifact.path, inspectErr)
		}
		if !serviceFileOwnedByCurrentUser(enablement.identity) || !serviceFileHasSingleLink(enablement.identity) {
			return snapshot, fmt.Errorf("refusing unsafe systemd service enablement %s", artifact.path)
		}
		if !containsExactString(artifact.allowedTargets, enablement.target) {
			return snapshot, fmt.Errorf(
				"refusing unexpected systemd service enablement target %q for %s", enablement.target, artifact.path,
			)
		}
		info = enablement.identity
		snapshot.target = enablement.target
	} else {
		info, err = inspectSingleLinkExactServiceFile(directory, name, artifact.content, artifact.mode)
		if err != nil {
			return snapshot, fmt.Errorf("attest exact systemd service artifact %s: %w", artifact.path, err)
		}
		if artifact.packageDropIn {
			snapshot.proof, err = host.attestPackageDrop(host.executor, artifact.path)
			if err != nil {
				return snapshot, fmt.Errorf("attest package-owned systemd drop-in %s: %w", artifact.path, err)
			}
			confirmed, confirmErr := inspectSingleLinkExactServiceFile(directory, name, artifact.content, artifact.mode)
			if confirmErr != nil || !sameServiceFileMetadata(info, confirmed) {
				return snapshot, errors.Join(
					fmt.Errorf("package-owned systemd drop-in %s changed during recovery attestation", artifact.path),
					confirmErr,
				)
			}
			info = confirmed
		}
	}
	identity, err := exactRemovalArtifactIdentity(info)
	if err != nil {
		return snapshot, fmt.Errorf("capture systemd service artifact identity %s: %w", artifact.path, err)
	}
	snapshot.present = true
	snapshot.identity = identity
	return snapshot, nil
}

func (host preparedSystemdServiceArtifactHost) capture() ([]preparedSystemdServiceArtifactSnapshot, error) {
	if err := host.validate(); err != nil {
		return nil, err
	}
	snapshots := make([]preparedSystemdServiceArtifactSnapshot, 0, len(host.artifacts))
	byPath := make(map[string]preparedSystemdServiceArtifactSnapshot, len(host.artifacts))
	for _, artifact := range host.artifacts {
		snapshot, err := host.captureArtifact(artifact)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
		byPath[artifact.path] = snapshot
	}
	for index, artifact := range host.artifacts {
		if len(artifact.allowedTargets) == 0 || !snapshots[index].present {
			continue
		}
		required, known := byPath[artifact.requiredServicePath]
		if !known || !required.present {
			return nil, fmt.Errorf(
				"refusing systemd enablement %s without its exact service file %s",
				artifact.path, artifact.requiredServicePath,
			)
		}
	}
	return snapshots, nil
}

func samePreparedSystemdServiceArtifactSnapshots(
	left []preparedSystemdServiceArtifactSnapshot,
	right []preparedSystemdServiceArtifactSnapshot,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (host preparedSystemdServiceArtifactHost) captureStable() ([]preparedSystemdServiceArtifactSnapshot, int, error) {
	first, err := host.capture()
	if err != nil {
		return nil, 0, err
	}
	if host.afterFirstCapture != nil {
		host.afterFirstCapture()
	}
	second, err := host.capture()
	if err != nil {
		return nil, 0, err
	}
	if !samePreparedSystemdServiceArtifactSnapshots(first, second) {
		return nil, 0, fmt.Errorf("systemd service artifact inventory changed during recovery attestation")
	}
	absent := 0
	for _, snapshot := range second {
		if !snapshot.present {
			absent++
		}
	}
	return second, absent, nil
}

func (host preparedSystemdServiceArtifactHost) recoverInterruptedRemoval() error {
	if err := host.validate(); err != nil {
		return err
	}
	if err := host.processScan(); err != nil {
		return fmt.Errorf("scan concurrent SysWarden CLI mutators before systemd removal recovery: %w", err)
	}
	managerState, err := host.classifyRuntime(false)
	if err != nil {
		return fmt.Errorf("classify systemd runtime before service artifact recovery: %w", err)
	}
	if managerState == serviceManagerOffline {
		return nil
	}
	if managerState != serviceManagerActive {
		return fmt.Errorf("refusing systemd service artifact recovery with manager state %s", managerState)
	}
	systemctlPath, err := resolveFirewallExecutable(host.executor, "systemctl")
	if err != nil {
		return err
	}
	before, absent, err := host.captureStable()
	if err != nil {
		return err
	}
	if absent == 0 {
		return nil
	}
	// daemon-reload never executes a unit. It only reconciles systemd's cache
	// after an exact monotonic removal crossed an earlier failure boundary.
	// The normal preparation immediately reattests every loaded unit, drop-in,
	// execution path, active state and enablement state before any service action.
	if _, err := host.executor.output(systemctlPath, "daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd during interrupted service artifact recovery: %w", err)
	}
	confirmedState, err := host.classifyRuntime(false)
	if err != nil {
		return fmt.Errorf("reclassify systemd runtime after service artifact recovery: %w", err)
	}
	if confirmedState != serviceManagerActive {
		return fmt.Errorf("systemd runtime changed to %s during service artifact recovery", confirmedState)
	}
	after, _, err := host.captureStable()
	if err != nil {
		return err
	}
	if !samePreparedSystemdServiceArtifactSnapshots(before, after) {
		return fmt.Errorf("systemd service artifact inventory changed across removal recovery")
	}
	return nil
}

func removePreparedExactServiceFile(path string, content string, mode os.FileMode) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect exact prepared service file %s: %w", path, err)
	}
	directory, err := openExistingPinnedServiceDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.close()
	name := filepath.Base(path)
	if err := quarantineAndRemoveServiceArtifact(
		directory,
		name,
		true,
		func(directory *pinnedServiceDirectory, candidate string) (os.FileInfo, error) {
			return inspectSingleLinkExactServiceFile(directory, candidate, content, mode)
		},
	); err != nil {
		return fmt.Errorf("remove exact prepared service file %s: %w", path, err)
	}
	return nil
}

func attestPreparedExactServiceFile(path string, content string, mode os.FileMode) error {
	directory, err := openExistingPinnedServiceDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.close()
	if _, err := inspectSingleLinkExactServiceFile(directory, filepath.Base(path), content, mode); err != nil {
		return fmt.Errorf("attest exact prepared service file %s: %w", path, err)
	}
	return nil
}

func removePreparedServiceEnablement(
	path string,
	servicePath string,
	serviceContent string,
	serviceMode os.FileMode,
	allowedTargets ...string,
) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect service enablement %s: %w", path, err)
	}
	if err := attestPreparedExactServiceFile(servicePath, serviceContent, serviceMode); err != nil {
		return fmt.Errorf("attest service definition before enablement removal %s: %w", path, err)
	}
	directory, err := openExistingPinnedServiceDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.close()
	enablement, err := inspectAttestedServiceEnablement(directory, filepath.Base(path))
	if err != nil {
		return fmt.Errorf("attest service enablement %s: %w", path, err)
	}
	if !serviceFileOwnedByCurrentUser(enablement.identity) || !serviceFileHasSingleLink(enablement.identity) {
		return fmt.Errorf("refusing unsafe service enablement %s", path)
	}
	if !containsExactString(allowedTargets, enablement.target) {
		return fmt.Errorf("refusing unexpected service enablement target %q for %s", enablement.target, path)
	}
	if err := quarantineAndRemoveServiceArtifact(
		directory,
		filepath.Base(path),
		false,
		func(directory *pinnedServiceDirectory, candidate string) (os.FileInfo, error) {
			current, inspectErr := inspectAttestedServiceEnablement(directory, candidate)
			if inspectErr != nil {
				return current.identity, inspectErr
			}
			if current.target != enablement.target || !serviceFileOwnedByCurrentUser(current.identity) ||
				!serviceFileHasSingleLink(current.identity) {
				return current.identity, fmt.Errorf("refusing changed or unsafe service enablement")
			}
			return current.identity, nil
		},
	); err != nil {
		return err
	}
	return nil
}

// RemovePreparedServiceArtifactsForRemoval deletes only exact attributable
// SysWarden service definitions after the durable barrier is present and all
// mutators have been verified inactive and disabled.
func RemovePreparedServiceArtifactsForRemoval() error {
	if err := RequireRemovalTombstone(); err != nil {
		return fmt.Errorf("service artifact removal requires the durable removal tombstone: %w", err)
	}
	rhelPackageOwned := false
	if !IsAlpine() {
		var err error
		rhelPackageOwned, err = attestInstalledRHELPackageOwnedProfile()
		if err != nil {
			return fmt.Errorf("attest RHEL package-owned profile before service artifact removal: %w", err)
		}
	}
	if err := ReattestFirewallStatePreparedForRemoval(); err != nil {
		if IsAlpine() || rhelPackageOwned {
			return fmt.Errorf("service artifact removal requires prepared firewall mutators: %w", err)
		}
		initialErr := err
		if recoveryErr := productionPreparedSystemdServiceArtifactHost().recoverInterruptedRemoval(); recoveryErr != nil {
			return errors.Join(
				fmt.Errorf("service artifact removal requires prepared firewall mutators: %w", initialErr),
				fmt.Errorf("recover interrupted systemd service artifact removal: %w", recoveryErr),
			)
		}
		if err := ReattestFirewallStatePreparedForRemoval(); err != nil {
			return fmt.Errorf("service artifact removal requires prepared firewall mutators after recovery: %w", err)
		}
	}
	if IsAlpine() {
		if err := removePreparedServiceEnablement(
			"/etc/runlevels/default/syswarden-core",
			"/etc/init.d/syswarden-core", openRCCoreService, 0755,
			"/etc/init.d/syswarden-core",
		); err != nil {
			return err
		}
		if err := removePreparedServiceEnablement(
			"/etc/runlevels/default/syswarden-firewall",
			"/etc/init.d/syswarden-firewall", openRCFirewallService, 0755,
			"/etc/init.d/syswarden-firewall",
		); err != nil {
			return err
		}
		if err := removeExactFirewallRemovalFile("/etc/init.d/syswarden-core", openRCCoreService, 0755); err != nil {
			return err
		}
		if err := removeExactFirewallRemovalFile("/etc/init.d/syswarden-firewall", openRCFirewallService, 0755); err != nil {
			return err
		}
	} else if rhelPackageOwned {
		if err := attestRHELPackageOwnedEnablementAbsentAt("/"); err != nil {
			return err
		}
		present, err := attestInstalledRHELPackageOwnedProfile()
		if err != nil || !present {
			return errors.Join(
				fmt.Errorf("RHEL package-owned payload changed while preserving it for RPM erase"), err,
			)
		}
	} else {
		host := productionPreparedSystemdServiceArtifactHost()
		managerState, err := host.classifyRuntime(false)
		if err != nil {
			return fmt.Errorf("classify systemd runtime before exact service removal: %w", err)
		}
		var systemctlPath string
		switch managerState {
		case serviceManagerActive:
			systemctlPath, err = resolveFirewallExecutable(host.executor, "systemctl")
			if err != nil {
				return err
			}
		case serviceManagerOffline:
		default:
			return fmt.Errorf("refusing service artifact removal with manager state %s", managerState)
		}
		if _, _, err := host.captureStable(); err != nil {
			return fmt.Errorf("preflight exact systemd service artifact removal: %w", err)
		}
		if err := removePreparedServiceEnablement(
			"/etc/systemd/system/multi-user.target.wants/syswarden-core.service",
			"/etc/systemd/system/syswarden-core.service", systemdCoreService, 0600,
			"../syswarden-core.service", "/etc/systemd/system/syswarden-core.service",
		); err != nil {
			return err
		}
		if err := removePreparedServiceEnablement(
			"/etc/systemd/system/multi-user.target.wants/syswarden-firewall.service",
			"/etc/systemd/system/syswarden-firewall.service", systemdFirewallService, 0600,
			"../syswarden-firewall.service", "/etc/systemd/system/syswarden-firewall.service",
		); err != nil {
			return err
		}
		if err := removePreparedExactServiceFile(
			"/etc/systemd/system/syswarden-core.service", systemdCoreService, 0600,
		); err != nil {
			return err
		}
		if err := removePreparedExactServiceFile(
			"/etc/systemd/system/syswarden-firewall.service", systemdFirewallService, 0600,
		); err != nil {
			return err
		}
		if err := removePreparedExactServiceFile(
			systemdFirewallWireGuardOrderingDropInPath,
			systemdFirewallWireGuardOrderingDropIn,
			0644,
		); err != nil {
			return err
		}
		switch managerState {
		case serviceManagerActive:
			if _, err := host.executor.output(systemctlPath, "daemon-reload"); err != nil {
				return fmt.Errorf("reload systemd after exact service removal: %w", err)
			}
		case serviceManagerOffline:
			// The exact unit files and enablement links are absent before the
			// package payload can disappear. No manager process exists to reload.
		}
	}
	if err := ReattestFirewallStatePreparedForRemoval(); err != nil {
		return fmt.Errorf("reattest host after exact service artifact removal: %w", err)
	}
	return nil
}
