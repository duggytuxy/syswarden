//go:build linux

package system

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	rhelPackageOwnedCoreUnitPath     = "/usr/lib/systemd/system/syswarden-core.service"
	rhelPackageOwnedFirewallUnitPath = "/usr/lib/systemd/system/syswarden-firewall.service"
	rhelPackageOwnedPresetPath       = "/usr/lib/systemd/system-preset/90-syswarden-rhel-image.preset"
	rhelPackageOwnedProfilePath      = "/usr/share/doc/syswarden/rhel-package-owned-profile.json"

	rhelPackageOwnedEraseReadyPath        = "/var/lib/.syswarden-rhelpo-erase-ready-v1"
	rhelPackageOwnedEraseReadyRecord      = "SYSWARDEN_RHELPO_ERASE_READY_V1\nnevra=syswarden-4.10.0-1.rhelpo.x86_64\n"
	rhelPackageOwnedPresetPendingPath     = "/var/lib/.syswarden-rhelpo-preset-pending-v1"
	rhelPackageOwnedPresetPendingTempPath = rhelPackageOwnedPresetPendingPath + ".new"

	rhelPackageOwnedPreset  = "enable syswarden-firewall.service\nenable syswarden-core.service\n"
	rhelPackageOwnedProfile = `{
  "schema_version": 2,
  "profile": "rhel-package-owned-runtime/v2",
  "status": "implemented-native-qualification-pending",
  "activation": "explicit-opt-in-only",
  "platform": {
    "family": "rhel",
    "minimum_major": 9,
    "architecture": "x86_64",
    "service_manager": "systemd",
    "firewall_frontend": "operator-selected"
  },
  "rpm": {
    "owns_units": true,
    "owns_preset": true,
    "owns_scriptlets": true,
    "lifecycle": {
      "pre_install": "scriptlets/pre-install.sh",
      "post_install": "scriptlets/post-install.sh",
      "pre_uninstall": "scriptlets/pre-uninstall.sh",
      "post_uninstall": "scriptlets/post-uninstall.sh"
    },
    "package_name": "syswarden",
    "package_release": "1.rhelpo",
    "nevra_template": "syswarden-{version}-1.rhelpo.x86_64",
    "filename_template": "syswarden-{version}-1.rhelpo.x86_64.rpm",
    "mutual_exclusion": "same-rpm-name",
    "payload_owner": "root:root"
  },
  "go_runtime_boundary": {
    "systemd_integration_ownership": "rpm",
    "firewall_integration_ownership": "rpm",
    "firewall_frontend_selection": "operator",
    "dynamic_policy_compilation_and_enforcement": "go-runtime",
    "product_binary_role": "runtime-only",
    "package_scriptlet_product_binary_calls": "forbidden"
  },
  "image_build_contract": {
    "supported_build_roots": ["mock", "chroot"],
    "running_systemd_required_during_transaction": false,
    "service_start_during_transaction": "forbidden",
    "first_real_boot_activation": "systemd-preset",
    "upgrade_preset_reapplication": "forbidden",
    "operator_configuration_replacement": "forbidden"
  },
  "firewall_frontend_contract": {
    "preserve_operator_selection": true,
    "supported_existing_frontends": ["firewalld", "nftables"],
    "firewalld_service_transition": "forbidden",
    "nftables_service_transition": "forbidden"
  },
  "selinux_contract": {
    "required_mode": "enforcing",
    "package_policy_mutation": "forbidden",
    "native_rhel_9_and_10_qualification": "pending"
  },
  "build_integration": {
    "entrypoint": "build_packages.sh --rhel-package-owned-profile",
    "default_builder_behavior": "unchanged",
    "activation": "explicit-command-line-flag"
  }
}
`
)

var errRHELPackageOwnedRPMUnavailable = errors.New("RHEL package-owned RPM authority is unavailable")

type rhelPackageOwnedFile struct {
	path    string
	content string
	mode    os.FileMode
}

var rhelPackageOwnedFiles = []rhelPackageOwnedFile{
	{path: rhelPackageOwnedCoreUnitPath, content: systemdCoreService, mode: 0644},
	{path: rhelPackageOwnedFirewallUnitPath, content: systemdFirewallService, mode: 0644},
	{
		path:    systemdFirewallWireGuardOrderingDropInPath,
		content: systemdFirewallWireGuardOrderingDropIn,
		mode:    0644,
	},
	{path: rhelPackageOwnedPresetPath, content: rhelPackageOwnedPreset, mode: 0644},
	{path: rhelPackageOwnedProfilePath, content: rhelPackageOwnedProfile, mode: 0644},
}

var rhelPackageOwnedUniquePaths = []string{
	rhelPackageOwnedCoreUnitPath,
	rhelPackageOwnedFirewallUnitPath,
	rhelPackageOwnedPresetPath,
	rhelPackageOwnedProfilePath,
}

var rhelPackageOwnedRuntimeDirectories = []string{
	"/etc/syswarden",
	"/etc/syswarden/config",
	"/etc/syswarden/config/modules",
	"/etc/syswarden/lists",
	"/etc/syswarden/tls",
	"/var/lib/syswarden",
	"/var/lib/syswarden/ui",
	"/var/log/syswarden",
}

var rhelPackageOwnedProductDirectories = []string{
	"/opt/syswarden",
	"/opt/syswarden/bin",
}

var rhelPackageOwnedProductFiles = []struct {
	path string
	mode os.FileMode
}{
	{path: "/opt/syswarden/bin/syswarden-cli", mode: 0750},
	{path: "/opt/syswarden/bin/syswarden-core", mode: 0750},
	{path: "/opt/syswarden/bin/syswarden-tui", mode: 0750},
	{path: "/opt/syswarden/signatures.json", mode: 0640},
}

var rhelPackageOwnedRequiredDirectories = []struct {
	path string
	mode os.FileMode
}{
	{path: "/etc", mode: 0755},
	{path: "/etc/systemd", mode: 0755},
	{path: "/etc/systemd/system", mode: 0755},
	{path: "/etc/systemd/system/multi-user.target.wants", mode: 0755},
	{path: "/etc/syswarden", mode: 0750},
	{path: "/etc/syswarden/config", mode: 0750},
	{path: "/etc/syswarden/config/modules", mode: 0750},
	{path: "/etc/syswarden/lists", mode: 0750},
	{path: "/etc/syswarden/tls", mode: 0750},
	{path: "/var", mode: 0755},
	{path: "/var/lib", mode: 0755},
	{path: "/var/lib/syswarden", mode: 0750},
	{path: "/var/lib/syswarden/ui", mode: 0750},
	{path: "/var/log", mode: 0755},
	{path: "/var/log/syswarden", mode: 0750},
	{path: "/opt", mode: 0755},
	{path: "/opt/syswarden", mode: 0755},
	{path: "/opt/syswarden/bin", mode: 0755},
	{path: "/usr", mode: 0755},
	{path: "/usr/lib", mode: 0755},
	{path: "/usr/lib/systemd", mode: 0755},
	{path: "/usr/lib/systemd/system", mode: 0755},
	{path: "/usr/lib/systemd/system/syswarden-firewall.service.d", mode: 0755},
	{path: "/usr/lib/systemd/system-preset", mode: 0755},
	{path: "/usr/libexec", mode: 0755},
	{path: "/usr/libexec/syswarden", mode: 0755},
	{path: "/usr/local", mode: 0755},
	{path: "/usr/local/bin", mode: 0755},
	{path: "/usr/share", mode: 0755},
	{path: "/usr/share/bash-completion", mode: 0755},
	{path: "/usr/share/bash-completion/completions", mode: 0755},
	{path: "/usr/share/doc", mode: 0755},
	{path: "/usr/share/doc/syswarden", mode: 0755},
}

var rhelPackageOwnedAdditionalOwnedPayloadFiles = []struct {
	path string
	mode os.FileMode
}{
	{path: "/usr/share/bash-completion/completions/syswarden", mode: 0644},
	{path: "/usr/share/doc/syswarden/GEOIP-DATA-LICENSE.txt", mode: 0644},
	{path: "/usr/share/doc/syswarden/LICENSE.txt", mode: 0644},
	{path: "/usr/libexec/syswarden/rhelpo-postun-recovery-v1", mode: 0755},
	{path: "/opt/syswarden/bin/syswarden-cli", mode: 0750},
	{path: "/opt/syswarden/bin/syswarden-core", mode: 0750},
	{path: "/opt/syswarden/bin/syswarden-tui", mode: 0750},
	{path: "/opt/syswarden/signatures.json", mode: 0640},
}

var rhelPackageOwnedAdditionalOwnedPayloadLinks = []struct {
	path   string
	target string
}{
	{path: "/usr/local/bin/syswarden", target: "/opt/syswarden/bin/syswarden-cli"},
	{path: "/usr/local/bin/syswarden-tui", target: "/opt/syswarden/bin/syswarden-tui"},
}

type rhelPackageOwnedAttestationHost struct {
	root                    string
	expectedUID             uint32
	expectedGID             uint32
	skipAbsentPackageQuery  bool
	queryInstalled          func() ([]byte, error)
	queryFileOwner          func(string) ([]byte, error)
	verifyInstalledPayload  func() ([]byte, error)
	attestRecoveryTemporary func(
		*pinnedServiceDirectory, string, string, uint32, uint32,
	) (os.FileInfo, bool, error)
}

type rhelPackageOwnedStaticInventory struct {
	path    string
	entries []string
}

var rhelPackageOwnedStaticInventories = []rhelPackageOwnedStaticInventory{
	{
		path:    "/usr/lib/systemd/system/syswarden-firewall.service.d",
		entries: []string{"10-syswarden-wireguard-ordering.conf"},
	},
	{
		path: "/usr/share/doc/syswarden",
		entries: []string{
			"GEOIP-DATA-LICENSE.txt",
			"LICENSE.txt",
			"rhel-package-owned-profile.json",
		},
	},
	{
		path:    "/usr/libexec/syswarden",
		entries: []string{"rhelpo-postun-recovery-v1"},
	},
}

var rhelPackageOwnedConflictingRecoveryPaths = []string{
	rhelPackageOwnedPresetPendingPath,
	rhelPackageOwnedPresetPendingTempPath,
	RemovalFinalizingPath,
	RemovalFinalizingPath + ".new",
	"/var/lib/syswarden/removal-in-progress-v1.new",
	"/etc/systemd/system/multi-user.target.wants/syswarden-core.service.syswarden-rhelpo-migration",
	"/etc/systemd/system/multi-user.target.wants/syswarden-firewall.service.syswarden-rhelpo-migration",
}

func exactRHELPackageOwnedRPMIdentity(output []byte) error {
	identity, err := parseInstalledRPMIdentity(output)
	if err != nil {
		return err
	}
	if identity != (installedRPMIdentity{
		name: installedRPMPackageName, epoch: "0", version: rhelPackageOwnedRPMVersion,
		release: rhelPackageOwnedRPMRelease, architecture: installedRPMArchitecture,
	}) {
		return fmt.Errorf("installed RPM identity is not exact RHEL package-owned NEVRA")
	}
	if Version != "v"+rhelPackageOwnedRPMVersion {
		return fmt.Errorf("running SysWarden release %q is not the RHEL package-owned release", Version)
	}
	return nil
}

func exactStandardRPMIdentity(output []byte) error {
	identity, err := parseInstalledRPMIdentity(output)
	if err != nil {
		return err
	}
	if identity != (installedRPMIdentity{
		name: installedRPMPackageName, epoch: "0", version: strings.TrimPrefix(Version, "v"),
		release: standardRPMPackageRelease, architecture: installedRPMArchitecture,
	}) {
		return fmt.Errorf("installed RPM identity is not exact standard SysWarden")
	}
	return nil
}

func (host rhelPackageOwnedAttestationHost) rooted(path string) (string, error) {
	if host.root == "" || !filepath.IsAbs(host.root) || filepath.Clean(host.root) != host.root ||
		path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("RHEL package-owned attestation path boundary is invalid")
	}
	if host.root == "/" {
		return path, nil
	}
	return filepath.Join(host.root, strings.TrimPrefix(path, "/")), nil
}

func (host rhelPackageOwnedAttestationHost) uniquePayloadPresence() (bool, error) {
	present := 0
	for _, path := range rhelPackageOwnedUniquePaths {
		rooted, err := host.rooted(path)
		if err != nil {
			return false, err
		}
		if _, err := os.Lstat(rooted); err == nil {
			present++
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("inspect RHEL package-owned payload %s: %w", path, err)
		}
	}
	if present == 0 {
		return false, nil
	}
	if present != len(rhelPackageOwnedUniquePaths) {
		return false, fmt.Errorf("refusing partial RHEL package-owned payload (%d of %d unique files)", present, len(rhelPackageOwnedUniquePaths))
	}
	return true, nil
}

func (host rhelPackageOwnedAttestationHost) attestPriorityUnitsAbsent() error {
	for _, path := range []string{
		"/etc/systemd/system/syswarden-core.service",
		"/etc/systemd/system/syswarden-firewall.service",
	} {
		rooted, err := host.rooted(path)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(rooted); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("inspect priority systemd unit %s: %w", path, err)
		}
		return fmt.Errorf("priority systemd unit remains after RHEL package-owned migration: %s", path)
	}
	return nil
}

func attestRHELPackageOwnedEnablementAbsentAt(root string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return fmt.Errorf("RHEL package-owned enablement root is invalid")
	}
	for _, path := range []string{
		"/etc/systemd/system/multi-user.target.wants/syswarden-core.service",
		"/etc/systemd/system/multi-user.target.wants/syswarden-firewall.service",
	} {
		candidate := path
		if root != "/" {
			candidate = filepath.Join(root, strings.TrimPrefix(path, "/"))
		}
		if _, err := os.Lstat(candidate); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("inspect RHEL package-owned enablement %s: %w", path, err)
		}
		return fmt.Errorf("RHEL package-owned enablement remains after disable: %s", path)
	}
	return nil
}

func (host rhelPackageOwnedAttestationHost) attest() (bool, error) {
	present, err := host.uniquePayloadPresence()
	if err != nil {
		return false, err
	}
	// Generic package scriptlets set SYSWARDEN_PKG_INSTALL while their package
	// manager already owns the transaction lock. A completely absent RHELPO
	// payload is the standard profile in that context and must not recursively
	// query rpm. Partial RHELPO payloads still fail above before this fast path.
	if !present && host.skipAbsentPackageQuery {
		return false, nil
	}
	if host.queryInstalled == nil || host.queryFileOwner == nil || host.verifyInstalledPayload == nil {
		return false, fmt.Errorf("RHEL package-owned attestation dependencies are incomplete")
	}
	installedBefore, err := host.queryInstalled()
	if err != nil {
		if errors.Is(err, errRHELPackageOwnedRPMUnavailable) && !present {
			return false, nil
		}
		return false, fmt.Errorf("query installed RHEL package-owned RPM: %w", err)
	}
	rhelIdentityErr := exactRHELPackageOwnedRPMIdentity(installedBefore)
	if rhelIdentityErr != nil {
		if standardErr := exactStandardRPMIdentity(installedBefore); standardErr == nil && !present {
			return false, nil
		}
		return false, errors.Join(
			fmt.Errorf("installed package identity conflicts with RHEL package-owned payload presence"),
			rhelIdentityErr,
		)
	}
	if !present {
		return true, fmt.Errorf("exact RHEL package-owned NEVRA is installed but its unique payload is absent")
	}
	if err := host.attestRecoveryBoundaries(); err != nil {
		return false, err
	}
	if err := host.attestPriorityUnitsAbsent(); err != nil {
		return false, err
	}
	for _, expected := range rhelPackageOwnedFiles {
		path, err := host.rooted(expected.path)
		if err != nil {
			return false, err
		}
		if err := attestApprovedSystemdServiceDropInParents(
			path, host.root, host.expectedUID, host.expectedGID,
		); err != nil {
			return false, fmt.Errorf("attest RHEL package-owned parent chain for %s: %w", expected.path, err)
		}
		first, err := readFirewallRemovalFileWithOwner(path, expected.mode, host.expectedUID, host.expectedGID)
		if err != nil || string(first.content) != expected.content {
			return false, errors.Join(fmt.Errorf("RHEL package-owned file is not exact: %s", expected.path), err)
		}
		ownerBefore, err := host.queryFileOwner(expected.path)
		ownerIdentityErr := exactRHELPackageOwnedRPMIdentity(ownerBefore)
		if err != nil || ownerIdentityErr != nil {
			return false, errors.Join(
				fmt.Errorf("attest RHEL package ownership for %s", expected.path), err, ownerIdentityErr,
			)
		}
		second, err := readFirewallRemovalFileWithOwner(path, expected.mode, host.expectedUID, host.expectedGID)
		if err != nil || !sameFirewallRemovalFileIdentity(first.identity, second.identity) ||
			!bytes.Equal(first.content, second.content) {
			return false, errors.Join(fmt.Errorf("RHEL package-owned file changed during attestation: %s", expected.path), err)
		}
		ownerAfter, err := host.queryFileOwner(expected.path)
		if err != nil || !bytes.Equal(ownerBefore, ownerAfter) {
			return false, errors.Join(fmt.Errorf("RHEL package ownership changed during attestation: %s", expected.path), err)
		}
	}
	if err := host.attestRequiredDirectories(); err != nil {
		return false, err
	}
	if err := host.attestAdditionalPayloadOwnership(); err != nil {
		return false, err
	}
	if err := host.attestStaticInventories(); err != nil {
		return false, err
	}
	verification, err := host.verifyInstalledPayload()
	if err != nil {
		return false, fmt.Errorf("verify exact RHEL package-owned RPM payload: %w", err)
	}
	if len(verification) != 0 {
		return false, fmt.Errorf("rpm verification reported RHEL package-owned payload deviations")
	}
	installedAfter, err := host.queryInstalled()
	if err != nil || !bytes.Equal(installedBefore, installedAfter) {
		return false, errors.Join(fmt.Errorf("installed RHEL package-owned RPM changed during attestation"), err)
	}
	if err := host.attestPriorityUnitsAbsent(); err != nil {
		return false, err
	}
	return true, nil
}

func (host rhelPackageOwnedAttestationHost) attestRecoveryBoundaries() error {
	for _, logicalPath := range rhelPackageOwnedConflictingRecoveryPaths {
		path, err := host.rooted(logicalPath)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("inspect conflicting RHEL package-owned recovery path %s: %w", logicalPath, err)
		}
		return fmt.Errorf("conflicting RHEL package-owned recovery path is present: %s", logicalPath)
	}
	marker, err := host.rooted(rhelPackageOwnedEraseReadyPath)
	if err != nil {
		return err
	}
	directory, err := openExistingRemovalStateDirectory(filepath.Dir(marker), host.expectedUID, host.expectedGID)
	if err != nil {
		return fmt.Errorf("pin RHEL package-owned erase-state directory: %w", err)
	}
	defer directory.close()
	name := filepath.Base(marker)
	if _, err := directory.root.Lstat(name); err == nil {
		if _, err := attestExactRemovalRecord(
			directory,
			name,
			rhelPackageOwnedEraseReadyRecord,
			host.expectedUID,
			host.expectedGID,
		); err != nil {
			return fmt.Errorf("attest existing RHEL package-owned erase-ready marker: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect RHEL package-owned erase-ready marker: %w", err)
	}
	temporaryName := name + ".new"
	if _, err := directory.root.Lstat(temporaryName); err == nil {
		if host.attestRecoveryTemporary == nil {
			return fmt.Errorf("RHEL package-owned recovery-temporary attestation is unavailable")
		}
		if _, _, err := host.attestRecoveryTemporary(
			directory,
			temporaryName,
			rhelPackageOwnedEraseReadyRecord,
			host.expectedUID,
			host.expectedGID,
		); err != nil {
			return fmt.Errorf("attest interrupted RHEL package-owned erase-ready publication: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect RHEL package-owned erase-ready temporary: %w", err)
	}
	return nil
}

func (host rhelPackageOwnedAttestationHost) attestRequiredDirectories() error {
	for _, expected := range rhelPackageOwnedRequiredDirectories {
		path, err := host.rooted(expected.path)
		if err != nil {
			return err
		}
		if _, err := attestRHELPackageOwnedDirectory(
			path,
			host.root,
			expected.mode,
			host.expectedUID,
			host.expectedGID,
		); err != nil {
			return fmt.Errorf("attest RHEL package-owned required directory %s: %w", expected.path, err)
		}
	}
	return nil
}

func (host rhelPackageOwnedAttestationHost) attestAdditionalPayloadOwnership() error {
	queryStableOwner := func(path string) error {
		before, err := host.queryFileOwner(path)
		identityErr := exactRHELPackageOwnedRPMIdentity(before)
		if err != nil || identityErr != nil {
			return errors.Join(fmt.Errorf("attest RHEL package ownership for %s", path), err, identityErr)
		}
		after, err := host.queryFileOwner(path)
		if err != nil || !bytes.Equal(before, after) {
			return errors.Join(fmt.Errorf("RHEL package ownership changed during attestation: %s", path), err)
		}
		return nil
	}
	for _, expected := range rhelPackageOwnedAdditionalOwnedPayloadFiles {
		path, err := host.rooted(expected.path)
		if err != nil {
			return err
		}
		beforeInfo, err := os.Lstat(path)
		before, identityErr := exactRemovalArtifactIdentity(beforeInfo)
		if err != nil || identityErr != nil ||
			beforeInfo.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
			!beforeInfo.Mode().IsRegular() || beforeInfo.Mode().Perm() != expected.mode ||
			before.uid != host.expectedUID || before.gid != host.expectedGID || before.nlink != 1 {
			return errors.Join(
				fmt.Errorf("RHEL package-owned payload metadata is not exact: %s", expected.path),
				err,
				identityErr,
			)
		}
		if err := queryStableOwner(expected.path); err != nil {
			return err
		}
		afterInfo, err := os.Lstat(path)
		after, afterIdentityErr := exactRemovalArtifactIdentity(afterInfo)
		if err != nil || afterIdentityErr != nil || before != after {
			return errors.Join(
				fmt.Errorf("RHEL package-owned payload changed during attestation: %s", expected.path),
				err,
				afterIdentityErr,
			)
		}
	}
	for _, expected := range rhelPackageOwnedAdditionalOwnedPayloadLinks {
		path, err := host.rooted(expected.path)
		if err != nil {
			return err
		}
		beforeInfo, err := os.Lstat(path)
		before, identityErr := exactRemovalArtifactIdentity(beforeInfo)
		beforeTarget, targetErr := os.Readlink(path)
		if err != nil || identityErr != nil || targetErr != nil || beforeInfo.Mode()&os.ModeSymlink == 0 ||
			beforeInfo.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
			beforeInfo.Mode().Perm() != 0777 || before.uid != host.expectedUID || before.gid != host.expectedGID ||
			before.nlink != 1 || beforeTarget != expected.target {
			return errors.Join(
				fmt.Errorf("RHEL package-owned symlink is not exact: %s", expected.path),
				err,
				identityErr,
				targetErr,
			)
		}
		if err := queryStableOwner(expected.path); err != nil {
			return err
		}
		afterInfo, err := os.Lstat(path)
		after, afterIdentityErr := exactRemovalArtifactIdentity(afterInfo)
		afterTarget, afterTargetErr := os.Readlink(path)
		if err != nil || afterIdentityErr != nil || afterTargetErr != nil || before != after ||
			beforeTarget != afterTarget {
			return errors.Join(
				fmt.Errorf("RHEL package-owned symlink changed during attestation: %s", expected.path),
				err,
				afterIdentityErr,
				afterTargetErr,
			)
		}
	}
	return nil
}

func (host rhelPackageOwnedAttestationHost) attestStaticInventories() error {
	for _, inventory := range rhelPackageOwnedStaticInventories {
		path, err := host.rooted(inventory.path)
		if err != nil {
			return err
		}
		before, err := attestRHELPackageOwnedProductDirectory(
			path, host.root, host.expectedUID, host.expectedGID,
		)
		if err != nil {
			return fmt.Errorf("attest RHEL package-owned inventory root %s: %w", inventory.path, err)
		}
		directory, err := openExistingRemovalStateDirectory(path, host.expectedUID, host.expectedGID)
		if err != nil {
			return fmt.Errorf("pin RHEL package-owned inventory root %s: %w", inventory.path, err)
		}
		entries, inventoryErr := readBoundedRemovalDirectory(directory)
		directory.close()
		if inventoryErr != nil {
			return fmt.Errorf("inventory RHEL package-owned directory %s: %w", inventory.path, inventoryErr)
		}
		expected := make(map[string]struct{}, len(inventory.entries))
		for _, name := range inventory.entries {
			expected[name] = struct{}{}
		}
		if len(entries) != len(expected) {
			return fmt.Errorf("RHEL package-owned directory %s has an unexpected entry count", inventory.path)
		}
		for _, entry := range entries {
			if _, ok := expected[entry.Name()]; !ok {
				return fmt.Errorf(
					"RHEL package-owned directory %s contains unexpected entry %s",
					inventory.path,
					entry.Name(),
				)
			}
		}
		after, err := attestRHELPackageOwnedProductDirectory(
			path, host.root, host.expectedUID, host.expectedGID,
		)
		if err != nil || !samePinnedRemovalDirectoryIdentity(before, after) {
			return errors.Join(
				fmt.Errorf("RHEL package-owned directory %s changed during inventory", inventory.path),
				err,
			)
		}
	}
	return nil
}

func productionRHELPackageOwnedAttestationHost() rhelPackageOwnedAttestationHost {
	executor := hostFirewallExecutor()
	queryInstalled := func() ([]byte, error) {
		rpm, available, err := resolveOptionalFirewallRemovalExecutable(executor, "rpm")
		if err != nil {
			return nil, err
		}
		if !available {
			return nil, errRHELPackageOwnedRPMUnavailable
		}
		output, queryErr := executor.output(
			rpm,
			"--noplugins", "--query", "--queryformat", installedRPMQueryFormat, installedRPMPackageName,
		)
		if queryErr != nil && bytes.Equal(output, []byte(syswardenDropInRPMAbsentEvidence)) {
			return nil, errRHELPackageOwnedRPMUnavailable
		}
		if queryErr != nil {
			return nil, queryErr
		}
		return output, nil
	}
	queryFileOwner := func(path string) ([]byte, error) {
		if err := executor.validate(installedRPMExecutablePath); err != nil {
			return nil, fmt.Errorf("validate RPM executable: %w", err)
		}
		return executor.output(
			installedRPMExecutablePath,
			"--noplugins", "--query", "--file", path, "--queryformat", installedRPMQueryFormat,
		)
	}
	verifyInstalledPayload := func() ([]byte, error) {
		if err := executor.validate(installedRPMExecutablePath); err != nil {
			return nil, fmt.Errorf("validate RPM executable: %w", err)
		}
		return executor.output(
			installedRPMExecutablePath,
			"--noplugins", "--verify", "--nodeps", "--noscripts", "--nomtime", installedRPMPackageName,
		)
	}
	return rhelPackageOwnedAttestationHost{
		root: "/", expectedUID: 0, expectedGID: 0,
		skipAbsentPackageQuery: os.Getenv("SYSWARDEN_PKG_INSTALL") == "1",
		queryInstalled:         queryInstalled, queryFileOwner: queryFileOwner,
		verifyInstalledPayload:  verifyInstalledPayload,
		attestRecoveryTemporary: attestRestrictiveRecoverableRemovalRecord,
	}
}

func attestInstalledRHELPackageOwnedProfile() (bool, error) {
	return productionRHELPackageOwnedAttestationHost().attest()
}

func attestRHELPackageOwnedUnit(path string) error {
	present, err := attestInstalledRHELPackageOwnedProfile()
	if err != nil || !present {
		return errors.Join(fmt.Errorf("RHEL package-owned profile is not exactly attested"), err)
	}
	for _, file := range rhelPackageOwnedFiles[:2] {
		if path == file.path {
			return readExactFirewallRemovalFile(path, file.content, file.mode)
		}
	}
	return fmt.Errorf("refusing unexpected RHEL package-owned systemd unit %s", path)
}

func publishRHELPackageOwnedEraseReadyAt(path string, expectedUID, expectedGID uint32) error {
	if filepath.Base(path) != ".syswarden-rhelpo-erase-ready-v1" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("RHEL package-owned erase-ready path is not exact")
	}
	if err := publishExactRemovalRecordAt(path, rhelPackageOwnedEraseReadyRecord, expectedUID, expectedGID); err != nil {
		return fmt.Errorf("publish RHEL package-owned erase-ready marker: %w", err)
	}
	directory, err := openExistingRemovalStateDirectory(filepath.Dir(path), expectedUID, expectedGID)
	if err != nil {
		return err
	}
	defer directory.close()
	if _, err := attestExactRemovalRecord(
		directory, filepath.Base(path), rhelPackageOwnedEraseReadyRecord, expectedUID, expectedGID,
	); err != nil {
		return fmt.Errorf("attest RHEL package-owned erase-ready marker: %w", err)
	}
	return nil
}

func recoverRHELPackageOwnedEraseReadyTemporaryAt(path string, expectedUID, expectedGID uint32) error {
	if filepath.Base(path) != ".syswarden-rhelpo-erase-ready-v1" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("RHEL package-owned erase-ready path is not exact")
	}
	directory, err := openExistingRemovalStateDirectory(filepath.Dir(path), expectedUID, expectedGID)
	if err != nil {
		return err
	}
	defer directory.close()
	temporaryName := filepath.Base(path) + ".new"
	_, err = directory.root.Lstat(temporaryName)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect RHEL package-owned erase-ready temporary: %w", err)
	}
	temporaryInfo, _, err := attestRecoverableRemovalRecordForPublication(
		directory,
		temporaryName,
		rhelPackageOwnedEraseReadyRecord,
		expectedUID,
		expectedGID,
	)
	if err != nil {
		return fmt.Errorf("attest RHEL package-owned erase-ready temporary: %w", err)
	}
	if err := removeRecoverableRemovalRecord(
		directory,
		temporaryName,
		rhelPackageOwnedEraseReadyRecord,
		temporaryInfo,
		expectedUID,
		expectedGID,
	); err != nil {
		return fmt.Errorf("recover RHEL package-owned erase-ready temporary: %w", err)
	}
	return nil
}

func attestRHELPackageOwnedDirectory(
	path string,
	trustedRoot string,
	expectedMode os.FileMode,
	expectedUID uint32,
	expectedGID uint32,
) (removalArtifactIdentity, error) {
	if err := attestApprovedSystemdServiceDropInParents(
		path, trustedRoot, expectedUID, expectedGID,
	); err != nil {
		return removalArtifactIdentity{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return removalArtifactIdentity{}, err
	}
	identity, identityErr := exactRemovalArtifactIdentity(info)
	if identityErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		info.Mode().Perm() != expectedMode || identity.uid != expectedUID || identity.gid != expectedGID {
		return removalArtifactIdentity{}, errors.Join(
			fmt.Errorf("RHEL package-owned directory is not exact: %s", path), identityErr,
		)
	}
	return identity, nil
}

func attestRHELPackageOwnedRuntimeDirectory(
	path string,
	trustedRoot string,
	expectedUID uint32,
	expectedGID uint32,
) (removalArtifactIdentity, error) {
	return attestRHELPackageOwnedDirectory(path, trustedRoot, 0750, expectedUID, expectedGID)
}

func attestRHELPackageOwnedProductDirectory(
	path string,
	trustedRoot string,
	expectedUID uint32,
	expectedGID uint32,
) (removalArtifactIdentity, error) {
	return attestRHELPackageOwnedDirectory(path, trustedRoot, 0755, expectedUID, expectedGID)
}

func attestRHELPackageOwnedProductFilesAt(
	rooted func(string) string,
	expectedUID uint32,
	expectedGID uint32,
) error {
	for _, expected := range rhelPackageOwnedProductFiles {
		path := rooted(expected.path)
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect RPM-owned product payload %s: %w", expected.path, err)
		}
		identity, identityErr := exactRemovalArtifactIdentity(info)
		if identityErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
			info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
			info.Mode().Perm() != expected.mode || identity.uid != expectedUID || identity.gid != expectedGID ||
			identity.nlink != 1 {
			return errors.Join(
				fmt.Errorf("RPM-owned product payload is not exact: %s", expected.path),
				identityErr,
			)
		}
	}
	return nil
}

func cleanRHELPackageOwnedDirectory(
	path string,
	allowed map[string]struct{},
	expectedUID uint32,
	expectedGID uint32,
) error {
	directory, err := openExistingRemovalStateDirectory(path, expectedUID, expectedGID)
	if err != nil {
		return err
	}
	defer directory.close()
	entries, err := readBoundedRemovalDirectory(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
			return fmt.Errorf("refusing invalid RHEL package-owned runtime entry %q", name)
		}
		if _, preserve := allowed[name]; preserve {
			continue
		}
		if err := directory.root.RemoveAll(name); err != nil {
			return fmt.Errorf("remove RHEL package-owned runtime entry %s: %w", filepath.Join(path, name), err)
		}
		if _, err := directory.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(fmt.Errorf("RHEL package-owned runtime entry remains: %s", filepath.Join(path, name)), err)
		}
	}
	if err := directory.sync(); err != nil {
		return fmt.Errorf("sync RHEL package-owned runtime cleanup %s: %w", path, err)
	}
	confirmed, err := readBoundedRemovalDirectory(directory)
	if err != nil {
		return err
	}
	if len(confirmed) != len(allowed) {
		return fmt.Errorf("RHEL package-owned directory %s has unexpected residual entries", path)
	}
	for _, entry := range confirmed {
		if _, expected := allowed[entry.Name()]; !expected {
			return fmt.Errorf("RHEL package-owned directory %s retained unexpected entry %s", path, entry.Name())
		}
	}
	return nil
}

func prepareRHELPackageOwnedRuntimeForEraseAt(
	root string,
	markerPath string,
	expectedUID uint32,
	expectedGID uint32,
	attestPackagePayload func() error,
) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return fmt.Errorf("RHEL package-owned cleanup root is invalid")
	}
	if attestPackagePayload == nil {
		return fmt.Errorf("RHEL package-owned payload attestation is unavailable")
	}
	if err := attestPackagePayload(); err != nil {
		return fmt.Errorf("attest complete RPM payload before erase-state recovery: %w", err)
	}
	rooted := func(path string) string {
		if root == "/" {
			return path
		}
		return filepath.Join(root, strings.TrimPrefix(path, "/"))
	}
	for _, path := range []string{
		rhelPackageOwnedPresetPendingPath,
		rhelPackageOwnedPresetPendingTempPath,
	} {
		if _, err := os.Lstat(rooted(path)); err == nil {
			return fmt.Errorf("refusing RHEL package-owned cleanup while preset recovery remains pending: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect RHEL package-owned preset recovery boundary %s: %w", path, err)
		}
	}
	if err := recoverRHELPackageOwnedEraseReadyTemporaryAt(markerPath, expectedUID, expectedGID); err != nil {
		return err
	}
	markerExisted := false
	var markerIdentity removalArtifactIdentity
	if markerInfo, err := os.Lstat(markerPath); err == nil {
		markerExisted = true
		markerIdentity, err = exactRemovalArtifactIdentity(markerInfo)
		if err != nil {
			return fmt.Errorf("attest existing RHEL package-owned erase-ready marker identity: %w", err)
		}
		markerDirectory, err := openExistingRemovalStateDirectory(filepath.Dir(markerPath), expectedUID, expectedGID)
		if err != nil {
			return err
		}
		_, markerErr := attestExactRemovalRecord(
			markerDirectory,
			filepath.Base(markerPath),
			rhelPackageOwnedEraseReadyRecord,
			expectedUID,
			expectedGID,
		)
		markerDirectory.close()
		if markerErr != nil {
			return fmt.Errorf("attest existing RHEL package-owned erase-ready marker: %w", markerErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect RHEL package-owned erase-ready marker: %w", err)
	}
	identities := make(map[string]removalArtifactIdentity, len(rhelPackageOwnedRuntimeDirectories))
	for _, path := range rhelPackageOwnedRuntimeDirectories {
		identity, err := attestRHELPackageOwnedRuntimeDirectory(
			rooted(path), root, expectedUID, expectedGID,
		)
		if err != nil {
			return fmt.Errorf("attest RPM-owned runtime directory %s: %w", path, err)
		}
		identities[path] = identity
	}
	productIdentities := make(map[string]removalArtifactIdentity, len(rhelPackageOwnedProductDirectories))
	for _, path := range rhelPackageOwnedProductDirectories {
		identity, err := attestRHELPackageOwnedProductDirectory(
			rooted(path), root, expectedUID, expectedGID,
		)
		if err != nil {
			return fmt.Errorf("attest RPM-owned product directory %s: %w", path, err)
		}
		productIdentities[path] = identity
	}
	if err := attestRHELPackageOwnedProductFilesAt(rooted, expectedUID, expectedGID); err != nil {
		return err
	}
	statePath := rooted("/var/lib/syswarden")
	stateDirectory, err := openExistingRemovalStateDirectory(statePath, expectedUID, expectedGID)
	if err != nil {
		return err
	}
	_, tombstoneErr := attestRemovalTombstone(stateDirectory, expectedUID, expectedGID)
	stateDirectory.close()
	if tombstoneErr != nil {
		return tombstoneErr
	}
	if err := attestPackagePayload(); err != nil {
		return fmt.Errorf("attest complete RPM payload before runtime cleanup: %w", err)
	}

	steps := []struct {
		path    string
		allowed []string
	}{
		{path: "/etc/syswarden/config/modules"},
		{path: "/etc/syswarden/lists"},
		{path: "/etc/syswarden/tls"},
		{path: "/etc/syswarden/config", allowed: []string{"modules"}},
		{path: "/etc/syswarden", allowed: []string{"config", "lists", "tls"}},
		{path: "/var/lib/syswarden/ui"},
		{path: "/var/lib/syswarden", allowed: []string{"ui", removalTombstoneName}},
		{path: "/var/log/syswarden"},
		{path: "/opt/syswarden/bin", allowed: []string{"syswarden-cli", "syswarden-core", "syswarden-tui"}},
		{path: "/opt/syswarden", allowed: []string{"bin", "signatures.json"}},
	}
	for _, step := range steps {
		allowed := make(map[string]struct{}, len(step.allowed))
		for _, name := range step.allowed {
			allowed[name] = struct{}{}
		}
		if err := cleanRHELPackageOwnedDirectory(
			rooted(step.path), allowed, expectedUID, expectedGID,
		); err != nil {
			return err
		}
	}
	for _, path := range rhelPackageOwnedRuntimeDirectories {
		current, err := attestRHELPackageOwnedRuntimeDirectory(rooted(path), root, expectedUID, expectedGID)
		if err != nil || !samePinnedRemovalDirectoryIdentity(identities[path], current) {
			return errors.Join(fmt.Errorf("RPM-owned runtime directory changed during cleanup: %s", path), err)
		}
	}
	for _, path := range rhelPackageOwnedProductDirectories {
		current, err := attestRHELPackageOwnedProductDirectory(rooted(path), root, expectedUID, expectedGID)
		if err != nil || !samePinnedRemovalDirectoryIdentity(productIdentities[path], current) {
			return errors.Join(fmt.Errorf("RPM-owned product directory changed during cleanup: %s", path), err)
		}
	}
	if err := attestRHELPackageOwnedProductFilesAt(rooted, expectedUID, expectedGID); err != nil {
		return err
	}
	if err := attestPackagePayload(); err != nil {
		return fmt.Errorf("reattest complete RPM payload after runtime cleanup: %w", err)
	}
	if markerExisted {
		markerDirectory, err := openExistingRemovalStateDirectory(filepath.Dir(markerPath), expectedUID, expectedGID)
		if err != nil {
			return err
		}
		markerInfo, markerErr := attestExactRemovalRecord(
			markerDirectory,
			filepath.Base(markerPath),
			rhelPackageOwnedEraseReadyRecord,
			expectedUID,
			expectedGID,
		)
		markerDirectory.close()
		currentIdentity, identityErr := exactRemovalArtifactIdentity(markerInfo)
		if markerErr != nil || identityErr != nil || currentIdentity != markerIdentity {
			return errors.Join(
				fmt.Errorf("RHEL package-owned erase-ready marker changed during cleanup"),
				markerErr,
				identityErr,
			)
		}
	}
	if err := publishRHELPackageOwnedEraseReadyAt(markerPath, expectedUID, expectedGID); err != nil {
		return err
	}
	return nil
}

func prepareRHELPackageOwnedRuntimeForErase() error {
	return prepareRHELPackageOwnedRuntimeForEraseAt(
		"/", rhelPackageOwnedEraseReadyPath, 0, 0,
		func() error {
			present, err := attestInstalledRHELPackageOwnedProfile()
			if err != nil || !present {
				return errors.Join(fmt.Errorf("exact RHEL package-owned profile is not present"), err)
			}
			return nil
		},
	)
}
