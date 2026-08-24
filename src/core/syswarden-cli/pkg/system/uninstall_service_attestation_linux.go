//go:build linux

package system

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- dpkg checksum metadata is defined as MD5
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"syswarden-cli/pkg/wireguardstate"
)

const maximumFirewallRemovalUnitSize = 64 << 10

const (
	systemdWireGuardPackageName    = "wireguard-tools"
	dpkgWireGuardStatusQueryFormat = "${Status}\\t${Package}\\t${Version}\\n"
	rpmWireGuardOwnerQueryFormat   = "%{NAME}\\t%{EVR}\\n"
)

type firewallRemovalWireGuardEvidence struct {
	present              bool
	transactionPending   bool
	transactionOperation wireguardstate.TransactionOperation
	inventory            wireguardstate.Inventory
	manifest             wireguardstate.Manifest
}

func attestFirewallRemovalWireGuardStateOperationAwareWith(
	inspectTransaction func() (wireguardstate.TransactionOperation, bool, error),
	inspect func() (wireguardstate.Inventory, error),
	verify func() (wireguardstate.Manifest, error),
) (firewallRemovalWireGuardEvidence, error) {
	if inspectTransaction == nil || inspect == nil || verify == nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("WireGuard state attestation dependencies are incomplete")
	}
	operation, transactionPending, err := inspectTransaction()
	if err != nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("inspect bounded WireGuard transaction: %w", err)
	}
	if !transactionPending {
		return attestFirewallRemovalWireGuardStateWith(inspect, verify)
	}
	switch operation {
	case wireguardstate.TransactionOperationRemovePendingReload:
	case wireguardstate.TransactionOperationRemove:
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf(
			"refusing unproven WireGuard removal transaction without durable nftables-cleanup evidence",
		)
	case wireguardstate.TransactionOperationPublish:
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf(
			"refusing WireGuard removal while a publication transaction is pending",
		)
	default:
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf(
			"refusing unknown WireGuard transaction operation %q", operation,
		)
	}
	inventory, err := inspect()
	if err != nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("inspect bounded WireGuard removal debt: %w", err)
	}
	if !inventory.Transaction {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf(
			"WireGuard removal journal disappeared during state attestation",
		)
	}
	confirmedOperation, confirmedPending, err := inspectTransaction()
	if err != nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("reinspect bounded WireGuard transaction: %w", err)
	}
	confirmedInventory, err := inspect()
	if err != nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("reinspect bounded WireGuard removal debt: %w", err)
	}
	if !confirmedPending || confirmedOperation != operation || !reflect.DeepEqual(inventory, confirmedInventory) {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf(
			"WireGuard removal transaction changed during state attestation",
		)
	}
	return firewallRemovalWireGuardEvidence{
		transactionPending:   true,
		transactionOperation: operation,
		inventory:            inventory,
	}, nil
}

func attestFirewallRemovalWireGuardStateWith(
	inspect func() (wireguardstate.Inventory, error),
	verify func() (wireguardstate.Manifest, error),
) (firewallRemovalWireGuardEvidence, error) {
	if inspect == nil || verify == nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("WireGuard state attestation dependencies are incomplete")
	}
	inventory, err := inspect()
	if err != nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("inspect bounded WireGuard state: %w", err)
	}
	if inventory.Transaction {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf(
			"refusing WireGuard removal while a recoverable transaction is pending",
		)
	}
	if inventory.Empty() {
		return firewallRemovalWireGuardEvidence{}, nil
	}
	manifest, err := verify()
	if err != nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("verify bounded WireGuard state: %w", err)
	}
	confirmed, err := inspect()
	if err != nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("reinspect bounded WireGuard state: %w", err)
	}
	if !reflect.DeepEqual(inventory, confirmed) {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("WireGuard state inventory changed during attestation")
	}
	return firewallRemovalWireGuardEvidence{
		present: true, inventory: inventory, manifest: manifest,
	}, nil
}

func attestFirewallRemovalWireGuardState() (firewallRemovalWireGuardEvidence, error) {
	return attestFirewallRemovalWireGuardStateOperationAwareWith(
		func() (wireguardstate.TransactionOperation, bool, error) {
			return wireguardstate.InspectTransaction("/", 0, 0)
		},
		func() (wireguardstate.Inventory, error) { return wireguardstate.Inspect("/") },
		func() (wireguardstate.Manifest, error) { return wireguardstate.ReadAndVerify("/", 0, 0) },
	)
}

var readWireGuardServerBeforeRemovalStop = func() ([]byte, error) {
	manifest, err := wireguardstate.ReadAndVerify("/", 0, 0)
	if err != nil {
		return nil, fmt.Errorf("reattest WireGuard ownership manifest: %w", err)
	}
	server, err := wireguardstate.ReadVerifiedArtifact(
		"/", manifest, wireguardstate.ServerConfigurationPath, 0, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("reattest WireGuard server artifact: %w", err)
	}
	return server, nil
}

var attestWireGuardStopHookExecutables = wireguardstate.AttestServerHookExecutables

func verifyWireGuardServerBeforeRemovalStop() error {
	server, err := readWireGuardServerBeforeRemovalStop()
	if err != nil {
		return err
	}
	identity, err := wireguardstate.ParseServerConfiguration(server)
	if err != nil {
		return fmt.Errorf("verify WireGuard server grammar: %w", err)
	}
	if err := attestWireGuardStopHookExecutables(identity); err != nil {
		return fmt.Errorf("reattest WireGuard server hook executables immediately before stop: %w", err)
	}
	return nil
}

func sameFirewallRemovalWireGuardEvidence(left, right firewallRemovalWireGuardEvidence) bool {
	return left.present == right.present && left.transactionPending == right.transactionPending &&
		left.transactionOperation == right.transactionOperation && reflect.DeepEqual(left.inventory, right.inventory) &&
		reflect.DeepEqual(left.manifest, right.manifest)
}

func inspectWireGuardRemovalInterface() (bool, error) {
	_, err := os.Lstat("/sys/class/net/wg-syswarden")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect wg-syswarden interface: %w", err)
	}
	return true, nil
}

func resolveWireGuardRemovalExecutable() (string, error) {
	resolved, err := filepath.EvalSymlinks("/usr/bin/wg-quick")
	if err != nil {
		return "", fmt.Errorf("resolve /usr/bin/wg-quick: %w", err)
	}
	resolved = filepath.Clean(resolved)
	if !filepath.IsAbs(resolved) {
		return "", fmt.Errorf("resolved wg-quick executable is not absolute")
	}
	if err := validateResolvedFirewallExecutable(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

func attestRootOwnedFirewallRemovalFile(path string, executable bool) (os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("firewall removal file path %q is not clean and absolute", path)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || before.Size() < 0 || before.Size() > maximumFirewallRemovalUnitSize {
		return nil, fmt.Errorf("refusing unsafe firewall removal file %s", path)
	}
	if executable && before.Mode().Perm()&0111 == 0 {
		return nil, fmt.Errorf("firewall removal service file %s is not executable", path)
	}
	return before, nil
}

type firewallRemovalFileSnapshot struct {
	identity os.FileInfo
	content  []byte
}

func sameFirewallRemovalFileIdentity(first, second os.FileInfo) bool {
	firstStat, firstOK := first.Sys().(*syscall.Stat_t)
	secondStat, secondOK := second.Sys().(*syscall.Stat_t)
	return firstOK && secondOK && os.SameFile(first, second) && first.Mode() == second.Mode() &&
		first.Size() == second.Size() && first.ModTime() == second.ModTime() &&
		firstStat.Uid == secondStat.Uid && firstStat.Gid == secondStat.Gid &&
		firstStat.Nlink == secondStat.Nlink && firstStat.Ctim == secondStat.Ctim
}

func readFirewallRemovalFile(path string, mode os.FileMode) (firewallRemovalFileSnapshot, error) {
	before, err := attestRootOwnedFirewallRemovalFile(path, mode&0111 != 0)
	if err != nil {
		return firewallRemovalFileSnapshot{}, err
	}
	if before.Mode().Perm() != mode {
		return firewallRemovalFileSnapshot{}, fmt.Errorf(
			"firewall removal service file %s has mode %04o, want %04o", path, before.Mode().Perm(), mode,
		)
	}
	file, err := os.Open(path) // #nosec G304 -- fixed product service paths are lstat/fstat identity attested
	if err != nil {
		return firewallRemovalFileSnapshot{}, err
	}
	opened, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, maximumFirewallRemovalUnitSize+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil ||
		!sameFirewallRemovalFileIdentity(before, opened) || len(content) > maximumFirewallRemovalUnitSize {
		return firewallRemovalFileSnapshot{}, fmt.Errorf("firewall removal service file %s changed while reading", path)
	}
	after, err := os.Lstat(path)
	if err != nil || !sameFirewallRemovalFileIdentity(opened, after) {
		return firewallRemovalFileSnapshot{}, fmt.Errorf("firewall removal service file %s changed during attestation", path)
	}
	return firewallRemovalFileSnapshot{identity: after, content: content}, nil
}

func readExactFirewallRemovalFile(path string, expected string, mode os.FileMode) error {
	snapshot, err := readFirewallRemovalFile(path, mode)
	if err != nil {
		return err
	}
	if string(snapshot.content) != expected {
		return fmt.Errorf("refusing modified firewall removal service file %s", path)
	}
	return nil
}

func removeExactFirewallRemovalFile(path string, expected string, mode os.FileMode) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect firewall removal service file %s: %w", path, err)
	}
	if err := readExactFirewallRemovalFile(path, expected, mode); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove exact firewall removal service file %s: %w", path, err)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("verify firewall removal service file absence %s: %w", path, err)
	}
	return fmt.Errorf("firewall removal service file %s remains after removal", path)
}

func resolveOptionalFirewallRemovalExecutable(
	executor firewallManagerExecutor,
	name string,
) (string, bool, error) {
	if executor.lookPath == nil || executor.validate == nil || executor.output == nil {
		return "", false, fmt.Errorf("firewall removal package attestation dependencies are incomplete")
	}
	candidate, err := executor.lookPath(name)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("resolve optional %s executable: %w", name, err)
	}
	frozen := executor
	frozen.lookPath = func(requested string) (string, error) {
		if requested != name {
			return "", fmt.Errorf("unexpected executable lookup %s", requested)
		}
		return candidate, nil
	}
	resolved, err := resolveFirewallExecutable(frozen, name)
	if err != nil {
		return "", false, err
	}
	return resolved, true, nil
}

func parseDPKGWireGuardPackageVersion(output []byte) (string, error) {
	if len(output) == 0 || strings.ContainsAny(string(output), "\x00\r") ||
		strings.Count(string(output), "\n") != 1 || output[len(output)-1] != '\n' {
		return "", fmt.Errorf("dpkg WireGuard package status is ambiguous")
	}
	fields := strings.Split(strings.TrimSuffix(string(output), "\n"), "\t")
	if len(fields) != 3 || fields[0] != "install ok installed" ||
		fields[1] != systemdWireGuardPackageName || !safePackageVersion(fields[2]) {
		return "", fmt.Errorf("dpkg WireGuard package status is not an exact installed package")
	}
	return fields[2], nil
}

func parseRPMWireGuardPackageVersion(output []byte) (string, error) {
	if len(output) == 0 || strings.ContainsAny(string(output), "\x00\r") ||
		strings.Count(string(output), "\n") != 1 || output[len(output)-1] != '\n' {
		return "", fmt.Errorf("RPM WireGuard package ownership is ambiguous")
	}
	fields := strings.Split(strings.TrimSuffix(string(output), "\n"), "\t")
	if len(fields) != 2 || fields[0] != systemdWireGuardPackageName || !safePackageVersion(fields[1]) {
		return "", fmt.Errorf("RPM WireGuard unit is not owned by the expected package")
	}
	return fields[1], nil
}

func attestDPKGWireGuardFileList(
	output []byte,
	path string,
	canonicalize func(string) (string, error),
) error {
	if canonicalize == nil || bytes.IndexByte(output, 0) >= 0 || bytes.IndexByte(output, '\r') >= 0 {
		return fmt.Errorf("dpkg WireGuard package file inventory is invalid")
	}
	want, err := canonicalize(path)
	if err != nil {
		return fmt.Errorf("canonicalize WireGuard unit path for package ownership: %w", err)
	}
	if !filepath.IsAbs(want) {
		return fmt.Errorf("canonicalized WireGuard unit path for package ownership is not absolute")
	}
	matches := 0
	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		if !filepath.IsAbs(line) {
			return fmt.Errorf("dpkg WireGuard package file inventory contains a diversion or malformed path")
		}
		candidate, err := canonicalize(line)
		if err == nil && filepath.Clean(candidate) == filepath.Clean(want) {
			matches++
		}
	}
	if matches != 1 {
		return fmt.Errorf("dpkg WireGuard package owns %d canonical unit paths, want 1", matches)
	}
	return nil
}

func attestDPKGWireGuardChecksumMetadata(
	output []byte,
	path string,
	canonicalize func(string) (string, error),
) (string, error) {
	if canonicalize == nil || len(output) == 0 || bytes.IndexByte(output, 0) >= 0 ||
		bytes.IndexByte(output, '\r') >= 0 || output[len(output)-1] != '\n' {
		return "", fmt.Errorf("dpkg WireGuard checksum metadata is invalid")
	}
	want, err := canonicalize(path)
	if err != nil {
		return "", fmt.Errorf("canonicalize WireGuard unit path for checksum metadata: %w", err)
	}
	if !filepath.IsAbs(want) {
		return "", fmt.Errorf("canonicalized WireGuard unit path for checksum metadata is not absolute")
	}
	seenPaths := make(map[string]struct{})
	matchedDigest := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(output), "\n"), "\n") {
		if len(line) < 35 || line[32:34] != "  " {
			return "", fmt.Errorf("dpkg WireGuard checksum metadata contains a malformed record")
		}
		digest := line[:32]
		for _, character := range digest {
			if !((character >= '0' && character <= '9') ||
				(character >= 'a' && character <= 'f') ||
				(character >= 'A' && character <= 'F')) {
				return "", fmt.Errorf("dpkg WireGuard checksum metadata contains a malformed digest")
			}
		}
		relativePath := line[34:]
		if relativePath == "" || filepath.IsAbs(relativePath) || filepath.Clean(relativePath) != relativePath ||
			relativePath == "." {
			return "", fmt.Errorf("dpkg WireGuard checksum metadata contains an unsafe path")
		}
		if _, duplicated := seenPaths[relativePath]; duplicated {
			return "", fmt.Errorf("dpkg WireGuard checksum metadata duplicates path %s", relativePath)
		}
		seenPaths[relativePath] = struct{}{}
		candidate, err := canonicalize(string(filepath.Separator) + relativePath)
		if err == nil && filepath.Clean(candidate) == filepath.Clean(want) {
			if matchedDigest != "" {
				return "", fmt.Errorf("dpkg WireGuard checksum metadata contains multiple canonical unit records")
			}
			matchedDigest = strings.ToLower(digest)
		}
	}
	if matchedDigest == "" {
		return "", fmt.Errorf("dpkg WireGuard checksum metadata omits the unit")
	}
	return matchedDigest, nil
}

func attestDPKGWireGuardVerification(output []byte) error {
	if len(output) == 0 {
		return nil
	}
	if bytes.IndexByte(output, 0) >= 0 || bytes.IndexByte(output, '\r') >= 0 || output[len(output)-1] != '\n' {
		return fmt.Errorf("dpkg WireGuard package verification output is malformed")
	}
	const missingPrefix = "missing     "
	seen := make(map[string]struct{})
	for _, line := range strings.Split(strings.TrimSuffix(string(output), "\n"), "\n") {
		if !strings.HasPrefix(line, missingPrefix) {
			return fmt.Errorf("dpkg WireGuard package verification reported non-missing drift")
		}
		path := strings.TrimPrefix(line, missingPrefix)
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("dpkg WireGuard package verification reported an unsafe missing path")
		}
		if _, duplicated := seen[path]; duplicated {
			return fmt.Errorf("dpkg WireGuard package verification duplicated missing path %s", path)
		}
		seen[path] = struct{}{}
		allowed := strings.HasPrefix(path, "/usr/share/doc/wireguard-tools/") ||
			path == "/usr/share/man/man8/wg.8.gz" ||
			path == "/usr/share/man/man8/wg-quick.8.gz" ||
			path == "/usr/share/lintian/overrides/wireguard-tools"
		if !allowed {
			return fmt.Errorf("dpkg WireGuard package verification reported disallowed missing path %s", path)
		}
	}
	return nil
}

type firewallRemovalPackageAuthorityEvidence struct {
	claim     string
	proof     string
	ambiguous bool
	err       error
}

func attestDPKGWireGuardUnitPackage(
	executor firewallManagerExecutor,
	dpkgQuery string,
	dpkg string,
	path string,
	canonicalize func(string) (string, error),
	expectedContent []byte,
) firewallRemovalPackageAuthorityEvidence {
	status, err := executor.output(
		dpkgQuery, "--show", "--showformat="+dpkgWireGuardStatusQueryFormat, systemdWireGuardPackageName,
	)
	if err != nil {
		return firewallRemovalPackageAuthorityEvidence{err: fmt.Errorf("query installed dpkg WireGuard package: %w", err)}
	}
	version, err := parseDPKGWireGuardPackageVersion(status)
	if err != nil {
		return firewallRemovalPackageAuthorityEvidence{ambiguous: true, err: err}
	}
	files, err := executor.output(dpkgQuery, "--listfiles", systemdWireGuardPackageName)
	if err != nil {
		return firewallRemovalPackageAuthorityEvidence{
			ambiguous: true,
			err:       fmt.Errorf("query dpkg WireGuard package files: %w", err),
		}
	}
	if err := attestDPKGWireGuardFileList(files, path, canonicalize); err != nil {
		return firewallRemovalPackageAuthorityEvidence{ambiguous: true, err: err}
	}
	evidence := firewallRemovalPackageAuthorityEvidence{claim: "dpkg@" + version}
	checksumMetadata, err := executor.output(
		dpkgQuery, "--control-show", systemdWireGuardPackageName, "md5sums",
	)
	if err != nil {
		evidence.err = fmt.Errorf("query dpkg WireGuard checksum metadata: %w", err)
		return evidence
	}
	checksum, err := attestDPKGWireGuardChecksumMetadata(checksumMetadata, path, canonicalize)
	if err != nil {
		evidence.err = err
		return evidence
	}
	contentChecksum := md5.Sum(expectedContent) // #nosec G401 -- compare a snapshot to dpkg's mandatory MD5 metadata
	if checksum != fmt.Sprintf("%x", contentChecksum) {
		evidence.err = fmt.Errorf("dpkg WireGuard unit content does not match package checksum metadata")
		return evidence
	}
	verification, err := executor.output(
		dpkg, "--verify", "--verify-format=rpm", systemdWireGuardPackageName,
	)
	if err != nil {
		evidence.err = fmt.Errorf("verify dpkg WireGuard package integrity: %w", err)
		return evidence
	}
	if err := attestDPKGWireGuardVerification(verification); err != nil {
		evidence.err = err
		return evidence
	}
	evidence.proof = evidence.claim + "#" + checksum
	return evidence
}

func attestRPMWireGuardUnitPackage(
	executor firewallManagerExecutor,
	rpm string,
	path string,
) firewallRemovalPackageAuthorityEvidence {
	owner, err := executor.output(
		rpm, "--query", "--file", path, "--queryformat", rpmWireGuardOwnerQueryFormat,
	)
	if err != nil {
		return firewallRemovalPackageAuthorityEvidence{err: fmt.Errorf("query RPM WireGuard unit ownership: %w", err)}
	}
	version, err := parseRPMWireGuardPackageVersion(owner)
	if err != nil {
		return firewallRemovalPackageAuthorityEvidence{ambiguous: true, err: err}
	}
	evidence := firewallRemovalPackageAuthorityEvidence{claim: "rpm@" + version}
	verification, err := executor.output(rpm, "--verify", "--file", path, "--noscripts")
	if err != nil {
		evidence.err = fmt.Errorf("verify RPM WireGuard package integrity: %w", err)
		return evidence
	}
	if len(verification) != 0 {
		evidence.err = fmt.Errorf("RPM WireGuard package integrity verification reported drift")
		return evidence
	}
	evidence.proof = evidence.claim
	return evidence
}

func attestSystemdWireGuardPackageEvidenceWith(
	executor firewallManagerExecutor,
	path string,
	canonicalize func(string) (string, error),
	expectedContent []byte,
) (string, error) {
	var ambiguities []string
	var claims []string
	var proven []string
	var failures []string

	dpkgQuery, dpkgQueryPresent, err := resolveOptionalFirewallRemovalExecutable(executor, "dpkg-query")
	if err != nil {
		return "", err
	}
	if dpkgQueryPresent {
		dpkg, dpkgPresent, err := resolveOptionalFirewallRemovalExecutable(executor, "dpkg")
		if err != nil {
			return "", err
		}
		if !dpkgPresent {
			failures = append(failures, "dpkg executable is absent")
		} else {
			evidence := attestDPKGWireGuardUnitPackage(
				executor, dpkgQuery, dpkg, path, canonicalize, expectedContent,
			)
			if evidence.claim != "" {
				claims = append(claims, evidence.claim)
			}
			if evidence.proof != "" {
				proven = append(proven, evidence.proof)
			}
			if evidence.err != nil {
				failures = append(failures, "dpkg: "+evidence.err.Error())
			}
			if evidence.ambiguous {
				ambiguities = append(ambiguities, "dpkg")
			}
		}
	}

	rpm, rpmPresent, err := resolveOptionalFirewallRemovalExecutable(executor, "rpm")
	if err != nil {
		return "", err
	}
	if rpmPresent {
		evidence := attestRPMWireGuardUnitPackage(executor, rpm, path)
		if evidence.claim != "" {
			claims = append(claims, evidence.claim)
		}
		if evidence.proof != "" {
			proven = append(proven, evidence.proof)
		}
		if evidence.err != nil {
			failures = append(failures, "rpm: "+evidence.err.Error())
		}
		if evidence.ambiguous {
			ambiguities = append(ambiguities, "rpm")
		}
	}

	if len(ambiguities) > 0 {
		return "", fmt.Errorf("refusing ambiguous WireGuard package-manager responses: %s", strings.Join(ambiguities, ", "))
	}
	if len(claims) > 1 {
		return "", fmt.Errorf("refusing ambiguous WireGuard unit package authorities: %s", strings.Join(claims, ", "))
	}
	if len(proven) == 1 && len(claims) == 1 {
		return proven[0], nil
	}
	if len(proven) > 1 {
		return "", fmt.Errorf("refusing multiple WireGuard unit package proofs: %s", strings.Join(proven, ", "))
	}
	if len(failures) == 0 {
		return "", fmt.Errorf("no supported package authority can attest the WireGuard unit")
	}
	return "", fmt.Errorf("no package authority attested the WireGuard unit: %s", strings.Join(failures, "; "))
}

func attestSystemdWireGuardPackageWith(
	executor firewallManagerExecutor,
	path string,
	canonicalize func(string) (string, error),
	expectedContent []byte,
) error {
	_, err := attestSystemdWireGuardPackageEvidenceWith(executor, path, canonicalize, expectedContent)
	return err
}

func attestStablePackageOwnedSystemdWireGuardUnit(
	path string,
	readSnapshot func(string, os.FileMode) (firewallRemovalFileSnapshot, error),
	attestPackage func([]byte) (string, error),
) error {
	if readSnapshot == nil || attestPackage == nil {
		return fmt.Errorf("WireGuard package attestation dependencies are incomplete")
	}
	before, err := readSnapshot(path, 0644)
	if err != nil {
		return err
	}
	firstEvidence, err := attestPackage(before.content)
	if err != nil {
		return err
	}
	secondEvidence, err := attestPackage(before.content)
	if err != nil {
		return err
	}
	after, err := readSnapshot(path, 0644)
	if err != nil || !sameFirewallRemovalFileIdentity(before.identity, after.identity) ||
		!bytes.Equal(before.content, after.content) || firstEvidence != secondEvidence {
		return fmt.Errorf("WireGuard unit %s changed during package attestation", path)
	}
	return nil
}

func attestPackageOwnedSystemdWireGuardUnit(executor firewallManagerExecutor, path string) error {
	return attestStablePackageOwnedSystemdWireGuardUnit(
		path,
		readFirewallRemovalFile,
		func(expectedContent []byte) (string, error) {
			return attestSystemdWireGuardPackageEvidenceWith(
				executor, path, filepath.EvalSymlinks, expectedContent,
			)
		},
	)
}

func attestSystemdFirewallRemovalUnitFileWith(executor firewallManagerExecutor, path string) error {
	switch path {
	case "/etc/systemd/system/syswarden-core.service":
		return readExactFirewallRemovalFile(path, systemdCoreService, 0600)
	case "/etc/systemd/system/syswarden-firewall.service":
		return readExactFirewallRemovalFile(path, systemdFirewallService, 0600)
	case "/usr/lib/systemd/system/wg-quick@.service", "/lib/systemd/system/wg-quick@.service":
		return attestPackageOwnedSystemdWireGuardUnit(executor, path)
	default:
		return fmt.Errorf("refusing unexpected systemd firewall removal unit file %s", path)
	}
}

func attestSystemdFirewallRemovalUnitFile(path string) error {
	return attestSystemdFirewallRemovalUnitFileWith(hostFirewallExecutor(), path)
}

func attestOpenRCFirewallRemovalUnit(service firewallRemovalService) error {
	switch service.name {
	case "syswarden-core":
		return readExactFirewallRemovalFile("/etc/init.d/syswarden-core", openRCCoreService, 0755)
	case "syswarden-firewall":
		return readExactFirewallRemovalFile("/etc/init.d/syswarden-firewall", openRCFirewallService, 0755)
	case "wg-quick@wg-syswarden":
		return attestOpenRCWireGuardDefinitionWith(productionOpenRCWireGuardDefinitionPaths())
	default:
		return fmt.Errorf("refusing ambiguous OpenRC firewall mutator %s", service.name)
	}
}

func inspectOpenRCFirewallRemovalUnitPresence(service firewallRemovalService) (bool, error) {
	path := ""
	switch service.name {
	case "syswarden-core", "syswarden-firewall", "syswarden", "syswarden-reporter":
		path = "/etc/init.d/" + service.name
	case "wg-quick@wg-syswarden":
		path = "/etc/init.d/wg-quick.wg-syswarden"
	default:
		return false, fmt.Errorf("refusing unknown OpenRC firewall removal unit %s", service.name)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("inspect OpenRC firewall removal unit %s: %w", path, err)
	}
	return true, nil
}

func attestOpenRCRemovalRunlevelDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 ||
		stat.Uid != 0 || stat.Gid != 0 {
		return fmt.Errorf("refusing unsafe OpenRC runlevel directory %s", path)
	}
	return nil
}

func attestOpenRCFirewallRemovalRunlevelLink(service firewallRemovalService, runlevel string) error {
	if !validOpenRCRunlevelForRemoval(runlevel) {
		return fmt.Errorf("refusing invalid OpenRC runlevel %q", runlevel)
	}
	if err := attestOpenRCRemovalRunlevelDirectory("/etc/runlevels"); err != nil {
		return err
	}
	parent := filepath.Join("/etc/runlevels", runlevel)
	if err := attestOpenRCRemovalRunlevelDirectory(parent); err != nil {
		return err
	}
	name := openRCFirewallRemovalServiceName(service)
	path := filepath.Join(parent, name)
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink == 0 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		return fmt.Errorf("refusing unsafe OpenRC runlevel link %s", path)
	}
	target, err := os.Readlink(path)
	expectedAbsolute := filepath.Join("/etc/init.d", name)
	expectedRelative := filepath.Join("..", "..", "init.d", name)
	if err != nil || target != expectedAbsolute && target != expectedRelative {
		return fmt.Errorf("refusing unexpected OpenRC runlevel target %q for %s", target, path)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return fmt.Errorf("OpenRC runlevel link %s changed during attestation", path)
	}
	return nil
}

func verifyOpenRCFirewallRemovalRunlevelLinkAbsent(service firewallRemovalService, runlevel string) error {
	name := openRCFirewallRemovalServiceName(service)
	path := filepath.Join("/etc/runlevels", runlevel, name)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("verify OpenRC runlevel link absence %s: %w", path, err)
	}
	return fmt.Errorf("OpenRC runlevel link %s remains after disable", path)
}
