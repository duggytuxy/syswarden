//go:build linux

package system

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
)

const (
	approvedSystemdServiceDropInPath             = "/usr/lib/systemd/system/service.d/10-timeout-abort.conf"
	approvedSystemdServiceDropInSHA              = "ae6b234f92bc22f1201a7572b59b454c9809f33c80d13f361b9674e1801acc37"
	approvedSystemdServiceDropInRPMQueryFormat   = "%{NAME}\\t%{EVR}\\t%{ARCH}\\t%{FILEDIGESTALGO}\\n"
	approvedSystemdServiceDropInRPMFilesFormat   = "[%{FILENAMES}\\n]"
	approvedSystemdServiceDropInRPMDigestsFormat = "[%{FILEDIGESTS}\\n]"
	syswardenDropInDPKGVersionFormat             = "${Version}\\t${Architecture}\\n"
	syswardenDropInDPKGInstalledFormat           = "${Status}\\t${Architecture}\\t${Version}\\n"
	syswardenDropInRPMOwnerFormat                = "%{NAME}\\t%{EVR}\\t%{ARCH}\\t%{FILEDIGESTALGO}\\n"
	syswardenDropInDPKGAbsentEvidence            = "dpkg-query: no packages found matching syswarden\n"
	syswardenDropInRPMAbsentEvidence             = "package syswarden is not installed\n"

	approvedSystemdServiceDropInContent = `# This file is part of the systemd package.
# See https://fedoraproject.org/wiki/Changes/Shorter_Shutdown_Timer.
#
# To facilitate debugging when a service fails to stop cleanly,
# TimeoutStopFailureMode=abort is set to "crash" services that fail to stop in
# the time allotted. This will cause the service to be terminated with SIGABRT
# and a coredump to be generated.
#
# To undo this configuration change, create a mask file:
#   sudo mkdir -p /etc/systemd/system/service.d
#   sudo ln -sv /dev/null /etc/systemd/system/service.d/10-timeout-abort.conf

[Service]
TimeoutStopFailureMode=abort
`
)

type approvedSystemdServiceDropInSnapshot struct {
	device      uint64
	inode       uint64
	mode        uint32
	uid         uint32
	gid         uint32
	links       uint64
	size        int64
	mtimeSecond int64
	mtimeNano   int64
	ctimeSecond int64
	ctimeNano   int64
	digest      [sha256.Size]byte
}

func approvedSystemdServiceDropInArchitecture() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64", nil
	default:
		return "", fmt.Errorf("unsupported architecture %q for the approved systemd service drop-in", runtime.GOARCH)
	}
}

func approvedSystemdServiceDropInStat(
	info os.FileInfo,
	expectedUID uint32,
	expectedGID uint32,
) (approvedSystemdServiceDropInSnapshot, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		!info.Mode().IsRegular() {
		return approvedSystemdServiceDropInSnapshot{}, fmt.Errorf("approved systemd service drop-in is not a regular file")
	}
	if info.Mode().Perm() != 0644 || stat.Uid != expectedUID || stat.Gid != expectedGID || stat.Nlink != 1 {
		return approvedSystemdServiceDropInSnapshot{}, fmt.Errorf("approved systemd service drop-in metadata is not exact")
	}
	if info.Size() != int64(len(approvedSystemdServiceDropInContent)) {
		return approvedSystemdServiceDropInSnapshot{}, fmt.Errorf("approved systemd service drop-in size is not exact")
	}
	return approvedSystemdServiceDropInSnapshot{
		device:      uint64(stat.Dev),
		inode:       stat.Ino,
		mode:        stat.Mode,
		uid:         stat.Uid,
		gid:         stat.Gid,
		links:       uint64(stat.Nlink),
		size:        info.Size(),
		mtimeSecond: stat.Mtim.Sec,
		mtimeNano:   stat.Mtim.Nsec,
		ctimeSecond: stat.Ctim.Sec,
		ctimeNano:   stat.Ctim.Nsec,
	}, nil
}

func attestApprovedSystemdServiceDropInParents(
	path string,
	trustedRoot string,
	expectedUID uint32,
	expectedGID uint32,
) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !filepath.IsAbs(trustedRoot) ||
		filepath.Clean(trustedRoot) != trustedRoot {
		return fmt.Errorf("approved systemd service drop-in path boundary is not clean and absolute")
	}
	relative, err := filepath.Rel(trustedRoot, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("approved systemd service drop-in escapes its trusted root")
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("inspect approved systemd service drop-in parent %s: %w", directory, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 ||
			stat.Uid != expectedUID || stat.Gid != expectedGID {
			return fmt.Errorf("approved systemd service drop-in parent %s is not trusted", directory)
		}
		if directory == trustedRoot {
			break
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return fmt.Errorf("approved systemd service drop-in parent chain escaped its trusted root")
		}
	}
	return nil
}

func captureApprovedSystemdServiceDropIn(
	path string,
	expectedUID uint32,
	expectedGID uint32,
) (approvedSystemdServiceDropInSnapshot, error) {
	beforeInfo, err := os.Lstat(path)
	if err != nil {
		return approvedSystemdServiceDropInSnapshot{}, fmt.Errorf("inspect approved systemd service drop-in: %w", err)
	}
	before, err := approvedSystemdServiceDropInStat(beforeInfo, expectedUID, expectedGID)
	if err != nil {
		return approvedSystemdServiceDropInSnapshot{}, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- path is matched to one compiled-in vendor file
	if err != nil {
		return approvedSystemdServiceDropInSnapshot{}, fmt.Errorf("open approved systemd service drop-in: %w", err)
	}
	defer file.Close()
	openedBeforeInfo, err := file.Stat()
	if err != nil {
		return approvedSystemdServiceDropInSnapshot{}, fmt.Errorf("inspect opened approved systemd service drop-in: %w", err)
	}
	openedBefore, err := approvedSystemdServiceDropInStat(openedBeforeInfo, expectedUID, expectedGID)
	if err != nil || openedBefore != before {
		return approvedSystemdServiceDropInSnapshot{}, fmt.Errorf("approved systemd service drop-in changed before reading")
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(len(approvedSystemdServiceDropInContent)+1)))
	if err != nil {
		return approvedSystemdServiceDropInSnapshot{}, fmt.Errorf("read approved systemd service drop-in: %w", err)
	}
	digest := sha256.Sum256(content)
	expectedDigest := sha256.Sum256([]byte(approvedSystemdServiceDropInContent))
	if fmt.Sprintf("%x", expectedDigest) != approvedSystemdServiceDropInSHA ||
		!bytes.Equal(content, []byte(approvedSystemdServiceDropInContent)) ||
		fmt.Sprintf("%x", digest) != approvedSystemdServiceDropInSHA {
		return approvedSystemdServiceDropInSnapshot{}, fmt.Errorf("approved systemd service drop-in content is not exact")
	}
	openedAfterInfo, err := file.Stat()
	if err != nil {
		return approvedSystemdServiceDropInSnapshot{}, fmt.Errorf("reinspect opened approved systemd service drop-in: %w", err)
	}
	openedAfter, err := approvedSystemdServiceDropInStat(openedAfterInfo, expectedUID, expectedGID)
	if err != nil {
		return approvedSystemdServiceDropInSnapshot{}, err
	}
	afterInfo, err := os.Lstat(path)
	if err != nil {
		return approvedSystemdServiceDropInSnapshot{}, fmt.Errorf("reinspect approved systemd service drop-in: %w", err)
	}
	after, err := approvedSystemdServiceDropInStat(afterInfo, expectedUID, expectedGID)
	if err != nil || openedAfter != before || after != before {
		return approvedSystemdServiceDropInSnapshot{}, fmt.Errorf("approved systemd service drop-in changed while reading")
	}
	before.digest = digest
	return before, nil
}

func parseApprovedSystemdServiceDropInRPMOwner(output []byte, expectedArchitecture string) (string, error) {
	if len(output) == 0 || output[len(output)-1] != '\n' || bytes.Count(output, []byte{'\n'}) != 1 ||
		bytes.ContainsAny(output, "\x00\r") {
		return "", fmt.Errorf("approved systemd service drop-in RPM ownership is ambiguous")
	}
	fields := strings.Split(strings.TrimSuffix(string(output), "\n"), "\t")
	if len(fields) != 4 || fields[0] != "systemd" || !safePackageVersion(fields[1]) ||
		fields[2] != expectedArchitecture || fields[3] != "8" {
		return "", fmt.Errorf("approved systemd service drop-in RPM provenance is not exact")
	}
	return fields[1], nil
}

func parseApprovedSystemdServiceDropInRPMMetadata(files []byte, digests []byte, approvedPath string) error {
	parse := func(output []byte, label string) ([]string, error) {
		if len(output) == 0 || output[len(output)-1] != '\n' || bytes.ContainsAny(output, "\x00\r") {
			return nil, fmt.Errorf("approved systemd service drop-in RPM %s metadata is ambiguous", label)
		}
		return strings.Split(strings.TrimSuffix(string(output), "\n"), "\n"), nil
	}
	fileValues, err := parse(files, "filename")
	if err != nil {
		return err
	}
	digestValues, err := parse(digests, "digest")
	if err != nil {
		return err
	}
	if len(fileValues) != len(digestValues) || len(fileValues) == 0 {
		return fmt.Errorf("approved systemd service drop-in RPM metadata arrays disagree")
	}
	matches := 0
	for index, path := range fileValues {
		if path != approvedPath {
			continue
		}
		matches++
		if digestValues[index] != approvedSystemdServiceDropInSHA {
			return fmt.Errorf("approved systemd service drop-in differs from its RPM digest")
		}
	}
	if matches != 1 {
		return fmt.Errorf("approved systemd service drop-in RPM filename metadata is not unique")
	}
	return nil
}

func queryApprovedSystemdServiceDropInRPMMetadata(
	executor firewallManagerExecutor,
	rpm string,
	approvedPath string,
) ([]byte, []byte, error) {
	files, err := executor.output(
		rpm, "--query", "--file", approvedPath, "--queryformat", approvedSystemdServiceDropInRPMFilesFormat,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("query approved systemd service drop-in RPM filenames: %w", err)
	}
	digests, err := executor.output(
		rpm, "--query", "--file", approvedPath, "--queryformat", approvedSystemdServiceDropInRPMDigestsFormat,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("query approved systemd service drop-in RPM digests: %w", err)
	}
	if err := parseApprovedSystemdServiceDropInRPMMetadata(files, digests, approvedPath); err != nil {
		return nil, nil, err
	}
	return files, digests, nil
}

func attestApprovedSystemdServiceDropInsAt(
	executor firewallManagerExecutor,
	dropIns string,
	approvedPath string,
	trustedRoot string,
	expectedUID uint32,
	expectedGID uint32,
) (string, error) {
	if dropIns == "" {
		return "", nil
	}
	if approvedPath == "" || !filepath.IsAbs(approvedPath) || filepath.Clean(approvedPath) != approvedPath ||
		dropIns != approvedPath {
		return "", fmt.Errorf("systemd service has unapproved drop-ins")
	}
	if err := attestApprovedSystemdServiceDropInParents(approvedPath, trustedRoot, expectedUID, expectedGID); err != nil {
		return "", err
	}
	first, err := captureApprovedSystemdServiceDropIn(approvedPath, expectedUID, expectedGID)
	if err != nil {
		return "", err
	}
	rpm, err := resolveFirewallExecutable(executor, "rpm")
	if err != nil {
		return "", fmt.Errorf("resolve RPM for approved systemd service drop-in: %w", err)
	}
	expectedArchitecture, err := approvedSystemdServiceDropInArchitecture()
	if err != nil {
		return "", err
	}
	owner, err := executor.output(
		rpm, "--query", "--file", approvedPath, "--queryformat", approvedSystemdServiceDropInRPMQueryFormat,
	)
	if err != nil {
		return "", fmt.Errorf("query approved systemd service drop-in RPM ownership: %w", err)
	}
	version, err := parseApprovedSystemdServiceDropInRPMOwner(owner, expectedArchitecture)
	if err != nil {
		return "", err
	}
	files, digests, err := queryApprovedSystemdServiceDropInRPMMetadata(executor, rpm, approvedPath)
	if err != nil {
		return "", err
	}
	second, err := captureApprovedSystemdServiceDropIn(approvedPath, expectedUID, expectedGID)
	if err != nil {
		return "", err
	}
	if second != first {
		return "", fmt.Errorf("approved systemd service drop-in changed during RPM attestation")
	}
	ownerAfter, err := executor.output(
		rpm, "--query", "--file", approvedPath, "--queryformat", approvedSystemdServiceDropInRPMQueryFormat,
	)
	if err != nil || !bytes.Equal(ownerAfter, owner) {
		return "", fmt.Errorf("approved systemd service drop-in RPM ownership changed during attestation")
	}
	filesAfter, digestsAfter, err := queryApprovedSystemdServiceDropInRPMMetadata(executor, rpm, approvedPath)
	if err != nil || !bytes.Equal(filesAfter, files) || !bytes.Equal(digestsAfter, digests) {
		return "", fmt.Errorf("approved systemd service drop-in RPM metadata changed during attestation")
	}
	final, err := captureApprovedSystemdServiceDropIn(approvedPath, expectedUID, expectedGID)
	if err != nil || final != first {
		return "", fmt.Errorf("approved systemd service drop-in changed after RPM metadata reattestation")
	}
	if err := attestApprovedSystemdServiceDropInParents(approvedPath, trustedRoot, expectedUID, expectedGID); err != nil {
		return "", fmt.Errorf("approved systemd service drop-in parent chain changed during attestation: %w", err)
	}
	return approvedPath + "#" + approvedSystemdServiceDropInSHA + "#systemd@" + version + "#" + expectedArchitecture, nil
}

func attestApprovedSystemdServiceDropIns(
	executor firewallManagerExecutor,
	dropIns string,
) (string, error) {
	if dropIns == "" {
		return "", nil
	}
	paths := strings.Split(dropIns, " ")
	if len(paths) > 2 {
		return "", fmt.Errorf("systemd service has unapproved drop-ins")
	}
	evidence := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path == "" {
			return "", fmt.Errorf("systemd service has ambiguous drop-ins")
		}
		if _, duplicate := seen[path]; duplicate {
			return "", fmt.Errorf("systemd service has duplicate drop-ins")
		}
		seen[path] = struct{}{}
		switch path {
		case approvedSystemdServiceDropInPath:
			item, err := attestApprovedSystemdServiceDropInsAt(
				executor, path, approvedSystemdServiceDropInPath, "/", 0, 0,
			)
			if err != nil {
				return "", err
			}
			evidence = append(evidence, item)
		case systemdCoreSocketCapabilityDropInPath:
			item, err := attestExactSystemdCoreSocketCapabilityDropIn(executor, path)
			if err != nil {
				return "", err
			}
			evidence = append(evidence, item)
		case systemdFirewallWireGuardOrderingDropInPath:
			item, err := attestExactSystemdFirewallOrderingDropIn(executor, path)
			if err != nil {
				return "", err
			}
			evidence = append(evidence, item)
		default:
			return "", fmt.Errorf("systemd service has unapproved drop-ins")
		}
	}
	sort.Strings(evidence)
	return strings.Join(evidence, ";"), nil
}

func attestExactSystemdFirewallOrderingDropIn(
	executor firewallManagerExecutor,
	path string,
) (string, error) {
	return attestExactSystemdFirewallOrderingDropInAt(
		executor,
		path,
		systemdFirewallWireGuardOrderingDropInPath,
		"/",
		0,
		0,
	)
}

func attestExactSystemdFirewallOrderingDropInAt(
	executor firewallManagerExecutor,
	path string,
	expectedPath string,
	trustedRoot string,
	expectedUID uint32,
	expectedGID uint32,
) (string, error) {
	return attestExactSystemdPackageDropInAt(
		executor, path, expectedPath, trustedRoot, expectedUID, expectedGID,
		systemdFirewallWireGuardOrderingDropIn, "ordering",
	)
}

func attestExactSystemdPackageDropInAt(
	executor firewallManagerExecutor,
	path, expectedPath, trustedRoot string,
	expectedUID, expectedGID uint32,
	expectedContent, description string,
) (string, error) {
	if path != expectedPath {
		return "", fmt.Errorf("refusing unexpected SysWarden systemd %s drop-in %s", description, path)
	}
	if err := attestApprovedSystemdServiceDropInParents(
		path, trustedRoot, expectedUID, expectedGID,
	); err != nil {
		return "", fmt.Errorf("attest SysWarden systemd %s drop-in parents: %w", description, err)
	}
	first, err := readFirewallRemovalFileWithOwner(path, 0644, expectedUID, expectedGID)
	if err != nil {
		return "", fmt.Errorf("attest SysWarden systemd %s drop-in: %w", description, err)
	}
	if string(first.content) != expectedContent {
		return "", fmt.Errorf("refusing modified SysWarden systemd %s drop-in %s", description, path)
	}
	firstPackageEvidence, err := attestSysWardenSystemdDropInPackageOwnership(executor, path)
	if err != nil {
		return "", err
	}
	second, err := readFirewallRemovalFileWithOwner(path, 0644, expectedUID, expectedGID)
	if err != nil || !sameFirewallRemovalFileIdentity(first.identity, second.identity) ||
		!bytes.Equal(first.content, second.content) {
		return "", fmt.Errorf("SysWarden systemd %s drop-in changed during attestation", description)
	}
	secondPackageEvidence, err := attestSysWardenSystemdDropInPackageOwnership(executor, path)
	if err != nil || secondPackageEvidence != firstPackageEvidence {
		return "", fmt.Errorf("SysWarden systemd %s drop-in package ownership changed during attestation", description)
	}
	if err := attestApprovedSystemdServiceDropInParents(
		path, trustedRoot, expectedUID, expectedGID,
	); err != nil {
		return "", fmt.Errorf("SysWarden systemd %s drop-in parent chain changed: %w", description, err)
	}
	digest := sha256.Sum256(first.content)
	return path + "#" + fmt.Sprintf("%x", digest) + "#" + firstPackageEvidence, nil
}

func attestSysWardenSystemdDropInPackageOwnership(
	executor firewallManagerExecutor,
	path string,
) (string, error) {
	var claims []string
	var failures []string

	dpkgQuery, dpkgPresent, err := resolveOptionalFirewallRemovalExecutable(executor, "dpkg-query")
	if err != nil {
		return "", err
	}
	if dpkgPresent {
		files, queryErr := executor.output(dpkgQuery, "--listfiles", "syswarden")
		if queryErr != nil {
			failures = append(failures, "dpkg-query file inventory failed")
		} else if err := attestSysWardenDPKGDropInFileList(files, path); err != nil {
			failures = append(failures, "dpkg-query: "+err.Error())
		} else {
			version, versionErr := executor.output(
				dpkgQuery, "--show", "--showformat="+syswardenDropInDPKGVersionFormat, "syswarden",
			)
			if versionErr != nil {
				failures = append(failures, "dpkg-query version failed")
			} else if claim, parseErr := parseSysWardenDPKGDropInOwner(version); parseErr != nil {
				failures = append(failures, "dpkg-query: "+parseErr.Error())
			} else {
				claims = append(claims, claim)
			}
		}
	}

	rpm, rpmPresent, err := resolveOptionalFirewallRemovalExecutable(executor, "rpm")
	if err != nil {
		return "", err
	}
	if rpmPresent {
		owner, queryErr := executor.output(
			rpm, "--query", "--file", path, "--queryformat", syswardenDropInRPMOwnerFormat,
		)
		if queryErr != nil {
			failures = append(failures, "RPM ownership query failed")
		} else if claim, parseErr := parseSysWardenRPMDropInOwners(
			owner, servicePackageEnvironment("SYSWARDEN_PKG_INSTALL") == "1",
		); parseErr != nil {
			failures = append(failures, "RPM: "+parseErr.Error())
		} else {
			claims = append(claims, claim)
		}
	}

	if len(claims) == 1 {
		return claims[0], nil
	}
	if len(claims) > 1 {
		return "", fmt.Errorf("refusing multiple package authorities for the SysWarden systemd ordering drop-in")
	}
	if len(failures) == 0 {
		return "", fmt.Errorf("no supported package authority can attest the SysWarden systemd ordering drop-in")
	}
	return "", fmt.Errorf(
		"no package authority attested the SysWarden systemd ordering drop-in: %s",
		strings.Join(failures, "; "),
	)
}

func attestSysWardenDPKGDropInFileList(output []byte, path string) error {
	if len(output) == 0 || output[len(output)-1] != '\n' || bytes.ContainsAny(output, "\x00\r") {
		return fmt.Errorf("SysWarden dpkg file inventory is ambiguous")
	}
	matches := 0
	for _, item := range strings.Split(strings.TrimSuffix(string(output), "\n"), "\n") {
		if item == "" || !filepath.IsAbs(item) || (item != "/." && filepath.Clean(item) != item) {
			return fmt.Errorf("SysWarden dpkg file inventory contains an unsafe path")
		}
		if item == path {
			matches++
		}
	}
	if matches != 1 {
		return fmt.Errorf("SysWarden dpkg file inventory contains %d exact ordering paths, want 1", matches)
	}
	return nil
}

func parseSysWardenDPKGDropInOwner(output []byte) (string, error) {
	if len(output) == 0 || output[len(output)-1] != '\n' || bytes.ContainsAny(output, "\x00\r") ||
		bytes.Count(output, []byte{'\n'}) != 1 {
		return "", fmt.Errorf("SysWarden dpkg owner is ambiguous")
	}
	fields := strings.Split(strings.TrimSuffix(string(output), "\n"), "\t")
	if len(fields) != 2 || !safePackageVersion(fields[0]) || fields[1] != "amd64" {
		return "", fmt.Errorf("SysWarden dpkg owner is not exact")
	}
	current, err := currentSysWardenPackageVersion()
	if err != nil {
		return "", err
	}
	if fields[0] != current {
		return "", fmt.Errorf("SysWarden dpkg owner differs from the running release")
	}
	return "syswarden@" + fields[0] + "#amd64#dpkg", nil
}

func currentSysWardenPackageVersion() (string, error) {
	version := strings.TrimPrefix(Version, "v")
	if version == Version || !safePackageVersion(version) {
		return "", fmt.Errorf("compiled SysWarden version is not an exact release version")
	}
	return version, nil
}

func currentSysWardenRPMEVR() (string, error) {
	version, err := currentSysWardenPackageVersion()
	if err != nil {
		return "", err
	}
	return version + "-1", nil
}

func currentSysWardenRPMEVRs() ([]string, error) {
	standard, err := currentSysWardenRPMEVR()
	if err != nil {
		return nil, err
	}
	version, err := currentSysWardenPackageVersion()
	if err != nil {
		return nil, err
	}
	return []string{standard, version + "-" + rhelPackageOwnedRPMRelease}, nil
}

func parseSysWardenRPMDropInOwners(output []byte, packageTransaction bool) (string, error) {
	if len(output) == 0 || output[len(output)-1] != '\n' || bytes.ContainsAny(output, "\x00\r") {
		return "", fmt.Errorf("SysWarden RPM ownership is ambiguous")
	}
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(lines) == 0 || len(lines) > 2 || (!packageTransaction && len(lines) != 1) {
		return "", fmt.Errorf("SysWarden RPM ownership count is not exact")
	}
	currentEVRs, err := currentSysWardenRPMEVRs()
	if err != nil {
		return "", err
	}
	claims := make([]string, 0, len(lines))
	currentPresent := false
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 4 || fields[0] != "syswarden" || !safePackageVersion(fields[1]) ||
			fields[2] != "x86_64" || fields[3] != "8" {
			return "", fmt.Errorf("SysWarden RPM owner is not exact")
		}
		for _, currentEVR := range currentEVRs {
			if fields[1] == currentEVR {
				currentPresent = true
				break
			}
		}
		claims = append(claims, "syswarden@"+fields[1]+"#x86_64#sha256#rpm")
	}
	if !currentPresent {
		return "", fmt.Errorf("SysWarden RPM ownership does not include the running release")
	}
	sort.Strings(claims)
	return strings.Join(claims, ","), nil
}

func parseSysWardenRPMDropInOwner(output []byte) (string, error) {
	return parseSysWardenRPMDropInOwners(output, false)
}

func parseInstalledSysWardenDPKG(output []byte) (string, error) {
	if len(output) == 0 || output[len(output)-1] != '\n' || bytes.ContainsAny(output, "\x00\r") ||
		bytes.Count(output, []byte{'\n'}) != 1 {
		return "", fmt.Errorf("installed SysWarden dpkg state is ambiguous")
	}
	fields := strings.Split(strings.TrimSuffix(string(output), "\n"), "\t")
	if len(fields) != 3 || fields[0] != "install ok installed" || fields[1] != "amd64" ||
		!safePackageVersion(fields[2]) {
		return "", fmt.Errorf("installed SysWarden dpkg state is not exact")
	}
	current, err := currentSysWardenPackageVersion()
	if err != nil {
		return "", err
	}
	if fields[2] != current {
		return "", fmt.Errorf("installed SysWarden dpkg release differs from the running release")
	}
	return "syswarden@" + fields[2] + "#amd64#dpkg", nil
}

func detectInstalledSysWardenPackageAuthority(executor firewallManagerExecutor) (string, error) {
	var claims []string
	var failures []string

	dpkgQuery, dpkgPresent, err := resolveOptionalFirewallRemovalExecutable(executor, "dpkg-query")
	if err != nil {
		return "", err
	}
	if dpkgPresent {
		output, queryErr := executor.output(
			dpkgQuery, "--show", "--showformat="+syswardenDropInDPKGInstalledFormat, "syswarden",
		)
		switch {
		case queryErr == nil:
			claim, parseErr := parseInstalledSysWardenDPKG(output)
			if parseErr != nil {
				failures = append(failures, "dpkg-query: "+parseErr.Error())
			} else {
				claims = append(claims, claim)
			}
		case bytes.Equal(output, []byte(syswardenDropInDPKGAbsentEvidence)):
		default:
			failures = append(failures, "dpkg-query package state failed ambiguously")
		}
	}

	rpm, rpmPresent, err := resolveOptionalFirewallRemovalExecutable(executor, "rpm")
	if err != nil {
		return "", err
	}
	if rpmPresent {
		output, queryErr := executor.output(
			rpm, "--query", "syswarden", "--queryformat", syswardenDropInRPMOwnerFormat,
		)
		switch {
		case queryErr == nil:
			claim, parseErr := parseSysWardenRPMDropInOwner(output)
			if parseErr != nil {
				failures = append(failures, "RPM: "+parseErr.Error())
			} else {
				claims = append(claims, claim)
			}
		case bytes.Equal(output, []byte(syswardenDropInRPMAbsentEvidence)):
		default:
			failures = append(failures, "RPM package state failed ambiguously")
		}
	}

	if len(failures) != 0 {
		return "", fmt.Errorf("cannot attest installed SysWarden package state: %s", strings.Join(failures, "; "))
	}
	if len(claims) > 1 {
		return "", fmt.Errorf("refusing multiple installed SysWarden package authorities")
	}
	if len(claims) == 1 {
		return claims[0], nil
	}
	return "", nil
}

func attestAbsentSystemdFirewallOrderingDropIn(
	executor firewallManagerExecutor,
	path string,
	packageTransaction bool,
) error {
	if packageTransaction {
		return fmt.Errorf("packaged systemd ordering drop-in is absent")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return fmt.Errorf("reinspect absent packaged systemd ordering drop-in: %w", err)
		}
		return fmt.Errorf("packaged systemd ordering drop-in appeared during absence attestation")
	}
	first, err := detectInstalledSysWardenPackageAuthority(executor)
	if err != nil {
		return err
	}
	if first != "" {
		return fmt.Errorf("packaged systemd ordering drop-in is absent for %s", first)
	}
	second, err := detectInstalledSysWardenPackageAuthority(executor)
	if err != nil || second != first {
		return fmt.Errorf("SysWarden package authority changed during ordering absence attestation")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return fmt.Errorf("finalize absent packaged systemd ordering drop-in: %w", err)
		}
		return fmt.Errorf("packaged systemd ordering drop-in appeared during absence attestation")
	}
	return nil
}
