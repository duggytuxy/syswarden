//go:build linux

package system

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

const (
	approvedSystemdServiceDropInPath             = "/usr/lib/systemd/system/service.d/10-timeout-abort.conf"
	approvedSystemdServiceDropInSHA              = "ae6b234f92bc22f1201a7572b59b454c9809f33c80d13f361b9674e1801acc37"
	approvedSystemdServiceDropInRPMQueryFormat   = "%{NAME}\\t%{EVR}\\t%{ARCH}\\t%{FILEDIGESTALGO}\\n"
	approvedSystemdServiceDropInRPMFilesFormat   = "[%{FILENAMES}\\n]"
	approvedSystemdServiceDropInRPMDigestsFormat = "[%{FILEDIGESTS}\\n]"

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
	case "arm64":
		return "aarch64", nil
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
	return attestApprovedSystemdServiceDropInsAt(executor, dropIns, approvedSystemdServiceDropInPath, "/", 0, 0)
}
