//go:build linux

package system

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const apkRecoveryParent = "/var/backups/syswarden-retired-v1"

// PreserveAPKRemovalPayload runs from APK's pre-commit hook, before APK can
// erase either a dependency or the installed payload. Package pre-deinstall
// failures are not a transaction veto. This creates only a private recovery
// copy; it does not change configuration, services, package state or policy.
func PreserveAPKRemovalPayload() (string, error) {
	if os.Geteuid() != 0 || !IsAlpine() {
		return "", fmt.Errorf("APK recovery requires root on Alpine")
	}
	expected, err := standalonePayloadDigests()
	if err != nil {
		return "", err
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	for _, path := range []string{"/opt/syswarden/bin/syswarden-cli", apkRecoveryParent} {
		if _, err := historicalRemovalCandidatePresent(root, path, 0, 0, func() {}); err != nil {
			return "", err
		}
	}
	return preserveAPKPayload("/opt/syswarden", "/var/backups", expected, nil)
}

func preserveAPKPayload(sourcePath, backupParentPath string, expected map[string]string, afterCopy func()) (string, error) {
	source, err := openExistingPinnedServiceDirectory(sourcePath)
	if err != nil {
		return "", err
	}
	defer source.close()
	before, err := inspectBoundPayload(source, expected, true)
	if err != nil {
		return "", err
	}
	parent, err := openOrCreateRetirementBackupParent(backupParentPath)
	if err != nil {
		return "", err
	}
	defer parent.close()
	const privateName = "syswarden-retired-v1"
	if err := parent.root.Mkdir(privateName, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	privatePath := filepath.Join(backupParentPath, privateName)
	private, err := openExistingPinnedServiceDirectory(privatePath)
	if err != nil {
		return "", err
	}
	defer private.close()
	info, err := private.file.Stat()
	if err != nil || info.Mode() != os.ModeDir|0700 {
		return "", fmt.Errorf("APK recovery parent must be private")
	}
	if err := syscall.Flock(private.fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return "", fmt.Errorf("APK recovery is already being prepared: %w", err)
	}
	defer func() { _ = syscall.Flock(private.fd, syscall.LOCK_UN) }()
	if err := parent.sync(); err != nil {
		return "", err
	}
	name := "apk-payload-" + before.digest
	destination := filepath.Join(privatePath, name)
	verifyParents := func() error {
		info, err := private.file.Stat()
		if err != nil || info.Mode() != os.ModeDir|0700 {
			return fmt.Errorf("APK recovery parent lost private permissions")
		}
		for path, pinned := range map[string]*pinnedServiceDirectory{sourcePath: source, backupParentPath: parent, privatePath: private} {
			if err := attestRetainedDirectoryParent(path, pinned, false); err != nil {
				return err
			}
		}
		return nil
	}
	verifySource := func() error {
		current, err := inspectBoundPayload(source, expected, true)
		if err != nil || !sameRetainedDirectorySnapshot(before, current, false) {
			return errors.Join(fmt.Errorf("APK recovery source changed"), err)
		}
		return verifyParents()
	}
	if _, err := private.root.Lstat(name); err == nil {
		saved, err := openExistingPinnedServiceDirectory(destination)
		if err != nil {
			return "", err
		}
		defer saved.close()
		snapshot, err := inspectStandalonePayload(saved, expected)
		if err != nil || snapshot.digest != before.digest {
			return "", errors.Join(fmt.Errorf("existing APK recovery copy changed; preserve it"), err)
		}
		if err := verifySource(); err != nil {
			return "", err
		}
		return destination, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	// An interrupted copy is never considered complete or overwritten. Its
	// bounded files remain private for diagnosis; a new run can retry safely.
	temporary, err := os.MkdirTemp(privatePath, ".apk-pending-")
	if err != nil {
		return "", err
	}
	staging, err := openExistingPinnedServiceDirectory(temporary)
	if err != nil {
		return "", err
	}
	defer staging.close()
	if err := staging.root.Chmod(".", 0750); err != nil {
		return "", err
	}
	if err := staging.root.Mkdir("bin", 0750); err != nil {
		return "", err
	}
	for _, name := range []string{"bin/syswarden-cli", "bin/syswarden-core", "bin/syswarden-tui", "signatures.json"} {
		mode := os.FileMode(0750)
		if name == "signatures.json" {
			mode = 0640
		}
		if err := copyAPKRecoveryFile(source.root, staging.root, name, mode, expected[name]); err != nil {
			return "", err
		}
	}
	bin, err := openExistingPinnedServiceDirectory(filepath.Join(temporary, "bin"))
	if err != nil {
		return "", err
	}
	err = bin.sync()
	bin.close()
	if err != nil {
		return "", err
	}
	if err := staging.sync(); err != nil {
		return "", err
	}
	if afterCopy != nil {
		afterCopy()
	}
	saved, err := inspectStandalonePayload(staging, expected)
	if err != nil || saved.digest != before.digest {
		return "", errors.Join(fmt.Errorf("APK recovery copy failed verification"), err)
	}
	if err := verifySource(); err != nil {
		return "", err
	}
	if err := attestRetainedDirectoryParent(temporary, staging, false); err != nil {
		return "", err
	}
	if err := unix.Renameat2(private.fd, filepath.Base(temporary), private.fd, name, unix.RENAME_NOREPLACE); err != nil {
		return "", err
	}
	if err := private.sync(); err != nil {
		return "", err
	}
	if err := attestRetainedDirectoryParent(destination, staging, false); err != nil {
		return "", err
	}
	if err := verifySource(); err != nil {
		return "", err
	}
	return destination, nil
}

func copyAPKRecoveryFile(source, destination *os.Root, name string, mode os.FileMode, expected string) error {
	input, err := source.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	before, digest, err := hashStandalonePayload(input, mode)
	if err != nil || digest != expected {
		return errors.Join(fmt.Errorf("APK recovery source is not attested: %s", name), err)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return err
	}
	output, err := destination.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	count, copyErr := io.Copy(output, io.LimitReader(input, maximumStandalonePayloadBytes+1))
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || count != before.size {
		return errors.Join(fmt.Errorf("APK recovery copy incomplete: %s", name), copyErr, syncErr, closeErr)
	}
	after, err := input.Stat()
	actual, identityErr := exactRemovalArtifactIdentity(after)
	if err != nil || identityErr != nil || actual != before {
		return fmt.Errorf("APK recovery source identity changed: %s", name)
	}
	return nil
}
