//go:build linux

package security

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type hardeningArtifactAttestor func(*os.Root, string) (fs.FileInfo, error)
type hardeningArtifactRename func(int, string, int, string, uint) error
type hardeningDirectorySync func(*os.Root) error

func sameHardeningArtifactIdentity(expected, actual fs.FileInfo) bool {
	if expected == nil || actual == nil || !os.SameFile(expected, actual) ||
		expected.Mode() != actual.Mode() || expected.Size() != actual.Size() ||
		!expected.ModTime().Equal(actual.ModTime()) {
		return false
	}
	expectedStat, expectedOK := expected.Sys().(*syscall.Stat_t)
	actualStat, actualOK := actual.Sys().(*syscall.Stat_t)
	return expectedOK && actualOK && expectedStat.Uid == actualStat.Uid &&
		expectedStat.Gid == actualStat.Gid && expectedStat.Nlink == actualStat.Nlink
}

func sameHardeningDirectoryIdentity(expected, actual fs.FileInfo) bool {
	if expected == nil || actual == nil || !expected.IsDir() || !actual.IsDir() ||
		!os.SameFile(expected, actual) || expected.Mode() != actual.Mode() {
		return false
	}
	expectedStat, expectedOK := expected.Sys().(*syscall.Stat_t)
	actualStat, actualOK := actual.Sys().(*syscall.Stat_t)
	return expectedOK && actualOK && expectedStat.Uid == actualStat.Uid &&
		expectedStat.Gid == actualStat.Gid
}

func randomHardeningQuarantineName() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return ".syswarden-quarantine-" + hex.EncodeToString(random), nil
}

func restoreHardeningQuarantine(
	root *os.Root,
	directoryFD int,
	name string,
	quarantineName string,
	rename hardeningArtifactRename,
	syncDirectory hardeningDirectorySync,
) error {
	quarantined, err := root.Lstat(quarantineName)
	if err != nil {
		return fmt.Errorf("inspect quarantined hardening artifact %s: %w", quarantineName, err)
	}
	for attempt := 0; attempt < 4; attempt++ {
		err = rename(directoryFD, quarantineName, directoryFD, name, unix.RENAME_NOREPLACE)
		if err == nil {
			restored, inspectErr := root.Lstat(name)
			syncErr := syncDirectory(root)
			if inspectErr != nil || !sameHardeningArtifactIdentity(quarantined, restored) || syncErr != nil {
				return errors.Join(
					fmt.Errorf("quarantined hardening artifact %s was not exactly restored", name),
					inspectErr,
					syncErr,
				)
			}
			return nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("restore quarantined hardening artifact %s without replacement: %w", name, err)
		}
		err = rename(directoryFD, quarantineName, directoryFD, name, unix.RENAME_EXCHANGE)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return fmt.Errorf("restore quarantined hardening artifact %s by exchange: %w", name, err)
		}
		restored, inspectErr := root.Lstat(name)
		displaced, displacedErr := root.Lstat(quarantineName)
		syncErr := syncDirectory(root)
		if inspectErr != nil || !sameHardeningArtifactIdentity(quarantined, restored) ||
			displacedErr != nil || displaced == nil || syncErr != nil {
			return errors.Join(
				fmt.Errorf("quarantined hardening artifact %s was not exactly restored by exchange", name),
				inspectErr,
				displacedErr,
				syncErr,
			)
		}
		return nil
	}
	return fmt.Errorf("restore quarantined hardening artifact %s after concurrent changes", name)
}

func quarantineAndRemoveHardeningArtifactUsing(
	root *os.Root,
	name string,
	missingOK bool,
	unlinkFlags int,
	attest hardeningArtifactAttestor,
	rename hardeningArtifactRename,
	syncDirectory hardeningDirectorySync,
) error {
	if syncDirectory == nil {
		return fmt.Errorf("hardening quarantine directory sync is unavailable")
	}
	expected, err := attest(root, name)
	if missingOK && errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("attest hardening artifact %s before quarantine: %w", name, err)
	}
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open hardening artifact parent for quarantine: %w", err)
	}
	defer func() { _ = directory.Close() }()
	directoryFD := int(directory.Fd())

	var quarantineName string
	for attempt := 0; attempt < 16; attempt++ {
		quarantineName, err = randomHardeningQuarantineName()
		if err != nil {
			return fmt.Errorf("generate hardening artifact quarantine: %w", err)
		}
		err = rename(directoryFD, name, directoryFD, quarantineName, unix.RENAME_NOREPLACE)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return fmt.Errorf("quarantine hardening artifact %s atomically: %w", name, err)
		}
		break
	}
	if err != nil {
		return fmt.Errorf("reserve a unique quarantine for hardening artifact %s", name)
	}

	moved, attestErr := attest(root, quarantineName)
	syncErr := syncDirectory(root)
	if attestErr != nil || !sameHardeningArtifactIdentity(expected, moved) || syncErr != nil {
		restoreErr := restoreHardeningQuarantine(
			root, directoryFD, name, quarantineName, rename, syncDirectory,
		)
		return errors.Join(
			fmt.Errorf("hardening artifact %s changed before atomic quarantine", name),
			attestErr,
			syncErr,
			restoreErr,
		)
	}
	if err := unix.Unlinkat(directoryFD, quarantineName, unlinkFlags); err != nil {
		restoreErr := restoreHardeningQuarantine(
			root, directoryFD, name, quarantineName, rename, syncDirectory,
		)
		return errors.Join(
			fmt.Errorf("remove quarantined hardening artifact %s: %w", name, err),
			restoreErr,
		)
	}
	if err := syncDirectory(root); err != nil {
		return fmt.Errorf("sync removal of quarantined hardening artifact %s: %w", name, err)
	}
	return nil
}
