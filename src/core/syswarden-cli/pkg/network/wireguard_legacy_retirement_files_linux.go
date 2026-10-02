//go:build linux

package network

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type legacyWireGuardDirectoryEvidence struct {
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func (host legacyWireGuardRecoveryHost) inspectRetirementDirectory() (*legacyWireGuardDirectoryEvidence, error) {
	root, err := os.OpenRoot(host.filesystemRoot)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(strings.TrimPrefix(legacyWireGuardArchiveDirectory, "/"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || stat.Uid != host.expectedUID || stat.Gid != host.expectedGID {
		return nil, fmt.Errorf("WireGuard retirement archive directory is not a protected owner-only directory")
	}
	return &legacyWireGuardDirectoryEvidence{Mode: uint32(info.Mode().Perm()), UID: stat.Uid, GID: stat.Gid, Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}

func (host legacyWireGuardRecoveryHost) archiveRetiredWireGuardConfiguration(plan LegacyWireGuardRetirementPlan) error {
	current, err := captureLegacyWireGuardConfiguration(host.filesystemRoot, legacyWireGuardConfigurationPath, host.expectedUID, host.expectedGID)
	if err != nil {
		return err
	}
	current.evidence.Source = "exact-historical-config"
	if current.evidence != plan.Configuration {
		return fmt.Errorf("historical configuration changed before private archival")
	}
	archiveDirectory, err := host.inspectRetirementDirectory()
	if err != nil || !reflect.DeepEqual(archiveDirectory, plan.ArchiveDirectory) {
		return errors.Join(fmt.Errorf("private archive directory changed before retirement"), err)
	}
	root, err := os.OpenRoot(host.filesystemRoot)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	wg, err := root.OpenRoot("etc/wireguard")
	if err != nil {
		return err
	}
	defer func() { _ = wg.Close() }()
	wgInfo, err := wg.Stat(".")
	if err != nil {
		return err
	}
	rootInfo, err := root.Lstat("etc/wireguard")
	if err != nil || !sameLegacyWireGuardFileIdentity(wgInfo, rootInfo) {
		return fmt.Errorf("WireGuard parent changed before private archival")
	}
	if archiveDirectory == nil {
		if err := wg.Mkdir(".syswarden-retired", 0700); err != nil {
			return fmt.Errorf("create private WireGuard archive: %w", err)
		}
	}
	// The directory is on the same filesystem. Pin both directories and use
	// RENAME_NOREPLACE: a preexisting archive is never overwritten, even on a race.
	archiveEvidence, err := host.inspectRetirementDirectory()
	if err != nil || archiveEvidence == nil {
		return errors.Join(fmt.Errorf("attest private archive before retirement"), err)
	}
	archive, err := wg.OpenRoot(".syswarden-retired")
	if err != nil {
		return err
	}
	defer func() { _ = archive.Close() }()
	sourceFD, err := wg.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = sourceFD.Close() }()
	targetFD, err := archive.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = targetFD.Close() }()
	targetInfo, err := targetFD.Stat()
	if err != nil {
		return err
	}
	targetStat, ok := targetInfo.Sys().(*syscall.Stat_t)
	if !ok || targetStat.Ino != archiveEvidence.Inode || uint64(targetStat.Dev) != archiveEvidence.Device || targetInfo.Mode().Perm() != 0700 || targetStat.Uid != host.expectedUID || targetStat.Gid != host.expectedGID {
		return fmt.Errorf("private archive directory changed while pinning")
	}
	// Repeat full bounded file attestation after pinning. No shell, copy or key
	// serialization is involved in retirement.
	checked, err := captureLegacyWireGuardConfiguration(host.filesystemRoot, legacyWireGuardConfigurationPath, host.expectedUID, host.expectedGID)
	if err != nil {
		return err
	}
	checked.evidence.Source = "exact-historical-config"
	sourceInfo, err := wg.Lstat("wg0.conf")
	if err != nil {
		return err
	}
	sourceStat, ok := sourceInfo.Sys().(*syscall.Stat_t)
	if !ok || checked.evidence != plan.Configuration || sourceStat.Ino != plan.Configuration.Inode || uint64(sourceStat.Dev) != plan.Configuration.Device {
		return fmt.Errorf("historical configuration changed at private archival boundary")
	}
	if err := unix.Renameat2(int(sourceFD.Fd()), "wg0.conf", int(targetFD.Fd()), "wg0.conf", unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("retire historical configuration without overwriting private archive: %w", err)
	}
	// Sync the archived file and both directories before reporting completion.
	file, err := archive.Open("wg0.conf")
	if err != nil {
		return fmt.Errorf("open retired private configuration for durability check: %w", err)
	}
	syncErr := errors.Join(file.Sync(), file.Close(), targetFD.Sync(), sourceFD.Sync())
	if syncErr != nil {
		return fmt.Errorf("sync private WireGuard archive; retain archive and retry inspection: %w", syncErr)
	}
	archived, err := captureLegacyWireGuardConfiguration(host.filesystemRoot, legacyWireGuardArchivePath, host.expectedUID, host.expectedGID)
	if err != nil {
		return fmt.Errorf("verify archived configuration: %w", err)
	}
	archived.evidence.Source = "exact-historical-config"
	expected := plan.Configuration
	expected.Path = legacyWireGuardArchivePath
	if archived.evidence != expected {
		return fmt.Errorf("retired configuration identity changed; private archive retained for inspection")
	}
	if _, err := root.Lstat(strings.TrimPrefix(legacyWireGuardConfigurationPath, "/")); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(fmt.Errorf("historical configuration path reappeared after retirement"), err)
	}
	return nil
}
