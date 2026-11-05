//go:build linux

package system

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"reflect"
	"strings"
	"syscall"
)

type apkTerminalGateRetirement struct {
	Schema     string                 `json:"schema"`
	Name       string                 `json:"name"`
	Quarantine string                 `json:"quarantine"`
	Parent     apkTransitionIdentity  `json:"parent"`
	Original   apkTransitionHostEntry `json:"original"`
}

// The durable exact quarantine intent precedes rename. A substituted object is
// preserved and restored without replacement; no target-shaped file is adopted.
func retireAPKTerminalGate(ctx context.Context, directory, journal *pinnedServiceDirectory, name string, expected apkTransitionHostEntry, mode os.FileMode, recordName string, rename serviceArtifactRename) error {
	if ctx == nil || directory == nil || journal == nil || rename == nil {
		return errors.New("APK gate retirement custody is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := directory.file.Stat()
	if err != nil {
		return err
	}
	parent := apkTransitionStat(info.Sys().(*syscall.Stat_t))
	var intent apkTerminalGateRetirement
	raw, readErr := readAPKTransitionBytes(journal, recordName, 16384)
	if errors.Is(readErr, os.ErrNotExist) {
		current, err := readAPKNativeHookMode(directory.root, name, mode)
		if err != nil || !reflect.DeepEqual(current, expected) {
			return errors.Join(errors.New("APK gate changed before retirement intent"), err)
		}
		quarantine, err := randomServiceArtifactName(".syswarden-apk-retired-")
		if err != nil {
			return err
		}
		intent = apkTerminalGateRetirement{apkExecutionSchema, name, quarantine, parent, expected}
		raw, err = apkExecutionJSON(intent)
		if err != nil {
			return err
		}
		if err := writeAPKTransitionBytes(journal, recordName, raw); err != nil {
			return err
		}
	} else if readErr != nil {
		return readErr
	} else {
		if decodeAPKTransitionJSON(raw, &intent) != nil || intent.Schema != apkExecutionSchema || intent.Name != name || !reflect.DeepEqual(intent.Original, expected) || !safeAssetName(intent.Quarantine) || !strings.HasPrefix(intent.Quarantine, ".syswarden-apk-retired-") || len(intent.Quarantine) > 128 || !apkLauncherSameParent(intent.Parent, parent) {
			return errors.New("APK retained gate retirement intent conflicts")
		}
	}
	checkParent := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := directory.file.Stat()
		if err != nil {
			return err
		}
		if !apkLauncherSameParent(intent.Parent, apkTransitionStat(current.Sys().(*syscall.Stat_t))) {
			return errors.New("APK gate parent changed during retirement")
		}
		return attestRetainedDirectoryParent(directory.file.Name(), directory, false)
	}
	if err := checkParent(); err != nil {
		return err
	}
	source, sourceErr := readAPKNativeHookMode(directory.root, name, mode)
	moved, movedErr := readAPKNativeHookMode(directory.root, intent.Quarantine, mode)
	if errors.Is(sourceErr, os.ErrNotExist) && errors.Is(movedErr, os.ErrNotExist) {
		return directory.sync()
	}
	if sourceErr == nil {
		if !reflect.DeepEqual(source, expected) || !errors.Is(movedErr, os.ErrNotExist) {
			return errors.New("APK gate retirement refuses competing named objects")
		}
		if err := rename(directory.fd, name, directory.fd, intent.Quarantine, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		moved, movedErr = readAPKNativeHookMode(directory.root, intent.Quarantine, mode)
	} else if !errors.Is(sourceErr, os.ErrNotExist) {
		return sourceErr
	}
	moved.Path = expected.Path
	matches := movedErr == nil && sameAPKLauncherMovedIdentity(expected.Identity, moved.Identity) && reflect.DeepEqual(moved.Content, expected.Content) && moved.Absent == expected.Absent && moved.LinkTarget == expected.LinkTarget
	if !matches {
		restoreErr := rename(directory.fd, intent.Quarantine, directory.fd, name, unix.RENAME_NOREPLACE)
		return errors.Join(errors.New("APK gate was substituted before quarantine; retained without deletion"), movedErr, restoreErr, directory.sync())
	}
	if err := errors.Join(directory.sync(), checkParent()); err != nil {
		return err
	}
	if _, err := directory.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return errors.New("APK gate name was repopulated during quarantine")
	}
	// Only the exact single-link quarantined object is now eligible for removal.
	// Retained intent makes any interrupted state inspectable without replaying APK.
	if err := unix.Unlinkat(directory.fd, intent.Quarantine, 0); err != nil {
		return err
	}
	return errors.Join(directory.sync(), checkParent())
}
