//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FinalizeRetainedOperatorConfiguration removes only empty known directories.
// The documented 99-user.toml operator surface stays at its original location.
// Its presence never authorizes deletion of another file or shared resource.
func FinalizeRetainedOperatorConfiguration() error {
	if err := RequireRemovalTombstone(); err != nil {
		return err
	}
	if err := preflightHostRemovalMountBoundaries(); err != nil {
		return err
	}
	return finalizeRetainedOperatorConfigurationAt("/etc/syswarden", 0, 0, nil)
}

func finalizeRetainedOperatorConfigurationAt(path string, uid, gid uint32, afterInventory func()) error {
	if err := attestRuntimeRetirementRoot(path, "/etc/syswarden", uid, gid, afterInventory); err != nil {
		return err
	}
	tree, err := openPinnedSharedRemovalTree(path, uid, gid, uid, sharedRemovalRaceHooks{})
	if err != nil {
		return err
	}
	defer tree.close()
	if tree.absent {
		return nil
	}
	bindings := make(map[string]removalArtifactIdentity)
	if err := attestRuntimeRetirementTree(tree, "/etc/syswarden", uid, gid, bindings); err != nil {
		return err
	}
	retained, err := finalizeOperatorConfigurationChildren(tree.root, "/etc/syswarden", bindings)
	if err != nil {
		return err
	}
	if retained {
		return attestRuntimeRetirementRoot(path, "/etc/syswarden", uid, gid, nil)
	}
	current, err := tree.parent.root.Lstat(tree.name)
	opened, openedErr := tree.root.Stat(".")
	if err != nil || openedErr != nil || !os.SameFile(current, opened) {
		return errors.Join(fmt.Errorf("configuration root changed before empty finalization"), err, openedErr)
	}
	return removeEmptyProductDirectory(tree.parent.root, tree.name, path)
}

func finalizeOperatorConfigurationChildren(root *os.Root, logical string, bindings map[string]removalArtifactIdentity) (bool, error) {
	entries, err := readBoundedSharedRemovalEntries(root)
	if err != nil {
		return false, err
	}
	retained := false
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(logical, name)
		before, err := root.Lstat(name)
		identity, identityErr := exactRemovalArtifactIdentity(before)
		expected, known := bindings[path]
		if err != nil || identityErr != nil || !known || identity != expected {
			return false, fmt.Errorf("configuration inventory changed before finalization: %q", path)
		}
		if path == "/etc/syswarden/config/modules/99-user.toml" {
			retained = true
			continue
		}
		if !before.IsDir() {
			return false, fmt.Errorf("unretired configuration file remains: %q", path)
		}
		child, err := root.OpenRoot(name)
		if err != nil {
			return false, err
		}
		opened, openedErr := child.Stat(".")
		openedIdentity, identityErr := exactRemovalArtifactIdentity(opened)
		if openedErr != nil || identityErr != nil || openedIdentity != expected {
			_ = child.Close()
			return false, fmt.Errorf("configuration directory changed while opening: %q", path)
		}
		childRetained, childErr := finalizeOperatorConfigurationChildren(child, path, bindings)
		current, statErr := root.Lstat(name)
		opened, openedErr = child.Stat(".")
		closeErr := child.Close()
		if childErr != nil || statErr != nil || openedErr != nil || closeErr != nil || !os.SameFile(current, opened) {
			return false, errors.Join(fmt.Errorf("configuration directory changed during finalization: %q", path), childErr, statErr, openedErr, closeErr)
		}
		if childRetained {
			retained = true
		} else if err := removeEmptyProductDirectory(root, name, path); err != nil {
			return false, err
		}
	}
	return retained, nil
}
