//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// AttestRuntimeRetirementBeforeNativeErase is the final non-payload boundary
// in prerm. A later postrm may run without the CLI, so it must never inherit
// unresolved generated files. This check grants no deletion authority over
// package payload or directory contents; the native manager retains its own
// package integrity and payload removal responsibilities.
func AttestRuntimeRetirementBeforeNativeErase() error {
	if err := RequireRemovalTombstone(); err != nil {
		return err
	}
	if err := preflightHostRemovalMountBoundaries(); err != nil {
		return err
	}
	for _, path := range hostRemovalMountRoots {
		if err := attestRuntimeRetirementRoot(path, path, 0, 0, nil); err != nil {
			return err
		}
	}
	return RequireRemovalTombstone()
}

// The list describes the package skeleton and documented retained operator
// surface, not ownership of its contents.
// Anything else must finish a separately verified retirement before prerm can
// return success. In particular, empty custom directories are not adopted.
func packageRetirementChildren(path string) ([]string, []string) {
	switch path {
	case "/opt/syswarden":
		return []string{"bin"}, []string{"signatures.json"}
	case "/opt/syswarden/bin":
		return nil, []string{"syswarden-cli", "syswarden-core", "syswarden-tui"}
	case "/etc/syswarden":
		return []string{"config", "lists", "tls"}, nil
	case "/etc/syswarden/config":
		return []string{"modules"}, nil
	case "/etc/syswarden/config/modules":
		// This documented operator surface is retained, never adopted as
		// package payload. Pristine generated defaults are retired earlier.
		return nil, []string{"99-user.toml"}
	case "/var/lib/syswarden":
		return []string{"ui"}, []string{removalTombstoneName}
	default:
		return nil, nil
	}
}

func attestRuntimeRetirementRoot(path, logicalPath string, uid, gid uint32, afterInventory func()) error {
	tree, err := openPinnedSharedRemovalTree(path, uid, gid, uid, sharedRemovalRaceHooks{})
	if err != nil {
		return err
	}
	defer tree.close()
	if tree.absent {
		return nil
	}
	bindings := make(map[string]removalArtifactIdentity)
	if err := attestRuntimeRetirementTree(tree, logicalPath, uid, gid, bindings); err != nil {
		return err
	}
	if afterInventory != nil {
		afterInventory()
	}
	// Keep every directory and entry identity, including nested directories.
	// A change in a child directory need not change its parent's timestamps.
	for candidate, expected := range bindings {
		relative, err := filepath.Rel(logicalPath, candidate)
		if err != nil {
			return err
		}
		current, err := tree.root.Lstat(relative)
		identity, identityErr := exactRemovalArtifactIdentity(current)
		if err != nil || identityErr != nil || identity != expected {
			return fmt.Errorf("package retirement inventory changed before completion: %q", candidate)
		}
	}
	current, err := tree.parent.root.Lstat(tree.name)
	identity, identityErr := exactRemovalArtifactIdentity(current)
	if err != nil || identityErr != nil || identity != tree.identity {
		return fmt.Errorf("package retirement root changed before completion: %q", logicalPath)
	}
	return nil
}

func attestRuntimeRetirementTree(tree *pinnedSharedRemovalTree, path string, uid, gid uint32, bindings map[string]removalArtifactIdentity) error {
	bindings[path] = tree.identity
	entries, err := readBoundedSharedRemovalEntries(tree.root)
	if err != nil {
		return err
	}
	directories, payload := packageRetirementChildren(path)
	for _, entry := range entries {
		name := entry.Name()
		candidate := filepath.Join(path, name)
		if !slices.Contains(directories, name) && !slices.Contains(payload, name) {
			return fmt.Errorf("unretired artifact remains at %q; preserve the CLI and complete verified file retirement before product removal", candidate)
		}
		before, err := tree.root.Lstat(name)
		if err != nil {
			return err
		}
		identity, identityErr := exactRemovalArtifactIdentity(before)
		if identityErr != nil || identity.uid != uid || identity.gid != gid ||
			before.Mode().Perm()&0022 != 0 || before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return errors.Join(fmt.Errorf("unsafe package retirement entry %q", candidate), identityErr)
		}
		bindings[candidate] = identity
		if candidate == "/etc/syswarden/config/modules/99-user.toml" &&
			before.Mode().Perm() != 0600 && before.Mode().Perm() != 0640 {
			return fmt.Errorf("retained operator configuration has unsafe permissions: %q", candidate)
		}
		if slices.Contains(directories, name) {
			if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("package retirement directory is not a real directory: %q", candidate)
			}
			child, err := tree.root.OpenRoot(name)
			if err != nil {
				return err
			}
			opened, openedErr := child.Stat(".")
			openedIdentity, openedIdentityErr := exactRemovalArtifactIdentity(opened)
			if openedErr != nil || openedIdentityErr != nil || openedIdentity != identity {
				_ = child.Close()
				return fmt.Errorf("package retirement directory changed while opening: %q", candidate)
			}
			// The parent descriptor is borrowed only for this recursive check.
			nested := &pinnedSharedRemovalTree{parent: &pinnedServiceDirectory{root: tree.root}, root: child, name: name, identity: identity}
			err = attestRuntimeRetirementTree(nested, candidate, uid, gid, bindings)
			closeErr := child.Close()
			if err != nil || closeErr != nil {
				return errors.Join(err, closeErr)
			}
		} else if !before.Mode().IsRegular() || identity.nlink != 1 {
			return fmt.Errorf("package retirement payload entry is not an exclusive regular file: %q", candidate)
		}
		current, err := tree.root.Lstat(name)
		currentIdentity, currentIdentityErr := exactRemovalArtifactIdentity(current)
		if err != nil || currentIdentityErr != nil || currentIdentity != identity {
			return fmt.Errorf("package retirement entry changed while inspecting: %q", candidate)
		}
	}
	confirmed, err := readBoundedSharedRemovalEntries(tree.root)
	if err != nil {
		return err
	}
	names := func(items []os.DirEntry) []string {
		result := make([]string, len(items))
		for index, item := range items {
			result[index] = item.Name()
		}
		slices.Sort(result)
		return result
	}
	if !slices.Equal(names(entries), names(confirmed)) {
		return fmt.Errorf("package retirement inventory changed: %q", path)
	}
	opened, openedErr := tree.root.Stat(".")
	named, namedErr := tree.parent.root.Lstat(tree.name)
	openedIdentity, openedIdentityErr := exactRemovalArtifactIdentity(opened)
	namedIdentity, namedIdentityErr := exactRemovalArtifactIdentity(named)
	if openedErr != nil || namedErr != nil || openedIdentityErr != nil || namedIdentityErr != nil ||
		openedIdentity != tree.identity || namedIdentity != tree.identity {
		return fmt.Errorf("package retirement root changed during inspection: %q", path)
	}
	return nil
}
