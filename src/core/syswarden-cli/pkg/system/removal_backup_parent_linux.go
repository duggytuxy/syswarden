//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Only mutation paths call this after validating the operation's authority.
// Create one missing backups child through its pinned existing parent. Never
// recursively create ancestors or alter an existing shared backup directory.
func openOrCreateRetirementBackupParent(path string) (*pinnedServiceDirectory, error) {
	if filepath.Base(path) != "backups" || filepath.Clean(path) != path || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("unsupported retirement backup parent")
	}
	if existing, err := openExistingPinnedServiceDirectory(path); err == nil {
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	parentPath := filepath.Dir(path)
	parent, err := openExistingPinnedServiceDirectory(parentPath)
	if err != nil {
		return nil, err
	}
	defer parent.close()
	if err := attestRetainedDirectoryParent(parentPath, parent, false); err != nil {
		return nil, err
	}
	if err := parent.root.Mkdir("backups", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := parent.sync(); err != nil {
		return nil, err
	}
	created, err := openExistingPinnedServiceDirectory(path)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(attestRetainedDirectoryParent(parentPath, parent, false), attestRetainedDirectoryParent(path, created, false)); err != nil {
		created.close()
		return nil, err
	}
	return created, nil
}
