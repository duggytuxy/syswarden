//go:build linux

package system

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"syswarden-cli/config"
)

// This phase removes only full literal current or byte-pinned historical
// default templates. Custom overrides and migrated administrator values
// remain untouched for the separate retained-file inventory.
// A familiar filename or a valid TOML document never grants deletion authority.
func RemovePristineDefaultConfigurationForRemoval() error {
	check := func() error {
		if err := RequireRemovalTombstone(); err != nil {
			return err
		}
		if err := preflightHostRemovalMountBoundaries(); err != nil {
			return err
		}
		root, err := os.OpenRoot("/")
		if err != nil {
			return err
		}
		defer func() { _ = root.Close() }()
		for _, path := range []string{"/etc/syswarden/config/config.toml", "/etc/syswarden/config/modules/99-user.toml"} {
			if _, err := historicalRemovalCandidatePresent(root, path, 0, 0, func() {}); err != nil {
				return err
			}
		}
		return ReattestFirewallStatePreparedForRemoval()
	}
	retained, err := retainedOperatorConfigurationPaths(operatorRetentionRecordsPath)
	if err != nil {
		return err
	}
	return retirePristineDefaultConfigurationWithRetention("/etc/syswarden/config", check, retained)
}

func retirePristineDefaultConfiguration(directory string, guard func() error) error {
	return retirePristineDefaultConfigurationWithRetention(directory, guard, nil)
}

func retirePristineDefaultConfigurationWithRetention(directory string, guard func() error, retained map[string]bool) error {
	if guard == nil {
		return fmt.Errorf("default configuration retirement requires a complete removal guard")
	}
	if err := guard(); err != nil {
		return err
	}
	if err := config.CheckModularRetirementState(directory); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	models, err := config.DefaultModularFileVariants(directory)
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(models))
	for relative := range models {
		paths = append(paths, relative)
	}
	slices.Sort(paths)
	var exact []string
	matched := make(map[string]string)
	for _, relative := range paths {
		if retained["/etc/syswarden/config/"+filepath.ToSlash(relative)] {
			continue
		}
		path := filepath.Join(directory, relative)
		parent, err := openExistingPinnedServiceDirectory(filepath.Dir(path))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		before, statErr := parent.root.Lstat(filepath.Base(path))
		if errors.Is(statErr, fs.ErrNotExist) {
			parent.close()
			continue
		}
		if statErr != nil {
			parent.close()
			return statErr
		}
		content, readErr := readDefaultRetirementCandidate(parent, filepath.Base(path), before)
		if readErr == nil && slices.Contains(models[relative], string(content)) {
			_, readErr = inspectSingleLinkExactServiceFileModes(parent, filepath.Base(path), string(content), []os.FileMode{0600, 0640})
			if readErr == nil {
				exact = append(exact, relative)
				matched[relative] = string(content)
			}
		}
		parent.close()
		if readErr != nil {
			return fmt.Errorf("inspect default configuration before retirement at %s: %w", path, readErr)
		}
	}
	// All candidate metadata has been inspected before the first deletion.
	// Each selected file is opened, matched and quarantined again at deletion.
	for _, relative := range exact {
		if err := guard(); err != nil {
			return err
		}
		if err := config.CheckModularRetirementState(directory); err != nil {
			return err
		}
		if err := removePreparedExactServiceFileModes(filepath.Join(directory, relative), matched[relative], []os.FileMode{0600, 0640}); err != nil {
			return err
		}
	}
	return guard()
}

func readDefaultRetirementCandidate(parent *pinnedServiceDirectory, name string, before os.FileInfo) ([]byte, error) {
	limit := int64(64 << 10)
	if name == "99-user.toml" {
		// The supported operator module may contain up to 256 KiB. Reading
		// it for literal comparison must not reject a valid retained module.
		limit = 256 << 10
	}
	return readRetirementCandidateBounded(parent, name, before, limit)
}

func readRetirementCandidateBounded(parent *pinnedServiceDirectory, name string, before os.FileInfo, limit int64) ([]byte, error) {
	if limit < 1 || limit > MaximumGeneratedFeedBytes {
		return nil, fmt.Errorf("retirement candidate read limit is invalid")
	}
	identity, err := exactRemovalArtifactIdentity(before)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		before.Mode().Perm()&0037 != 0 || !serviceFileOwnedByCurrentUser(before) || identity.nlink != 1 || identity.size < 0 || identity.size > limit {
		return nil, fmt.Errorf("configuration candidate is not a bounded exclusive private regular file")
	}
	file, err := parent.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	openedIdentity, identityErr := exactRemovalArtifactIdentity(opened)
	if err != nil || identityErr != nil || openedIdentity != identity {
		return nil, fmt.Errorf("configuration candidate changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) != identity.size {
		return nil, fmt.Errorf("configuration candidate changed while reading")
	}
	after, err := parent.root.Lstat(name)
	afterIdentity, identityErr := exactRemovalArtifactIdentity(after)
	if err != nil || identityErr != nil || afterIdentity != identity {
		return nil, fmt.Errorf("configuration candidate changed during inspection")
	}
	return content, nil
}
