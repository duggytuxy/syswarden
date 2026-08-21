package config

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type secureFileIdentity struct {
	info   os.FileInfo
	digest [sha256.Size]byte
}

func newSecureFileIdentity(content []byte, info os.FileInfo) *secureFileIdentity {
	return &secureFileIdentity{info: info, digest: sha256.Sum256(content)}
}

func (identity *secureFileIdentity) matches(content []byte, info os.FileInfo) bool {
	if identity == nil || identity.info == nil || info == nil {
		return false
	}
	expectedUID, expectedGID, expectedOK := fileOwnerUIDGID(identity.info)
	currentUID, currentGID, currentOK := fileOwnerUIDGID(info)
	return expectedOK && currentOK && expectedUID == currentUID && expectedGID == currentGID &&
		os.SameFile(identity.info, info) && identity.info.Mode() == info.Mode() &&
		identity.digest == sha256.Sum256(content)
}

// openDirectoryNoSymlinks resolves path one directory descriptor at a time.
// Each component is checked before and after opening, so neither a pre-existing
// symlink nor a rename between inspection and use can redirect the returned
// root. Missing components are created only when create is true.
func openDirectoryNoSymlinks(path string, create bool, mode os.FileMode) (*os.Root, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve directory %s: %w", path, err)
	}
	absolute = filepath.Clean(absolute)
	volume := filepath.VolumeName(absolute)
	anchor := volume + string(os.PathSeparator)
	current, err := os.OpenRoot(anchor)
	if err != nil {
		return nil, fmt.Errorf("open filesystem anchor for %s: %w", path, err)
	}

	relative := strings.TrimPrefix(absolute, anchor)
	components := strings.FieldsFunc(relative, func(r rune) bool {
		return r == rune(os.PathSeparator)
	})
	for _, component := range components {
		before, statErr := current.Lstat(component)
		if statErr != nil && os.IsNotExist(statErr) && create {
			if mkdirErr := current.Mkdir(component, mode); mkdirErr != nil && !os.IsExist(mkdirErr) {
				_ = current.Close()
				return nil, fmt.Errorf("create directory component %s in %s: %w", component, path, mkdirErr)
			}
			before, statErr = current.Lstat(component)
		}
		if statErr != nil {
			_ = current.Close()
			return nil, fmt.Errorf("inspect directory component %s in %s: %w", component, path, statErr)
		}
		if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			_ = current.Close()
			return nil, fmt.Errorf("directory component %s in %s is not a real directory", component, path)
		}

		next, openErr := current.OpenRoot(component)
		if openErr != nil {
			_ = current.Close()
			return nil, fmt.Errorf("open directory component %s in %s: %w", component, path, openErr)
		}
		opened, openedErr := rootDirectoryInfo(next)
		after, afterErr := current.Lstat(component)
		if openedErr != nil || afterErr != nil || after.Mode()&os.ModeSymlink != 0 ||
			!os.SameFile(before, opened) || !os.SameFile(opened, after) {
			_ = next.Close()
			_ = current.Close()
			if openedErr != nil {
				return nil, fmt.Errorf("verify opened directory component %s in %s: %w", component, path, openedErr)
			}
			if afterErr != nil {
				return nil, fmt.Errorf("reinspect directory component %s in %s: %w", component, path, afterErr)
			}
			return nil, fmt.Errorf("directory component %s in %s changed while opening", component, path)
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func rootDirectoryInfo(root *os.Root) (os.FileInfo, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	return directory.Stat()
}

func validateConfigDirectory(root *os.Root, path string) error {
	info, err := rootDirectoryInfo(root)
	if err != nil {
		return fmt.Errorf("inspect configuration directory %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("configuration directory %s is not a real directory", path)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("configuration directory %s has unsafe mode %#o", path, info.Mode().Perm())
	}
	return nil
}

func openConfigDirectory(path string, create bool, mode os.FileMode) (*os.Root, error) {
	root, err := openDirectoryNoSymlinks(path, create, mode)
	if err != nil {
		return nil, err
	}
	if err := validateConfigDirectory(root, path); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

// readSecureRegularFile reads through a rooted descriptor and verifies that the
// same restrictive regular inode remains installed for the complete read.
func readSecureRegularFile(root *os.Root, name, displayPath string) ([]byte, error) {
	content, _, err := readSecureRegularFileSnapshot(root, name, displayPath)
	return content, err
}

func readSecureRegularFileIdentity(root *os.Root, name, displayPath string) ([]byte, *secureFileIdentity, error) {
	content, info, err := readSecureRegularFileSnapshot(root, name, displayPath)
	if err != nil {
		return nil, nil, err
	}
	return content, newSecureFileIdentity(content, info), nil
}

func readSecureRegularFileSnapshot(root *os.Root, name, displayPath string) ([]byte, os.FileInfo, error) {
	if name == "" || filepath.Base(name) != name {
		return nil, nil, fmt.Errorf("invalid configuration filename %q", name)
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("configuration file %s is not a regular file", displayPath)
	}
	if before.Mode().Perm()&0037 != 0 {
		return nil, nil, fmt.Errorf("configuration file %s has unsafe mode %#o", displayPath, before.Mode().Perm())
	}

	file, err := root.Open(name)
	if err != nil {
		return nil, nil, fmt.Errorf("open configuration file %s: %w", displayPath, err)
	}
	defer func() { _ = file.Close() }()
	openedBefore, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("inspect opened configuration file %s: %w", displayPath, err)
	}
	if !openedBefore.Mode().IsRegular() || !os.SameFile(before, openedBefore) {
		return nil, nil, fmt.Errorf("configuration file %s changed while opening", displayPath)
	}

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, nil, fmt.Errorf("read configuration file %s: %w", displayPath, err)
	}
	openedAfter, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("reinspect opened configuration file %s: %w", displayPath, err)
	}
	after, err := root.Lstat(name)
	if err != nil {
		return nil, nil, fmt.Errorf("reinspect configuration file %s: %w", displayPath, err)
	}
	if after.Mode()&os.ModeSymlink != 0 || after.Mode().Perm()&0037 != 0 ||
		!os.SameFile(openedBefore, openedAfter) || !os.SameFile(openedAfter, after) ||
		openedBefore.Size() != openedAfter.Size() || !openedBefore.ModTime().Equal(openedAfter.ModTime()) {
		return nil, nil, fmt.Errorf("configuration file %s changed while reading", displayPath)
	}
	return bytes.Clone(content), openedAfter, nil
}

func readSecureFileByPath(path string) ([]byte, error) {
	content, _, err := readSecureFileIdentityByPath(path)
	return content, err
}

func readSecureFileIdentityByPath(path string) ([]byte, *secureFileIdentity, error) {
	parent := filepath.Dir(path)
	root, err := openDirectoryNoSymlinks(parent, false, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	return readSecureRegularFileIdentity(root, filepath.Base(path), path)
}
