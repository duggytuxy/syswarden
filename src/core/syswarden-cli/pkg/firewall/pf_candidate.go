package firewall

import (
	"fmt"
	"os"
	"path/filepath"
)

func createPrivatePFConfig(baseDirectory string, rules []byte) (string, func(), error) {
	directory, err := os.MkdirTemp(baseDirectory, "syswarden-pf-")
	if err != nil {
		return "", nil, fmt.Errorf("create private PF directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	directoryInfo, err := os.Lstat(directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0700 {
		cleanup()
		return "", nil, fmt.Errorf("private PF directory has unsafe type or permissions: %v", err)
	}

	root, err := os.OpenRoot(directory)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("open private PF directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	file, err := root.OpenFile("candidate.conf", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("create private PF candidate: %w", err)
	}
	if _, err := file.Write(rules); err != nil {
		_ = file.Close()
		cleanup()
		return "", nil, fmt.Errorf("write private PF candidate: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return "", nil, fmt.Errorf("sync private PF candidate: %w", err)
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("close private PF candidate: %w", err)
	}
	if err := verifyPrivatePFConfigRoot(root, "candidate.conf"); err != nil {
		cleanup()
		return "", nil, err
	}
	path := filepath.Join(directory, "candidate.conf")
	return path, cleanup, nil
}

func verifyPrivatePFConfigRoot(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf("inspect private PF candidate: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("PF candidate is not a regular file")
	}
	if info.Mode().Perm() != 0600 {
		return fmt.Errorf("PF candidate permissions are %04o, expected 0600", info.Mode().Perm())
	}
	return nil
}

func verifyPrivatePFConfig(path string) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return fmt.Errorf("PF candidate path is not absolute")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open PF candidate directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	return verifyPrivatePFConfigRoot(root, filepath.Base(path))
}
