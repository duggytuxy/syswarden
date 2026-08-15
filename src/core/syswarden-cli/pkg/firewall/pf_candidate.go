package firewall

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

var (
	pfRuntimeLockPath = "/var/run/syswarden-firewall.lock"
	pfRuntimeMu       sync.Mutex
)

type pfRuntimeLock struct {
	file *os.File
}

func openRootedPFRuntimeFile(path string, flags int, permission fs.FileMode) (*os.File, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path {
		return nil, fmt.Errorf("PF runtime lock path is not absolute and canonical: %q", path)
	}
	root, err := os.OpenRoot(filepath.Dir(clean))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.OpenFile(filepath.Base(clean), flags|syscall.O_NOFOLLOW, permission)
}

func acquirePFRuntimeLock() (*pfRuntimeLock, error) {
	pfRuntimeMu.Lock()
	file, err := openRootedPFRuntimeFile(pfRuntimeLockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		pfRuntimeMu.Unlock()
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		pfRuntimeMu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("PF runtime lock is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		_ = file.Close()
		pfRuntimeMu.Unlock()
		return nil, fmt.Errorf("PF runtime lock is not owned by the effective user")
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		pfRuntimeMu.Unlock()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		pfRuntimeMu.Unlock()
		return nil, err
	}
	return &pfRuntimeLock{file: file}, nil
}

func releasePFRuntimeLock(lock *pfRuntimeLock) {
	if lock != nil && lock.file != nil {
		_ = syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
		_ = lock.file.Close()
	}
	pfRuntimeMu.Unlock()
}

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

func openPrivatePFConfig(path string) (*os.File, error) {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("PF candidate path is not absolute")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("open PF candidate directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	name := filepath.Base(path)
	before, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect private PF candidate: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("PF candidate is not a private regular file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open private PF candidate: %w", err)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("inspect opened PF candidate: %w", err)
		}
		return nil, fmt.Errorf("PF candidate changed while opening")
	}
	return file, nil
}
