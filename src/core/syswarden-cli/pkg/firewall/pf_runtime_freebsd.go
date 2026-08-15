//go:build freebsd

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
