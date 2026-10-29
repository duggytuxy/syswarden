//go:build linux

package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
)

const apkDatabaseLockSchema = "syswarden-apk-database-lock/v1"

type apkDatabaseLockProposal struct {
	Schema  string                   `json:"schema"`
	Parents []apkTransitionHostEntry `json:"parents"`
	Lock    apkTransitionIdentity    `json:"lock"`
}

type apkDatabaseLock struct {
	root     *os.Root
	file     *os.File
	proposal apkDatabaseLockProposal
	held     bool
}

// This is APK's actual existing flock object, reacquired only after the native
// child exits. It is neither the private custody lock nor a continuous lease
// across APK startup. No database file is created or changed here.
func openAPKDatabaseLock(ctx context.Context, host string, expected *apkDatabaseLockProposal, acquire bool) (_ *apkDatabaseLock, result error) {
	if ctx == nil || !filepath.IsAbs(host) || filepath.Clean(host) != host {
		return nil, errors.New("APK database observation requires a bounded host root")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(host)
	if err != nil {
		return nil, err
	}
	lock := &apkDatabaseLock{root: root}
	defer func() {
		if result != nil {
			result = errors.Join(result, lock.Close())
		}
	}()
	for _, name := range []string{".", "lib", "lib/apk", "lib/apk/db"} {
		info, err := root.Lstat(name)
		if err != nil {
			return nil, err
		}
		status, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || int64(status.Uid) != int64(os.Geteuid()) || int64(status.Gid) != int64(os.Getegid()) {
			return nil, errors.New("APK database ancestry is not protected")
		}
		lock.proposal.Parents = append(lock.proposal.Parents, apkTransitionHostEntry{Path: name, Identity: apkTransitionStat(status)})
	}
	lock.file, err = root.OpenFile("lib/apk/db/lock", os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := lock.file.Stat()
	if err != nil {
		return nil, err
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || status.Nlink != 1 || info.Size() != 0 || int64(status.Uid) != int64(os.Geteuid()) || int64(status.Gid) != int64(os.Getegid()) {
		return nil, errors.New("APK database lock is not an existing protected single-link file")
	}
	lock.proposal.Schema, lock.proposal.Lock = apkDatabaseLockSchema, apkTransitionStat(status)
	if expected != nil {
		if expected.Schema != apkDatabaseLockSchema || len(expected.Parents) != len(lock.proposal.Parents) || expected.Lock != lock.proposal.Lock {
			return nil, errors.New("APK database lock differs from the approved inode")
		}
		for index, parent := range expected.Parents {
			actual := lock.proposal.Parents[index]
			if parent.Path != actual.Path || parent.Absent || !apkLauncherSameParent(parent.Identity, actual.Identity) {
				return nil, errors.New("APK database ancestry differs from execution approval")
			}
		}
		lock.proposal = *expected
		lock.proposal.Parents = append([]apkTransitionHostEntry(nil), expected.Parents...)
	}
	if acquire {
		if err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			return nil, errors.Join(errors.New("APK database is busy; terminal authority remains unavailable"), err)
		}
		lock.held = true
	}
	return lock, lock.Revalidate(ctx)
}

func captureAPKDatabaseLock(ctx context.Context, host string) (_ *apkDatabaseLockProposal, result error) {
	lock, err := openAPKDatabaseLock(ctx, host, nil, false)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, lock.Close()) }()
	proposal := lock.proposal
	return &proposal, nil
}

func (lock *apkDatabaseLock) Revalidate(ctx context.Context) error {
	if ctx == nil || lock == nil || lock.root == nil || lock.file == nil {
		return errors.New("APK database custody is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, parent := range lock.proposal.Parents {
		info, err := lock.root.Lstat(parent.Path)
		if err != nil {
			return err
		}
		status, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !apkLauncherSameParent(parent.Identity, apkTransitionStat(status)) {
			return errors.New("APK database ancestry changed")
		}
	}
	named, err := lock.root.Lstat("lib/apk/db/lock")
	opened, openErr := lock.file.Stat()
	if err != nil || openErr != nil {
		return errors.Join(err, openErr)
	}
	for _, info := range []os.FileInfo{named, opened} {
		status, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !reflect.DeepEqual(apkTransitionStat(status), lock.proposal.Lock) {
			return errors.New("APK database lock inode changed")
		}
	}
	return ctx.Err()
}

func (lock *apkDatabaseLock) Close() error {
	if lock == nil {
		return nil
	}
	var result error
	if lock.file != nil {
		if lock.held {
			result = syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
			lock.held = false
		}
		result = errors.Join(result, lock.file.Close())
		lock.file = nil
	}
	if lock.root != nil {
		result = errors.Join(result, lock.root.Close())
		lock.root = nil
	}
	return result
}
