//go:build linux

package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

var errNativeLauncherBoundary = errors.New("native command launchers require administrator review before package execution")

type nativeLauncherIdentity struct {
	device, inode, links uint64
	uid, gid, mode       uint32
	size                 int64
	modified, changed    syscall.Timespec
}

type nativeLauncherSnapshot struct {
	directories [4]nativeLauncherIdentity
	launchers   [2]nativeLauncherIdentity
}

type nativeLauncherReader func(context.Context) (nativeLauncherSnapshot, error)

// The initial read precedes dependency preparation. The second read follows the
// package-byte guard and precedes native execution. This detects observed drift;
// it does not lock arbitrary administrator writers or protect direct APK calls.
func prepareNativeLauncherGuard(ctx context.Context, beforeExecute func(context.Context) error, read nativeLauncherReader) (func(context.Context) error, error) {
	if ctx == nil || beforeExecute == nil || read == nil {
		return nil, errNativeLauncherBoundary
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	before, err := read(ctx)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, errNativeLauncherBoundary
	}
	return func(executionCtx context.Context) error {
		if executionCtx == nil {
			return errNativeLauncherBoundary
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := executionCtx.Err(); err != nil {
			return err
		}
		if err := beforeExecute(executionCtx); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := executionCtx.Err(); err != nil {
			return err
		}
		after, err := read(executionCtx)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if ctxErr := executionCtx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil || after != before {
			return errNativeLauncherBoundary
		}
		return nil
	}, nil
}

func inspectInstalledNativeLaunchers(ctx context.Context) (nativeLauncherSnapshot, error) {
	return inspectNativeLaunchersAt(ctx, "/", 0, 0)
}

func inspectNativeLaunchersAt(ctx context.Context, anchor string, uid, gid int) (nativeLauncherSnapshot, error) {
	var result nativeLauncherSnapshot
	if ctx == nil || !filepath.IsAbs(anchor) || filepath.Clean(anchor) != anchor || uid < 0 || gid < 0 {
		return result, errNativeLauncherBoundary
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	identity := func(info os.FileInfo, directory bool) (nativeLauncherIdentity, error) {
		status, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(status.Uid) != uid || int(status.Gid) != gid ||
			(directory && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0)) ||
			(!directory && (info.Mode()&os.ModeSymlink == 0 || status.Nlink != 1)) {
			return nativeLauncherIdentity{}, errNativeLauncherBoundary
		}
		return nativeLauncherIdentity{status.Dev, status.Ino, status.Nlink, status.Uid, status.Gid, status.Mode, status.Size, status.Mtim, status.Ctim}, nil
	}
	anchorInfo, err := os.Lstat(anchor)
	if err != nil {
		return result, errNativeLauncherBoundary
	}
	result.directories[0], err = identity(anchorInfo, true)
	if err != nil {
		return result, err
	}
	root, err := os.OpenRoot(anchor)
	if err != nil {
		return result, errNativeLauncherBoundary
	}
	defer func() { _ = root.Close() }()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(anchorInfo, opened) {
		return result, errNativeLauncherBoundary
	}
	openedIdentity, err := identity(opened, true)
	if err != nil || openedIdentity != result.directories[0] {
		return result, errNativeLauncherBoundary
	}
	for index, component := range []string{"usr", "local", "bin"} {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		before, err := root.Lstat(component)
		if err != nil {
			return result, errNativeLauncherBoundary
		}
		result.directories[index+1], err = identity(before, true)
		if err != nil {
			return result, err
		}
		next, err := root.OpenRoot(component)
		if err != nil {
			return result, errNativeLauncherBoundary
		}
		after, statErr := next.Stat(".")
		if statErr != nil || !os.SameFile(before, after) {
			_ = next.Close()
			return result, errNativeLauncherBoundary
		}
		openedIdentity, err := identity(after, true)
		if err != nil || openedIdentity != result.directories[index+1] {
			_ = next.Close()
			return result, errNativeLauncherBoundary
		}
		if err := root.Close(); err != nil {
			_ = next.Close()
			return result, errNativeLauncherBoundary
		}
		root = next
	}
	for index, entry := range [2]struct{ name, target string }{
		{"syswarden", "/opt/syswarden/bin/syswarden-cli"},
		{"syswarden-tui", "/opt/syswarden/bin/syswarden-tui"},
	} {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		before, err := root.Lstat(entry.name)
		if err != nil {
			return result, errNativeLauncherBoundary
		}
		result.launchers[index], err = identity(before, false)
		if err != nil || before.Size() != int64(len(entry.target)) {
			return result, errNativeLauncherBoundary
		}
		target, err := root.Readlink(entry.name)
		if err != nil || target != entry.target {
			return result, errNativeLauncherBoundary
		}
		after, err := root.Lstat(entry.name)
		if err != nil {
			return result, errNativeLauncherBoundary
		}
		observed, err := identity(after, false)
		if err != nil || observed != result.launchers[index] {
			return result, errNativeLauncherBoundary
		}
	}
	return result, ctx.Err()
}
