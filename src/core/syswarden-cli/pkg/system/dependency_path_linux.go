//go:build linux

package system

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var errDependencyPath = errors.New("dependency path is not a protected executable chain")

// Inspect every directory and symlink traversed, including intermediate links
// outside the final executable directory. Resolution is bounded and read-only;
// it does not retain authority to execute after a privileged concurrent change.
func resolveDependencyExecutableAt(anchor, path string, uid int) (string, error) {
	if uid < 0 || !filepath.IsAbs(anchor) || filepath.Clean(anchor) != anchor ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 {
		return "", errDependencyPath
	}
	protected := func(info os.FileInfo, directory bool) bool {
		status, ok := info.Sys().(*syscall.Stat_t)
		return ok && int(status.Uid) == uid && info.Mode().Perm()&0022 == 0 &&
			((directory && info.IsDir()) || (!directory && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0))
	}
	before, err := os.Lstat(anchor)
	if err != nil || !protected(before, true) {
		return "", errDependencyPath
	}
	root, err := os.OpenRoot(anchor)
	if err != nil {
		return "", errDependencyPath
	}
	defer root.Close()
	after, err := root.Stat(".")
	if err != nil || !protected(after, true) || !os.SameFile(before, after) {
		return "", errDependencyPath
	}
	pending := strings.Split(strings.TrimPrefix(path, "/"), "/")
	var resolved []string
	for steps := 0; len(pending) > 0 && steps < 128; steps++ {
		if len(pending) > 256 {
			return "", errDependencyPath
		}
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
			continue
		}
		components := append(append([]string(nil), resolved...), part)
		relative := strings.Join(components, "/")
		info, err := root.Lstat(relative)
		if err != nil {
			return "", errDependencyPath
		}
		if info.Mode()&os.ModeSymlink != 0 {
			status, ok := info.Sys().(*syscall.Stat_t)
			if !ok || int(status.Uid) != uid || status.Nlink != 1 {
				return "", errDependencyPath
			}
			target, err := root.Readlink(relative)
			if err != nil || target == "" || len(target) > 4096 {
				return "", errDependencyPath
			}
			if filepath.IsAbs(target) {
				resolved = nil
			}
			pending = append(strings.Split(target, "/"), pending...)
			continue
		}
		if len(pending) == 0 {
			if !protected(info, false) {
				return "", errDependencyPath
			}
			return "/" + relative, nil
		}
		if !protected(info, true) {
			return "", errDependencyPath
		}
		resolved = components
	}
	return "", errDependencyPath
}
