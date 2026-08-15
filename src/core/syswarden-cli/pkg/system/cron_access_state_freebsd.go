//go:build freebsd

package system

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

const (
	freeBSDCronAccessStateName = "cron-access-state.json"
	freeBSDCronDirectory       = "/var/cron"
	freeBSDCronAllowName       = "allow"
	freeBSDCronDenyName        = "deny"
)

var freeBSDManagedCronAllow = []byte("root\n")

type freeBSDCronAccessState struct {
	SchemaVersion int `json:"schema_version"`
}

func readFreeBSDCronAccessState() (bool, error) {
	var state freeBSDCronAccessState
	found, err := readFreeBSDOwnedState(freeBSDCronAccessStateName, 4<<10, &state)
	if err != nil || !found {
		return found, err
	}
	if state.SchemaVersion != 1 {
		return false, fmt.Errorf("invalid FreeBSD cron access ownership state")
	}
	return true, nil
}

func secureFreeBSDCronDirectory() (*os.Root, error) {
	info, err := os.Lstat(freeBSDCronDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("unsafe FreeBSD cron directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return nil, fmt.Errorf("FreeBSD cron directory is not root-owned")
	}
	return os.OpenRoot(freeBSDCronDirectory)
}

func validateManagedFreeBSDCronAllow(root *os.Root) error {
	info, err := root.Lstat(freeBSDCronAllowName)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0600 || info.Size() != int64(len(freeBSDManagedCronAllow)) {
		return fmt.Errorf("FreeBSD cron allow file is not the exact SysWarden-owned file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return fmt.Errorf("FreeBSD cron allow file is not root-owned")
	}
	payload, err := root.ReadFile(freeBSDCronAllowName)
	if err != nil || !bytes.Equal(payload, freeBSDManagedCronAllow) {
		return fmt.Errorf("FreeBSD cron allow content changed after SysWarden created it")
	}
	if _, err := root.Lstat(freeBSDCronDenyName); !errors.Is(err, fs.ErrNotExist) {
		if err == nil {
			return fmt.Errorf("FreeBSD cron deny appeared after SysWarden captured an empty baseline")
		}
		return err
	}
	return nil
}

func validatePreservedFreeBSDCronAccess(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0022 != 0 || info.Size() > 1<<20 {
		return fmt.Errorf("unsafe operator-owned FreeBSD cron access file %s", name)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Errorf("operator-owned FreeBSD cron access file %s is not root-owned", name)
	}
	return nil
}

// EnsureFreeBSDCronAccess creates a root-only allow file only when neither
// operator-owned access file existed before SysWarden. Existing safe policy is
// preserved byte-for-byte and is never claimed as SysWarden-owned state.
func EnsureFreeBSDCronAccess() error {
	found, err := readFreeBSDCronAccessState()
	if err != nil {
		return err
	}
	root, err := secureFreeBSDCronDirectory()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if found {
		return validateManagedFreeBSDCronAllow(root)
	}
	operatorPolicy := false
	for _, name := range []string{freeBSDCronAllowName, freeBSDCronDenyName} {
		if err := validatePreservedFreeBSDCronAccess(root, name); err != nil {
			return err
		}
		if _, err := root.Lstat(name); err == nil {
			operatorPolicy = true
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if operatorPolicy {
		return nil
	}
	if err := writeFreeBSDOwnedState(freeBSDCronAccessStateName, freeBSDCronAccessState{SchemaVersion: 1}); err != nil {
		return err
	}
	file, err := root.OpenFile(
		freeBSDCronAllowName,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW,
		0600,
	)
	if err != nil {
		_ = removeFreeBSDOwnedState(freeBSDCronAccessStateName)
		return err
	}
	clean := false
	defer func() {
		_ = file.Close()
		if !clean {
			_ = root.Remove(freeBSDCronAllowName)
			_ = removeFreeBSDOwnedState(freeBSDCronAccessStateName)
		}
	}()
	if _, err := file.Write(freeBSDManagedCronAllow); err != nil {
		return err
	}
	if err := file.Chown(0, 0); err != nil {
		return err
	}
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	clean = true
	return file.Close()
}

// RestoreFreeBSDCronAccess removes only the exact file created by SysWarden.
// Operator changes cause a fail-closed refusal and are never overwritten.
func RestoreFreeBSDCronAccess() error {
	found, err := readFreeBSDCronAccessState()
	if err != nil || !found {
		return err
	}
	root, err := secureFreeBSDCronDirectory()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := validateManagedFreeBSDCronAllow(root); err != nil {
		return err
	}
	if err := root.Remove(freeBSDCronAllowName); err != nil {
		return err
	}
	return removeFreeBSDOwnedState(freeBSDCronAccessStateName)
}
