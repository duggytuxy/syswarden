//go:build freebsd

package system

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"syswarden-cli/config"
)

const maxSSHConfigBytes = 4 << 20

var (
	freeBSDSSHDirectory = "/etc/ssh"
	freeBSDSSHConfig    = "sshd_config"
	freeBSDSSHConfigTmp = ".sshd_config.syswarden.tmp"
	freeBSDSSHBackup    = ".sshd_config.syswarden.rollback"
	freeBSDSSHRename    = func(root *os.Root, oldName, newName string) error {
		return root.Rename(oldName, newName)
	}
	freeBSDSSHRestart = func() error {
		return exec.Command("service", "sshd", "restart").Run()
	}
	freeBSDSSHValidate = func() error {
		return exec.Command("sshd", "-t", "-f", freeBSDSSHDirectory+"/"+freeBSDSSHConfigTmp).Run()
	}
	freeBSDSSHWritePrivateFile = writePrivateSSHFile
	freeBSDSSHSyncDirectory    = syncSSHDirectory
	freeBSDSSHExpectedOwner    = os.Geteuid
)

type freeBSDSSHConfigSnapshot struct {
	content []byte
	info    fs.FileInfo
	digest  [sha256.Size]byte
	mode    fs.FileMode
	uid     int
	gid     int
}

func readSafeFreeBSDSSHFile(root *os.Root, name string) (freeBSDSSHConfigSnapshot, error) {
	pathInfo, err := root.Lstat(name)
	if err != nil {
		return freeBSDSSHConfigSnapshot{}, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 ||
		pathInfo.Mode().Perm()&0022 != 0 || pathInfo.Size() > maxSSHConfigBytes {
		return freeBSDSSHConfigSnapshot{}, fmt.Errorf("sshd_config is not a bounded safe regular file")
	}
	stat, ok := pathInfo.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != freeBSDSSHExpectedOwner() {
		return freeBSDSSHConfigSnapshot{}, fmt.Errorf("sshd_config is not owned by root")
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return freeBSDSSHConfigSnapshot{}, err
	}
	defer func() { _ = file.Close() }()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) {
		return freeBSDSSHConfigSnapshot{}, fmt.Errorf("sshd_config changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxSSHConfigBytes+1))
	if err != nil {
		return freeBSDSSHConfigSnapshot{}, fmt.Errorf("read bounded sshd_config: %w", err)
	}
	if len(content) > maxSSHConfigBytes || int64(len(content)) != openedInfo.Size() {
		return freeBSDSSHConfigSnapshot{}, fmt.Errorf("sshd_config changed or exceeds the size bound")
	}
	return freeBSDSSHConfigSnapshot{
		content: content,
		info:    openedInfo,
		digest:  sha256.Sum256(content),
		mode:    openedInfo.Mode().Perm(),
		uid:     int(stat.Uid),
		gid:     int(stat.Gid),
	}, nil
}

func sameFreeBSDSSHConfig(left, right freeBSDSSHConfigSnapshot) bool {
	return os.SameFile(left.info, right.info) && left.info.Size() == right.info.Size() &&
		left.mode == right.mode && left.uid == right.uid && left.gid == right.gid &&
		left.digest == right.digest
}

func writePrivateSSHFile(root *os.Root, name string, content []byte, mode fs.FileMode, uid, gid int) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	clean := false
	defer func() {
		_ = file.Close()
		if !clean {
			_ = root.Remove(name)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if err := file.Chown(uid, gid); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	clean = true
	return nil
}

func syncSSHDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

// ConfigureFreeBSDSSHDirectives applies the approved directive set through a
// validated compare-and-swap transaction and restarts sshd with safe rollback.
func ConfigureFreeBSDSSHDirectives(directives map[string]string) error {
	root, err := os.OpenRoot(freeBSDSSHDirectory)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	original, err := readSafeFreeBSDSSHFile(root, freeBSDSSHConfig)
	if err != nil {
		return err
	}
	if _, err := root.Lstat(freeBSDSSHConfigTmp); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("temporary sshd_config path is not clean")
	}
	if _, err := root.Lstat(freeBSDSSHBackup); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("rollback sshd_config path is not clean")
	}
	originalContent := string(original.content)
	normalized, err := normalizeSSHDirectives(originalContent, directives)
	if err != nil {
		return err
	}
	// A byte-identical result has no transaction to commit and must not restart
	// sshd, which could disrupt the qualification transport itself.
	if normalized == originalContent {
		return nil
	}
	updated := []byte(normalized)
	if err := freeBSDSSHWritePrivateFile(root, freeBSDSSHBackup, original.content, original.mode, original.uid, original.gid); err != nil {
		return fmt.Errorf("create sshd_config rollback snapshot: %w", err)
	}
	backupPresent := true
	preserveBackup := false
	defer func() {
		if backupPresent && !preserveBackup {
			_ = root.Remove(freeBSDSSHBackup)
		}
		_ = root.Remove(freeBSDSSHConfigTmp)
	}()
	if err := freeBSDSSHWritePrivateFile(root, freeBSDSSHConfigTmp, updated, original.mode, original.uid, original.gid); err != nil {
		return fmt.Errorf("create candidate sshd_config: %w", err)
	}
	if err := freeBSDSSHValidate(); err != nil {
		return fmt.Errorf("candidate sshd_config validation failed: %w", err)
	}
	current, err := readSafeFreeBSDSSHFile(root, freeBSDSSHConfig)
	if err != nil || !sameFreeBSDSSHConfig(original, current) {
		return fmt.Errorf("sshd_config changed before atomic replacement")
	}
	candidate, err := readSafeFreeBSDSSHFile(root, freeBSDSSHConfigTmp)
	if err != nil {
		return fmt.Errorf("inspect candidate sshd_config: %w", err)
	}
	if err := freeBSDSSHRename(root, freeBSDSSHConfigTmp, freeBSDSSHConfig); err != nil {
		return fmt.Errorf("replace sshd_config atomically: %w", err)
	}
	installed, err := readSafeFreeBSDSSHFile(root, freeBSDSSHConfig)
	if err != nil || !sameFreeBSDSSHConfig(candidate, installed) {
		preserveBackup = true
		return fmt.Errorf("installed sshd_config does not match the validated candidate")
	}
	rollback := func(cause error) error {
		current, currentErr := readSafeFreeBSDSSHFile(root, freeBSDSSHConfig)
		if currentErr != nil || !sameFreeBSDSSHConfig(installed, current) {
			preserveBackup = true
			return fmt.Errorf("%v; concurrent sshd_config edit detected, rollback snapshot preserved", cause)
		}
		if rollbackErr := freeBSDSSHRename(root, freeBSDSSHBackup, freeBSDSSHConfig); rollbackErr != nil {
			preserveBackup = true
			return fmt.Errorf("%v; rollback failed and snapshot was preserved: %w", cause, rollbackErr)
		}
		backupPresent = false
		if syncErr := freeBSDSSHSyncDirectory(root); syncErr != nil {
			return fmt.Errorf("%v; rollback directory sync failed: %w", cause, syncErr)
		}
		if restartErr := freeBSDSSHRestart(); restartErr != nil {
			return errors.Join(cause, fmt.Errorf("restart sshd after rollback: %w", restartErr))
		}
		return cause
	}
	if err := freeBSDSSHSyncDirectory(root); err != nil {
		return rollback(fmt.Errorf("sync SSH configuration directory: %w", err))
	}
	if err := freeBSDSSHRestart(); err != nil {
		return rollback(fmt.Errorf("restart sshd after hardening: %w", err))
	}
	if err := root.Remove(freeBSDSSHBackup); err != nil {
		return fmt.Errorf("remove sshd_config rollback snapshot: %w", err)
	}
	backupPresent = false
	return freeBSDSSHSyncDirectory(root)
}

// ConfigureSSH configures the SSH daemon securely on FreeBSD.
func ConfigureSSH() error {
	fmt.Println("[INFO] Configuring SSH...")
	port := config.GlobalConfig.SSHPort
	if port == "" {
		if output, err := exec.Command("sshd", "-T").Output(); err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && strings.EqualFold(fields[0], "port") {
					port = fields[1]
					break
				}
			}
		}
	}
	if port == "" {
		port = "22"
	}
	if _, err := os.Stat(freeBSDSSHDirectory + "/" + freeBSDSSHConfig); err == nil {
		fmt.Println("[INFO] Ensuring SSH TCP Forwarding is strictly DISABLED...")
		if err := ConfigureFreeBSDSSHDirectives(map[string]string{"AllowTcpForwarding": "no"}); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	config.GlobalConfig.SSHPort = port
	fmt.Printf("[INFO] SSH Port configured as: %s\n", port)
	return nil
}
