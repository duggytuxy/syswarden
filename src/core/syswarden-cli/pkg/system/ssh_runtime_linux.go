//go:build linux

package system

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const maxSSHConfigurationBytes = 1 << 20

type sshCommandExecutor struct {
	run    func(name string, args ...string) error
	output func(name string, args ...string) ([]byte, error)
}

type sshRestartTarget struct {
	name string
	args []string
}

type sshConfigurationSnapshot struct {
	info    fs.FileInfo
	content []byte
	digest  [sha256.Size]byte
	uid     int
	gid     int
}

type sshConfigurationTransaction struct {
	root        *os.Root
	name        string
	expectedUID uint32
	original    sshConfigurationSnapshot
	current     sshConfigurationSnapshot
	changed     bool
}

func sshConfigurationApplicable(
	configPath string,
	requestedPort string,
	daemonSignals []string,
	lookPath func(string) (string, error),
	expectedOwnerUID uint32,
) (bool, error) {
	if configPath == "" {
		return false, fmt.Errorf("SSH configuration path is empty")
	}
	if lookPath == nil {
		return false, fmt.Errorf("SSH executable resolver is missing")
	}
	if _, err := os.Lstat(configPath); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect SSH configuration: %w", err)
	}
	parentInfo, err := os.Lstat(filepath.Dir(configPath))
	if err == nil {
		if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("SSH configuration parent is not a real directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect SSH configuration parent: %w", err)
	}

	if strings.TrimSpace(requestedPort) != "" {
		return false, fmt.Errorf("SSH port is configured but %s is absent", configPath)
	}
	if executable, err := lookPath("sshd"); err == nil {
		return false, fmt.Errorf("SSH daemon executable %s exists but %s is absent", executable, configPath)
	} else if !errors.Is(err, exec.ErrNotFound) {
		return false, fmt.Errorf("resolve SSH daemon executable: %w", err)
	}
	for _, signalPath := range daemonSignals {
		if signalPath == "" {
			return false, fmt.Errorf("SSH daemon signal path is empty")
		}
		if signalInfo, err := os.Lstat(signalPath); err == nil {
			if filepath.Clean(signalPath) == filepath.Join(filepath.Dir(configPath), "sshd_config.d") {
				ignorable, inspectErr := ignorableEmptySSHDropInDirectory(signalPath, signalInfo, expectedOwnerUID)
				if inspectErr != nil {
					return false, fmt.Errorf("inspect SSH daemon component %s: %w", signalPath, inspectErr)
				}
				if ignorable {
					continue
				}
			}
			return false, fmt.Errorf("SSH daemon component %s exists but %s is absent", signalPath, configPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("inspect SSH daemon component %s: %w", signalPath, err)
		}
	}
	return false, nil
}

func ignorableEmptySSHDropInDirectory(path string, before fs.FileInfo, expectedOwnerUID uint32) (bool, error) {
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0022 != 0 {
		return false, nil
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("SSH drop-in directory ownership is unavailable")
	}
	if beforeStat.Uid != expectedOwnerUID {
		return false, nil
	}

	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = syscall.Close(fd)
		return false, fmt.Errorf("open SSH drop-in directory")
	}
	defer func() { _ = directory.Close() }()

	opened, err := directory.Stat()
	if err != nil {
		return false, err
	}
	if !opened.IsDir() || !os.SameFile(before, opened) || opened.Mode() != before.Mode() ||
		opened.Size() != before.Size() || !opened.ModTime().Equal(before.ModTime()) {
		return false, fmt.Errorf("SSH drop-in directory changed while opening")
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || openedStat.Uid != expectedOwnerUID {
		return false, fmt.Errorf("SSH drop-in directory ownership changed while opening")
	}

	names, readErr := directory.Readdirnames(1)
	if readErr == nil || len(names) != 0 {
		return false, nil
	}
	if !errors.Is(readErr, io.EOF) {
		return false, readErr
	}

	finalOpened, err := directory.Stat()
	if err != nil {
		return false, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return false, fmt.Errorf("reinspect SSH drop-in directory: %w", err)
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || !after.IsDir() || after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(opened, finalOpened) || !os.SameFile(finalOpened, after) ||
		finalOpened.Mode() != opened.Mode() || finalOpened.Size() != opened.Size() ||
		!finalOpened.ModTime().Equal(opened.ModTime()) || after.Mode() != finalOpened.Mode() ||
		after.Size() != finalOpened.Size() || !after.ModTime().Equal(finalOpened.ModTime()) ||
		afterStat.Uid != expectedOwnerUID {
		return false, fmt.Errorf("SSH drop-in directory changed while inspecting")
	}
	return true, nil
}

func captureSSHConfiguration(root *os.Root, name string, expectedUID uint32) (sshConfigurationSnapshot, error) {
	var snapshot sshConfigurationSnapshot
	pathInfo, err := root.Lstat(name)
	if err != nil {
		return snapshot, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return snapshot, fmt.Errorf("SSH configuration is not a real regular file")
	}
	if pathInfo.Mode().Perm()&0022 != 0 {
		return snapshot, fmt.Errorf("SSH configuration is writable by group or other")
	}
	pathStat, ok := pathInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return snapshot, fmt.Errorf("SSH configuration ownership is unavailable")
	}
	if pathStat.Uid != expectedUID {
		return snapshot, fmt.Errorf("SSH configuration has unexpected owner UID %d", pathStat.Uid)
	}
	if pathStat.Nlink != 1 {
		return snapshot, fmt.Errorf("SSH configuration must have exactly one hard link")
	}

	file, err := root.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return snapshot, err
	}
	before, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return snapshot, err
	}
	if !before.Mode().IsRegular() || !os.SameFile(pathInfo, before) {
		_ = file.Close()
		return snapshot, fmt.Errorf("SSH configuration changed while opening")
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maxSSHConfigurationBytes+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil {
		return snapshot, readErr
	}
	if statErr != nil {
		return snapshot, statErr
	}
	if closeErr != nil {
		return snapshot, closeErr
	}
	if len(content) > maxSSHConfigurationBytes {
		return snapshot, fmt.Errorf("SSH configuration exceeds %d bytes", maxSSHConfigurationBytes)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return snapshot, fmt.Errorf("SSH configuration changed while reading")
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || afterStat.Uid != expectedUID || afterStat.Nlink != 1 {
		return snapshot, fmt.Errorf("SSH configuration metadata changed while reading")
	}

	snapshot.info = after
	snapshot.content = content
	snapshot.digest = sha256.Sum256(content)
	snapshot.uid = int(afterStat.Uid)
	snapshot.gid = int(afterStat.Gid)
	return snapshot, nil
}

func beginSSHConfigurationTransaction(path string, expectedUID uint32) (*sshConfigurationTransaction, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("SSH configuration path must be canonical and absolute")
	}
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return nil, fmt.Errorf("SSH configuration path has no safe basename")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("open SSH configuration directory: %w", err)
	}
	snapshot, err := captureSSHConfiguration(root, name, expectedUID)
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("snapshot SSH configuration: %w", err)
	}
	return &sshConfigurationTransaction{
		root:        root,
		name:        name,
		expectedUID: expectedUID,
		original:    snapshot,
		current:     snapshot,
	}, nil
}

func (transaction *sshConfigurationTransaction) close() {
	_ = transaction.root.Close()
}

func sameSSHConfigurationSnapshot(expected, actual sshConfigurationSnapshot) bool {
	return os.SameFile(expected.info, actual.info) &&
		expected.info.Mode() == actual.info.Mode() &&
		expected.info.Size() == actual.info.Size() &&
		expected.info.ModTime().Equal(actual.info.ModTime()) &&
		expected.digest == actual.digest &&
		expected.uid == actual.uid && expected.gid == actual.gid
}

func (transaction *sshConfigurationTransaction) verifyCurrent() error {
	current, err := captureSSHConfiguration(transaction.root, transaction.name, transaction.expectedUID)
	if err != nil {
		return err
	}
	if !sameSSHConfigurationSnapshot(transaction.current, current) {
		return fmt.Errorf("SSH configuration changed during transaction")
	}
	return nil
}

func createSSHConfigurationStagingFile(root *os.Root, name string) (*os.File, string, error) {
	for range 128 {
		var random [16]byte
		if _, err := cryptorand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate SSH staging name: %w", err)
		}
		stagingName := "." + name + ".syswarden-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := root.OpenFile(stagingName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create SSH staging file: %w", err)
		}
		return file, stagingName, nil
	}
	return nil, "", fmt.Errorf("create SSH staging file: too many name collisions")
}

func syncSSHConfigurationDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

func (transaction *sshConfigurationTransaction) replace(content []byte) error {
	if err := transaction.verifyCurrent(); err != nil {
		return fmt.Errorf("verify SSH configuration before publication: %w", err)
	}
	file, stagingName, err := createSSHConfigurationStagingFile(transaction.root, transaction.name)
	if err != nil {
		return err
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
		if stagingName != "" {
			_ = transaction.root.Remove(stagingName)
		}
	}()
	if err := file.Chown(transaction.original.uid, transaction.original.gid); err != nil {
		return fmt.Errorf("preserve SSH configuration owner: %w", err)
	}
	if err := file.Chmod(transaction.original.info.Mode().Perm()); err != nil {
		return fmt.Errorf("preserve SSH configuration mode: %w", err)
	}
	written, err := file.Write(content)
	if err != nil {
		return fmt.Errorf("write SSH staging file: %w", err)
	}
	if written != len(content) {
		return fmt.Errorf("write SSH staging file: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync SSH staging file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close SSH staging file: %w", err)
	}
	file = nil
	if err := transaction.verifyCurrent(); err != nil {
		return fmt.Errorf("reverify SSH configuration before publication: %w", err)
	}
	staged, err := captureSSHConfiguration(transaction.root, stagingName, transaction.expectedUID)
	if err != nil {
		return fmt.Errorf("verify SSH staging file: %w", err)
	}
	if staged.digest != sha256.Sum256(content) {
		return fmt.Errorf("SSH staging content changed before publication")
	}
	if err := transaction.root.Rename(stagingName, transaction.name); err != nil {
		return fmt.Errorf("publish SSH configuration: %w", err)
	}
	stagingName = ""
	transaction.current = staged
	current, err := captureSSHConfiguration(transaction.root, transaction.name, transaction.expectedUID)
	if err != nil {
		return fmt.Errorf("verify published SSH configuration: %w", err)
	}
	if !sameSSHConfigurationSnapshot(staged, current) {
		return fmt.Errorf("SSH configuration changed during publication")
	}
	transaction.current = current
	if err := syncSSHConfigurationDirectory(transaction.root); err != nil {
		return fmt.Errorf("sync SSH configuration directory: %w", err)
	}
	return nil
}

func (transaction *sshConfigurationTransaction) publish(content []byte) error {
	before := transaction.current
	err := transaction.replace(content)
	if !sameSSHConfigurationSnapshot(before, transaction.current) {
		transaction.changed = true
	}
	return err
}

func (transaction *sshConfigurationTransaction) restore() error {
	if !transaction.changed {
		return nil
	}
	err := transaction.replace(transaction.original.content)
	if transaction.current.digest == transaction.original.digest &&
		transaction.current.uid == transaction.original.uid &&
		transaction.current.gid == transaction.original.gid &&
		transaction.current.info.Mode() == transaction.original.info.Mode() {
		transaction.changed = false
	}
	return err
}

func validateSSHPort(port string) (string, error) {
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return "", fmt.Errorf("invalid SSH port %q", port)
	}
	return port, nil
}

func effectiveSSHValues(output []byte, directive string) []string {
	values := make([]string, 0, 1)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.EqualFold(fields[0], directive) {
			values = append(values, strings.ToLower(fields[1]))
		}
	}
	return values
}

func effectiveSSHPort(output []byte) (string, error) {
	ports := effectiveSSHValues(output, "port")
	if len(ports) != 1 {
		return "", fmt.Errorf("sshd -T reported %d effective ports", len(ports))
	}
	return validateSSHPort(ports[0])
}

func verifyEffectiveSSHConfiguration(output []byte, expectedPort string) error {
	forwarding := effectiveSSHValues(output, "allowtcpforwarding")
	if len(forwarding) != 1 || forwarding[0] != "no" {
		return fmt.Errorf("sshd -T did not attest allowtcpforwarding no")
	}
	port, err := effectiveSSHPort(output)
	if err != nil {
		return err
	}
	if port != expectedPort {
		return fmt.Errorf("sshd -T reported port %s, expected %s", port, expectedPort)
	}
	return nil
}

func exactSystemdProperty(output []byte, property, unit string) (string, error) {
	value := strings.TrimSpace(string(output))
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("systemd returned an invalid %s for %s", property, unit)
	}
	return value, nil
}

func resolveSSHRestartTarget(alpine bool, executor sshCommandExecutor) (sshRestartTarget, error) {
	if alpine {
		return sshRestartTarget{name: "rc-service", args: []string{"sshd", "restart"}}, nil
	}

	candidates := []string{"ssh.service", "sshd.service"}
	loaded := make([]string, 0, len(candidates))
	for _, unit := range candidates {
		output, err := executor.output("systemctl", "show", "--property=LoadState", "--value", unit)
		if err != nil {
			return sshRestartTarget{}, fmt.Errorf("inspect systemd SSH unit %s: %w", unit, err)
		}
		state, err := exactSystemdProperty(output, "LoadState", unit)
		if err != nil {
			return sshRestartTarget{}, err
		}
		switch state {
		case "loaded":
			loaded = append(loaded, unit)
		case "not-found":
		default:
			return sshRestartTarget{}, fmt.Errorf("systemd SSH unit %s has unsupported LoadState %s", unit, state)
		}
	}
	if len(loaded) == 0 {
		return sshRestartTarget{}, fmt.Errorf("no loaded systemd SSH service unit")
	}
	if len(loaded) == 1 {
		return sshRestartTarget{name: "systemctl", args: []string{"restart", loaded[0]}}, nil
	}

	canonicalIDs := make([]string, 0, len(loaded))
	for _, unit := range loaded {
		output, err := executor.output("systemctl", "show", "--property=Id", "--value", unit)
		if err != nil {
			return sshRestartTarget{}, fmt.Errorf("resolve systemd SSH unit %s: %w", unit, err)
		}
		id, err := exactSystemdProperty(output, "Id", unit)
		if err != nil {
			return sshRestartTarget{}, err
		}
		canonicalIDs = append(canonicalIDs, id)
	}
	if canonicalIDs[0] != canonicalIDs[1] || (canonicalIDs[0] != "ssh.service" && canonicalIDs[0] != "sshd.service") {
		return sshRestartTarget{}, fmt.Errorf("ambiguous loaded systemd SSH service units")
	}
	return sshRestartTarget{name: "systemctl", args: []string{"restart", canonicalIDs[0]}}, nil
}

func restartSSHService(target sshRestartTarget, executor sshCommandExecutor) error {
	return executor.run(target.name, target.args...)
}

func rollbackSSHMutation(transaction *sshConfigurationTransaction, cause error) error {
	if !transaction.changed {
		return cause
	}
	if err := transaction.restore(); err != nil {
		return errors.Join(cause, fmt.Errorf("rollback SSH configuration: %w", err))
	}
	return cause
}

func configureSSHFile(path, requestedPort string, expectedUID uint32, alpine bool, managerState serviceManagerState, executor sshCommandExecutor) (string, error) {
	if executor.run == nil || executor.output == nil {
		return "", fmt.Errorf("SSH command executor is incomplete")
	}
	if managerState != serviceManagerActive && managerState != serviceManagerOffline {
		return "", fmt.Errorf("refusing SSH configuration with service-manager state %q", managerState)
	}
	transaction, err := beginSSHConfigurationTransaction(path, expectedUID)
	if err != nil {
		return "", err
	}
	defer transaction.close()

	port := requestedPort
	if port == "" {
		output, err := executor.output("sshd", "-T", "-f", path)
		if err != nil {
			return "", fmt.Errorf("discover effective SSH port: %w", err)
		}
		port, err = effectiveSSHPort(output)
		if err != nil {
			return "", fmt.Errorf("discover effective SSH port: %w", err)
		}
	} else {
		port, err = validateSSHPort(port)
		if err != nil {
			return "", err
		}
	}
	var restartTarget sshRestartTarget
	if managerState == serviceManagerActive {
		restartTarget, err = resolveSSHRestartTarget(alpine, executor)
		if err != nil {
			return "", err
		}
	}

	normalized := normalizeSSHForwarding(string(transaction.original.content))
	if normalized != string(transaction.original.content) {
		if err := transaction.publish([]byte(normalized)); err != nil {
			return "", rollbackSSHMutation(transaction, fmt.Errorf("publish SSH forwarding policy: %w", err))
		}
	}
	if err := executor.run("sshd", "-t", "-f", path); err != nil {
		return "", rollbackSSHMutation(transaction, fmt.Errorf("validate SSH configuration: %w", err))
	}
	effective, err := executor.output("sshd", "-T", "-f", path)
	if err != nil {
		return "", rollbackSSHMutation(transaction, fmt.Errorf("read effective SSH configuration: %w", err))
	}
	if err := verifyEffectiveSSHConfiguration(effective, port); err != nil {
		return "", rollbackSSHMutation(transaction, err)
	}
	if managerState == serviceManagerOffline {
		return port, nil
	}
	if err := restartSSHService(restartTarget, executor); err != nil {
		cause := fmt.Errorf("restart SSH service: %w", err)
		if !transaction.changed {
			return "", cause
		}
		if restoreErr := transaction.restore(); restoreErr != nil {
			return "", errors.Join(cause, fmt.Errorf("rollback SSH configuration: %w", restoreErr))
		}
		if validateErr := executor.run("sshd", "-t", "-f", path); validateErr != nil {
			return "", errors.Join(cause, fmt.Errorf("validate rolled-back SSH configuration: %w", validateErr))
		}
		if restartErr := restartSSHService(restartTarget, executor); restartErr != nil {
			return "", errors.Join(cause, fmt.Errorf("restart SSH service after rollback: %w", restartErr))
		}
		return "", cause
	}
	return port, nil
}
