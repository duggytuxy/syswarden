//go:build linux

package security

import (
	"context"
	"crypto/sha256"
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
	"time"
)

const hardeningMaximumFileSize = 4 << 20

type hardeningExecutor struct {
	run    func(name string, args ...string) error
	output func(name string, args ...string) ([]byte, error)
	status func(name string, args ...string) ([]byte, int, error)
}

type hardeningHost struct {
	root                string
	expectedRootUID     int
	expectedRootGID     int
	executor            hardeningExecutor
	executionProbe      func() (hardeningExecutionDecision, error)
	capabilityProbe     func(uint) (bool, error)
	processProbe        func(string) (bool, error)
	systemdRuntimeProbe func() (bool, error)
	profileFlagsProbe   func(*os.File) (int, error)
	profileFlagsSet     func(*os.File, int) error
	profileChmod        func(*os.File, fs.FileMode) error
	directorySync       func(*os.Root) error
}

type hardeningExecutionState uint8

const (
	hardeningExecutionActive hardeningExecutionState = iota
	hardeningExecutionDeferred
	hardeningExecutionNotApplicable
)

type hardeningExecutionDecision struct {
	state           hardeningExecutionState
	packageInstall  bool
	rootUIDRemapped bool
	manager         string
	reason          string
}

type hardeningRuntimeEvidence struct {
	packageInstall bool
	effectiveUID   int
	uidMap         string
	initName       string
	initExecutable string
	systemdActive  bool
	openRCActive   bool
}

type hardeningFileSnapshot struct {
	existed  bool
	content  []byte
	mode     fs.FileMode
	identity securityFileIdentity
}

func productionHardeningHost() hardeningHost {
	return hardeningHost{
		root:                "/",
		expectedRootUID:     0,
		expectedRootGID:     0,
		executionProbe:      productionHardeningExecutionDecision,
		capabilityProbe:     productionEffectiveCapability,
		processProbe:        productionProcessNamedRunning,
		systemdRuntimeProbe: productionSystemdRuntimeActive,
		profileFlagsProbe:   productionProfileFlags,
		profileFlagsSet:     productionSetProfileFlags,
		profileChmod:        func(file *os.File, mode fs.FileMode) error { return file.Chmod(mode) },
		directorySync:       syncSecurityDirectory,
		executor: hardeningExecutor{
			run: func(name string, args ...string) error {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				command := exec.CommandContext(ctx, name, args...) // #nosec G204 -- callers constrain executable names and arguments
				output, err := command.CombinedOutput()
				if err != nil {
					message := strings.TrimSpace(string(output))
					if len(message) > 1024 {
						message = message[:1024]
					}
					if message != "" {
						return fmt.Errorf("%s failed: %w: %s", name, err, message)
					}
					return fmt.Errorf("%s failed: %w", name, err)
				}
				return nil
			},
			output: func(name string, args ...string) ([]byte, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				output, err := exec.CommandContext(ctx, name, args...).Output() // #nosec G204 -- callers constrain executable names and arguments
				if err != nil {
					return nil, fmt.Errorf("%s failed: %w", name, err)
				}
				if len(output) > hardeningMaximumFileSize {
					return nil, fmt.Errorf("%s output exceeds %d bytes", name, hardeningMaximumFileSize)
				}
				return output, nil
			},
			status: func(name string, args ...string) ([]byte, int, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				output, err := exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- callers constrain executable names and arguments
				if len(output) > hardeningMaximumFileSize {
					return nil, 0, fmt.Errorf("%s output exceeds %d bytes", name, hardeningMaximumFileSize)
				}
				if err == nil {
					return output, 0, nil
				}
				var exitError *exec.ExitError
				if errors.As(err, &exitError) {
					return output, exitError.ExitCode(), nil
				}
				return output, 0, fmt.Errorf("%s status probe failed: %w", name, err)
			},
		},
	}
}

func (host hardeningHost) hasEffectiveCapability(capability uint) (bool, error) {
	if host.capabilityProbe == nil {
		return true, nil
	}
	return host.capabilityProbe(capability)
}

func (host hardeningHost) processNamedRunning(name string) (bool, error) {
	if host.processProbe == nil {
		return false, nil
	}
	return host.processProbe(name)
}

func productionEffectiveCapability(capability uint) (bool, error) {
	if capability >= 64 {
		return false, fmt.Errorf("capability index %d is outside the supported mask", capability)
	}
	status, err := readBoundedProcFile(fmt.Sprintf("/proc/%d/status", os.Getpid()), 64<<10)
	if err != nil {
		return false, fmt.Errorf("read effective capabilities: %w", err)
	}
	var encoded string
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "CapEff:" {
			if encoded != "" {
				return false, fmt.Errorf("process status contains multiple CapEff values")
			}
			encoded = fields[1]
		}
	}
	if encoded == "" {
		return false, fmt.Errorf("process status does not contain CapEff")
	}
	mask, err := strconv.ParseUint(encoded, 16, 64)
	if err != nil {
		return false, fmt.Errorf("parse effective capability mask: %w", err)
	}
	return mask&(uint64(1)<<capability) != 0, nil
}

func productionProcessNamedRunning(name string) (bool, error) {
	if name == "" || strings.ContainsAny(name, "/\x00\r\n") {
		return false, fmt.Errorf("process name is invalid")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, fmt.Errorf("enumerate processes: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.ParseUint(entry.Name(), 10, 31); err != nil {
			continue
		}
		comm, err := readBoundedProcFile(filepath.Join("/proc", entry.Name(), "comm"), 256)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("inspect process %s: %w", entry.Name(), err)
		}
		commName := strings.TrimSpace(string(comm))
		executable, executableErr := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if errors.Is(executableErr, fs.ErrNotExist) {
			if commName == name {
				return false, fmt.Errorf("process %s has matching name but no attestable executable", entry.Name())
			}
			continue
		}
		if executableErr != nil {
			return false, fmt.Errorf("inspect process %s executable: %w", entry.Name(), executableErr)
		}
		if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable || strings.HasSuffix(executable, " (deleted)") {
			return false, fmt.Errorf("process %s has untrusted executable identity", entry.Name())
		}
		executableName := filepath.Base(executable)
		if commName == name || executableName == name {
			if commName != name || executableName != name {
				return false, fmt.Errorf("process %s name and executable disagree for %s", entry.Name(), name)
			}
			return true, nil
		}
	}
	return false, nil
}

func (host hardeningHost) executionDecision() (hardeningExecutionDecision, error) {
	if host.executionProbe == nil {
		return hardeningExecutionDecision{state: hardeningExecutionActive}, nil
	}
	return host.executionProbe()
}

func hardeningKernelRuntimeApplicable(host hardeningHost, control string) (bool, string, error) {
	decision, err := host.executionDecision()
	if err != nil {
		return false, "", fmt.Errorf("classify %s runtime context: %w", control, err)
	}
	if decision.rootUIDRemapped {
		return false, "root UID is remapped, so the kernel belongs to a parent namespace", nil
	}
	switch decision.state {
	case hardeningExecutionActive:
		return true, "", nil
	case hardeningExecutionNotApplicable:
		return false, decision.reason, nil
	case hardeningExecutionDeferred:
		return false, "", fmt.Errorf("%s runtime activation cannot be deferred without an attested convergence path", control)
	default:
		return false, "", fmt.Errorf("%s runtime context has unknown state %d", control, decision.state)
	}
}

func reportHardeningRuntimeNotApplicable(control, reason string) {
	fmt.Printf(" -> %s runtime mutation is not applicable: %s. Persistent policy was written and attested; no current runtime enforcement is claimed.\n", control, reason)
}

func productionHardeningExecutionDecision() (hardeningExecutionDecision, error) {
	packageInstall := os.Getenv("SYSWARDEN_PKG_INSTALL") == "1"
	if !packageInstall {
		return hardeningExecutionDecision{state: hardeningExecutionActive}, nil
	}

	uidMap, err := readBoundedProcFile(fmt.Sprintf("/proc/%d/uid_map", os.Getpid()), 4096)
	if err != nil {
		return hardeningExecutionDecision{}, fmt.Errorf("read package-hook user namespace map: %w", err)
	}
	initNameBytes, err := readBoundedProcFile("/proc/1/comm", 256)
	if err != nil {
		return hardeningExecutionDecision{}, fmt.Errorf("read package-hook PID 1 identity: %w", err)
	}
	initExecutable, err := os.Readlink("/proc/1/exe")
	if err != nil {
		return hardeningExecutionDecision{}, fmt.Errorf("read package-hook PID 1 executable: %w", err)
	}
	systemdParent, err := inspectRuntimeDirectory("/run/systemd", 0)
	if err != nil {
		return hardeningExecutionDecision{}, err
	}
	systemdActive := false
	if systemdParent {
		systemdActive, err = inspectRuntimeDirectory("/run/systemd/system", 0)
		if err != nil {
			return hardeningExecutionDecision{}, err
		}
	}
	openRCParent, err := inspectRuntimeDirectory("/run/openrc", 0)
	if err != nil {
		return hardeningExecutionDecision{}, err
	}
	openRCActive := false
	if openRCParent {
		openRCActive, err = inspectRuntimeFile("/run/openrc/softlevel", 0)
		if err != nil {
			return hardeningExecutionDecision{}, err
		}
	}
	return classifyHardeningRuntime(hardeningRuntimeEvidence{
		packageInstall: true,
		effectiveUID:   os.Geteuid(),
		uidMap:         string(uidMap),
		initName:       strings.TrimSpace(string(initNameBytes)),
		initExecutable: initExecutable,
		systemdActive:  systemdActive,
		openRCActive:   openRCActive,
	})
}

func productionSystemdRuntimeActive() (bool, error) {
	parent, err := inspectRuntimeDirectory("/run/systemd", 0)
	if err != nil {
		return false, err
	}
	marker := false
	if parent {
		marker, err = inspectRuntimeDirectory("/run/systemd/system", 0)
		if err != nil {
			return false, err
		}
	}
	name, err := readBoundedProcFile("/proc/1/comm", 256)
	if err != nil {
		return false, fmt.Errorf("read PID 1 name for systemd runtime attestation: %w", err)
	}
	executable, err := os.Readlink("/proc/1/exe")
	if err != nil {
		return false, fmt.Errorf("read PID 1 executable for systemd runtime attestation: %w", err)
	}
	pidOne := strings.TrimSpace(string(name)) == "systemd" &&
		(executable == "/usr/lib/systemd/systemd" || executable == "/lib/systemd/systemd")
	if marker != pidOne {
		return false, fmt.Errorf("systemd runtime marker and PID 1 identity disagree")
	}
	return marker, nil
}

func readBoundedProcFile(path string, maximum int64) ([]byte, error) {
	if maximum <= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.HasPrefix(path, "/proc/") {
		return nil, fmt.Errorf("proc path or read bound is invalid: %q", path)
	}
	root, err := os.OpenRoot("/proc")
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	file, err := root.Open(strings.TrimPrefix(path, "/proc/"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maximum)
	}
	return content, nil
}

func inspectRuntimeDirectory(path string, expectedUID uint32) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect runtime directory %s: %w", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return false, fmt.Errorf("runtime marker is not a real directory: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID {
		return false, fmt.Errorf("runtime directory is not owned by root: %s", path)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("open runtime directory %s: %w", path, err)
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = syscall.Close(fd)
		return false, fmt.Errorf("open runtime directory %s", path)
	}
	opened, statErr := directory.Stat()
	closeErr := directory.Close()
	if statErr != nil {
		return false, fmt.Errorf("attest runtime directory %s: %w", path, statErr)
	}
	if closeErr != nil {
		return false, fmt.Errorf("close runtime directory %s: %w", path, closeErr)
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !opened.IsDir() || !os.SameFile(info, opened) || opened.Mode() != info.Mode() ||
		!ok || openedStat.Uid != expectedUID {
		return false, fmt.Errorf("runtime directory changed while opening: %s", path)
	}
	return true, nil
}

func inspectRuntimeFile(path string, expectedUID uint32) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect runtime file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return false, fmt.Errorf("runtime marker is not a real regular file: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID || stat.Nlink != 1 {
		return false, fmt.Errorf("runtime file has unsafe ownership or links: %s", path)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("open runtime file %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return false, fmt.Errorf("open runtime file %s", path)
	}
	opened, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil {
		return false, fmt.Errorf("attest runtime file %s: %w", path, statErr)
	}
	if closeErr != nil {
		return false, fmt.Errorf("close runtime file %s: %w", path, closeErr)
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Mode() != info.Mode() ||
		!ok || openedStat.Uid != expectedUID || openedStat.Nlink != 1 {
		return false, fmt.Errorf("runtime file changed while opening: %s", path)
	}
	return true, nil
}

func classifyHardeningRuntime(evidence hardeningRuntimeEvidence) (hardeningExecutionDecision, error) {
	if !evidence.packageInstall {
		return hardeningExecutionDecision{state: hardeningExecutionActive}, nil
	}
	if evidence.effectiveUID != 0 {
		return hardeningExecutionDecision{}, fmt.Errorf("package hardening hook effective UID is %d, want 0", evidence.effectiveUID)
	}
	rootless, err := rootUIDIsRemapped(evidence.uidMap)
	if err != nil {
		return hardeningExecutionDecision{}, fmt.Errorf("validate package-hook user namespace map: %w", err)
	}
	initName := strings.TrimSpace(evidence.initName)
	initExecutable := strings.TrimSpace(evidence.initExecutable)
	if initName == "" || strings.ContainsAny(initName, "\r\n") || !filepath.IsAbs(initExecutable) ||
		filepath.Clean(initExecutable) != initExecutable || strings.ContainsAny(initExecutable, "\r\n") {
		return hardeningExecutionDecision{}, fmt.Errorf("package-hook PID 1 identity is invalid")
	}
	systemdPID1 := initName == "systemd" &&
		(initExecutable == "/usr/lib/systemd/systemd" || initExecutable == "/lib/systemd/systemd")
	openRCPID1 := (initName == "init" || initName == "openrc-init" || initName == "openrc") &&
		(initExecutable == "/sbin/openrc-init" || initExecutable == "/bin/busybox" || initExecutable == "/usr/bin/busybox")
	if evidence.systemdActive && evidence.openRCActive {
		return hardeningExecutionDecision{}, fmt.Errorf("systemd and OpenRC runtime markers are both active")
	}
	if evidence.systemdActive != systemdPID1 {
		return hardeningExecutionDecision{}, fmt.Errorf("systemd runtime marker and PID 1 identity disagree")
	}
	if evidence.openRCActive != openRCPID1 {
		return hardeningExecutionDecision{}, fmt.Errorf("OpenRC runtime marker and PID 1 identity disagree")
	}
	decision := hardeningExecutionDecision{
		state:           hardeningExecutionActive,
		packageInstall:  true,
		rootUIDRemapped: rootless,
	}
	if evidence.systemdActive {
		decision.manager = "systemd"
	}
	if evidence.openRCActive {
		decision.manager = "openrc"
	}
	if evidence.systemdActive || evidence.openRCActive {
		return decision, nil
	}
	return hardeningExecutionDecision{
		state:           hardeningExecutionNotApplicable,
		packageInstall:  true,
		rootUIDRemapped: rootless,
		reason:          "package hook has no active systemd or OpenRC init",
	}, nil
}

func rootUIDIsRemapped(uidMap string) (bool, error) {
	foundRoot := false
	rootRemapped := false
	for lineNumber, raw := range strings.Split(uidMap, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return false, fmt.Errorf("malformed uid_map line %d", lineNumber+1)
		}
		inside, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			return false, fmt.Errorf("invalid inside UID on uid_map line %d", lineNumber+1)
		}
		outside, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return false, fmt.Errorf("invalid outside UID on uid_map line %d", lineNumber+1)
		}
		length, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil || length == 0 {
			return false, fmt.Errorf("invalid range length on uid_map line %d", lineNumber+1)
		}
		if inside == 0 {
			if foundRoot {
				return false, fmt.Errorf("uid_map contains multiple root mappings")
			}
			foundRoot = true
			rootRemapped = outside != 0
		}
	}
	if !foundRoot {
		return false, fmt.Errorf("uid_map does not map container UID 0")
	}
	return rootRemapped, nil
}

func (host hardeningHost) path(logical string) (string, error) {
	if !filepath.IsAbs(logical) || filepath.Clean(logical) != logical {
		return "", fmt.Errorf("hardening path must be canonical and absolute: %q", logical)
	}
	root := filepath.Clean(host.root)
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("hardening root must be absolute: %q", host.root)
	}
	if root == "/" {
		return logical, nil
	}
	physical := filepath.Join(root, strings.TrimPrefix(logical, "/"))
	if physical != root && !strings.HasPrefix(physical, root+string(filepath.Separator)) {
		return "", fmt.Errorf("hardening path escapes root: %q", logical)
	}
	return physical, nil
}

func secureEnsureDirectory(path string, mode fs.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("hardening directory must be canonical and absolute: %q", path)
	}
	if mode.Perm() == 0 || mode != mode.Perm() {
		return fmt.Errorf("hardening directory mode must contain permissions only: %v", mode)
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return fmt.Errorf("open filesystem root: %w", err)
	}
	defer func() { _ = root.Close() }()
	current := root
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" {
			continue
		}
		info, inspectErr := current.Lstat(component)
		if errors.Is(inspectErr, fs.ErrNotExist) {
			if err := current.Mkdir(component, mode); err != nil && !errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("create hardening directory %s: %w", path, err)
			}
			info, inspectErr = current.Lstat(component)
		}
		if inspectErr != nil {
			return fmt.Errorf("inspect hardening directory %s: %w", path, inspectErr)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("hardening directory component is not a real directory: %s", component)
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			return fmt.Errorf("open hardening directory component %s: %w", component, err)
		}
		openedInfo, err := next.Stat(".")
		if err != nil || !os.SameFile(info, openedInfo) {
			_ = next.Close()
			return fmt.Errorf("hardening directory component changed while opening: %s", component)
		}
		if current != root {
			_ = current.Close()
		}
		current = next
	}
	if current != root {
		return current.Close()
	}
	return nil
}

func validateHardeningDirectoryInfo(path string, info fs.FileInfo, expectedUID, expectedGID int) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("hardening policy directory is not a real directory: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != expectedUID || int(stat.Gid) != expectedGID {
		return fmt.Errorf("hardening policy directory has unsafe ownership: %s", path)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("hardening policy directory is group/world writable: %s", path)
	}
	return nil
}

func (host hardeningHost) verifyHardeningDirectoryChain(directory string) error {
	rootPath := filepath.Clean(host.root)
	relative, err := filepath.Rel(rootPath, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("hardening policy directory escapes root: %s", directory)
	}
	rootInfo, err := os.Lstat(rootPath)
	if err != nil {
		return fmt.Errorf("inspect hardening policy root: %w", err)
	}
	if err := validateHardeningDirectoryInfo(rootPath, rootInfo, host.expectedRootUID, host.expectedRootGID); err != nil {
		return err
	}
	current, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open hardening policy root: %w", err)
	}
	openedRoot, err := current.Stat(".")
	if err != nil || !os.SameFile(rootInfo, openedRoot) || openedRoot.Mode() != rootInfo.Mode() {
		_ = current.Close()
		return fmt.Errorf("hardening policy root changed while opening: %s", rootPath)
	}
	if relative == "." {
		return current.Close()
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		info, err := current.Lstat(component)
		if err != nil {
			_ = current.Close()
			return fmt.Errorf("inspect hardening policy directory component %s: %w", component, err)
		}
		componentPath := filepath.Join(rootPath, component)
		if err := validateHardeningDirectoryInfo(componentPath, info, host.expectedRootUID, host.expectedRootGID); err != nil {
			_ = current.Close()
			return err
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return fmt.Errorf("open hardening policy directory component %s: %w", component, err)
		}
		opened, statErr := next.Stat(".")
		if statErr != nil || !os.SameFile(info, opened) || opened.Mode() != info.Mode() {
			_ = next.Close()
			_ = current.Close()
			return fmt.Errorf("hardening policy directory component changed while opening: %s", component)
		}
		if err := validateHardeningDirectoryInfo(componentPath, opened, host.expectedRootUID, host.expectedRootGID); err != nil {
			_ = next.Close()
			_ = current.Close()
			return err
		}
		_ = current.Close()
		current = next
		rootPath = componentPath
	}
	return current.Close()
}

func (host hardeningHost) ensureHardeningPolicyParent(logical string, mode fs.FileMode) error {
	physical, err := host.path(logical)
	if err != nil {
		return err
	}
	directory := filepath.Dir(physical)
	rootPath := filepath.Clean(host.root)
	relative, err := filepath.Rel(rootPath, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("hardening policy directory escapes root: %s", directory)
	}
	rootInfo, err := os.Lstat(rootPath)
	if err != nil {
		return fmt.Errorf("inspect hardening policy root: %w", err)
	}
	if err := validateHardeningDirectoryInfo(rootPath, rootInfo, host.expectedRootUID, host.expectedRootGID); err != nil {
		return err
	}
	current, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open hardening policy root: %w", err)
	}
	openedRoot, err := current.Stat(".")
	if err != nil || !os.SameFile(rootInfo, openedRoot) || openedRoot.Mode() != rootInfo.Mode() {
		_ = current.Close()
		return fmt.Errorf("hardening policy root changed while opening: %s", rootPath)
	}
	if relative == "." {
		return current.Close()
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		componentPath := filepath.Join(rootPath, component)
		info, inspectErr := current.Lstat(component)
		if errors.Is(inspectErr, fs.ErrNotExist) {
			if err := current.Mkdir(component, mode); err != nil && !errors.Is(err, fs.ErrExist) {
				_ = current.Close()
				return fmt.Errorf("create hardening policy directory %s: %w", componentPath, err)
			}
			info, inspectErr = current.Lstat(component)
		}
		if inspectErr != nil {
			_ = current.Close()
			return fmt.Errorf("inspect hardening policy directory component %s: %w", component, inspectErr)
		}
		if err := validateHardeningDirectoryInfo(componentPath, info, host.expectedRootUID, host.expectedRootGID); err != nil {
			_ = current.Close()
			return err
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return fmt.Errorf("open hardening policy directory component %s: %w", component, err)
		}
		opened, statErr := next.Stat(".")
		if statErr != nil || !os.SameFile(info, opened) || opened.Mode() != info.Mode() {
			_ = next.Close()
			_ = current.Close()
			return fmt.Errorf("hardening policy directory component changed while opening: %s", component)
		}
		if err := validateHardeningDirectoryInfo(componentPath, opened, host.expectedRootUID, host.expectedRootGID); err != nil {
			_ = next.Close()
			_ = current.Close()
			return err
		}
		_ = current.Close()
		current = next
		rootPath = componentPath
	}
	return current.Close()
}

func (host hardeningHost) target(logical string, createParent bool) (securityFileTarget, error) {
	physical, err := host.path(logical)
	if err != nil {
		return securityFileTarget{}, err
	}
	directory := filepath.Dir(physical)
	if createParent {
		if err := secureEnsureDirectory(directory, 0750); err != nil {
			return securityFileTarget{}, err
		}
	}
	return securityFileTarget{directory: directory, name: filepath.Base(physical)}, nil
}

func (host hardeningHost) verifyHardeningPolicyParent(logical string) error {
	physical, err := host.path(logical)
	if err != nil {
		return err
	}
	return host.verifyHardeningDirectoryChain(filepath.Dir(physical))
}

func (host hardeningHost) snapshot(logical string) (hardeningFileSnapshot, error) {
	target, err := host.target(logical, false)
	if err != nil {
		return hardeningFileSnapshot{}, err
	}
	root, err := openSecurityDirectory(target)
	if err != nil {
		return hardeningFileSnapshot{}, err
	}
	defer func() { _ = root.Close() }()
	pathInfo, err := root.Lstat(target.name)
	if errors.Is(err, fs.ErrNotExist) {
		return hardeningFileSnapshot{}, nil
	}
	if err != nil {
		return hardeningFileSnapshot{}, fmt.Errorf("inspect hardening file %s: %w", logical, err)
	}
	if !pathInfo.Mode().IsRegular() {
		return hardeningFileSnapshot{}, fmt.Errorf("hardening file is not regular: %s", logical)
	}
	if stat, ok := pathInfo.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return hardeningFileSnapshot{}, fmt.Errorf("hardening file must have exactly one link: %s", logical)
	}
	file, err := root.OpenFile(target.name, os.O_RDONLY, 0)
	if err != nil {
		return hardeningFileSnapshot{}, fmt.Errorf("open hardening file %s: %w", logical, err)
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || !os.SameFile(pathInfo, before) {
		return hardeningFileSnapshot{}, fmt.Errorf("hardening file changed while opening: %s", logical)
	}
	content, err := io.ReadAll(io.LimitReader(file, hardeningMaximumFileSize+1))
	if err != nil {
		return hardeningFileSnapshot{}, fmt.Errorf("read hardening file %s: %w", logical, err)
	}
	if len(content) > hardeningMaximumFileSize {
		return hardeningFileSnapshot{}, fmt.Errorf("hardening file exceeds %d bytes: %s", hardeningMaximumFileSize, logical)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return hardeningFileSnapshot{}, fmt.Errorf("hardening file changed while reading: %s", logical)
	}
	digest := sha256.Sum256(content)
	identity := securityFileIdentity{info: after, digest: digest}
	if stat, ok := after.Sys().(*syscall.Stat_t); ok {
		identity.uid = int(stat.Uid)
		identity.gid = int(stat.Gid)
		identity.ownerKnown = true
	}
	return hardeningFileSnapshot{existed: true, content: content, mode: before.Mode().Perm(), identity: identity}, nil
}

func (host hardeningHost) write(logical string, content []byte, mode fs.FileMode) error {
	if err := host.ensureHardeningPolicyParent(logical, 0750); err != nil {
		return err
	}
	snapshot, err := host.snapshot(logical)
	if err != nil {
		return err
	}
	return host.writeExpected(logical, content, mode, snapshot)
}

func (host hardeningHost) writeExpected(logical string, content []byte, mode fs.FileMode, expected hardeningFileSnapshot) error {
	if err := host.ensureHardeningPolicyParent(logical, 0750); err != nil {
		return err
	}
	target, err := host.target(logical, false)
	if err != nil {
		return err
	}
	expectedExists := expected.existed
	var identity *securityFileIdentity
	if expected.existed {
		identity = &expected.identity
	}
	desiredOwner := &securityFileOwner{uid: host.expectedRootUID, gid: host.expectedRootGID}
	if err := rewriteSecurityTargetExpectedStateOwned(target, content, mode, nil, identity, &expectedExists, desiredOwner, nil); err != nil {
		return err
	}
	current, err := host.snapshot(logical)
	if err == nil && hardeningSnapshotMatches(current, content, mode, desiredOwner.uid, desiredOwner.gid) {
		return nil
	}
	if err == nil {
		err = fmt.Errorf("hardening file ownership or content attestation failed: %s", logical)
	}
	return errors.Join(err, host.restore(logical, expected, content))
}

func hardeningSnapshotMatches(snapshot hardeningFileSnapshot, content []byte, mode fs.FileMode, uid, gid int) bool {
	return snapshot.existed && string(snapshot.content) == string(content) && snapshot.mode == mode.Perm() &&
		snapshot.identity.ownerKnown && snapshot.identity.uid == uid && snapshot.identity.gid == gid
}

func (host hardeningHost) removeExpected(logical string, expected []byte) error {
	if err := host.verifyHardeningPolicyParent(logical); err != nil {
		return err
	}
	target, err := host.target(logical, false)
	if err != nil {
		return err
	}
	root, err := openSecurityDirectory(target)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	identity, existed, err := inspectSecurityDestination(root, target)
	if err != nil {
		return fmt.Errorf("inspect hardening file before removal: %w", err)
	}
	if !existed {
		return nil
	}
	if identity.digest != sha256.Sum256(expected) {
		return fmt.Errorf("hardening file changed before removal: %s", logical)
	}
	if err := root.Remove(target.name); err != nil {
		return fmt.Errorf("remove hardening file %s: %w", logical, err)
	}
	return syncSecurityDirectory(root)
}

func (host hardeningHost) restore(logical string, snapshot hardeningFileSnapshot, expectedCurrent []byte) error {
	if !snapshot.existed {
		return host.removeExpected(logical, expectedCurrent)
	}
	if err := host.verifyHardeningPolicyParent(logical); err != nil {
		return err
	}
	target, err := host.target(logical, false)
	if err != nil {
		return err
	}
	if !snapshot.identity.ownerKnown {
		return fmt.Errorf("original hardening file ownership is unavailable: %s", logical)
	}
	expected := sha256.Sum256(expectedCurrent)
	desiredOwner := &securityFileOwner{uid: snapshot.identity.uid, gid: snapshot.identity.gid}
	if err := rewriteSecurityTargetExpectedStateOwned(target, snapshot.content, snapshot.mode, &expected, nil, nil, desiredOwner, nil); err != nil {
		return err
	}
	current, err := host.snapshot(logical)
	if err != nil {
		return err
	}
	if !hardeningSnapshotMatches(current, snapshot.content, snapshot.mode, desiredOwner.uid, desiredOwner.gid) {
		return fmt.Errorf("restored hardening file attestation failed: %s", logical)
	}
	return nil
}

func (host hardeningHost) removeRegular(logical string) error {
	snapshot, err := host.snapshot(logical)
	if err != nil || !snapshot.existed {
		return err
	}
	return host.removeExpected(logical, snapshot.content)
}

func (host hardeningHost) applyManagedFile(logical string, content []byte, validate, reload func() error) error {
	if err := host.ensureHardeningPolicyParent(logical, 0750); err != nil {
		return err
	}
	snapshot, err := host.snapshot(logical)
	if err != nil {
		return err
	}
	return host.applyManagedFileFromSnapshot(logical, snapshot, content, validate, reload)
}

func (host hardeningHost) applyManagedFileFromSnapshot(logical string, snapshot hardeningFileSnapshot, content []byte, validate, reload func() error) error {
	if err := host.writeExpected(logical, content, 0600, snapshot); err != nil {
		current, inspectErr := host.snapshot(logical)
		if inspectErr == nil && current.existed && string(current.content) == string(content) {
			return errors.Join(err, host.restore(logical, snapshot, content))
		}
		return errors.Join(err, inspectErr)
	}
	rollback := func(cause error, reloadOld bool) error {
		restoreErr := host.restore(logical, snapshot, content)
		if restoreErr != nil {
			return errors.Join(cause, fmt.Errorf("rollback %s: %w", logical, restoreErr))
		}
		if reloadOld && reload != nil {
			if err := reload(); err != nil {
				return errors.Join(cause, fmt.Errorf("reload previous state for %s: %w", logical, err))
			}
		}
		return cause
	}
	if validate != nil {
		if err := validate(); err != nil {
			return rollback(fmt.Errorf("validate %s: %w", logical, err), false)
		}
	}
	if reload != nil {
		if err := reload(); err != nil {
			return rollback(fmt.Errorf("activate %s: %w", logical, err), true)
		}
	}
	current, err := host.snapshot(logical)
	if err != nil {
		return rollback(fmt.Errorf("attest hardening file %s: %w", logical, err), reload != nil)
	}
	if !hardeningSnapshotMatches(current, content, 0600, host.expectedRootUID, host.expectedRootGID) {
		return rollback(fmt.Errorf("hardening file attestation failed: %s", logical), true)
	}
	return nil
}

func (host hardeningHost) markerExists(logical string) (bool, error) {
	physical, err := host.path(logical)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(physical)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.Mode().IsRegular(), nil
}

func (host hardeningHost) trustedStructuralRegularFile(logical string, executable bool) (bool, error) {
	physical, err := host.path(logical)
	if err != nil {
		return false, err
	}
	if err := host.verifyHardeningDirectoryChain(filepath.Dir(physical)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	target, err := host.target(logical, false)
	if err != nil {
		return false, err
	}
	root, err := openSecurityDirectory(target)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(target.name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || !ok || stat.Nlink != 1 ||
		int(stat.Uid) != host.expectedRootUID || int(stat.Gid) != host.expectedRootGID {
		return false, fmt.Errorf("systemd structural file has unsafe metadata: %s", logical)
	}
	if executable && info.Mode().Perm()&0100 == 0 {
		return false, fmt.Errorf("systemd structural executable is not owner-executable: %s", logical)
	}
	file, err := root.OpenFile(target.name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, fmt.Errorf("open systemd structural file %s: %w", logical, err)
	}
	opened, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil || !os.SameFile(info, opened) || opened.Mode() != info.Mode() {
		return false, fmt.Errorf("systemd structural file changed while opening: %s", logical)
	}
	if closeErr != nil {
		return false, closeErr
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || openedStat.Nlink != 1 || int(openedStat.Uid) != host.expectedRootUID || int(openedStat.Gid) != host.expectedRootGID {
		return false, fmt.Errorf("systemd structural file ownership changed while opening: %s", logical)
	}
	return true, nil
}

func (host hardeningHost) systemdStructuralSurface() (bool, error) {
	required := []string{
		"/usr/bin/systemctl",
		"/usr/bin/systemd-analyze",
		"/usr/lib/systemd/systemd-journald",
	}
	present := make(map[string]bool, len(required)+1)
	any := false
	for _, logical := range required {
		exists, err := host.trustedStructuralRegularFile(logical, true)
		if err != nil {
			return false, err
		}
		present[logical] = exists
		any = any || exists
	}
	manager := false
	for _, logical := range []string{"/usr/lib/systemd/systemd", "/lib/systemd/systemd"} {
		exists, err := host.trustedStructuralRegularFile(logical, true)
		if err != nil {
			return false, err
		}
		any = any || exists
		manager = manager || exists
		if exists {
			break
		}
	}
	if !any {
		return false, nil
	}
	var missing []error
	for _, logical := range required {
		if !present[logical] {
			missing = append(missing, fmt.Errorf("systemd structural surface is partial: missing %s", logical))
		}
	}
	if !manager {
		missing = append(missing, fmt.Errorf("systemd structural surface is partial: manager binary is missing"))
	}
	if len(missing) > 0 {
		return false, errors.Join(missing...)
	}
	return true, nil
}

func (host hardeningHost) systemdCoredumpStructuralSurface() (bool, error) {
	base, err := host.systemdStructuralSurface()
	if err != nil || !base {
		return base, err
	}
	required := []string{
		"/usr/lib/systemd/systemd-coredump",
		"/usr/lib/systemd/system/systemd-coredump.socket",
		"/usr/lib/systemd/system/systemd-coredump@.service",
	}
	present := 0
	for index, logical := range required {
		exists, err := host.trustedStructuralRegularFile(logical, index == 0)
		if err != nil {
			return false, err
		}
		if exists {
			present++
		}
	}
	if present == 0 {
		return false, nil
	}
	if present != len(required) {
		return false, fmt.Errorf("systemd coredump structural surface is partial: found %d of %d required files", present, len(required))
	}
	return true, nil
}

func (host hardeningHost) systemdPolicyRuntime(decision hardeningExecutionDecision) (bool, bool, error) {
	installed, err := host.systemdStructuralSurface()
	return host.systemdPolicyRuntimeForSurface(decision, installed, err)
}

func (host hardeningHost) systemdCoredumpPolicyRuntime(decision hardeningExecutionDecision) (bool, bool, error) {
	installed, err := host.systemdCoredumpStructuralSurface()
	return host.systemdPolicyRuntimeForSurface(decision, installed, err)
}

func (host hardeningHost) systemdPolicyRuntimeForSurface(decision hardeningExecutionDecision, installed bool, surfaceErr error) (bool, bool, error) {
	err := surfaceErr
	if err != nil || !installed {
		return installed, false, err
	}
	if host.systemdRuntimeProbe == nil {
		return true, false, fmt.Errorf("systemd runtime probe is unavailable")
	}
	active, err := host.systemdRuntimeProbe()
	if err != nil {
		return true, false, err
	}
	if decision.manager == "systemd" && !active {
		return true, false, fmt.Errorf("systemd execution decision disagrees with runtime attestation")
	}
	if decision.manager == "openrc" && active {
		return true, false, fmt.Errorf("OpenRC execution decision disagrees with systemd runtime attestation")
	}
	if active {
		return true, true, nil
	}
	if decision.packageInstall && decision.state == hardeningExecutionNotApplicable && decision.manager == "" {
		return true, false, nil
	}
	return true, false, fmt.Errorf("systemd is installed but its inactive runtime cannot be deferred in this execution context")
}

func (host hardeningHost) pathEntryExists(logical string) (bool, error) {
	target, err := host.target(logical, false)
	if err != nil {
		return false, err
	}
	root, err := openSecurityDirectory(target)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = root.Close() }()
	_, err = root.Lstat(target.name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (host hardeningHost) directoryExists(logical string) (bool, error) {
	physical, err := host.path(logical)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(physical)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("hardening path is not a real directory: %s", logical)
	}
	return true, nil
}

func (host hardeningHost) securePathPermissions(logical string, wantDirectory bool, mode fs.FileMode, uid, gid int) (bool, error) {
	target, err := host.target(logical, false)
	if err != nil {
		return false, err
	}
	root, err := openSecurityDirectory(target)
	if err != nil {
		return false, err
	}
	defer func() { _ = root.Close() }()
	pathInfo, err := root.Lstat(target.name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if wantDirectory {
		if !pathInfo.IsDir() || pathInfo.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("hardening path is not a real directory: %s", logical)
		}
	} else {
		if !pathInfo.Mode().IsRegular() {
			return false, fmt.Errorf("hardening path is not a regular file: %s", logical)
		}
		if stat, ok := pathInfo.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
			return false, fmt.Errorf("hardening file must have exactly one link: %s", logical)
		}
	}
	file, err := root.Open(target.name)
	if err != nil {
		return false, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, opened) {
		return false, fmt.Errorf("hardening path changed while opening: %s", logical)
	}
	if err := file.Chmod(mode); err != nil {
		return false, fmt.Errorf("set permissions on %s: %w", logical, err)
	}
	if uid >= 0 || gid >= 0 {
		if err := file.Chown(uid, gid); err != nil {
			return false, fmt.Errorf("set ownership on %s: %w", logical, err)
		}
	}
	attested, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("attest %s: %w", logical, err)
	}
	if attested.Mode().Perm() != mode.Perm() {
		return false, fmt.Errorf("permission attestation failed for %s", logical)
	}
	if uid >= 0 || gid >= 0 {
		stat, ok := attested.Sys().(*syscall.Stat_t)
		if !ok || (uid >= 0 && int(stat.Uid) != uid) || (gid >= 0 && int(stat.Gid) != gid) {
			return false, fmt.Errorf("ownership attestation failed for %s", logical)
		}
	}
	return true, nil
}

func (host hardeningHost) regularFileExists(logical string) (bool, error) {
	target, err := host.target(logical, false)
	if err != nil {
		return false, err
	}
	root, err := openSecurityDirectory(target)
	if err != nil {
		return false, err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(target.name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("hardening path is not a regular file: %s", logical)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return false, fmt.Errorf("hardening file must have exactly one link: %s", logical)
	}
	return true, nil
}

func parseNumericID(value string) (int, error) {
	id, err := strconv.Atoi(value)
	if err != nil || id < 0 {
		return 0, fmt.Errorf("invalid numeric ID %q", value)
	}
	return id, nil
}
