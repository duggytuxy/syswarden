//go:build linux

package system

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"syswarden-cli/pkg/platformpaths"
)

const (
	maximumFirewallRemovalProcesses   = 131072
	maximumFirewallRemovalCmdlineSize = 64 << 10
)

var firewallMutatingCLISubcommands = map[string]struct{}{
	"allow-ssh":               {},
	"block":                   {},
	"config":                  {},
	"ha-sync":                 {},
	"install":                 {},
	"migrate-config":          {},
	"prepare-package-removal": {},
	"reload":                  {},
	"revoke-ssh":              {},
	"tui":                     {},
	"unblock":                 {},
	"uninstall":               {},
	"unwhitelist":             {},
	"update":                  {},
	"update-feeds":            {},
	"whitelist":               {},
	"whitelist-infra":         {},
}

type firewallRemovalProcessScanner struct {
	procRoot    string
	cliPath     string
	tuiPath     string
	corePath    string
	rejectCore  bool
	selfPID     int
	readDir     func(string) ([]os.DirEntry, error)
	openRoot    func(string) (*os.Root, error)
	lstat       func(string) (os.FileInfo, error)
	stat        func(string) (os.FileInfo, error)
	readlink    func(string) (string, error)
	validateCLI func(string) error
	ownerUID    func(os.FileInfo) (uint32, bool)
}

func productionFirewallRemovalProcessScanner() firewallRemovalProcessScanner {
	return firewallRemovalProcessScanner{
		procRoot:    "/proc",
		cliPath:     platformpaths.CLI,
		tuiPath:     platformpaths.TUI,
		corePath:    filepath.Join(platformpaths.InstallRoot, "bin/syswarden-core"),
		selfPID:     os.Getpid(),
		readDir:     os.ReadDir,
		openRoot:    os.OpenRoot,
		lstat:       os.Lstat,
		stat:        os.Stat,
		readlink:    os.Readlink,
		validateCLI: validateResolvedFirewallExecutable,
		ownerUID: func(info os.FileInfo) (uint32, bool) {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return 0, false
			}
			return stat.Uid, true
		},
	}
}

func readBoundedFirewallRemovalProcFile(root *os.Root, relative string, maximum int64) ([]byte, error) {
	if root == nil || relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) || maximum <= 0 {
		return nil, fmt.Errorf("invalid bounded process file request")
	}
	before, err := root.Lstat(relative)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("process file %s is not a real regular file", relative)
	}
	file, err := root.Open(relative)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("process file %s changed while reading", relative)
	}
	if int64(len(content)) > maximum {
		return nil, fmt.Errorf("process file %s exceeds %d bytes", relative, maximum)
	}
	after, err := root.Lstat(relative)
	if err != nil || !os.SameFile(opened, after) {
		return nil, fmt.Errorf("process file %s changed during attestation", relative)
	}
	return content, nil
}

func parseFirewallRemovalProcessArguments(content []byte) ([]string, error) {
	if len(content) == 0 {
		return nil, nil
	}
	if content[len(content)-1] != 0 {
		return nil, fmt.Errorf("process command line is not NUL terminated")
	}
	parts := bytes.Split(content[:len(content)-1], []byte{0})
	arguments := make([]string, len(parts))
	for index, part := range parts {
		if bytes.IndexByte(part, 0) >= 0 {
			return nil, fmt.Errorf("process command line contains an embedded NUL")
		}
		arguments[index] = string(part)
	}
	return arguments, nil
}

func nextFirewallRemovalCommandWord(arguments []string, start int) (string, int, bool) {
	for index := start; index < len(arguments); index++ {
		argument := arguments[index]
		switch {
		case argument == "--config":
			index++
			if index >= len(arguments) || arguments[index] == "" {
				return "", index, false
			}
		case strings.HasPrefix(argument, "--config="):
			if strings.TrimPrefix(argument, "--config=") == "" {
				return "", index, false
			}
		case strings.HasPrefix(argument, "-"):
			return "", index, false
		default:
			return argument, index, true
		}
	}
	return "", len(arguments), false
}

func exactFirewallMutatingCLISubcommand(arguments []string) (string, bool) {
	if len(arguments) < 2 {
		return "", false
	}
	topLevel, index, valid := nextFirewallRemovalCommandWord(arguments, 1)
	if !valid {
		return "", false
	}
	if topLevel != "ha-fence" {
		_, mutating := firewallMutatingCLISubcommands[topLevel]
		if mutating {
			return topLevel, true
		}
		return "", false
	}
	subcommand, index, valid := nextFirewallRemovalCommandWord(arguments, index+1)
	if !valid {
		return "", false
	}
	switch subcommand {
	case "engage", "recover", "release":
		return "ha-fence " + subcommand, true
	case "manifest":
		action, _, valid := nextFirewallRemovalCommandWord(arguments, index+1)
		if valid && action == "create" {
			return "ha-fence manifest create", true
		}
	}
	return "", false
}

func (scanner firewallRemovalProcessScanner) validate() error {
	if scanner.procRoot == "" || !filepath.IsAbs(scanner.procRoot) || filepath.Clean(scanner.procRoot) != scanner.procRoot {
		return fmt.Errorf("process inventory root is not clean and absolute")
	}
	if scanner.cliPath == "" || !filepath.IsAbs(scanner.cliPath) || filepath.Clean(scanner.cliPath) != scanner.cliPath {
		return fmt.Errorf("SysWarden CLI path is not clean and absolute")
	}
	if scanner.tuiPath == "" || !filepath.IsAbs(scanner.tuiPath) || filepath.Clean(scanner.tuiPath) != scanner.tuiPath ||
		scanner.tuiPath == scanner.cliPath {
		return fmt.Errorf("SysWarden TUI path is not distinct, clean, and absolute")
	}
	if scanner.corePath == "" || !filepath.IsAbs(scanner.corePath) ||
		filepath.Clean(scanner.corePath) != scanner.corePath || scanner.corePath == scanner.cliPath ||
		scanner.corePath == scanner.tuiPath {
		return fmt.Errorf("SysWarden core path is not distinct, clean, and absolute")
	}
	if scanner.selfPID <= 0 || scanner.readDir == nil || scanner.openRoot == nil || scanner.lstat == nil ||
		scanner.stat == nil || scanner.readlink == nil || scanner.validateCLI == nil || scanner.ownerUID == nil {
		return fmt.Errorf("process inventory dependencies are incomplete")
	}
	return scanner.validateCLI(scanner.cliPath)
}

func (scanner firewallRemovalProcessScanner) attestOptionalInstalledExecutable(path string) (os.FileInfo, error) {
	before, err := scanner.lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := scanner.validateCLI(path); err != nil {
		return nil, err
	}
	after, err := scanner.stat(path)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return nil, errors.Join(fmt.Errorf("installed executable changed during attestation"), err)
	}
	return after, nil
}

func exactRemovalProcessExecutable(
	executable os.FileInfo,
	installed os.FileInfo,
	target string,
	path string,
) bool {
	return executable != nil &&
		(installed != nil && os.SameFile(installed, executable) ||
			target == path || target == path+" (deleted)")
}

func (scanner firewallRemovalProcessScanner) scan() error {
	if err := scanner.validate(); err != nil {
		return err
	}
	cliInfo, err := scanner.attestOptionalInstalledExecutable(scanner.cliPath)
	if err != nil {
		return fmt.Errorf("attest installed SysWarden CLI executable: %w", err)
	}
	if cliInfo == nil {
		return fmt.Errorf("installed SysWarden CLI executable is absent")
	}
	tuiInfo, err := scanner.attestOptionalInstalledExecutable(scanner.tuiPath)
	if err != nil {
		return fmt.Errorf("attest installed SysWarden TUI executable: %w", err)
	}
	var coreInfo os.FileInfo
	if scanner.rejectCore {
		coreInfo, err = scanner.attestOptionalInstalledExecutable(scanner.corePath)
		if err != nil {
			return fmt.Errorf("attest installed SysWarden core executable: %w", err)
		}
	}
	entries, err := scanner.readDir(scanner.procRoot)
	if err != nil {
		return fmt.Errorf("enumerate process inventory: %w", err)
	}
	root, err := scanner.openRoot(scanner.procRoot)
	if err != nil {
		return fmt.Errorf("pin process inventory: %w", err)
	}
	defer root.Close()

	processCount := 0
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 0 {
			continue
		}
		processCount++
		if processCount > maximumFirewallRemovalProcesses {
			return fmt.Errorf("process inventory exceeds %d entries", maximumFirewallRemovalProcesses)
		}
		if pid == scanner.selfPID {
			continue
		}
		processPath := filepath.Join(scanner.procRoot, entry.Name())
		before, err := scanner.lstat(processPath)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect process %d: %w", pid, err)
		}
		if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing unsafe process inventory entry %d", pid)
		}
		uid, ok := scanner.ownerUID(before)
		if !ok {
			return fmt.Errorf("process %d ownership is unavailable", pid)
		}
		if uid != 0 {
			continue
		}

		executablePath := filepath.Join(processPath, "exe")
		executableInfo, err := scanner.stat(executablePath)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect root process %d executable: %w", pid, err)
		}
		executableTarget, err := scanner.readlink(executablePath)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read root process %d executable target: %w", pid, err)
		}
		exactCLI := exactRemovalProcessExecutable(executableInfo, cliInfo, executableTarget, scanner.cliPath)
		exactTUI := exactRemovalProcessExecutable(executableInfo, tuiInfo, executableTarget, scanner.tuiPath)
		exactCore := scanner.rejectCore && exactRemovalProcessExecutable(
			executableInfo, coreInfo, executableTarget, scanner.corePath,
		)
		if !exactCLI && !exactTUI && !exactCore {
			continue
		}
		if exactTUI || exactCore {
			processName := "TUI"
			installedInfo := tuiInfo
			targetPath := scanner.tuiPath
			if exactCore {
				processName = "core"
				installedInfo = coreInfo
				targetPath = scanner.corePath
			}
			after, err := scanner.lstat(processPath)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return fmt.Errorf("reattest exact SysWarden %s process %d: %w", processName, pid, err)
			}
			if !os.SameFile(before, after) {
				continue
			}
			confirmedExecutable, statErr := scanner.stat(executablePath)
			confirmedTarget, readlinkErr := scanner.readlink(executablePath)
			if statErr != nil || readlinkErr != nil ||
				!exactRemovalProcessExecutable(confirmedExecutable, installedInfo, confirmedTarget, targetPath) ||
				executableTarget != confirmedTarget {
				return errors.Join(
					fmt.Errorf("exact SysWarden %s process %d changed during attestation", processName, pid),
					statErr,
					readlinkErr,
				)
			}
			return fmt.Errorf("root-owned SysWarden %s is active as process %d", processName, pid)
		}
		relativeCmdline := filepath.Join(entry.Name(), "cmdline")
		firstCmdline, err := readBoundedFirewallRemovalProcFile(
			root, relativeCmdline, maximumFirewallRemovalCmdlineSize,
		)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read exact SysWarden CLI process %d command line: %w", pid, err)
		}
		arguments, err := parseFirewallRemovalProcessArguments(firstCmdline)
		if err != nil {
			return fmt.Errorf("parse exact SysWarden CLI process %d command line: %w", pid, err)
		}
		subcommand, mutating := exactFirewallMutatingCLISubcommand(arguments)
		if !mutating {
			continue
		}

		secondCmdline, err := readBoundedFirewallRemovalProcFile(
			root, relativeCmdline, maximumFirewallRemovalCmdlineSize,
		)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !bytes.Equal(firstCmdline, secondCmdline) {
			return fmt.Errorf("exact SysWarden CLI process %d changed during command-line attestation", pid)
		}
		after, err := scanner.lstat(processPath)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("reattest exact SysWarden CLI process %d: %w", pid, err)
		}
		if !os.SameFile(before, after) {
			continue
		}
		confirmedExecutable, err := scanner.stat(executablePath)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		confirmedTarget, readlinkErr := scanner.readlink(executablePath)
		if err != nil || readlinkErr != nil ||
			!exactRemovalProcessExecutable(confirmedExecutable, cliInfo, confirmedTarget, scanner.cliPath) ||
			executableTarget != confirmedTarget {
			return fmt.Errorf("exact SysWarden CLI process %d executable changed during attestation", pid)
		}
		return fmt.Errorf("root-owned SysWarden CLI firewall mutator %s is active as process %d", subcommand, pid)
	}
	return nil
}

func scanExactRootSysWardenCLIMutators() error {
	return productionFirewallRemovalProcessScanner().scan()
}

func scanExactRootSysWardenProcessesAfterServiceStop() error {
	scanner := productionFirewallRemovalProcessScanner()
	scanner.rejectCore = true
	return scanner.scan()
}
