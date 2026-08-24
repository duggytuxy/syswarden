//go:build linux

package system

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"syswarden-cli/pkg/cronstate"
)

const (
	CronDProviderRuntime = "runtime"
	CronDProviderOffline = "offline-package"
)

// CronDProviderEvidence is the complete provider and package contract proven
// for the current target. Offline evidence never claims a live daemon.
type CronDProviderEvidence struct {
	Mode            string
	Manager         string
	Unit            string
	Daemon          string
	Fragment        string
	Packages        []string
	DefaultRunlevel bool
}

type cronDProviderSnapshot struct {
	mode            string
	manager         string
	unit            string
	daemon          string
	fragment        string
	packageEvidence string
	active          string
	enabled         string
	dropIns         string
	execStart       string
}

type cronOfflineCandidate struct {
	unit      string
	fragment  string
	daemon    string
	packageID string
	wantsLink string
}

type cronDProviderHost struct {
	alpine            bool
	classifyRuntime   func(bool) (serviceManagerState, error)
	executor          firewallManagerExecutor
	attestDropIns     func(firewallManagerExecutor, string) (string, error)
	attestPath        func(string, bool) (string, error)
	pathExists        func(string) (bool, error)
	attestEnablement  func(string, string) error
	canonicalizePath  func(string) (string, error)
	offlineCandidates []cronOfflineCandidate
}

func productionCronDProviderHost() cronDProviderHost {
	return cronDProviderHost{
		alpine:           IsAlpine(),
		classifyRuntime:  classifyServiceManagerRuntime,
		executor:         hostFirewallExecutor(),
		attestDropIns:    attestApprovedSystemdServiceDropIns,
		attestPath:       attestCronProviderPath,
		pathExists:       cronProviderPathExists,
		attestEnablement: attestCronProviderEnablement,
		canonicalizePath: filepath.EvalSymlinks,
		offlineCandidates: []cronOfflineCandidate{
			{
				unit:      "cron.service",
				fragment:  "/lib/systemd/system/cron.service",
				daemon:    "/usr/sbin/cron",
				packageID: "cron",
				wantsLink: "/etc/systemd/system/multi-user.target.wants/cron.service",
			},
			{
				unit:      "crond.service",
				fragment:  "/usr/lib/systemd/system/crond.service",
				daemon:    "/usr/sbin/crond",
				packageID: "cronie",
				wantsLink: "/etc/systemd/system/multi-user.target.wants/crond.service",
			},
		},
	}
}

func (host cronDProviderHost) validate() error {
	if host.classifyRuntime == nil || host.executor.lookPath == nil ||
		host.executor.validate == nil || host.executor.output == nil || host.attestDropIns == nil ||
		host.attestPath == nil || host.pathExists == nil ||
		host.attestEnablement == nil || host.canonicalizePath == nil {
		return fmt.Errorf("cron.d provider attestation dependencies are incomplete")
	}
	return nil
}

func cronProviderPathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect cron provider path %s: %w", path, err)
	}
	return true, nil
}

func attestCronProviderDirectoryChain(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("cron provider directory path %q is not clean and absolute", path)
	}
	rootInfo, err := os.Lstat(string(filepath.Separator))
	if err != nil {
		return fmt.Errorf("inspect filesystem root for cron provider: %w", err)
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("filesystem root identity is unavailable")
	}
	for directory := path; ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("inspect cron provider parent %s: %w", directory, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 ||
			(stat.Uid != 0 && stat.Uid != rootStat.Uid && int(stat.Uid) != os.Geteuid()) {
			return fmt.Errorf("cron provider parent %s is not trusted", directory)
		}
		if directory == string(filepath.Separator) {
			break
		}
	}
	return nil
}

func attestCronProviderPath(path string, executable bool) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("cron provider path %q is not clean and absolute", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve cron provider path %s: %w", path, err)
	}
	resolved = filepath.Clean(resolved)
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect cron provider path %s: %w", resolved, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 ||
		(executable && info.Mode().Perm()&0111 == 0) ||
		(stat.Uid != 0 && int(stat.Uid) != os.Geteuid()) {
		return "", fmt.Errorf("cron provider path %s is not a trusted regular file", resolved)
	}
	if err := attestCronProviderDirectoryChain(filepath.Dir(resolved)); err != nil {
		return "", err
	}
	return resolved, nil
}

func attestCronProviderEnablement(linkPath string, expectedTarget string) error {
	if !filepath.IsAbs(linkPath) || filepath.Clean(linkPath) != linkPath {
		return fmt.Errorf("cron provider enablement path is not clean and absolute")
	}
	info, err := os.Lstat(linkPath)
	if err != nil {
		return fmt.Errorf("inspect cron provider enablement %s: %w", linkPath, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink == 0 || stat.Uid != 0 {
		return fmt.Errorf("cron provider enablement %s is not a root-owned symlink", linkPath)
	}
	if err := attestCronProviderDirectoryChain(filepath.Dir(linkPath)); err != nil {
		return fmt.Errorf("attest cron provider enablement parent: %w", err)
	}
	actual, err := filepath.EvalSymlinks(linkPath)
	if err != nil {
		return fmt.Errorf("resolve cron provider enablement %s: %w", linkPath, err)
	}
	want, err := filepath.EvalSymlinks(expectedTarget)
	if err != nil {
		return fmt.Errorf("resolve cron provider target %s: %w", expectedTarget, err)
	}
	if filepath.Clean(actual) != filepath.Clean(want) {
		return fmt.Errorf("cron provider enablement %s targets %s, expected %s", linkPath, actual, want)
	}
	return nil
}

func queryCronProperty(
	executor firewallManagerExecutor,
	systemctlPath string,
	unit string,
	property string,
	allowEmpty bool,
) (string, error) {
	output, err := executor.output(systemctlPath, "show", "--property="+property, "--value", unit)
	if err != nil {
		return "", fmt.Errorf("query %s for %s: %w", property, unit, err)
	}
	value := strings.TrimSuffix(string(output), "\n")
	if strings.ContainsAny(value, "\x00\r\n") || (!allowEmpty && value == "") {
		return "", fmt.Errorf("invalid %s for %s", property, unit)
	}
	return value, nil
}

func parseSystemdExecStart(value string, expectedBase string) (string, error) {
	if strings.Count(value, "path=") != 1 || strings.Count(value, "argv[]=") != 1 ||
		strings.Count(value, "ignore_errors=no") != 1 {
		return "", fmt.Errorf("cron provider ExecStart is ambiguous")
	}
	pathStart := strings.Index(value, "path=") + len("path=")
	pathEnd := strings.Index(value[pathStart:], " ;")
	if pathEnd < 0 {
		return "", fmt.Errorf("cron provider ExecStart lacks a bounded path")
	}
	path := value[pathStart : pathStart+pathEnd]
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != expectedBase || strings.ContainsAny(path, " \t") {
		return "", fmt.Errorf("cron provider ExecStart path %q is not canonical", path)
	}
	argvValue := strings.TrimPrefix(value[strings.Index(value, "argv[]=")+len("argv[]="):], " ")
	argvEnd := strings.Index(argvValue, " ;")
	if argvEnd < 0 {
		return "", fmt.Errorf("cron provider ExecStart lacks bounded argv")
	}
	argv := strings.Fields(argvValue[:argvEnd])
	if len(argv) == 0 || argv[0] != path {
		return "", fmt.Errorf("cron provider ExecStart argv does not bind the executable path")
	}
	return path, nil
}

func safePackageVersion(value string) bool {
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\x00\r\n \t") {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && !strings.ContainsRune(".+:~_-", character) {
			return false
		}
	}
	return true
}

func packageListContains(
	output []byte,
	target string,
	canonicalize func(string) (string, error),
) bool {
	want, err := canonicalize(target)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(output), "\n") {
		if !filepath.IsAbs(line) || filepath.Clean(line) != line {
			continue
		}
		candidate, err := canonicalize(line)
		if err == nil && filepath.Clean(candidate) == filepath.Clean(want) {
			return true
		}
	}
	return false
}

func (host cronDProviderHost) attestSystemPackage(
	packageID string,
	fragment string,
	daemon string,
) (string, error) {
	switch packageID {
	case "cron":
		manager, err := resolveFirewallExecutable(host.executor, "dpkg-query")
		if err != nil {
			return "", err
		}
		versionOutput, err := host.executor.output(manager, "--show", "--showformat=${Version}\\n", "cron")
		if err != nil {
			return "", fmt.Errorf("query installed cron package: %w", err)
		}
		version := strings.TrimSuffix(string(versionOutput), "\n")
		if !safePackageVersion(version) {
			return "", fmt.Errorf("installed cron package version is ambiguous")
		}
		files, err := host.executor.output(manager, "--listfiles", "cron")
		if err != nil {
			return "", fmt.Errorf("query cron package files: %w", err)
		}
		if !packageListContains(files, fragment, host.canonicalizePath) ||
			!packageListContains(files, daemon, host.canonicalizePath) {
			return "", fmt.Errorf("cron package does not own the attested unit and daemon")
		}
		return "cron@" + version, nil
	case "cronie":
		manager, err := resolveFirewallExecutable(host.executor, "rpm")
		if err != nil {
			return "", err
		}
		query := func(path string) (string, error) {
			output, err := host.executor.output(
				manager, "--query", "--file", path, "--queryformat", "%{NAME}\\t%{EVR}\\n",
			)
			if err != nil {
				return "", err
			}
			if len(output) == 0 || strings.ContainsAny(string(output), "\x00\r") ||
				strings.Count(string(output), "\n") != 1 || output[len(output)-1] != '\n' {
				return "", fmt.Errorf("RPM ownership for %s is ambiguous", path)
			}
			fields := strings.Split(strings.TrimSuffix(string(output), "\n"), "\t")
			if len(fields) != 2 || fields[0] != "cronie" || !safePackageVersion(fields[1]) {
				return "", fmt.Errorf("RPM ownership for %s is ambiguous", path)
			}
			return fields[1], nil
		}
		fragmentVersion, err := query(fragment)
		if err != nil {
			return "", fmt.Errorf("attest cronie unit package ownership: %w", err)
		}
		daemonVersion, err := query(daemon)
		if err != nil || daemonVersion != fragmentVersion {
			return "", fmt.Errorf("cronie unit and daemon package provenance disagree")
		}
		return "cronie@" + fragmentVersion, nil
	default:
		return "", fmt.Errorf("unsupported cron provider package %q", packageID)
	}
}

func (host cronDProviderHost) captureSystemdRuntime(systemctlPath string) (cronDProviderSnapshot, error) {
	loaded := make([]string, 0, 2)
	for _, unit := range []string{"cron.service", "crond.service"} {
		state, err := queryCronProperty(host.executor, systemctlPath, unit, "LoadState", false)
		if err != nil {
			return cronDProviderSnapshot{}, err
		}
		switch state {
		case "loaded":
			loaded = append(loaded, unit)
		case "not-found":
		default:
			return cronDProviderSnapshot{}, fmt.Errorf("cron provider %s has ambiguous LoadState %q", unit, state)
		}
	}
	if len(loaded) != 1 {
		return cronDProviderSnapshot{}, fmt.Errorf("systemd must expose exactly one loaded cron.d provider, found %d", len(loaded))
	}
	unit := loaded[0]
	active, err := queryCronProperty(host.executor, systemctlPath, unit, "ActiveState", false)
	if err != nil || active != "active" {
		return cronDProviderSnapshot{}, fmt.Errorf("cron provider %s is not active", unit)
	}
	enabled, err := queryCronProperty(host.executor, systemctlPath, unit, "UnitFileState", false)
	if err != nil || enabled != "enabled" {
		return cronDProviderSnapshot{}, fmt.Errorf("cron provider %s is not persistently enabled", unit)
	}
	fragmentValue, err := queryCronProperty(host.executor, systemctlPath, unit, "FragmentPath", false)
	if err != nil {
		return cronDProviderSnapshot{}, err
	}
	dropIns, err := queryCronProperty(host.executor, systemctlPath, unit, "DropInPaths", true)
	if err != nil {
		return cronDProviderSnapshot{}, fmt.Errorf("cron provider %s has unapproved systemd drop-ins", unit)
	}
	dropInEvidence, err := host.attestDropIns(host.executor, dropIns)
	if err != nil {
		return cronDProviderSnapshot{}, fmt.Errorf("cron provider %s has unapproved systemd drop-ins: %w", unit, err)
	}
	execStart, err := queryCronProperty(host.executor, systemctlPath, unit, "ExecStart", false)
	if err != nil {
		return cronDProviderSnapshot{}, err
	}
	expectedBase := "cron"
	packageID := "cron"
	if unit == "crond.service" {
		expectedBase = "crond"
		packageID = "cronie"
	}
	execPath, err := parseSystemdExecStart(execStart, expectedBase)
	if err != nil {
		return cronDProviderSnapshot{}, err
	}
	fragment, err := host.attestPath(fragmentValue, false)
	if err != nil {
		return cronDProviderSnapshot{}, fmt.Errorf("attest cron provider fragment: %w", err)
	}
	daemon, err := host.attestPath(execPath, true)
	if err != nil {
		return cronDProviderSnapshot{}, fmt.Errorf("attest cron provider executable: %w", err)
	}
	if filepath.Base(daemon) != expectedBase {
		return cronDProviderSnapshot{}, fmt.Errorf("cron provider executable target %q is not %s", daemon, expectedBase)
	}
	packageEvidence, err := host.attestSystemPackage(packageID, fragmentValue, execPath)
	if err != nil {
		return cronDProviderSnapshot{}, err
	}
	return cronDProviderSnapshot{
		mode:            CronDProviderRuntime,
		manager:         "systemd",
		unit:            unit,
		daemon:          daemon,
		fragment:        fragment,
		packageEvidence: packageEvidence,
		active:          active,
		enabled:         enabled,
		dropIns:         dropInEvidence,
		execStart:       execStart,
	}, nil
}

func parseAPKOwner(output []byte, path string, packageID string) (string, error) {
	prefix := path + " is owned by " + packageID + "-"
	value := strings.TrimSuffix(string(output), "\n")
	if !strings.HasPrefix(value, prefix) || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("APK ownership for %s is ambiguous", path)
	}
	version := strings.TrimPrefix(value, prefix)
	if !safePackageVersion(version) {
		return "", fmt.Errorf("APK package version for %s is invalid", path)
	}
	return version, nil
}

func parseExactAlpineCronieDefault(output []byte) error {
	seen := false
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 2 {
			return fmt.Errorf("OpenRC runlevel inventory is malformed")
		}
		if strings.TrimSpace(parts[0]) != "cronie" {
			continue
		}
		if seen || strings.Join(strings.Fields(parts[1]), " ") != "default" {
			return fmt.Errorf("Cronie service must belong to the default OpenRC runlevel only")
		}
		seen = true
	}
	if !seen {
		return fmt.Errorf("Cronie service is not enabled in the default OpenRC runlevel")
	}
	return nil
}

func (host cronDProviderHost) captureAlpineBase(mode string) (cronDProviderSnapshot, error) {
	apkPath, err := resolveFirewallExecutable(host.executor, "apk")
	if err != nil {
		return cronDProviderSnapshot{}, err
	}
	for _, packageID := range []string{"cronie", "cronie-openrc"} {
		if _, err := host.executor.output(apkPath, "info", "--installed", packageID); err != nil {
			return cronDProviderSnapshot{}, fmt.Errorf("Alpine cron.d scheduling requires package %s: %w", packageID, err)
		}
	}
	crondPath, err := resolveFirewallExecutable(host.executor, "crond")
	if err != nil || filepath.Base(crondPath) != "crond" {
		return cronDProviderSnapshot{}, fmt.Errorf("Alpine cron.d scheduling requires the Cronie crond executable")
	}
	crondPath, err = host.attestPath(crondPath, true)
	if err != nil {
		return cronDProviderSnapshot{}, fmt.Errorf("attest Alpine Cronie executable: %w", err)
	}
	if filepath.Base(crondPath) != "crond" {
		return cronDProviderSnapshot{}, fmt.Errorf("Alpine cron.d scheduling refuses non-Cronie daemon target %q", crondPath)
	}
	// Alpine names the OpenRC service "cronie" even though its daemon is crond.
	initPath, err := host.attestPath("/etc/init.d/cronie", true)
	if err != nil {
		return cronDProviderSnapshot{}, fmt.Errorf("attest Alpine Cronie init script: %w", err)
	}
	daemonOwner, err := host.executor.output(apkPath, "info", "--who-owns", crondPath)
	if err != nil {
		return cronDProviderSnapshot{}, fmt.Errorf("query Alpine Cronie executable ownership: %w", err)
	}
	daemonVersion, err := parseAPKOwner(daemonOwner, crondPath, "cronie")
	if err != nil {
		return cronDProviderSnapshot{}, err
	}
	initOwner, err := host.executor.output(apkPath, "info", "--who-owns", initPath)
	if err != nil {
		return cronDProviderSnapshot{}, fmt.Errorf("query Alpine Cronie init ownership: %w", err)
	}
	initVersion, err := parseAPKOwner(initOwner, initPath, "cronie-openrc")
	if err != nil || initVersion != daemonVersion {
		return cronDProviderSnapshot{}, fmt.Errorf("Alpine Cronie executable and init package provenance disagree")
	}
	return cronDProviderSnapshot{
		mode:            mode,
		manager:         "openrc",
		unit:            "cronie",
		daemon:          crondPath,
		fragment:        initPath,
		packageEvidence: "cronie@" + daemonVersion + ",cronie-openrc@" + initVersion,
	}, nil
}

func (host cronDProviderHost) captureAlpineRuntime() (cronDProviderSnapshot, error) {
	snapshot, err := host.captureAlpineBase(CronDProviderRuntime)
	if err != nil {
		return cronDProviderSnapshot{}, err
	}
	rcServicePath, err := resolveFirewallExecutable(host.executor, "rc-service")
	if err != nil {
		return cronDProviderSnapshot{}, err
	}
	rcUpdatePath, err := resolveFirewallExecutable(host.executor, "rc-update")
	if err != nil {
		return cronDProviderSnapshot{}, err
	}
	if _, err := host.executor.output(rcServicePath, "--exists", "cronie"); err != nil {
		return cronDProviderSnapshot{}, fmt.Errorf("inspect Alpine Cronie OpenRC service: %w", err)
	}
	status, err := host.executor.output(rcServicePath, "cronie", "status")
	if err != nil {
		return cronDProviderSnapshot{}, fmt.Errorf("Alpine Cronie OpenRC service must be active: %w", err)
	}
	runlevels, err := host.executor.output(rcUpdatePath, "show")
	if err != nil {
		return cronDProviderSnapshot{}, fmt.Errorf("inspect Alpine Cronie runlevel enablement: %w", err)
	}
	if err := parseExactAlpineCronieDefault(runlevels); err != nil {
		return cronDProviderSnapshot{}, err
	}
	snapshot.active = string(status)
	snapshot.enabled = string(runlevels)
	return snapshot, nil
}

func (host cronDProviderHost) captureAlpineOffline() (cronDProviderSnapshot, error) {
	snapshot, err := host.captureAlpineBase(CronDProviderOffline)
	if err != nil {
		return cronDProviderSnapshot{}, err
	}
	if err := host.attestEnablement("/etc/runlevels/default/cronie", snapshot.fragment); err != nil {
		return cronDProviderSnapshot{}, fmt.Errorf("attest offline Alpine Cronie default runlevel: %w", err)
	}
	snapshot.enabled = "default"
	return snapshot, nil
}

func (host cronDProviderHost) captureSystemdOffline() (cronDProviderSnapshot, error) {
	var selected *cronDProviderSnapshot
	for _, candidate := range host.offlineCandidates {
		fragmentPresent, err := host.pathExists(candidate.fragment)
		if err != nil {
			return cronDProviderSnapshot{}, err
		}
		daemonPresent, err := host.pathExists(candidate.daemon)
		if err != nil {
			return cronDProviderSnapshot{}, err
		}
		if !fragmentPresent && !daemonPresent {
			continue
		}
		if !fragmentPresent || !daemonPresent {
			return cronDProviderSnapshot{}, fmt.Errorf("offline cron provider %s is partially installed", candidate.unit)
		}
		fragment, err := host.attestPath(candidate.fragment, false)
		if err != nil {
			return cronDProviderSnapshot{}, err
		}
		daemon, err := host.attestPath(candidate.daemon, true)
		if err != nil {
			return cronDProviderSnapshot{}, err
		}
		packageEvidence, err := host.attestSystemPackage(candidate.packageID, candidate.fragment, candidate.daemon)
		if err != nil {
			return cronDProviderSnapshot{}, err
		}
		if err := host.attestEnablement(candidate.wantsLink, candidate.fragment); err != nil {
			return cronDProviderSnapshot{}, err
		}
		snapshot := cronDProviderSnapshot{
			mode:            CronDProviderOffline,
			manager:         "systemd",
			unit:            candidate.unit,
			daemon:          daemon,
			fragment:        fragment,
			packageEvidence: packageEvidence,
			enabled:         "multi-user.target",
		}
		if selected != nil {
			return cronDProviderSnapshot{}, fmt.Errorf("offline target has multiple cron.d providers")
		}
		selected = &snapshot
	}
	if selected == nil {
		return cronDProviderSnapshot{}, fmt.Errorf("offline target has no complete cron.d provider")
	}
	return *selected, nil
}

func packageNames(snapshot cronDProviderSnapshot) []string {
	if snapshot.manager == "openrc" {
		return []string{"cronie", "cronie-openrc"}
	}
	if snapshot.unit == "cron.service" {
		return []string{"cron"}
	}
	return []string{"cronie"}
}

func (host cronDProviderHost) attest() (CronDProviderEvidence, error) {
	if err := host.validate(); err != nil {
		return CronDProviderEvidence{}, err
	}
	state, err := host.classifyRuntime(host.alpine)
	if err != nil {
		return CronDProviderEvidence{}, fmt.Errorf("attest service-manager runtime for cron.d: %w", err)
	}
	var first cronDProviderSnapshot
	switch state {
	case serviceManagerActive:
		if host.alpine {
			first, err = host.captureAlpineRuntime()
		} else {
			systemctlPath, resolveErr := resolveFirewallExecutable(host.executor, "systemctl")
			if resolveErr != nil {
				return CronDProviderEvidence{}, resolveErr
			}
			first, err = host.captureSystemdRuntime(systemctlPath)
			if err == nil {
				second, secondErr := host.captureSystemdRuntime(systemctlPath)
				if secondErr != nil {
					return CronDProviderEvidence{}, fmt.Errorf("systemd cron.d provider changed during complete snapshot reattestation: %w", secondErr)
				}
				if second != first {
					return CronDProviderEvidence{}, fmt.Errorf("systemd cron.d provider changed during complete snapshot reattestation")
				}
			}
		}
	case serviceManagerOffline:
		if host.alpine {
			first, err = host.captureAlpineOffline()
		} else {
			first, err = host.captureSystemdOffline()
		}
	default:
		return CronDProviderEvidence{}, fmt.Errorf("cron.d provider target state is %s, not runtime or attested offline package mode", state)
	}
	if err != nil {
		return CronDProviderEvidence{}, err
	}
	if host.alpine {
		var second cronDProviderSnapshot
		if state == serviceManagerActive {
			second, err = host.captureAlpineRuntime()
		} else {
			second, err = host.captureAlpineOffline()
		}
		if err != nil {
			return CronDProviderEvidence{}, fmt.Errorf("Alpine cron.d provider changed during complete snapshot reattestation: %w", err)
		}
		if second != first {
			return CronDProviderEvidence{}, fmt.Errorf("Alpine cron.d provider changed during complete snapshot reattestation")
		}
	} else if state == serviceManagerOffline {
		second, secondErr := host.captureSystemdOffline()
		if secondErr != nil {
			return CronDProviderEvidence{}, fmt.Errorf("offline systemd cron.d provider changed during complete snapshot reattestation: %w", secondErr)
		}
		if second != first {
			return CronDProviderEvidence{}, fmt.Errorf("offline systemd cron.d provider changed during complete snapshot reattestation")
		}
	}
	return CronDProviderEvidence{
		Mode:            first.mode,
		Manager:         first.manager,
		Unit:            first.unit,
		Daemon:          first.daemon,
		Fragment:        first.fragment,
		Packages:        packageNames(first),
		DefaultRunlevel: first.manager == "openrc" && first.enabled != "",
	}, nil
}

// InspectCronDProvider returns a complete runtime or offline-package provider
// proof. Offline mode proves files and enablement only and never claims PID 1.
func InspectCronDProvider() (CronDProviderEvidence, error) {
	return productionCronDProviderHost().attest()
}

func inspectCronDProviderMode(expected string) (CronDProviderEvidence, error) {
	evidence, err := InspectCronDProvider()
	if err != nil {
		return CronDProviderEvidence{}, err
	}
	if evidence.Mode != expected {
		return CronDProviderEvidence{}, fmt.Errorf(
			"cron.d provider mode is %s, expected %s", evidence.Mode, expected,
		)
	}
	return evidence, nil
}

// InspectRuntimeCronDProvider requires coherent target-host PID 1 evidence and
// refuses offline package proofs.
func InspectRuntimeCronDProvider() (CronDProviderEvidence, error) {
	return inspectCronDProviderMode(CronDProviderRuntime)
}

// InspectOfflineCronDProvider requires the package-transaction state and
// refuses to describe a live target host as an offline image.
func InspectOfflineCronDProvider() (CronDProviderEvidence, error) {
	return inspectCronDProviderMode(CronDProviderOffline)
}

// AttestCronDProvider verifies the mode-dispatched provider contract for
// diagnostics. Security-boundary callers must use the explicit runtime or
// offline variant. No variant changes service state.
func AttestCronDProvider() error {
	_, err := InspectCronDProvider()
	return err
}

// AttestRuntimeCronDProvider requires the live target-host provider contract.
func AttestRuntimeCronDProvider() error {
	_, err := InspectRuntimeCronDProvider()
	return err
}

// AttestOfflineCronDProvider requires the offline package/image contract.
func AttestOfflineCronDProvider() error {
	_, err := InspectOfflineCronDProvider()
	return err
}

// PreflightCronScheduling performs a mode-dispatched diagnostic preflight.
// Security-boundary callers must use an explicit runtime or offline preflight.
func PreflightCronScheduling(haEnabled bool) (cronstate.Inspection, error) {
	options := cronstate.DefaultOptions(ReadOnlyRootCrontabEvidence)
	options.AttestCronDProvider = AttestCronDProvider
	return cronstate.Preflight(options, haEnabled)
}

// PreflightRuntimeCronScheduling is the mandatory live install/reload gate.
func PreflightRuntimeCronScheduling(haEnabled bool) (cronstate.Inspection, error) {
	options := cronstate.DefaultOptions(ReadOnlyRootCrontabEvidence)
	options.AttestCronDProvider = AttestRuntimeCronDProvider
	return cronstate.Preflight(options, haEnabled)
}

// PreflightOfflineCronScheduling is the mandatory package/ISO chroot gate.
func PreflightOfflineCronScheduling(haEnabled bool) (cronstate.Inspection, error) {
	options := cronstate.DefaultOptions(ReadOnlyRootCrontabEvidence)
	options.AttestCronDProvider = AttestOfflineCronDProvider
	return cronstate.Preflight(options, haEnabled)
}
