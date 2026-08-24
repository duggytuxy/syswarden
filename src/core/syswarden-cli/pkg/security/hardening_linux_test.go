//go:build linux

package security

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

type automaticUpdateStatusResult struct {
	output string
	status int
	err    error
}

type automaticUpdateTestManager struct {
	enabled         map[string]bool
	active          map[string]bool
	calls           []string
	runFailures     map[string][]error
	statusOverrides map[string][]automaticUpdateStatusResult
}

type profileImmutableProbeResult struct {
	flags int
	err   error
}

type profileTransactionTestState struct {
	flags         int
	probeResults  []profileImmutableProbeResult
	setFailures   map[int][]error
	chmodFailures []error
	onSet         func(int)
	calls         []string
}

func newProfileTransactionTestState(flags int) *profileTransactionTestState {
	return &profileTransactionTestState{flags: flags, setFailures: make(map[int][]error)}
}

func (state *profileTransactionTestState) probe(*os.File) (int, error) {
	state.calls = append(state.calls, "probe")
	if len(state.probeResults) == 0 {
		return state.flags, nil
	}
	result := state.probeResults[0]
	state.probeResults = state.probeResults[1:]
	return result.flags, result.err
}

func (state *profileTransactionTestState) set(_ *os.File, flags int) error {
	state.calls = append(state.calls, "set "+strconv.Itoa(flags))
	state.flags = flags
	if state.onSet != nil {
		state.onSet(flags)
	}
	results := state.setFailures[flags]
	if len(results) == 0 {
		return nil
	}
	state.setFailures[flags] = results[1:]
	return results[0]
}

func (state *profileTransactionTestState) chmod(file *os.File, mode os.FileMode) error {
	state.calls = append(state.calls, "chmod "+mode.Perm().String())
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if len(state.chmodFailures) == 0 {
		return nil
	}
	err := state.chmodFailures[0]
	state.chmodFailures = state.chmodFailures[1:]
	return err
}

func newAutomaticUpdateTestManager() *automaticUpdateTestManager {
	return &automaticUpdateTestManager{
		enabled:         make(map[string]bool),
		active:          make(map[string]bool),
		runFailures:     make(map[string][]error),
		statusOverrides: make(map[string][]automaticUpdateStatusResult),
	}
}

func automaticUpdateCommandKey(name string, args ...string) string {
	return strings.Join(append([]string{name}, args...), " ")
}

func (manager *automaticUpdateTestManager) run(name string, args ...string) error {
	key := automaticUpdateCommandKey(name, args...)
	manager.calls = append(manager.calls, key)
	if name != "systemctl" || len(args) != 2 {
		return errors.New("unexpected automatic-update manager command")
	}
	timer := args[1]
	switch args[0] {
	case "enable":
		manager.enabled[timer] = true
	case "disable":
		manager.enabled[timer] = false
	case "start":
		manager.active[timer] = true
	case "stop":
		manager.active[timer] = false
	default:
		return errors.New("unexpected automatic-update manager action")
	}
	results := manager.runFailures[key]
	if len(results) == 0 {
		return nil
	}
	manager.runFailures[key] = results[1:]
	return results[0]
}

func (manager *automaticUpdateTestManager) status(name string, args ...string) ([]byte, int, error) {
	key := automaticUpdateCommandKey(name, args...)
	manager.calls = append(manager.calls, key)
	results := manager.statusOverrides[key]
	if len(results) > 0 {
		manager.statusOverrides[key] = results[1:]
		result := results[0]
		return []byte(result.output), result.status, result.err
	}
	if name != "systemctl" || len(args) != 2 {
		return nil, -1, errors.New("unexpected automatic-update manager status command")
	}
	timer := args[1]
	switch args[0] {
	case "is-enabled":
		if manager.enabled[timer] {
			return []byte("enabled\n"), 0, nil
		}
		return []byte("disabled\n"), 1, nil
	case "is-active":
		if manager.active[timer] {
			return []byte("active\n"), 0, nil
		}
		return []byte("inactive\n"), 3, nil
	default:
		return nil, -1, errors.New("unexpected automatic-update manager status action")
	}
}

func hardeningTestHost(t *testing.T, executor hardeningExecutor) hardeningHost {
	t.Helper()
	if executor.run == nil {
		executor.run = func(string, ...string) error { return nil }
	}
	if executor.output == nil {
		executor.output = func(string, ...string) ([]byte, error) { return nil, nil }
	}
	if executor.status == nil {
		executor.status = func(name string, args ...string) ([]byte, int, error) {
			output, err := executor.output(name, args...)
			if err != nil {
				return output, 0, err
			}
			return output, 0, nil
		}
	}
	return hardeningHost{
		root:                t.TempDir(),
		expectedRootUID:     os.Getuid(),
		expectedRootGID:     os.Getgid(),
		executor:            executor,
		systemdRuntimeProbe: func() (bool, error) { return false, nil },
		profileFlagsProbe:   func(*os.File) (int, error) { return 0, nil },
		profileFlagsSet:     func(*os.File, int) error { return nil },
		profileChmod:        func(file *os.File, mode os.FileMode) error { return file.Chmod(mode) },
		directorySync:       syncSecurityDirectory,
	}
}

func hardeningFixtureRoot(t *testing.T, path string) (*os.Root, string) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Errorf("close fixture root: %v", err)
		}
	})
	return root, filepath.Base(path)
}

func writeHardeningFixtureFile(path string, content []byte, mode os.FileMode) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	name := filepath.Base(path)
	if err := root.WriteFile(name, content, 0600); err != nil {
		return errors.Join(err, root.Close())
	}
	if err := root.Chmod(name, mode); err != nil {
		return errors.Join(err, root.Close())
	}
	return root.Close()
}

func readHardeningFixtureFile(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	content, readErr := root.ReadFile(filepath.Base(path))
	return content, errors.Join(readErr, root.Close())
}

func chmodHardeningFixture(path string, mode os.FileMode) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	chmodErr := root.Chmod(filepath.Base(path), mode)
	return errors.Join(chmodErr, root.Close())
}

func writeOSReleaseFixture(t *testing.T, host hardeningHost, id string) {
	t.Helper()
	usrLib, err := host.path("/usr/lib")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(usrLib, 0750); err != nil {
		t.Fatal(err)
	}
	usrRelease, _ := host.path("/usr/lib/os-release")
	if err := writeHardeningFixtureFile(usrRelease, []byte("NAME=Fixture\nID="+id+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	etc, _ := host.path("/etc")
	if err := os.MkdirAll(etc, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../usr/lib/os-release", filepath.Join(etc, "os-release")); err != nil {
		t.Fatal(err)
	}
}

func writeSystemdStructuralFixture(t *testing.T, host hardeningHost, includeCoredump bool) {
	t.Helper()
	files := map[string]os.FileMode{
		"/usr/bin/systemctl":                0755,
		"/usr/bin/systemd-analyze":          0755,
		"/usr/lib/systemd/systemd":          0755,
		"/usr/lib/systemd/systemd-journald": 0755,
	}
	if includeCoredump {
		files["/usr/lib/systemd/systemd-coredump"] = 0755
		files["/usr/lib/systemd/system/systemd-coredump.socket"] = 0644
		files["/usr/lib/systemd/system/systemd-coredump@.service"] = 0644
	}
	for logical, mode := range files {
		physical, err := host.path(logical)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(physical), 0750); err != nil {
			t.Fatal(err)
		}
		if err := writeHardeningFixtureFile(physical, []byte("fixture\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
}

func setAlternateTestGroup(t *testing.T, path string, current int) int {
	t.Helper()
	candidates, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		candidates = append(candidates, current+1)
	}
	for _, candidate := range candidates {
		if candidate == current {
			continue
		}
		if err := os.Chown(path, -1, candidate); err == nil {
			return candidate
		}
	}
	t.Skip("no alternate writable group is available for ownership rollback test")
	return -1
}

func TestRunHardeningStagesCollectsEveryFailure(t *testing.T) {
	first := errors.New("first failure")
	second := errors.New("second failure")
	calls := 0
	err := runHardeningStages([]hardeningStage{
		{name: "first", run: func() error { calls++; return first }},
		{name: "success", run: func() error { calls++; return nil }},
		{name: "second", run: func() error { calls++; return second }},
	})
	if calls != 3 || !errors.Is(err, first) || !errors.Is(err, second) {
		t.Fatalf("calls=%d error=%v, want all stages and joined failures", calls, err)
	}
}

func TestHardeningManagedFileRollsBackValidationFailure(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	path, err := host.path("/etc/example.conf")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		t.Fatal(err)
	}
	root, name := hardeningFixtureRoot(t, path)
	if err := root.WriteFile(name, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.Chmod(name, 0640); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("invalid generated configuration")
	err = host.applyManagedFile("/etc/example.conf", []byte("replacement\n"), func() error { return injected }, nil)
	if !errors.Is(err, injected) {
		t.Fatalf("error=%v, want validation failure", err)
	}
	content, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "original\n" || info.Mode().Perm() != 0640 {
		t.Fatalf("rollback content=%q mode=%04o", content, info.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "example.conf" {
		t.Fatalf("rollback left staging residue: %#v", entries)
	}
}

func TestHardeningManagedFileRejectsUpdateAfterSourceSnapshot(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	path, _ := host.path("/etc/example.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		t.Fatal(err)
	}
	if err := writeHardeningFixtureFile(path, []byte("source\n"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := host.snapshot("/etc/example.conf")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeHardeningFixtureFile(path, []byte("operator update\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := host.applyManagedFileFromSnapshot("/etc/example.conf", snapshot, []byte("replacement\n"), nil, nil); err == nil {
		t.Fatal("concurrent operator update was overwritten")
	}
	root, name := hardeningFixtureRoot(t, path)
	content, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "operator update\n" {
		t.Fatalf("concurrent update changed: %q", content)
	}
}

func TestHardeningManagedFileRollsBackFinalAttestationFailure(t *testing.T) {
	for _, rollbackFailure := range []bool{false, true} {
		name := "rollback succeeds"
		if rollbackFailure {
			name = "reload rollback failure is aggregated"
		}
		t.Run(name, func(t *testing.T) {
			host := hardeningTestHost(t, hardeningExecutor{})
			logical := "/etc/example/final-attestation.conf"
			physical, _ := host.path(logical)
			if err := os.MkdirAll(filepath.Dir(physical), 0750); err != nil {
				t.Fatal(err)
			}
			original := []byte("original\n")
			if err := writeHardeningFixtureFile(physical, original, 0640); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("reload previous state failed")
			reloads := 0
			err := host.applyManagedFile(logical, []byte("replacement\n"), nil, func() error {
				reloads++
				if reloads == 1 {
					return chmodHardeningFixture(physical, 0644)
				}
				if rollbackFailure {
					return injected
				}
				return nil
			})
			if err == nil || (rollbackFailure && !errors.Is(err, injected)) {
				t.Fatalf("final attestation result: %v", err)
			}
			content, readErr := readHardeningFixtureFile(physical)
			info, statErr := os.Stat(physical)
			if readErr != nil || statErr != nil || string(content) != string(original) || info.Mode().Perm() != 0640 {
				t.Fatalf("rollback content=%q mode=%v read=%v stat=%v", content, info.Mode(), readErr, statErr)
			}
		})
	}
}

func TestHardeningWriteRejectsSymlinkTargetAndParent(t *testing.T) {
	t.Run("target", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		etc, _ := host.path("/etc")
		if err := os.MkdirAll(etc, 0750); err != nil {
			t.Fatal(err)
		}
		victim := filepath.Join(etc, "victim")
		if err := writeHardeningFixtureFile(victim, []byte("preserve\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("victim", filepath.Join(etc, "cron.allow")); err != nil {
			t.Fatal(err)
		}
		if err := lockCrontabOn(host); err == nil {
			t.Fatal("symlink cron.allow was accepted")
		}
		root, name := hardeningFixtureRoot(t, victim)
		content, _ := root.ReadFile(name)
		if string(content) != "preserve\n" {
			t.Fatalf("symlink victim changed: %q", content)
		}
	})

	t.Run("parent", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(host.root, "etc")); err != nil {
			t.Fatal(err)
		}
		if err := host.write("/etc/sysctl.d/policy.conf", []byte("unsafe\n"), 0600); err == nil {
			t.Fatal("symlink parent was accepted")
		}
		if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
			t.Fatalf("symlink parent target changed: entries=%v error=%v", entries, err)
		}
	})
}

func TestHardeningPolicyRejectsUnsafeParentDirectories(t *testing.T) {
	t.Run("unsafe ancestor leaves no child residue", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		ancestor, _ := host.path("/etc")
		if err := os.MkdirAll(ancestor, 0750); err != nil {
			t.Fatal(err)
		}
		if err := chmodHardeningFixture(ancestor, 0770); err != nil {
			t.Fatal(err)
		}
		if err := host.write("/etc/sysctl.d/policy.conf", []byte("policy\n"), 0600); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Fatalf("unsafe ancestor result: %v", err)
		}
		child, _ := host.path("/etc/sysctl.d")
		if _, err := os.Lstat(child); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("child residue was created below unsafe ancestor: %v", err)
		}
	})

	t.Run("group writable", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		directory, _ := host.path("/etc/sysctl.d")
		if err := os.MkdirAll(directory, 0750); err != nil {
			t.Fatal(err)
		}
		if err := chmodHardeningFixture(directory, 0770); err != nil {
			t.Fatal(err)
		}
		if err := host.write("/etc/sysctl.d/policy.conf", []byte("policy\n"), 0600); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Fatalf("unsafe parent result: %v", err)
		}
	})

	t.Run("unexpected group owner", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		directory, _ := host.path("/etc/sysctl.d")
		if err := os.MkdirAll(directory, 0750); err != nil {
			t.Fatal(err)
		}
		setAlternateTestGroup(t, directory, host.expectedRootGID)
		if err := host.write("/etc/sysctl.d/policy.conf", []byte("policy\n"), 0600); err == nil || !strings.Contains(err.Error(), "ownership") {
			t.Fatalf("unsafe parent result: %v", err)
		}
	})
}

func TestRemoveLoadedModulesSkipsAbsentAndPropagatesLoadedFailure(t *testing.T) {
	calls := 0
	injected := errors.New("rmmod failed")
	host := hardeningTestHost(t, hardeningExecutor{run: func(name string, args ...string) error {
		calls++
		if name != "rmmod" || len(args) != 1 || args[0] != "dccp" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return injected
	}})
	proc, _ := host.path("/proc")
	if err := os.MkdirAll(proc, 0750); err != nil {
		t.Fatal(err)
	}
	modules, _ := host.path("/proc/modules")
	if err := writeHardeningFixtureFile(modules, []byte("dccp 1 0 - Live 0x0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeLoadedModules(host, []string{"sctp"}); err != nil || calls != 0 {
		t.Fatalf("absent module error=%v calls=%d", err, calls)
	}
	if err := removeLoadedModules(host, []string{"dccp"}); !errors.Is(err, injected) || calls != 1 {
		t.Fatalf("loaded module error=%v calls=%d", err, calls)
	}
}

func TestApplySysctlRollsBackFileAndRuntimeAfterApplyFailure(t *testing.T) {
	injected := errors.New("sysctl apply failed")
	restoreCalls := 0
	host := hardeningTestHost(t, hardeningExecutor{
		run: func(name string, args ...string) error {
			if name != "sysctl" {
				t.Fatalf("unexpected command %s", name)
			}
			if len(args) > 0 && args[0] == "-p" {
				return injected
			}
			if len(args) > 0 && args[0] == "-w" {
				restoreCalls++
				return nil
			}
			t.Fatalf("unexpected sysctl arguments: %v", args)
			return nil
		},
		output: func(name string, args ...string) ([]byte, error) {
			if name != "sysctl" || len(args) != 2 || args[0] != "-n" {
				t.Fatalf("unexpected output command: %s %v", name, args)
			}
			return []byte("9\n"), nil
		},
	})
	bpfControl, _ := host.path("/proc/sys/net/core/bpf_jit_harden")
	if err := os.MkdirAll(filepath.Dir(bpfControl), 0750); err != nil {
		t.Fatal(err)
	}
	if err := writeHardeningFixtureFile(bpfControl, []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := applySysctlOn(host); !errors.Is(err, injected) {
		t.Fatalf("error=%v, want apply failure", err)
	}
	policy, _ := host.path("/etc/sysctl.d/99-syswarden-cis-level2.conf")
	if _, err := os.Lstat(policy); !os.IsNotExist(err) {
		t.Fatalf("failed sysctl policy was retained: %v", err)
	}
	if restoreCalls != 18 {
		t.Fatalf("runtime restore calls=%d, want 18", restoreCalls)
	}
}

func TestNormalizeCISSSHConfigurationIsGlobalAndIdempotent(t *testing.T) {
	input := "X11Forwarding yes\nInclude /etc/ssh/sshd_config.d/*.conf\nMatch User backup\n  MaxAuthTries 9\n"
	first, err := normalizeCISSSHConfiguration(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := normalizeCISSSHConfiguration(first)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("normalization is not idempotent:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	policy := strings.Index(first, "X11Forwarding no")
	include := strings.Index(first, "Include ")
	match := strings.Index(first, "Match ")
	if policy < 0 || policy > include || policy > match {
		t.Fatalf("CIS policy is not in global first-value scope:\n%s", first)
	}
	if strings.Count(first, "X11Forwarding no") != 1 || strings.Count(first, "MaxAuthTries 4") != 1 {
		t.Fatalf("CIS directives are not unique:\n%s", first)
	}
	if _, err := normalizeCISSSHConfiguration("# --- SYSWARDEN CIS SSH HARDENING ---\nX11Forwarding no\n"); err == nil {
		t.Fatal("unterminated managed block was accepted")
	}
}

func TestAutomaticUpdatesBranchesAreExplicit(t *testing.T) {
	t.Run("Alpine documented skip", func(t *testing.T) {
		commands := 0
		host := hardeningTestHost(t, hardeningExecutor{
			run:    func(string, ...string) error { commands++; return nil },
			output: func(string, ...string) ([]byte, error) { commands++; return nil, nil },
		})
		writeOSReleaseFixture(t, host, "alpine")
		if err := enableAutomaticSecurityUpdatesOn(host); err != nil || commands != 0 {
			t.Fatalf("error=%v commands=%d", err, commands)
		}
	})

	t.Run("unknown distribution", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		writeOSReleaseFixture(t, host, "gentoo")
		if err := enableAutomaticSecurityUpdatesOn(host); err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("unexpected result: %v", err)
		}
	})
}

func TestGroupAndLogrotateTransformContracts(t *testing.T) {
	groups, err := parseGroupMembership([]byte("root:x:0:\nsudo:x:27:root,alice\n"))
	if err != nil || !containsString(groups["sudo"], "alice") {
		t.Fatalf("group parse=%v error=%v", groups, err)
	}
	if _, err := parseGroupMembership([]byte("malformed\n")); err == nil {
		t.Fatal("malformed group database was accepted")
	}
	content, changed, err := hardenLogrotateCreateRules([]byte("{\n  create 0644 root adm\n}\n"), "create 0640 root adm")
	if err != nil {
		t.Fatal(err)
	}
	if !changed || strings.Contains(string(content), "0644") || !strings.Contains(string(content), "  create 0640 root adm") {
		t.Fatalf("unexpected logrotate transform: changed=%t content=%q", changed, content)
	}
}

func TestClassifyHardeningRuntimeMatrix(t *testing.T) {
	hostMap := "0 0 4294967295\n"
	rootlessMap := "0 1000 1\n1 524288 65536\n"
	tests := []struct {
		name         string
		evidence     hardeningRuntimeEvidence
		wantState    hardeningExecutionState
		wantManager  string
		wantRootless bool
		wantError    string
	}{
		{name: "ordinary execution", evidence: hardeningRuntimeEvidence{}, wantState: hardeningExecutionActive},
		{name: "host package without init", evidence: hardeningRuntimeEvidence{packageInstall: true, effectiveUID: 0, uidMap: hostMap, initName: "sh", initExecutable: "/usr/bin/sh"}, wantState: hardeningExecutionNotApplicable},
		{name: "rootless package without init", evidence: hardeningRuntimeEvidence{packageInstall: true, effectiveUID: 0, uidMap: rootlessMap, initName: "sh", initExecutable: "/usr/bin/sh"}, wantState: hardeningExecutionNotApplicable, wantRootless: true},
		{name: "rootless systemd", evidence: hardeningRuntimeEvidence{packageInstall: true, effectiveUID: 0, uidMap: rootlessMap, initName: "systemd", initExecutable: "/usr/lib/systemd/systemd", systemdActive: true}, wantState: hardeningExecutionActive, wantManager: "systemd", wantRootless: true},
		{name: "rootless OpenRC", evidence: hardeningRuntimeEvidence{packageInstall: true, effectiveUID: 0, uidMap: rootlessMap, initName: "init", initExecutable: "/bin/busybox", openRCActive: true}, wantState: hardeningExecutionActive, wantManager: "openrc", wantRootless: true},
		{name: "non-root hook", evidence: hardeningRuntimeEvidence{packageInstall: true, effectiveUID: 1000, uidMap: rootlessMap}, wantError: "effective UID"},
		{name: "malformed uid map", evidence: hardeningRuntimeEvidence{packageInstall: true, effectiveUID: 0, uidMap: "0 1000\n"}, wantError: "malformed uid_map"},
		{name: "systemd marker mismatch", evidence: hardeningRuntimeEvidence{packageInstall: true, effectiveUID: 0, uidMap: rootlessMap, initName: "sh", initExecutable: "/usr/bin/sh", systemdActive: true}, wantError: "systemd runtime marker"},
		{name: "systemd executable mismatch", evidence: hardeningRuntimeEvidence{packageInstall: true, effectiveUID: 0, uidMap: rootlessMap, initName: "systemd", initExecutable: "/usr/bin/sh", systemdActive: true}, wantError: "systemd runtime marker"},
		{name: "both managers", evidence: hardeningRuntimeEvidence{packageInstall: true, effectiveUID: 0, uidMap: rootlessMap, initName: "systemd", initExecutable: "/usr/lib/systemd/systemd", systemdActive: true, openRCActive: true}, wantError: "both active"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := classifyHardeningRuntime(test.evidence)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error=%v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if decision.state != test.wantState || decision.manager != test.wantManager || decision.rootUIDRemapped != test.wantRootless {
				t.Fatalf("decision=%+v", decision)
			}
		})
	}

	host := hardeningTestHost(t, hardeningExecutor{})
	host.executionProbe = func() (hardeningExecutionDecision, error) {
		return hardeningExecutionDecision{state: hardeningExecutionDeferred}, nil
	}
	if _, _, err := hardeningKernelRuntimeApplicable(host, "test control"); err == nil || !strings.Contains(err.Error(), "cannot be deferred") {
		t.Fatalf("unattested deferred state was accepted: %v", err)
	}
}

func TestRuntimeMarkerInspectionRejectsUnsafeState(t *testing.T) {
	ownerRoot := t.TempDir()
	ownerInfo, err := os.Stat(ownerRoot)
	if err != nil {
		t.Fatal(err)
	}
	ownerStat, ok := ownerInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("fixture ownership is unavailable")
	}
	owner := ownerStat.Uid
	t.Run("trusted directory and file", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(root, "runtime")
		if err := os.Mkdir(directory, 0750); err != nil {
			t.Fatal(err)
		}
		if present, err := inspectRuntimeDirectory(directory, owner); err != nil || !present {
			t.Fatalf("directory present=%t error=%v", present, err)
		}
		marker := filepath.Join(root, "marker")
		if err := writeHardeningFixtureFile(marker, []byte("default\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if present, err := inspectRuntimeFile(marker, owner); err != nil || !present {
			t.Fatalf("file present=%t error=%v", present, err)
		}
	})
	t.Run("writable and symlink markers", func(t *testing.T) {
		root := t.TempDir()
		writable := filepath.Join(root, "writable")
		if err := os.Mkdir(writable, 0750); err != nil {
			t.Fatal(err)
		}
		if err := chmodHardeningFixture(writable, 0777); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectRuntimeDirectory(writable, owner); err == nil {
			t.Fatal("group-writable runtime directory was accepted")
		}
		target := filepath.Join(root, "target")
		if err := writeHardeningFixtureFile(target, []byte("x\n"), 0644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "link")
		if err := os.Symlink("target", link); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectRuntimeFile(link, owner); err == nil {
			t.Fatal("symlink runtime marker was accepted")
		}
		if _, err := inspectRuntimeFile(target, owner^1); err == nil {
			t.Fatal("unexpected-owner runtime marker was accepted")
		}
	})
}

func TestOpenRCRuntimeDirectoryAttestationAcceptsOnlyExactStandardModes(t *testing.T) {
	ownerRoot := t.TempDir()
	ownerInfo, err := os.Stat(ownerRoot)
	if err != nil {
		t.Fatal(err)
	}
	ownerStat, ok := ownerInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("fixture ownership is unavailable")
	}

	for _, mode := range []os.FileMode{0755, 0775} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "openrc")
			if err := os.Mkdir(path, 0750); err != nil {
				t.Fatal(err)
			}
			if err := chmodHardeningFixture(path, mode); err != nil {
				t.Fatal(err)
			}
			proof, present, err := beginHardeningOpenRCRuntimeDirectoryAttestation(
				path,
				ownerStat.Uid,
				ownerStat.Gid,
			)
			if err != nil || !present || proof == nil {
				t.Fatalf("proof=%v present=%t error=%v", proof, present, err)
			}
			defer func() { _ = proof.directory.Close() }()
			if err := proof.reattest(ownerStat.Uid, ownerStat.Gid); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOpenRCRuntimeDirectoryAttestationRejectsUnsafeState(t *testing.T) {
	ownerRoot := t.TempDir()
	ownerInfo, err := os.Stat(ownerRoot)
	if err != nil {
		t.Fatal(err)
	}
	ownerStat, ok := ownerInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("fixture ownership is unavailable")
	}

	tests := []struct {
		name        string
		mode        os.FileMode
		expectedUID uint32
		expectedGID uint32
	}{
		{name: "mode 0770", mode: 0770, expectedUID: ownerStat.Uid, expectedGID: ownerStat.Gid},
		{name: "mode 0777", mode: 0777, expectedUID: ownerStat.Uid, expectedGID: ownerStat.Gid},
		{name: "sticky", mode: 0775 | os.ModeSticky, expectedUID: ownerStat.Uid, expectedGID: ownerStat.Gid},
		{name: "setuid", mode: 0775 | os.ModeSetuid, expectedUID: ownerStat.Uid, expectedGID: ownerStat.Gid},
		{name: "setgid", mode: 0775 | os.ModeSetgid, expectedUID: ownerStat.Uid, expectedGID: ownerStat.Gid},
		{name: "wrong owner", mode: 0775, expectedUID: ownerStat.Uid ^ 1, expectedGID: ownerStat.Gid},
		{name: "wrong group", mode: 0775, expectedUID: ownerStat.Uid, expectedGID: ownerStat.Gid ^ 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "openrc")
			if err := os.Mkdir(path, 0750); err != nil {
				t.Fatal(err)
			}
			if err := chmodHardeningFixture(path, test.mode); err != nil {
				t.Fatal(err)
			}
			proof, present, err := beginHardeningOpenRCRuntimeDirectoryAttestation(
				path,
				test.expectedUID,
				test.expectedGID,
			)
			if proof != nil {
				_ = proof.directory.Close()
			}
			if err == nil || present || proof != nil {
				t.Fatalf("unsafe OpenRC runtime accepted: proof=%v present=%t error=%v", proof, present, err)
			}
		})
	}

	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		if err := os.Mkdir(target, 0750); err != nil {
			t.Fatal(err)
		}
		if err := chmodHardeningFixture(target, 0775); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "openrc")
		if err := os.Symlink("target", path); err != nil {
			t.Fatal(err)
		}
		if proof, present, err := beginHardeningOpenRCRuntimeDirectoryAttestation(
			path,
			ownerStat.Uid,
			ownerStat.Gid,
		); err == nil || present || proof != nil {
			t.Fatalf("symlink OpenRC runtime accepted: proof=%v present=%t error=%v", proof, present, err)
		}
	})

	t.Run("regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "openrc")
		if err := writeHardeningFixtureFile(path, []byte("not a directory\n"), 0755); err != nil {
			t.Fatal(err)
		}
		if proof, present, err := beginHardeningOpenRCRuntimeDirectoryAttestation(
			path,
			ownerStat.Uid,
			ownerStat.Gid,
		); err == nil || present || proof != nil {
			t.Fatalf("regular-file OpenRC runtime accepted: proof=%v present=%t error=%v", proof, present, err)
		}
	})

	t.Run("generic policy remains strict", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "systemd")
		if err := os.Mkdir(path, 0750); err != nil {
			t.Fatal(err)
		}
		if err := chmodHardeningFixture(path, 0775); err != nil {
			t.Fatal(err)
		}
		if present, err := inspectRuntimeDirectory(path, ownerStat.Uid); err == nil || present {
			t.Fatalf("generic runtime policy accepted mode 0775: present=%t error=%v", present, err)
		}
	})
}

func TestOpenRCRuntimeDirectoryProofRejectsReplacementAndModeDrift(t *testing.T) {
	ownerRoot := t.TempDir()
	ownerInfo, err := os.Stat(ownerRoot)
	if err != nil {
		t.Fatal(err)
	}
	ownerStat, ok := ownerInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("fixture ownership is unavailable")
	}

	t.Run("replacement", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "openrc")
		if err := os.Mkdir(path, 0750); err != nil {
			t.Fatal(err)
		}
		if err := chmodHardeningFixture(path, 0775); err != nil {
			t.Fatal(err)
		}
		proof, present, err := beginHardeningOpenRCRuntimeDirectoryAttestation(
			path,
			ownerStat.Uid,
			ownerStat.Gid,
		)
		if err != nil || !present || proof == nil {
			t.Fatalf("proof=%v present=%t error=%v", proof, present, err)
		}
		defer func() { _ = proof.directory.Close() }()
		original := filepath.Join(root, "original")
		if err := os.Rename(path, original); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0750); err != nil {
			t.Fatal(err)
		}
		if err := chmodHardeningFixture(path, 0775); err != nil {
			t.Fatal(err)
		}
		if err := proof.reattest(ownerStat.Uid, ownerStat.Gid); err == nil {
			t.Fatal("replacement OpenRC runtime was accepted")
		}
	})

	t.Run("mode drift", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "openrc")
		if err := os.Mkdir(path, 0750); err != nil {
			t.Fatal(err)
		}
		if err := chmodHardeningFixture(path, 0775); err != nil {
			t.Fatal(err)
		}
		proof, present, err := beginHardeningOpenRCRuntimeDirectoryAttestation(
			path,
			ownerStat.Uid,
			ownerStat.Gid,
		)
		if err != nil || !present || proof == nil {
			t.Fatalf("proof=%v present=%t error=%v", proof, present, err)
		}
		defer func() { _ = proof.directory.Close() }()
		if err := chmodHardeningFixture(path, 0777); err != nil {
			t.Fatal(err)
		}
		if err := proof.reattest(ownerStat.Uid, ownerStat.Gid); err == nil {
			t.Fatal("OpenRC runtime mode drift was accepted")
		}
	})
}

func TestSysctlPersistentPolicyWhenKernelRuntimeIsOutsideNamespace(t *testing.T) {
	commands := 0
	host := hardeningTestHost(t, hardeningExecutor{
		run:    func(string, ...string) error { commands++; return nil },
		output: func(string, ...string) ([]byte, error) { commands++; return nil, nil },
	})
	host.executionProbe = func() (hardeningExecutionDecision, error) {
		return hardeningExecutionDecision{state: hardeningExecutionActive, rootUIDRemapped: true}, nil
	}
	for path, value := range map[string]string{
		"/proc/sys/net/core/bpf_jit_harden":          "2\n",
		"/proc/sys/kernel/unprivileged_bpf_disabled": "2\n",
		"/proc/sys/kernel/yama/ptrace_scope":         "3\n",
	} {
		physical, _ := host.path(path)
		if err := os.MkdirAll(filepath.Dir(physical), 0750); err != nil {
			t.Fatal(err)
		}
		if err := writeHardeningFixtureFile(physical, []byte(value), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := applySysctlOn(host); err != nil {
		t.Fatal(err)
	}
	if commands != 0 {
		t.Fatalf("kernel command count=%d, want 0", commands)
	}
	policy, _ := host.path("/etc/sysctl.d/99-syswarden-cis-level2.conf")
	content, err := readHardeningFixtureFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "kernel.unprivileged_bpf_disabled = 2") ||
		!strings.Contains(string(content), "kernel.yama.ptrace_scope = 3") {
		t.Fatalf("strong runtime values were not preserved:\n%s", content)
	}
	info, err := os.Stat(policy)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("policy mode=%v error=%v", info.Mode(), err)
	}
}

func TestSystemdPersistentPoliciesOfflineAndActive(t *testing.T) {
	offline := hardeningExecutionDecision{state: hardeningExecutionNotApplicable, packageInstall: true, rootUIDRemapped: true}

	t.Run("offline coredump consumer writes policy without activation", func(t *testing.T) {
		calls := []string{}
		host := hardeningTestHost(t, hardeningExecutor{
			run: func(name string, args ...string) error {
				calls = append(calls, automaticUpdateCommandKey(name, args...))
				return nil
			},
			output: func(name string, args ...string) ([]byte, error) {
				calls = append(calls, automaticUpdateCommandKey(name, args...))
				return []byte("[Coredump]\nStorage=none\nProcessSizeMax=0\n"), nil
			},
		})
		host.executionProbe = func() (hardeningExecutionDecision, error) { return offline, nil }
		writeSystemdStructuralFixture(t, host, true)
		if err := restrictCoreDumpsOn(host); err != nil {
			t.Fatal(err)
		}
		policy, _ := host.path("/etc/systemd/coredump.conf.d/99-syswarden.conf")
		if _, err := os.Stat(policy); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(calls, "|"), "systemctl") {
			t.Fatalf("offline systemd activation was attempted: %v", calls)
		}
	})

	t.Run("base systemd without coredump consumer is not applicable", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{
			run:    func(string, ...string) error { t.Fatal("runtime command called"); return nil },
			output: func(string, ...string) ([]byte, error) { t.Fatal("validator called"); return nil, nil },
		})
		host.executionProbe = func() (hardeningExecutionDecision, error) { return offline, nil }
		writeSystemdStructuralFixture(t, host, false)
		if err := restrictCoreDumpsOn(host); err != nil {
			t.Fatal(err)
		}
		limits, _ := host.path("/etc/security/limits.d/99-syswarden-cis.conf")
		if _, err := os.Stat(limits); err != nil {
			t.Fatal(err)
		}
		policy, _ := host.path("/etc/systemd/coredump.conf.d/99-syswarden.conf")
		if _, err := os.Stat(policy); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("coredump policy was claimed without a consumer: %v", err)
		}
	})

	t.Run("partial coredump consumer fails closed", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		host.executionProbe = func() (hardeningExecutionDecision, error) { return offline, nil }
		writeSystemdStructuralFixture(t, host, false)
		binary, _ := host.path("/usr/lib/systemd/systemd-coredump")
		if err := writeHardeningFixtureFile(binary, []byte("fixture\n"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := restrictCoreDumpsOn(host); err == nil || !strings.Contains(err.Error(), "partial") {
			t.Fatalf("partial coredump surface result: %v", err)
		}
	})

	t.Run("non-executable systemd consumer fails closed", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		host.executionProbe = func() (hardeningExecutionDecision, error) { return offline, nil }
		writeSystemdStructuralFixture(t, host, true)
		journald, _ := host.path("/usr/lib/systemd/systemd-journald")
		if err := chmodHardeningFixture(journald, 0644); err != nil {
			t.Fatal(err)
		}
		if err := restrictCoreDumpsOn(host); err == nil || !strings.Contains(err.Error(), "owner-executable") {
			t.Fatalf("non-executable consumer result: %v", err)
		}
	})

	t.Run("active coredump policy reloads systemd", func(t *testing.T) {
		calls := []string{}
		host := hardeningTestHost(t, hardeningExecutor{
			run: func(name string, args ...string) error {
				calls = append(calls, automaticUpdateCommandKey(name, args...))
				return nil
			},
			output: func(string, ...string) ([]byte, error) {
				return []byte("Storage=none\nProcessSizeMax=0\n"), nil
			},
		})
		host.executionProbe = func() (hardeningExecutionDecision, error) {
			return hardeningExecutionDecision{state: hardeningExecutionActive, manager: "systemd"}, nil
		}
		host.systemdRuntimeProbe = func() (bool, error) { return true, nil }
		writeSystemdStructuralFixture(t, host, true)
		if err := restrictCoreDumpsOn(host); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(calls, "|"), "systemctl daemon-reload") {
			t.Fatalf("active systemd reload was not called: %v", calls)
		}
	})

	t.Run("offline coredump validation failure rolls back", func(t *testing.T) {
		injected := errors.New("invalid coredump policy")
		host := hardeningTestHost(t, hardeningExecutor{output: func(string, ...string) ([]byte, error) { return nil, injected }})
		host.executionProbe = func() (hardeningExecutionDecision, error) { return offline, nil }
		writeSystemdStructuralFixture(t, host, true)
		if err := restrictCoreDumpsOn(host); !errors.Is(err, injected) {
			t.Fatalf("validation result: %v", err)
		}
		policy, _ := host.path("/etc/systemd/coredump.conf.d/99-syswarden.conf")
		if _, err := os.Stat(policy); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("invalid coredump policy was retained: %v", err)
		}
	})

	t.Run("offline journald writes policy without restart", func(t *testing.T) {
		calls := []string{}
		probes := 0
		host := hardeningTestHost(t, hardeningExecutor{
			run: func(name string, args ...string) error {
				calls = append(calls, automaticUpdateCommandKey(name, args...))
				return nil
			},
			output: func(name string, args ...string) ([]byte, error) {
				calls = append(calls, automaticUpdateCommandKey(name, args...))
				return []byte("[Journal]\nForwardToSyslog=yes\n"), nil
			},
		})
		host.executionProbe = func() (hardeningExecutionDecision, error) { return offline, nil }
		host.processProbe = func(name string) (bool, error) {
			if name != "systemd-journald" {
				t.Fatalf("unexpected process probe %s", name)
			}
			probes++
			return false, nil
		}
		writeSystemdStructuralFixture(t, host, false)
		if err := applyLogAntiForgingOn(host); err != nil {
			t.Fatal(err)
		}
		policy, _ := host.path("/etc/systemd/journald.conf.d/99-syswarden.conf")
		if _, err := os.Stat(policy); err != nil {
			t.Fatal(err)
		}
		if probes != 2 || strings.Contains(strings.Join(calls, "|"), "systemctl") {
			t.Fatalf("offline journald probes=%d calls=%v", probes, calls)
		}
	})

	t.Run("active journald validates and restarts", func(t *testing.T) {
		calls := []string{}
		host := hardeningTestHost(t, hardeningExecutor{
			run: func(name string, args ...string) error {
				calls = append(calls, automaticUpdateCommandKey(name, args...))
				return nil
			},
			output: func(string, ...string) ([]byte, error) { return []byte("ForwardToSyslog=yes\n"), nil },
		})
		host.executionProbe = func() (hardeningExecutionDecision, error) {
			return hardeningExecutionDecision{state: hardeningExecutionActive, manager: "systemd"}, nil
		}
		host.systemdRuntimeProbe = func() (bool, error) { return true, nil }
		host.processProbe = func(string) (bool, error) { t.Fatal("offline process probe called"); return false, nil }
		writeSystemdStructuralFixture(t, host, false)
		if err := applyLogAntiForgingOn(host); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(calls, "|"), "systemctl restart systemd-journald.service") {
			t.Fatalf("journald restart was not called: %v", calls)
		}
	})

	t.Run("journald appearing during offline publication rolls back", func(t *testing.T) {
		probes := 0
		host := hardeningTestHost(t, hardeningExecutor{output: func(string, ...string) ([]byte, error) {
			return []byte("ForwardToSyslog=yes\n"), nil
		}})
		host.executionProbe = func() (hardeningExecutionDecision, error) { return offline, nil }
		host.processProbe = func(string) (bool, error) {
			probes++
			return probes == 2, nil
		}
		writeSystemdStructuralFixture(t, host, false)
		if err := applyLogAntiForgingOn(host); err == nil || !strings.Contains(err.Error(), "started during") {
			t.Fatalf("journald race result: %v", err)
		}
		policy, _ := host.path("/etc/systemd/journald.conf.d/99-syswarden.conf")
		if _, err := os.Stat(policy); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("raced journald policy was retained: %v", err)
		}
	})

	t.Run("systemd runtime probe errors fail closed", func(t *testing.T) {
		injected := errors.New("runtime probe failed")
		host := hardeningTestHost(t, hardeningExecutor{})
		host.executionProbe = func() (hardeningExecutionDecision, error) { return offline, nil }
		host.systemdRuntimeProbe = func() (bool, error) { return false, injected }
		writeSystemdStructuralFixture(t, host, false)
		if err := applyLogAntiForgingOn(host); !errors.Is(err, injected) {
			t.Fatalf("runtime probe result: %v", err)
		}
	})
}

func TestProfileImmutableCapabilityMatrix(t *testing.T) {
	const otherProfileFlag = 0x20
	mutableFlags := otherProfileFlag
	immutableFlags := otherProfileFlag | linuxImmutableFileFlag
	newHost := func(t *testing.T, state *profileTransactionTestState, decision hardeningExecutionDecision, capable bool) (hardeningHost, string) {
		t.Helper()
		host := hardeningTestHost(t, hardeningExecutor{})
		host.executionProbe = func() (hardeningExecutionDecision, error) {
			return decision, nil
		}
		host.capabilityProbe = func(uint) (bool, error) { return capable, nil }
		host.profileFlagsProbe = state.probe
		host.profileFlagsSet = state.set
		host.profileChmod = state.chmod
		profile, _ := host.path("/home/alice/.profile")
		if err := os.MkdirAll(filepath.Dir(profile), 0750); err != nil {
			t.Fatal(err)
		}
		if err := writeHardeningFixtureFile(profile, []byte("fixture\n"), 0644); err != nil {
			t.Fatal(err)
		}
		return host, profile
	}

	t.Run("mode only without capability", func(t *testing.T) {
		state := newProfileTransactionTestState(mutableFlags)
		host, profile := newHost(t, state, hardeningExecutionDecision{state: hardeningExecutionNotApplicable, rootUIDRemapped: true}, false)
		if err := lockUserProfilesOn(host); err != nil {
			t.Fatal(err)
		}
		info, _ := os.Stat(profile)
		if strings.Contains(strings.Join(state.calls, "|"), "probe") || info.Mode().Perm() != 0600 || state.flags != mutableFlags {
			t.Fatalf("calls=%v mode=%04o flags=%#x", state.calls, info.Mode().Perm(), state.flags)
		}
	})

	for _, initial := range []bool{false, true} {
		name := "initial mutable"
		if initial {
			name = "initial immutable"
		}
		t.Run(name, func(t *testing.T) {
			initialFlags := mutableFlags
			if initial {
				initialFlags = immutableFlags
			}
			state := newProfileTransactionTestState(initialFlags)
			host, profile := newHost(t, state, hardeningExecutionDecision{state: hardeningExecutionActive}, true)
			if err := lockUserProfilesOn(host); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(profile)
			if err != nil || info.Mode()&profileFileModeMask != 0600 || state.flags != immutableFlags {
				t.Fatalf("mode=%v flags=%#x error=%v calls=%v", info.Mode(), state.flags, err, state.calls)
			}
		})
	}

	t.Run("special mode bits are cleared on success", func(t *testing.T) {
		state := newProfileTransactionTestState(mutableFlags)
		host, profile := newHost(t, state, hardeningExecutionDecision{state: hardeningExecutionActive}, true)
		initialMode := os.FileMode(0644) | os.ModeSetuid
		if err := chmodHardeningFixture(profile, initialMode); err != nil {
			t.Fatal(err)
		}
		if err := lockUserProfilesOn(host); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(profile)
		if err != nil || info.Mode()&profileFileModeMask != 0600 {
			t.Fatalf("special mode survived hardening: mode=%v error=%v", info.Mode(), err)
		}
	})

	t.Run("special mode bits are restored on rollback", func(t *testing.T) {
		state := newProfileTransactionTestState(mutableFlags)
		cause := errors.New("set immutable failed")
		state.setFailures[immutableFlags] = []error{cause}
		host, profile := newHost(t, state, hardeningExecutionDecision{state: hardeningExecutionActive}, true)
		initialMode := os.FileMode(0644) | os.ModeSetuid
		if err := chmodHardeningFixture(profile, initialMode); err != nil {
			t.Fatal(err)
		}
		if err := lockUserProfilesOn(host); !errors.Is(err, cause) {
			t.Fatalf("cause was masked: %v", err)
		}
		info, err := os.Stat(profile)
		if err != nil || info.Mode()&profileFileModeMask != initialMode {
			t.Fatalf("special mode rollback=%v error=%v", info.Mode(), err)
		}
	})

	failureTests := []struct {
		name      string
		initial   bool
		configure func(*profileTransactionTestState, error)
	}{
		{
			name: "initial immutable probe",
			configure: func(state *profileTransactionTestState, cause error) {
				state.probeResults = []profileImmutableProbeResult{{err: cause}}
			},
		},
		{
			name:    "clear immutable flag",
			initial: true,
			configure: func(state *profileTransactionTestState, cause error) {
				state.setFailures[mutableFlags] = []error{cause}
			},
		},
		{
			name: "chmod after mutation",
			configure: func(state *profileTransactionTestState, cause error) {
				state.chmodFailures = []error{cause}
			},
		},
		{
			name: "set immutable flag after mutation",
			configure: func(state *profileTransactionTestState, cause error) {
				state.setFailures[immutableFlags] = []error{cause}
			},
		},
		{
			name: "final immutable attestation",
			configure: func(state *profileTransactionTestState, cause error) {
				state.probeResults = []profileImmutableProbeResult{
					{flags: mutableFlags},
					{flags: mutableFlags},
					{err: cause},
				}
			},
		},
	}
	for _, test := range failureTests {
		t.Run(test.name, func(t *testing.T) {
			initialFlags := mutableFlags
			if test.initial {
				initialFlags = immutableFlags
			}
			state := newProfileTransactionTestState(initialFlags)
			cause := errors.New("injected profile transaction failure")
			test.configure(state, cause)
			host, profile := newHost(t, state, hardeningExecutionDecision{state: hardeningExecutionActive}, true)
			infoBefore, err := os.Stat(profile)
			if err != nil {
				t.Fatal(err)
			}
			ownerBefore := *infoBefore.Sys().(*syscall.Stat_t)
			err = lockUserProfilesOn(host)
			if !errors.Is(err, cause) {
				t.Fatalf("transaction cause was masked: %v", err)
			}
			infoAfter, statErr := os.Stat(profile)
			ownerAfter := *infoAfter.Sys().(*syscall.Stat_t)
			if statErr != nil || infoAfter.Mode()&profileFileModeMask != 0644 || state.flags != initialFlags ||
				ownerAfter.Uid != ownerBefore.Uid || ownerAfter.Gid != ownerBefore.Gid {
				t.Fatalf("rollback mode=%v flags=%#x owner=%v error=%v calls=%v", infoAfter.Mode(), state.flags, ownerAfter, statErr, state.calls)
			}
		})
	}

	t.Run("rollback errors are aggregated", func(t *testing.T) {
		state := newProfileTransactionTestState(mutableFlags)
		cause := errors.New("set immutable failed")
		rollbackFailure := errors.New("rollback clear failed")
		state.setFailures[immutableFlags] = []error{cause}
		state.setFailures[mutableFlags] = []error{rollbackFailure}
		host, profile := newHost(t, state, hardeningExecutionDecision{state: hardeningExecutionActive}, true)
		err := lockUserProfilesOn(host)
		if !errors.Is(err, cause) || !errors.Is(err, rollbackFailure) {
			t.Fatalf("profile errors were not aggregated: %v", err)
		}
		info, statErr := os.Stat(profile)
		if statErr != nil || info.Mode()&profileFileModeMask != 0644 || state.flags != mutableFlags {
			t.Fatalf("rollback mode=%v flags=%#x error=%v", info.Mode(), state.flags, statErr)
		}
	})

	t.Run("path replacement cannot produce false success", func(t *testing.T) {
		state := newProfileTransactionTestState(mutableFlags)
		host, profile := newHost(t, state, hardeningExecutionDecision{state: hardeningExecutionActive}, true)
		originalPath := profile + ".original"
		replaced := false
		state.onSet = func(flags int) {
			if flags&linuxImmutableFileFlag == 0 || replaced {
				return
			}
			replaced = true
			if err := os.Rename(profile, originalPath); err != nil {
				t.Fatal(err)
			}
			if err := writeHardeningFixtureFile(profile, []byte("attacker\n"), 0666); err != nil {
				t.Fatal(err)
			}
			if err := chmodHardeningFixture(profile, 0666); err != nil {
				t.Fatal(err)
			}
		}
		if err := lockUserProfilesOn(host); err == nil || !strings.Contains(err.Error(), "changed") {
			t.Fatalf("path replacement result: %v", err)
		}
		original, err := os.Stat(originalPath)
		if err != nil || original.Mode()&profileFileModeMask != 0644 || state.flags != mutableFlags {
			t.Fatalf("pinned original rollback mode=%v flags=%#x error=%v", original.Mode(), state.flags, err)
		}
		attacker, err := os.Stat(profile)
		if err != nil || attacker.Mode().Perm() != 0666 {
			t.Fatalf("replacement was falsely hardened: mode=%v error=%v", attacker.Mode(), err)
		}
	})

	t.Run("host permission error fails closed", func(t *testing.T) {
		state := newProfileTransactionTestState(mutableFlags)
		state.setFailures[immutableFlags] = []error{syscall.EPERM}
		host, _ := newHost(t, state, hardeningExecutionDecision{state: hardeningExecutionActive}, true)
		if err := lockUserProfilesOn(host); !errors.Is(err, syscall.EPERM) {
			t.Fatalf("error=%v, want EPERM", err)
		}
	})
}

func TestRsyslogOfflineAndActiveContracts(t *testing.T) {
	newHost := func(t *testing.T, decision hardeningExecutionDecision, process func(string) (bool, error), run func(string, ...string) error) hardeningHost {
		t.Helper()
		host := hardeningTestHost(t, hardeningExecutor{run: run})
		host.executionProbe = func() (hardeningExecutionDecision, error) { return decision, nil }
		host.processProbe = process
		directory, _ := host.path("/etc/rsyslog.d")
		if err := os.MkdirAll(directory, 0750); err != nil {
			t.Fatal(err)
		}
		return host
	}
	offline := hardeningExecutionDecision{state: hardeningExecutionNotApplicable, packageInstall: true, rootUIDRemapped: true}

	t.Run("offline absent daemon", func(t *testing.T) {
		probes := 0
		commands := []string{}
		host := newHost(t, offline, func(string) (bool, error) { probes++; return false, nil }, func(name string, args ...string) error {
			commands = append(commands, strings.Join(append([]string{name}, args...), " "))
			return nil
		})
		if err := applyLogAntiForgingOn(host); err != nil {
			t.Fatal(err)
		}
		if probes != 2 || strings.Join(commands, "|") != "rsyslogd -N1" {
			t.Fatalf("probes=%d commands=%v", probes, commands)
		}
		policy, _ := host.path("/etc/rsyslog.d/99-syswarden-antiforging.conf")
		if _, err := os.Stat(policy); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("offline running daemon", func(t *testing.T) {
		host := newHost(t, offline, func(string) (bool, error) { return true, nil }, func(string, ...string) error { t.Fatal("validator called"); return nil })
		if err := applyLogAntiForgingOn(host); err == nil || !strings.Contains(err.Error(), "running without") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("daemon appears after publication", func(t *testing.T) {
		probes := 0
		host := newHost(t, offline, func(string) (bool, error) { probes++; return probes == 2, nil }, func(string, ...string) error { return nil })
		if err := applyLogAntiForgingOn(host); err == nil || !strings.Contains(err.Error(), "started during") {
			t.Fatalf("error=%v", err)
		}
		policy, _ := host.path("/etc/rsyslog.d/99-syswarden-antiforging.conf")
		if _, err := os.Stat(policy); !os.IsNotExist(err) {
			t.Fatalf("raced policy was not rolled back: %v", err)
		}
	})

	t.Run("probe error", func(t *testing.T) {
		injected := errors.New("probe failed")
		host := newHost(t, offline, func(string) (bool, error) { return false, injected }, func(string, ...string) error { return nil })
		if err := applyLogAntiForgingOn(host); !errors.Is(err, injected) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("validation rollback", func(t *testing.T) {
		injected := errors.New("invalid rsyslog")
		host := newHost(t, offline, func(string) (bool, error) { return false, nil }, func(string, ...string) error { return injected })
		if err := applyLogAntiForgingOn(host); !errors.Is(err, injected) {
			t.Fatalf("error=%v", err)
		}
		policy, _ := host.path("/etc/rsyslog.d/99-syswarden-antiforging.conf")
		if _, err := os.Stat(policy); !os.IsNotExist(err) {
			t.Fatalf("invalid policy was not rolled back: %v", err)
		}
	})

	t.Run("active restart failure", func(t *testing.T) {
		injected := errors.New("restart failed")
		host := newHost(t, hardeningExecutionDecision{state: hardeningExecutionActive}, nil, func(name string, args ...string) error {
			if name == "systemctl" {
				return injected
			}
			return nil
		})
		if err := applyLogAntiForgingOn(host); !errors.Is(err, injected) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestAutomaticUpdateTimerActivationMatrix(t *testing.T) {
	const logical = "/etc/syswarden-test/automatic-updates.conf"
	policy := []byte("policy = enabled\n")
	timers := []string{"one.timer", "two.timer"}
	offline := hardeningExecutionDecision{state: hardeningExecutionNotApplicable, packageInstall: true, rootUIDRemapped: true}
	active := hardeningExecutionDecision{state: hardeningExecutionActive}

	newFixture := func(t *testing.T, manager *automaticUpdateTestManager, original []byte, mode os.FileMode) (hardeningHost, string, hardeningFileSnapshot) {
		t.Helper()
		host := hardeningTestHost(t, hardeningExecutor{run: manager.run, status: manager.status})
		physical, err := host.path(logical)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(physical), 0750); err != nil {
			t.Fatal(err)
		}
		if original != nil {
			if err := writeHardeningFixtureFile(physical, original, mode); err != nil {
				t.Fatal(err)
			}
		}
		unitDirectory, err := host.path("/usr/lib/systemd/system")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(unitDirectory, 0750); err != nil {
			t.Fatal(err)
		}
		for _, timer := range timers {
			if err := writeHardeningFixtureFile(filepath.Join(unitDirectory, timer), []byte("[Timer]\nOnCalendar=daily\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		snapshot, err := host.snapshot(logical)
		if err != nil {
			t.Fatal(err)
		}
		return host, physical, snapshot
	}
	assertMissingConfig := func(t *testing.T, physical string) {
		t.Helper()
		if _, err := os.Lstat(physical); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("configuration was not removed during rollback: %v", err)
		}
	}
	assertExistingConfig := func(t *testing.T, physical string, content []byte, mode os.FileMode, owner syscall.Stat_t) {
		t.Helper()
		current, err := readHardeningFixtureFile(physical)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(physical)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if string(current) != string(content) || info.Mode().Perm() != mode.Perm() || !ok || stat.Uid != owner.Uid || stat.Gid != owner.Gid {
			t.Fatalf("configuration rollback content=%q mode=%04o owner=%v", current, info.Mode().Perm(), info.Sys())
		}
	}
	assertTimerState := func(t *testing.T, manager *automaticUpdateTestManager, enabled, running map[string]bool) {
		t.Helper()
		for _, timer := range timers {
			if manager.enabled[timer] != enabled[timer] || manager.active[timer] != running[timer] {
				t.Fatalf("timer %s enabled=%t active=%t, want enabled=%t active=%t; calls=%v", timer, manager.enabled[timer], manager.active[timer], enabled[timer], running[timer], manager.calls)
			}
		}
	}

	t.Run("offline enables without claiming runtime activation", func(t *testing.T) {
		manager := newAutomaticUpdateTestManager()
		host, physical, snapshot := newFixture(t, manager, nil, 0)
		host.executor = hardeningExecutor{
			run: func(name string, args ...string) error {
				t.Fatalf("offline executor call: %s %v", name, args)
				return nil
			},
			status: func(name string, args ...string) ([]byte, int, error) {
				t.Fatalf("offline executor status call: %s %v", name, args)
				return nil, 0, nil
			},
		}
		if err := applyAutomaticUpdatePolicy(host, logical, snapshot, policy, offline, timers...); err != nil {
			t.Fatal(err)
		}
		content, err := readHardeningFixtureFile(physical)
		if err != nil || string(content) != string(policy) {
			t.Fatalf("policy=%q error=%v", content, err)
		}
		for _, timer := range timers {
			link, _ := host.path("/etc/systemd/system/timers.target.wants/" + timer)
			target, err := os.Readlink(link)
			if err != nil || target != "/usr/lib/systemd/system/"+timer {
				t.Fatalf("offline link %s target=%q error=%v", timer, target, err)
			}
		}
	})

	t.Run("active enables starts and attests", func(t *testing.T) {
		manager := newAutomaticUpdateTestManager()
		manager.enabled["one.timer"] = true
		manager.active["one.timer"] = true
		host, _, snapshot := newFixture(t, manager, nil, 0)
		if err := applyAutomaticUpdatePolicy(host, logical, snapshot, policy, active, timers...); err != nil {
			t.Fatal(err)
		}
		assertTimerState(t, manager,
			map[string]bool{"one.timer": true, "two.timer": true},
			map[string]bool{"one.timer": true, "two.timer": true})
	})

	t.Run("success corrects an untrusted existing group owner", func(t *testing.T) {
		manager := newAutomaticUpdateTestManager()
		original := []byte("operator = replaced\n")
		host, physical, _ := newFixture(t, manager, original, 0644)
		setAlternateTestGroup(t, physical, host.expectedRootGID)
		snapshot, err := host.snapshot(logical)
		if err != nil {
			t.Fatal(err)
		}
		if err := applyAutomaticUpdatePolicy(host, logical, snapshot, policy, offline, timers...); err != nil {
			t.Fatal(err)
		}
		current, err := host.snapshot(logical)
		if err != nil {
			t.Fatal(err)
		}
		if !hardeningSnapshotMatches(current, policy, 0600, host.expectedRootUID, host.expectedRootGID) {
			t.Fatalf("published policy retained unsafe ownership: %+v", current.identity)
		}
	})

	t.Run("rollback restores exact untrusted ownership and mode", func(t *testing.T) {
		manager := newAutomaticUpdateTestManager()
		cause := errors.New("second timer enable failed")
		manager.runFailures["systemctl enable two.timer"] = []error{cause}
		original := []byte("operator = retained\n")
		host, physical, _ := newFixture(t, manager, original, 0640)
		alternateGroup := setAlternateTestGroup(t, physical, host.expectedRootGID)
		snapshot, err := host.snapshot(logical)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(physical)
		if err != nil {
			t.Fatal(err)
		}
		owner := *info.Sys().(*syscall.Stat_t)
		if err := applyAutomaticUpdatePolicy(host, logical, snapshot, policy, active, timers...); !errors.Is(err, cause) {
			t.Fatalf("cause was masked: %v", err)
		}
		assertExistingConfig(t, physical, original, 0640, owner)
		restored, err := os.Stat(physical)
		if err != nil || int(restored.Sys().(*syscall.Stat_t).Gid) != alternateGroup {
			t.Fatalf("original group was not restored: info=%v error=%v", restored, err)
		}
	})

	failureTests := []struct {
		name      string
		decision  hardeningExecutionDecision
		configure func(*automaticUpdateTestManager, error)
	}{
		{
			name:     "second enable fails after mutation",
			decision: active,
			configure: func(manager *automaticUpdateTestManager, cause error) {
				manager.runFailures["systemctl enable two.timer"] = []error{cause}
			},
		},
		{
			name:     "second enablement attestation fails",
			decision: active,
			configure: func(manager *automaticUpdateTestManager, _ error) {
				manager.statusOverrides["systemctl is-enabled two.timer"] = []automaticUpdateStatusResult{
					{output: "disabled\n", status: 1},
					{output: "disabled\n", status: 1},
				}
			},
		},
		{
			name:     "second start fails after mutation",
			decision: active,
			configure: func(manager *automaticUpdateTestManager, cause error) {
				manager.runFailures["systemctl start two.timer"] = []error{cause}
			},
		},
		{
			name:     "second activation attestation fails",
			decision: active,
			configure: func(manager *automaticUpdateTestManager, _ error) {
				manager.statusOverrides["systemctl is-active two.timer"] = []automaticUpdateStatusResult{
					{output: "inactive\n", status: 3},
					{output: "inactive\n", status: 3},
				}
			},
		},
	}
	for _, test := range failureTests {
		t.Run(test.name, func(t *testing.T) {
			manager := newAutomaticUpdateTestManager()
			original := []byte("operator = retained\n")
			host, physical, snapshot := newFixture(t, manager, original, 0640)
			info, err := os.Stat(physical)
			if err != nil {
				t.Fatal(err)
			}
			owner := *info.Sys().(*syscall.Stat_t)
			cause := errors.New("injected transaction failure")
			test.configure(manager, cause)
			err = applyAutomaticUpdatePolicy(host, logical, snapshot, policy, test.decision, timers...)
			if err == nil {
				t.Fatal("partial automatic-update transaction was accepted")
			}
			if strings.Contains(test.name, "fails after mutation") && !errors.Is(err, cause) {
				t.Fatalf("cause was masked: %v", err)
			}
			assertExistingConfig(t, physical, original, 0640, owner)
			assertTimerState(t, manager,
				map[string]bool{"one.timer": false, "two.timer": false},
				map[string]bool{"one.timer": false, "two.timer": false})
		})
	}

	t.Run("rollback restores mixed initial timer states", func(t *testing.T) {
		manager := newAutomaticUpdateTestManager()
		manager.enabled["one.timer"] = true
		manager.active["two.timer"] = true
		manager.statusOverrides["systemctl is-enabled two.timer"] = []automaticUpdateStatusResult{
			{output: "disabled\n", status: 1},
			{output: "disabled\n", status: 1},
		}
		host, physical, snapshot := newFixture(t, manager, nil, 0)
		if err := applyAutomaticUpdatePolicy(host, logical, snapshot, policy, active, timers...); err == nil {
			t.Fatal("failed enablement attestation was accepted")
		}
		assertMissingConfig(t, physical)
		assertTimerState(t, manager,
			map[string]bool{"one.timer": true, "two.timer": false},
			map[string]bool{"one.timer": false, "two.timer": true})
	})

	t.Run("rollback failures are aggregated without masking the cause", func(t *testing.T) {
		manager := newAutomaticUpdateTestManager()
		cause := errors.New("second timer enable failed")
		rollbackFailure := errors.New("first timer rollback failed")
		manager.runFailures["systemctl enable two.timer"] = []error{cause}
		manager.runFailures["systemctl disable one.timer"] = []error{rollbackFailure}
		host, physical, snapshot := newFixture(t, manager, nil, 0)
		err := applyAutomaticUpdatePolicy(host, logical, snapshot, policy, active, timers...)
		if !errors.Is(err, cause) || !errors.Is(err, rollbackFailure) {
			t.Fatalf("transaction errors were not aggregated: %v", err)
		}
		assertMissingConfig(t, physical)
		assertTimerState(t, manager,
			map[string]bool{"one.timer": false, "two.timer": false},
			map[string]bool{"one.timer": false, "two.timer": false})
	})
}

func TestOSReleaseFamiliesAndHostileMetadata(t *testing.T) {
	for id, want := range map[string]string{
		"debian": "debian", "ubuntu": "debian", "fedora": "redhat",
		"almalinux": "redhat", "alpine": "alpine",
	} {
		t.Run(id, func(t *testing.T) {
			host := hardeningTestHost(t, hardeningExecutor{})
			writeOSReleaseFixture(t, host, id)
			got, err := linuxDistributionFamilyOn(host)
			if err != nil || got != want {
				t.Fatalf("family=%q error=%v", got, err)
			}
		})
	}

	t.Run("untrusted symlink", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		writeOSReleaseFixture(t, host, "debian")
		etcRelease, _ := host.path("/etc/os-release")
		if err := os.Remove(etcRelease); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/tmp/hostile", etcRelease); err != nil {
			t.Fatal(err)
		}
		if _, err := linuxDistributionFamilyOn(host); err == nil || !strings.Contains(err.Error(), "untrusted symlink") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("writable metadata", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		writeOSReleaseFixture(t, host, "fedora")
		path, _ := host.path("/usr/lib/os-release")
		if err := chmodHardeningFixture(path, 0664); err != nil {
			t.Fatal(err)
		}
		if _, err := linuxDistributionFamilyOn(host); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("unexpected owner", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		writeOSReleaseFixture(t, host, "alpine")
		host.expectedRootUID ^= 1
		if _, err := linuxDistributionFamilyOn(host); err == nil ||
			(!strings.Contains(err.Error(), "ownership") && !strings.Contains(err.Error(), "owned")) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("conflicting regular metadata", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		writeOSReleaseFixture(t, host, "fedora")
		etcRelease, _ := host.path("/etc/os-release")
		if err := os.Remove(etcRelease); err != nil {
			t.Fatal(err)
		}
		if err := writeHardeningFixtureFile(etcRelease, []byte("ID=debian\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := linuxDistributionFamilyOn(host); err == nil || !strings.Contains(err.Error(), "conflicting") {
			t.Fatalf("error=%v", err)
		}
	})

	if _, err := parseOSReleaseID([]byte("ID=debian\nID=ubuntu\n")); err == nil {
		t.Fatal("duplicate os-release ID was accepted")
	}
}

func TestOfflineAutomaticUpdatesFedoraAndAlma(t *testing.T) {
	offline := hardeningExecutionDecision{
		state: hardeningExecutionNotApplicable, packageInstall: true, rootUIDRemapped: true,
		reason: "package hook has no active systemd or OpenRC init",
	}
	newHost := func(t *testing.T, id string) hardeningHost {
		t.Helper()
		host := hardeningTestHost(t, hardeningExecutor{
			run: func(name string, args ...string) error {
				t.Fatalf("offline executor call: %s %v", name, args)
				return nil
			},
			status: func(name string, args ...string) ([]byte, int, error) {
				t.Fatalf("offline executor status call: %s %v", name, args)
				return nil, 0, nil
			},
		})
		host.executionProbe = func() (hardeningExecutionDecision, error) { return offline, nil }
		writeOSReleaseFixture(t, host, id)
		return host
	}
	writeFile := func(t *testing.T, host hardeningHost, logical string, content []byte) {
		t.Helper()
		physical, err := host.path(logical)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(physical), 0750); err != nil {
			t.Fatal(err)
		}
		if err := writeHardeningFixtureFile(physical, content, 0644); err != nil {
			t.Fatal(err)
		}
	}
	configuration := []byte("[commands]\nupgrade_type = default\ndownload_updates = yes\napply_updates = no\nreboot = when-needed\n")

	t.Run("Fedora creates configuration from the trusted dnf5 template", func(t *testing.T) {
		host := newHost(t, "fedora")
		writeFile(t, host, "/usr/share/dnf5/dnf5-plugins/automatic.conf", configuration)
		writeFile(t, host, "/usr/lib/systemd/system/dnf5-automatic.timer", []byte("[Timer]\nOnCalendar=daily\n"))
		dnfDirectory, _ := host.path("/etc/dnf")
		if err := os.MkdirAll(dnfDirectory, 0750); err != nil {
			t.Fatal(err)
		}
		if err := enableAutomaticSecurityUpdatesOn(host); err != nil {
			t.Fatal(err)
		}
		policy, _ := host.path("/etc/dnf/automatic.conf")
		content, err := readHardeningFixtureFile(policy)
		if err != nil || !strings.Contains(string(content), "upgrade_type = security") ||
			!strings.Contains(string(content), "apply_updates = yes") || !strings.Contains(string(content), "reboot = never") {
			t.Fatalf("Fedora policy=%q error=%v", content, err)
		}
		link, _ := host.path("/etc/systemd/system/timers.target.wants/dnf5-automatic.timer")
		if target, err := os.Readlink(link); err != nil || target != "/usr/lib/systemd/system/dnf5-automatic.timer" {
			t.Fatalf("Fedora timer target=%q error=%v", target, err)
		}
	})

	t.Run("Alma keeps the legacy payload and timer", func(t *testing.T) {
		host := newHost(t, "almalinux")
		writeFile(t, host, "/etc/dnf/automatic.conf", configuration)
		writeFile(t, host, "/usr/lib/systemd/system/dnf-automatic.timer", []byte("[Timer]\nOnCalendar=daily\n"))
		if err := enableAutomaticSecurityUpdatesOn(host); err != nil {
			t.Fatal(err)
		}
		link, _ := host.path("/etc/systemd/system/timers.target.wants/dnf-automatic.timer")
		if target, err := os.Readlink(link); err != nil || target != "/usr/lib/systemd/system/dnf-automatic.timer" {
			t.Fatalf("Alma timer target=%q error=%v", target, err)
		}
	})

	t.Run("Fedora fsync failure rolls back configuration and link", func(t *testing.T) {
		host := newHost(t, "fedora")
		writeFile(t, host, "/usr/share/dnf5/dnf5-plugins/automatic.conf", configuration)
		writeFile(t, host, "/usr/lib/systemd/system/dnf5-automatic.timer", []byte("[Timer]\nOnCalendar=daily\n"))
		dnfDirectory, _ := host.path("/etc/dnf")
		wantsDirectory, _ := host.path("/etc/systemd/system/timers.target.wants")
		if err := os.MkdirAll(dnfDirectory, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(wantsDirectory, 0750); err != nil {
			t.Fatal(err)
		}
		cause := errors.New("injected link fsync failure")
		calls := 0
		host.directorySync = func(root *os.Root) error {
			calls++
			if calls == 1 {
				return cause
			}
			return syncSecurityDirectory(root)
		}
		if err := enableAutomaticSecurityUpdatesOn(host); !errors.Is(err, cause) {
			t.Fatalf("fsync cause was masked: %v", err)
		}
		for _, logical := range []string{"/etc/dnf/automatic.conf", "/etc/systemd/system/timers.target.wants/dnf5-automatic.timer"} {
			physical, _ := host.path(logical)
			if _, err := os.Lstat(physical); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial offline state remained at %s: %v", logical, err)
			}
		}
	})
}

func TestPackageHookNeverRunsRecursivePackageManager(t *testing.T) {
	newHost := func(t *testing.T, id string) hardeningHost {
		t.Helper()
		host := hardeningTestHost(t, hardeningExecutor{
			run: func(name string, args ...string) error {
				t.Fatalf("unexpected package-manager command %s %v", name, args)
				return nil
			},
		})
		host.executionProbe = func() (hardeningExecutionDecision, error) {
			return hardeningExecutionDecision{state: hardeningExecutionActive, packageInstall: true}, nil
		}
		writeOSReleaseFixture(t, host, id)
		return host
	}
	t.Run("APT", func(t *testing.T) {
		host := newHost(t, "debian")
		if err := enableAutomaticSecurityUpdatesOn(host); err == nil || !strings.Contains(err.Error(), "refusing recursive APT") {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("DNF", func(t *testing.T) {
		host := newHost(t, "fedora")
		directory, _ := host.path("/etc/dnf")
		if err := os.MkdirAll(directory, 0750); err != nil {
			t.Fatal(err)
		}
		if err := enableAutomaticSecurityUpdatesOn(host); err == nil || !strings.Contains(err.Error(), "refusing recursive DNF") {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestCISSSHAbsenceAllowsOnlyTrustedEmptyDropIn(t *testing.T) {
	t.Run("empty trusted drop-in", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		dropIn, _ := host.path("/etc/ssh/sshd_config.d")
		if err := os.MkdirAll(dropIn, 0750); err != nil {
			t.Fatal(err)
		}
		if err := applySSHHardeningOn(host); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("nonempty drop-in", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		dropIn, _ := host.path("/etc/ssh/sshd_config.d")
		if err := os.MkdirAll(dropIn, 0750); err != nil {
			t.Fatal(err)
		}
		if err := writeHardeningFixtureFile(filepath.Join(dropIn, "operator.conf"), []byte("Port 22\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := applySSHHardeningOn(host); err == nil || !strings.Contains(err.Error(), "exists but") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("symlink drop-in", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		ssh, _ := host.path("/etc/ssh")
		if err := os.MkdirAll(ssh, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), filepath.Join(ssh, "sshd_config.d")); err != nil {
			t.Fatal(err)
		}
		if err := applySSHHardeningOn(host); err == nil {
			t.Fatal("symlink drop-in was accepted")
		}
	})
}

func TestCISSSHMergedUsrAliases(t *testing.T) {
	makeDirectory := func(t *testing.T, host hardeningHost, logical string) string {
		t.Helper()
		physical, err := host.path(logical)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(physical, 0750); err != nil {
			t.Fatal(err)
		}
		return physical
	}
	makeAlias := func(t *testing.T, host hardeningHost, logical, target string) {
		t.Helper()
		physical, err := host.path(logical)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, physical); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("Debian merged usr without sshd is not applicable", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		makeDirectory(t, host, "/usr/sbin")
		makeDirectory(t, host, "/usr/lib/systemd/system")
		makeAlias(t, host, "/sbin", "usr/sbin")
		makeAlias(t, host, "/lib", "usr/lib")
		if err := applySSHHardeningOn(host); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Alma merged usr without sshd is not applicable", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		makeDirectory(t, host, "/usr/sbin")
		makeDirectory(t, host, "/usr/lib/systemd/system")
		makeAlias(t, host, "/sbin", "usr/sbin")
		makeAlias(t, host, "/lib", "/usr/lib")
		if err := applySSHHardeningOn(host); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Fedora double alias without sshd is not applicable", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		makeDirectory(t, host, "/usr/bin")
		makeDirectory(t, host, "/usr/local/bin")
		makeDirectory(t, host, "/usr/lib/systemd/system")
		makeAlias(t, host, "/usr/sbin", "bin")
		makeAlias(t, host, "/sbin", "usr/sbin")
		makeAlias(t, host, "/usr/local/sbin", "bin")
		makeAlias(t, host, "/lib", "usr/lib")
		if err := applySSHHardeningOn(host); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Fedora alias still reports an existing sshd", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		bin := makeDirectory(t, host, "/usr/bin")
		if err := writeHardeningFixtureFile(filepath.Join(bin, "sshd"), []byte("fixture\n"), 0755); err != nil {
			t.Fatal(err)
		}
		makeAlias(t, host, "/usr/sbin", "bin")
		makeAlias(t, host, "/sbin", "usr/sbin")
		if err := applySSHHardeningOn(host); err == nil || !strings.Contains(err.Error(), "exists but") {
			t.Fatalf("existing sshd signal result: %v", err)
		}
	})

	t.Run("Fedora local sbin alias still reports an existing sshd", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		makeDirectory(t, host, "/usr/bin")
		localBin := makeDirectory(t, host, "/usr/local/bin")
		if err := writeHardeningFixtureFile(filepath.Join(localBin, "sshd"), []byte("fixture\n"), 0755); err != nil {
			t.Fatal(err)
		}
		makeAlias(t, host, "/usr/sbin", "bin")
		makeAlias(t, host, "/sbin", "usr/sbin")
		makeAlias(t, host, "/usr/local/sbin", "bin")
		if err := applySSHHardeningOn(host); err == nil || !strings.Contains(err.Error(), "exists but") {
			t.Fatalf("existing local sshd signal result: %v", err)
		}
	})

	t.Run("merged lib alias still reports an existing systemd unit", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		systemd := makeDirectory(t, host, "/usr/lib/systemd/system")
		if err := writeHardeningFixtureFile(filepath.Join(systemd, "ssh.service"), []byte("[Service]\n"), 0644); err != nil {
			t.Fatal(err)
		}
		makeAlias(t, host, "/lib", "usr/lib")
		if err := applySSHHardeningOn(host); err == nil || !strings.Contains(err.Error(), "exists but") {
			t.Fatalf("existing merged-lib SSH unit result: %v", err)
		}
	})

	t.Run("merged lib alias replacement is rejected on re-attestation", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		makeDirectory(t, host, "/usr/lib/systemd/system")
		makeAlias(t, host, "/lib", "usr/lib")
		resolved, _, exists, err := resolveCISSSHSignalDirectory(host, "/lib/systemd/system/ssh.service")
		if err != nil || !exists {
			t.Fatalf("resolve merged-lib signal: exists=%t error=%v", exists, err)
		}
		lib, _ := host.path("/lib")
		if err := os.Remove(lib); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/usr/lib", lib); err != nil {
			t.Fatal(err)
		}
		if err := reattestCISSSHDirectoryAliases(host, resolved); err == nil {
			t.Fatal("replaced merged-lib alias was accepted on re-attestation")
		}
	})

	t.Run("multiply linked merged lib alias is rejected", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		makeDirectory(t, host, "/usr/lib")
		makeAlias(t, host, "/lib", "usr/lib")
		lib, _ := host.path("/lib")
		shadow, _ := host.path("/lib-shadow")
		if err := os.Link(lib, shadow); err != nil {
			t.Fatal(err)
		}
		if err := applySSHHardeningOn(host); err == nil {
			t.Fatal("multiply linked merged-lib alias was accepted")
		}
	})

	for name, fixture := range map[string]func(*testing.T, hardeningHost){
		"arbitrary sbin target": func(t *testing.T, host hardeningHost) {
			makeDirectory(t, host, "/tmp")
			makeAlias(t, host, "/sbin", "tmp")
		},
		"arbitrary Fedora target": func(t *testing.T, host hardeningHost) {
			makeDirectory(t, host, "/usr/tmp")
			makeAlias(t, host, "/usr/sbin", "tmp")
		},
		"writable resolved directory": func(t *testing.T, host hardeningHost) {
			bin := makeDirectory(t, host, "/usr/bin")
			if err := chmodHardeningFixture(bin, 0770); err != nil {
				t.Fatal(err)
			}
			makeAlias(t, host, "/usr/sbin", "bin")
		},
		"arbitrary lib target": func(t *testing.T, host hardeningHost) {
			makeDirectory(t, host, "/tmp")
			makeAlias(t, host, "/lib", "tmp")
		},
		"arbitrary Fedora local sbin target": func(t *testing.T, host hardeningHost) {
			makeDirectory(t, host, "/usr/local/tmp")
			makeAlias(t, host, "/usr/local/sbin", "tmp")
		},
		"writable merged lib target": func(t *testing.T, host hardeningHost) {
			lib := makeDirectory(t, host, "/usr/lib")
			if err := chmodHardeningFixture(lib, 0770); err != nil {
				t.Fatal(err)
			}
			makeAlias(t, host, "/lib", "usr/lib")
		},
	} {
		t.Run(name, func(t *testing.T) {
			host := hardeningTestHost(t, hardeningExecutor{})
			fixture(t, host)
			if err := applySSHHardeningOn(host); err == nil {
				t.Fatal("hostile merged-usr alias was accepted")
			}
		})
	}
}

func TestOfflineAutomaticUpdateTrustedLibAliasCompatibility(t *testing.T) {
	timersByDistribution := map[string][]string{
		"debian":    {"apt-daily.timer", "apt-daily-upgrade.timer"},
		"ubuntu":    {"apt-daily.timer", "apt-daily-upgrade.timer"},
		"fedora":    {"dnf5-automatic.timer"},
		"almalinux": {"dnf-automatic.timer"},
	}
	for distribution, timers := range timersByDistribution {
		t.Run(distribution, func(t *testing.T) {
			host := hardeningTestHost(t, hardeningExecutor{
				run: func(name string, args ...string) error {
					t.Fatalf("offline executor call: %s %v", name, args)
					return nil
				},
				status: func(name string, args ...string) ([]byte, int, error) {
					t.Fatalf("offline executor status call: %s %v", name, args)
					return nil, 0, nil
				},
			})
			writeOSReleaseFixture(t, host, distribution)
			unitDirectory, _ := host.path("/usr/lib/systemd/system")
			if err := os.MkdirAll(unitDirectory, 0750); err != nil {
				t.Fatal(err)
			}
			for _, timer := range timers {
				if err := writeHardeningFixtureFile(filepath.Join(unitDirectory, timer), []byte("[Timer]\nOnCalendar=daily\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			lib, _ := host.path("/lib")
			libTarget := "usr/lib"
			if distribution == "ubuntu" {
				libTarget = "/usr/lib"
			}
			if err := os.Symlink(libTarget, lib); err != nil {
				t.Fatal(err)
			}
			wants, _ := host.path("/etc/systemd/system/timers.target.wants")
			if err := os.MkdirAll(wants, 0750); err != nil {
				t.Fatal(err)
			}
			for _, timer := range timers {
				if err := os.Symlink("/lib/systemd/system/"+timer, filepath.Join(wants, timer)); err != nil {
					t.Fatal(err)
				}
			}
			configuration, _ := host.path("/etc/syswarden-test/automatic.conf")
			if err := os.MkdirAll(filepath.Dir(configuration), 0750); err != nil {
				t.Fatal(err)
			}
			snapshot, err := host.snapshot("/etc/syswarden-test/automatic.conf")
			if err != nil {
				t.Fatal(err)
			}
			decision := hardeningExecutionDecision{state: hardeningExecutionNotApplicable, packageInstall: true}
			if err := applyAutomaticUpdatePolicy(host, "/etc/syswarden-test/automatic.conf", snapshot, []byte("enabled\n"), decision, timers...); err != nil {
				t.Fatal(err)
			}
			for _, timer := range timers {
				target, err := os.Readlink(filepath.Join(wants, timer))
				if err != nil || target != "/lib/systemd/system/"+timer {
					t.Fatalf("preserved timer %s target=%q error=%v", timer, target, err)
				}
			}
		})
	}
}

func TestOfflineAutomaticUpdateRejectsUntrustedEquivalentTargets(t *testing.T) {
	const timer = "fixture.timer"
	newFixture := func(t *testing.T) (hardeningHost, offlineAutomaticUpdateTimerSnapshot, string) {
		t.Helper()
		host := hardeningTestHost(t, hardeningExecutor{})
		unit, _ := host.path("/usr/lib/systemd/system/" + timer)
		if err := os.MkdirAll(filepath.Dir(unit), 0750); err != nil {
			t.Fatal(err)
		}
		if err := writeHardeningFixtureFile(unit, []byte("[Timer]\n"), 0644); err != nil {
			t.Fatal(err)
		}
		lib, _ := host.path("/lib")
		if err := os.Symlink("usr/lib", lib); err != nil {
			t.Fatal(err)
		}
		snapshot, err := resolveOfflineAutomaticUpdateTimer(host, timer)
		if err != nil {
			t.Fatal(err)
		}
		wants, _ := host.path("/etc/systemd/system/timers.target.wants")
		if err := os.MkdirAll(wants, 0750); err != nil {
			t.Fatal(err)
		}
		return host, snapshot, wants
	}

	t.Run("unknown target", func(t *testing.T) {
		host, snapshot, wants := newFixture(t)
		if err := os.Symlink("/opt/fixture.timer", filepath.Join(wants, timer)); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectOfflineAutomaticUpdateLink(host, snapshot); err == nil || !strings.Contains(err.Error(), "unexpected target") {
			t.Fatalf("unknown timer target result: %v", err)
		}
	})

	t.Run("real lib hardlink is not an alias", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		usrUnit, _ := host.path("/usr/lib/systemd/system/" + timer)
		if err := os.MkdirAll(filepath.Dir(usrUnit), 0750); err != nil {
			t.Fatal(err)
		}
		if err := writeHardeningFixtureFile(usrUnit, []byte("[Timer]\n"), 0644); err != nil {
			t.Fatal(err)
		}
		libUnit, _ := host.path("/lib/systemd/system/" + timer)
		if err := os.MkdirAll(filepath.Dir(libUnit), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(usrUnit, libUnit); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveOfflineAutomaticUpdateTimer(host, timer); err == nil || !strings.Contains(err.Error(), "unsafe metadata") {
			t.Fatalf("real /lib equivalence result: %v", err)
		}
	})

	t.Run("alias changed after resolution", func(t *testing.T) {
		host, snapshot, wants := newFixture(t)
		lib, _ := host.path("/lib")
		if err := os.Remove(lib); err != nil {
			t.Fatal(err)
		}
		libUnit := filepath.Join(lib, "systemd/system", timer)
		if err := os.MkdirAll(filepath.Dir(libUnit), 0750); err != nil {
			t.Fatal(err)
		}
		if err := writeHardeningFixtureFile(libUnit, []byte("[Timer]\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/lib/systemd/system/"+timer, filepath.Join(wants, timer)); err != nil {
			t.Fatal(err)
		}
		if _, err := inspectOfflineAutomaticUpdateLink(host, snapshot); err == nil || !strings.Contains(err.Error(), "alias changed") {
			t.Fatalf("changed /lib alias result: %v", err)
		}
	})

	t.Run("arbitrary lib alias", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{})
		usrLib, _ := host.path("/usr/lib/systemd/system")
		if err := os.MkdirAll(usrLib, 0750); err != nil {
			t.Fatal(err)
		}
		if err := writeHardeningFixtureFile(filepath.Join(usrLib, timer), []byte("[Timer]\n"), 0644); err != nil {
			t.Fatal(err)
		}
		lib, _ := host.path("/lib")
		if err := os.Symlink("tmp", lib); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveOfflineAutomaticUpdateTimer(host, timer); err == nil || !strings.Contains(err.Error(), "untrusted") {
			t.Fatalf("arbitrary /lib alias result: %v", err)
		}
	})
}

func TestHardeningFileRemovalRestoresConcurrentSubstitution(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	logical := "/etc/syswarden-test/remove.conf"
	physical, err := host.path(logical)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(physical), 0750); err != nil {
		t.Fatal(err)
	}
	expected := []byte("managed\n")
	if err := writeHardeningFixtureFile(physical, expected, 0600); err != nil {
		t.Fatal(err)
	}
	var operatorIdentity os.FileInfo
	calls := 0
	rename := func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		calls++
		if calls == 1 {
			if err := os.Remove(physical); err != nil {
				t.Fatal(err)
			}
			if err := writeHardeningFixtureFile(physical, expected, 0600); err != nil {
				t.Fatal(err)
			}
			operatorIdentity, err = os.Lstat(physical)
			if err != nil {
				t.Fatal(err)
			}
		}
		return unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags)
	}
	if err := host.removeExpectedUsing(logical, expected, rename); err == nil {
		t.Fatal("concurrent hardening file substitution was accepted")
	}
	restored, err := os.Lstat(physical)
	if err != nil || !os.SameFile(operatorIdentity, restored) {
		t.Fatalf("operator hardening file was not restored: info=%v error=%v", restored, err)
	}
	content, err := readHardeningFixtureFile(physical)
	if err != nil || string(content) != string(expected) {
		t.Fatalf("operator hardening file content=%q error=%v", content, err)
	}
}

func TestHardeningQuarantineNeverDeletesSubstitutionWhenRestoreFails(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	logical := "/etc/syswarden-test/remove-failure.conf"
	physical, err := host.path(logical)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(physical)
	if err := os.MkdirAll(parent, 0750); err != nil {
		t.Fatal(err)
	}
	expected := []byte("managed\n")
	if err := writeHardeningFixtureFile(physical, expected, 0600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected hardening quarantine restoration failure")
	var operatorIdentity os.FileInfo
	calls := 0
	rename := func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		calls++
		if calls == 1 {
			if err := os.Remove(physical); err != nil {
				t.Fatal(err)
			}
			if err := writeHardeningFixtureFile(physical, expected, 0600); err != nil {
				t.Fatal(err)
			}
			operatorIdentity, err = os.Lstat(physical)
			if err != nil {
				t.Fatal(err)
			}
			return unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags)
		}
		return injected
	}
	if err := host.removeExpectedUsing(logical, expected, rename); !errors.Is(err, injected) {
		t.Fatalf("quarantine restoration failure was not propagated: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	preserved := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".syswarden-quarantine-") {
			continue
		}
		candidate := filepath.Join(parent, entry.Name())
		info, statErr := os.Lstat(candidate)
		if statErr == nil && os.SameFile(operatorIdentity, info) {
			preserved = true
		}
	}
	if !preserved {
		t.Fatalf("substituted hardening file was deleted after restore failure: %v", entries)
	}
}

func TestAutomaticUpdateLinkRollbackRestoresConcurrentSubstitution(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	const timer = "fixture.timer"
	unit, _ := host.path("/usr/lib/systemd/system/" + timer)
	if err := os.MkdirAll(filepath.Dir(unit), 0750); err != nil {
		t.Fatal(err)
	}
	if err := writeHardeningFixtureFile(unit, []byte("[Timer]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := resolveOfflineAutomaticUpdateTimer(host, timer)
	if err != nil {
		t.Fatal(err)
	}
	wants, _ := host.path("/etc/systemd/system/timers.target.wants")
	if err := os.MkdirAll(wants, 0750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(wants, timer)
	if err := os.Symlink(snapshot.linkTarget, link); err != nil {
		t.Fatal(err)
	}
	snapshot.linkCreated = true
	snapshot.publishedLink, err = os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	const operatorTarget = "/opt/operator.timer"
	var operatorIdentity os.FileInfo
	calls := 0
	rename := func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		calls++
		if calls == 1 {
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(operatorTarget, link); err != nil {
				t.Fatal(err)
			}
			operatorIdentity, err = os.Lstat(link)
			if err != nil {
				t.Fatal(err)
			}
		}
		return unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags)
	}
	if err := restoreOfflineAutomaticUpdateLinkUsing(host, snapshot, rename); err == nil {
		t.Fatal("concurrent automatic-update link substitution was accepted")
	}
	restored, err := os.Lstat(link)
	if err != nil || !os.SameFile(operatorIdentity, restored) {
		t.Fatalf("operator automatic-update link was not restored: info=%v error=%v", restored, err)
	}
	target, err := os.Readlink(link)
	if err != nil || target != operatorTarget {
		t.Fatalf("operator automatic-update target=%q error=%v", target, err)
	}
}

func TestAutomaticUpdateDirectoryRollbackRestoresConcurrentSubstitution(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	parent, _ := host.path("/etc/systemd/system")
	if err := os.MkdirAll(parent, 0750); err != nil {
		t.Fatal(err)
	}
	const name = "timers.target.wants"
	directory := filepath.Join(parent, name)
	if err := os.Mkdir(directory, 0750); err != nil {
		t.Fatal(err)
	}
	createdIdentity, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	record := offlineAutomaticUpdateCreatedDirectory{
		parentPhysical: parent,
		name:           name,
		identity:       createdIdentity,
	}
	marker := filepath.Join(directory, "operator.marker")
	var operatorIdentity os.FileInfo
	calls := 0
	rename := func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		calls++
		if calls == 1 {
			if err := os.Remove(directory); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(directory, 0750); err != nil {
				t.Fatal(err)
			}
			if err := writeHardeningFixtureFile(marker, []byte("operator\n"), 0600); err != nil {
				t.Fatal(err)
			}
			operatorIdentity, err = os.Lstat(directory)
			if err != nil {
				t.Fatal(err)
			}
		}
		return unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags)
	}
	if err := removeCreatedAutomaticUpdateDirectoriesUsing(host, []offlineAutomaticUpdateCreatedDirectory{record}, rename); err == nil {
		t.Fatal("concurrent automatic-update directory substitution was accepted")
	}
	restored, err := os.Lstat(directory)
	if err != nil || !os.SameFile(operatorIdentity, restored) {
		t.Fatalf("operator automatic-update directory was not restored: info=%v error=%v", restored, err)
	}
	content, err := readHardeningFixtureFile(marker)
	if err != nil || string(content) != "operator\n" {
		t.Fatalf("operator directory marker=%q error=%v", content, err)
	}
}

func TestAutomaticUpdateNestedDirectoryRollbackUsesStableIdentity(t *testing.T) {
	host := hardeningTestHost(t, hardeningExecutor{})
	const link = "/etc/systemd/system/timers.target.wants/fixture.timer"
	created, err := prepareOfflineAutomaticUpdateLinkParent(host, link)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) < 2 {
		t.Fatalf("nested fixture created only %d directories", len(created))
	}
	if err := removeCreatedAutomaticUpdateDirectories(host, created); err != nil {
		t.Fatalf("remove nested automatic-update directories: %v", err)
	}
	for _, record := range created {
		path := filepath.Join(record.parentPhysical, record.name)
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("created automatic-update directory remains at %s: %v", path, err)
		}
	}
}

func TestCISSSHOfflinePackageHookNeverContactsServiceManager(t *testing.T) {
	for _, rootless := range []bool{false, true} {
		name := "rootful"
		if rootless {
			name = "rootless"
		}
		t.Run(name, func(t *testing.T) {
			managerCalls := 0
			host := hardeningTestHost(t, hardeningExecutor{
				run: func(command string, args ...string) error {
					if command != "sshd" || len(args) != 1 || args[0] != "-t" {
						managerCalls++
						t.Fatalf("offline manager command: %s %v", command, args)
					}
					return nil
				},
				output: func(command string, args ...string) ([]byte, error) {
					if command != "sshd" || len(args) != 1 || args[0] != "-T" {
						managerCalls++
						t.Fatalf("offline manager output command: %s %v", command, args)
					}
					return []byte("x11forwarding no\nmaxauthtries 4\nclientaliveinterval 300\nclientalivecountmax 3\n"), nil
				},
			})
			host.executionProbe = func() (hardeningExecutionDecision, error) {
				return hardeningExecutionDecision{
					state: hardeningExecutionNotApplicable, packageInstall: true,
					rootUIDRemapped: rootless, reason: "package hook has no active systemd or OpenRC init",
				}, nil
			}
			probes := 0
			host.processProbe = func(name string) (bool, error) {
				if name != "sshd" {
					t.Fatalf("unexpected process probe %q", name)
				}
				probes++
				return false, nil
			}
			configuration, _ := host.path("/etc/ssh/sshd_config")
			if err := os.MkdirAll(filepath.Dir(configuration), 0750); err != nil {
				t.Fatal(err)
			}
			if err := writeHardeningFixtureFile(configuration, []byte("X11Forwarding yes\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := applySSHHardeningOn(host); err != nil {
				t.Fatal(err)
			}
			if managerCalls != 0 || probes < 2 {
				t.Fatalf("manager calls=%d process probes=%d", managerCalls, probes)
			}
		})
	}

	t.Run("daemon appears and policy rolls back", func(t *testing.T) {
		host := hardeningTestHost(t, hardeningExecutor{
			run: func(string, ...string) error { return nil },
			output: func(string, ...string) ([]byte, error) {
				return []byte("x11forwarding no\nmaxauthtries 4\nclientaliveinterval 300\nclientalivecountmax 3\n"), nil
			},
		})
		host.executionProbe = func() (hardeningExecutionDecision, error) {
			return hardeningExecutionDecision{state: hardeningExecutionNotApplicable, packageInstall: true}, nil
		}
		probes := 0
		host.processProbe = func(string) (bool, error) { probes++; return probes >= 2, nil }
		configuration, _ := host.path("/etc/ssh/sshd_config")
		if err := os.MkdirAll(filepath.Dir(configuration), 0750); err != nil {
			t.Fatal(err)
		}
		original := []byte("X11Forwarding yes\n")
		if err := writeHardeningFixtureFile(configuration, original, 0600); err != nil {
			t.Fatal(err)
		}
		if err := applySSHHardeningOn(host); err == nil || !strings.Contains(err.Error(), "started during") {
			t.Fatalf("daemon race error=%v", err)
		}
		content, err := readHardeningFixtureFile(configuration)
		if err != nil || string(content) != string(original) {
			t.Fatalf("SSH policy rollback=%q error=%v", content, err)
		}
	})
}
