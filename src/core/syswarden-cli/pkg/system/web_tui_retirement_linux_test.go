//go:build linux

package system

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type webTUIRetirementFixture struct {
	servicePath    string
	enablementPath string
	pendingPath    string
	pidPath        string
	systemdDropIn  string
	runtimeUnit    string
	runtimeDropIn  string
	managerRuntime string
	openRCRuntime  string
	openRCConf     string
	expectedUnit   string
	linkTarget     string
	calls          []string
}

func newWebTUIRetirementFixture(t *testing.T, alpine bool) *webTUIRetirementFixture {
	t.Helper()
	t.Setenv("SYSWARDEN_PKG_INSTALL", "1")
	root := t.TempDir()
	systemdService := filepath.Join(root, "etc/systemd/system/syswarden-webtui.service")
	systemdEnablement := filepath.Join(root, "etc/systemd/system/multi-user.target.wants/syswarden-webtui.service")
	openRCService := filepath.Join(root, "etc/init.d/syswarden-webtui")
	openRCEnablement := filepath.Join(root, "etc/runlevels/default/syswarden-webtui")
	systemdDropIn := filepath.Join(root, "etc/systemd/system/syswarden-webtui.service.d")
	runtimeUnit := filepath.Join(root, "run/systemd/system/syswarden-webtui.service")
	runtimeDropIn := filepath.Join(root, "run/systemd/system/syswarden-webtui.service.d")
	managerRuntime := filepath.Join(root, "run/systemd/system")
	openRCRuntime := filepath.Join(root, "run/openrc")
	openRCConf := filepath.Join(root, "etc/conf.d/syswarden-webtui")
	pidPath := filepath.Join(root, "run/syswarden-webtui.pid")
	executablePath := filepath.Join(root, "opt/syswarden/bin/syswarden-cli")
	procPath := filepath.Join(root, "proc")
	for _, directory := range []string{
		filepath.Dir(systemdService),
		filepath.Dir(systemdEnablement),
		filepath.Dir(openRCService),
		filepath.Dir(openRCEnablement),
		filepath.Dir(pidPath),
		filepath.Dir(executablePath),
		procPath,
	} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(executablePath, []byte("attested test executable\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !alpine {
		mustSeedSystemdRuntime(t, root, managerRuntime)
	}

	fixture := &webTUIRetirementFixture{
		servicePath:    systemdService,
		enablementPath: systemdEnablement,
		pendingPath:    systemdService + ".syswarden-retiring",
		pidPath:        pidPath,
		systemdDropIn:  systemdDropIn,
		runtimeUnit:    runtimeUnit,
		runtimeDropIn:  runtimeDropIn,
		managerRuntime: managerRuntime,
		openRCRuntime:  openRCRuntime,
		openRCConf:     openRCConf,
		expectedUnit:   legacySystemdWebTUITemplate,
		linkTarget:     "../syswarden-webtui.service",
	}
	if alpine {
		fixture.servicePath = openRCService
		fixture.enablementPath = openRCEnablement
		fixture.pendingPath = openRCService + ".syswarden-retiring"
		fixture.expectedUnit = legacyOpenRCWebTUITemplate
		fixture.linkTarget = "/etc/init.d/syswarden-webtui"
	}

	previousSystemdService := legacySystemdWebTUIPath
	previousSystemdEnablement := legacySystemdWebTUIEnablementPath
	previousSystemdDropIn := legacySystemdWebTUIDropInPath
	previousSystemdManagerRuntime := legacySystemdManagerRuntimePath
	previousSystemdRuntime := legacySystemdWebTUIRuntimePath
	previousSystemdRuntimeDropIn := legacySystemdWebTUIRuntimeDropIn
	previousOpenRCService := legacyOpenRCWebTUIPath
	previousOpenRCEnablement := legacyOpenRCWebTUIEnablementPath
	previousOpenRCConf := legacyOpenRCWebTUIConfPath
	previousOpenRCRuntime := legacyOpenRCManagerRuntimePath
	previousPID := legacyWebTUIPIDPath
	previousExecutable := legacyWebTUIExecutablePath
	previousProc := legacyWebTUIProcPath
	previousExpectedUID := legacyWebTUIExpectedOwnerUID
	previousExpectedGID := legacyWebTUIExpectedOwnerGID
	previousRunner := runRetirementCommand
	previousOutputReader := readRetirementCommandOutput
	previousProbe := probeRetiredService
	previousDiscover := discoverRetiredProcesses
	previousInspect := inspectRetiredProcess
	previousSignal := signalRetiredProcess
	previousNow := retirementProcessNow
	previousSleep := retirementProcessSleep
	previousTermGrace := legacyWebTUITermGrace
	previousKillGrace := legacyWebTUIKillGrace
	previousPoll := legacyWebTUIPollInterval
	legacySystemdWebTUIPath = systemdService
	legacySystemdWebTUIEnablementPath = systemdEnablement
	legacySystemdWebTUIDropInPath = systemdDropIn
	legacySystemdManagerRuntimePath = managerRuntime
	legacySystemdWebTUIRuntimePath = runtimeUnit
	legacySystemdWebTUIRuntimeDropIn = runtimeDropIn
	legacyOpenRCWebTUIPath = openRCService
	legacyOpenRCWebTUIEnablementPath = openRCEnablement
	legacyOpenRCWebTUIConfPath = openRCConf
	legacyOpenRCManagerRuntimePath = openRCRuntime
	legacyWebTUIPIDPath = pidPath
	legacyWebTUIExecutablePath = executablePath
	legacyWebTUIProcPath = procPath
	legacyWebTUIExpectedOwnerUID, legacyWebTUIExpectedOwnerGID = testFileOwner(t, executablePath)
	runRetirementCommand = func(name string, args ...string) error {
		fixture.calls = append(fixture.calls, strings.Join(append([]string{name}, args...), " "))
		return nil
	}
	readRetirementCommandOutput = func(name string, args ...string) (string, error) {
		call := strings.Join(append([]string{name}, args...), " ")
		switch call {
		case "systemctl show syswarden-webtui.service --property=LoadState --value":
			if _, err := os.Lstat(systemdService); err == nil {
				return "loaded", nil
			}
			return "not-found", nil
		case "systemctl show syswarden-webtui.service --property=ActiveState --value":
			return "inactive", nil
		case "systemctl show syswarden-webtui.service --property=FragmentPath --value":
			return systemdService, nil
		case "systemctl show syswarden-webtui.service --property=DropInPaths --value":
			return "", nil
		case "systemctl show syswarden-webtui.service --property=ExecStart --value":
			return "{ path=/opt/syswarden/bin/syswarden-cli ; argv[]=/opt/syswarden/bin/syswarden-cli web-tui ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }", nil
		default:
			return "", fmt.Errorf("unexpected manager query %s", call)
		}
	}
	probeRetiredService = func(bool) (bool, error) { return false, nil }
	discoverRetiredProcesses = discoverExactLegacyWebTUIProcesses
	inspectRetiredProcess = inspectExactLegacyWebTUIProcess
	signalRetiredProcess = func(pid int, signal syscall.Signal) error { return syscall.Kill(pid, signal) }
	retirementProcessNow = time.Now
	retirementProcessSleep = time.Sleep
	legacyWebTUITermGrace = 5 * time.Second
	legacyWebTUIKillGrace = 5 * time.Second
	legacyWebTUIPollInterval = 50 * time.Millisecond
	t.Cleanup(func() {
		legacySystemdWebTUIPath = previousSystemdService
		legacySystemdWebTUIEnablementPath = previousSystemdEnablement
		legacySystemdWebTUIDropInPath = previousSystemdDropIn
		legacySystemdManagerRuntimePath = previousSystemdManagerRuntime
		legacySystemdWebTUIRuntimePath = previousSystemdRuntime
		legacySystemdWebTUIRuntimeDropIn = previousSystemdRuntimeDropIn
		legacyOpenRCWebTUIPath = previousOpenRCService
		legacyOpenRCWebTUIEnablementPath = previousOpenRCEnablement
		legacyOpenRCWebTUIConfPath = previousOpenRCConf
		legacyOpenRCManagerRuntimePath = previousOpenRCRuntime
		legacyWebTUIPIDPath = previousPID
		legacyWebTUIExecutablePath = previousExecutable
		legacyWebTUIProcPath = previousProc
		legacyWebTUIExpectedOwnerUID = previousExpectedUID
		legacyWebTUIExpectedOwnerGID = previousExpectedGID
		runRetirementCommand = previousRunner
		readRetirementCommandOutput = previousOutputReader
		probeRetiredService = previousProbe
		discoverRetiredProcesses = previousDiscover
		inspectRetiredProcess = previousInspect
		signalRetiredProcess = previousSignal
		retirementProcessNow = previousNow
		retirementProcessSleep = previousSleep
		legacyWebTUITermGrace = previousTermGrace
		legacyWebTUIKillGrace = previousKillGrace
		legacyWebTUIPollInterval = previousPoll
	})
	return fixture
}

func (fixture *webTUIRetirementFixture) seedExact(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(fixture.servicePath, []byte(fixture.expectedUnit), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fixture.linkTarget, fixture.enablementPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.pidPath, []byte("123\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRetireLegacyWebTUIServiceExactSystemdUnitIsBoundedAndIdempotent(t *testing.T) {
	fixture := newWebTUIRetirementFixture(t, false)
	fixture.seedExact(t)
	if err := os.MkdirAll(fixture.managerRuntime, 0700); err != nil {
		t.Fatal(err)
	}
	probeCount := 0
	probeRetiredService = func(bool) (bool, error) {
		probeCount++
		return probeCount == 1, nil
	}

	if err := retireLegacyWebTUIService(false); err != nil {
		t.Fatal(err)
	}
	assertRetiredPathsAbsent(t, fixture.servicePath, fixture.pendingPath, fixture.enablementPath, fixture.pidPath)
	if err := retireLegacyWebTUIService(false); err != nil {
		t.Fatalf("idempotent retirement failed: %v", err)
	}
	wantCalls := []string{
		"systemctl stop syswarden-webtui.service",
		"systemctl disable syswarden-webtui.service",
		"systemctl daemon-reload",
	}
	if strings.Join(fixture.calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("manager calls = %v, want %v", fixture.calls, wantCalls)
	}
}

func TestRetireLegacyWebTUIServiceExactOpenRCUnit(t *testing.T) {
	fixture := newWebTUIRetirementFixture(t, true)
	fixture.seedExact(t)
	mustSeedOpenRCRuntime(t, filepath.Dir(filepath.Dir(fixture.openRCRuntime)), fixture.openRCRuntime)
	probeCount := 0
	probeRetiredService = func(bool) (bool, error) {
		probeCount++
		return probeCount == 1, nil
	}

	if err := retireLegacyWebTUIService(true); err != nil {
		t.Fatal(err)
	}
	assertRetiredPathsAbsent(t, fixture.servicePath, fixture.pendingPath, fixture.enablementPath, fixture.pidPath)
	wantCalls := []string{
		"rc-service syswarden-webtui stop",
		"rc-update del syswarden-webtui default",
	}
	if strings.Join(fixture.calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("manager calls = %v, want %v", fixture.calls, wantCalls)
	}
}

func TestRetireLegacyWebTUIServiceWithoutOpenRCRuntimeNeverCallsManager(t *testing.T) {
	fixture := newWebTUIRetirementFixture(t, true)
	fixture.seedExact(t)
	discoveryCount := 0
	discoverRetiredProcesses = func() ([]legacyWebTUIProcess, error) {
		discoveryCount++
		return nil, nil
	}
	probeRetiredService = func(bool) (bool, error) {
		return false, errors.New("OpenRC status must not be probed without a runtime")
	}

	if err := retireLegacyWebTUIService(true); err != nil {
		t.Fatal(err)
	}
	assertRetiredPathsAbsent(t, fixture.servicePath, fixture.pendingPath, fixture.enablementPath, fixture.pidPath)
	if len(fixture.calls) != 0 {
		t.Fatalf("offline OpenRC retirement triggered manager calls: %v", fixture.calls)
	}
	if discoveryCount == 0 {
		t.Fatal("offline OpenRC retirement bypassed the exact process inventory")
	}
}

func TestRetireLegacyWebTUIServiceRejectsAmbiguousOpenRCRuntime(t *testing.T) {
	for _, test := range []struct {
		name    string
		symlink bool
	}{
		{name: "regular file"},
		{name: "symlink", symlink: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWebTUIRetirementFixture(t, true)
			fixture.seedExact(t)
			if test.symlink {
				target := filepath.Join(filepath.Dir(fixture.openRCRuntime), "operator-runtime")
				if err := os.MkdirAll(target, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, fixture.openRCRuntime); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(fixture.openRCRuntime, []byte("ambiguous\n"), 0600); err != nil {
				t.Fatal(err)
			}

			err := retireLegacyWebTUIService(true)
			if err == nil || !strings.Contains(err.Error(), "unsafe service-manager runtime") {
				t.Fatalf("ambiguous OpenRC runtime error = %v", err)
			}
			if len(fixture.calls) != 0 {
				t.Fatalf("ambiguous OpenRC runtime triggered manager calls: %v", fixture.calls)
			}
			assertFileContent(t, fixture.servicePath, fixture.expectedUnit)
			assertPathExists(t, fixture.enablementPath)
			assertFileContent(t, fixture.pidPath, "123\n")
		})
	}
}

func TestRetireLegacyWebTUIServiceRequiresByteExactHistoricalUnit(t *testing.T) {
	for _, test := range []struct {
		name   string
		alpine bool
		suffix string
	}{
		{name: "systemd additional ExecStart", suffix: "ExecStart=/srv/operator/bin/listener\n"},
		{name: "openrc additional command", alpine: true, suffix: "command=/srv/operator/bin/listener\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWebTUIRetirementFixture(t, test.alpine)
			modified := fixture.expectedUnit + test.suffix
			if err := os.WriteFile(fixture.servicePath, []byte(modified), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(fixture.linkTarget, fixture.enablementPath); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fixture.pidPath, []byte("123\n"), 0600); err != nil {
				t.Fatal(err)
			}

			err := retireLegacyWebTUIService(test.alpine)
			if err == nil || !strings.Contains(err.Error(), "modified legacy Web-TUI service") {
				t.Fatalf("modified unit retirement error = %v", err)
			}
			if len(fixture.calls) != 0 {
				t.Fatalf("modified unit triggered manager calls: %v", fixture.calls)
			}
			assertFileContent(t, fixture.servicePath, modified)
			assertPathExists(t, fixture.enablementPath)
			assertFileContent(t, fixture.pidPath, "123\n")
		})
	}
}

func TestRetireLegacyWebTUIServiceRejectsManagerOverridesBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name      string
		alpine    bool
		path      func(*webTUIRetirementFixture) string
		directory bool
	}{
		{name: "systemd persistent drop-in", path: func(f *webTUIRetirementFixture) string { return f.systemdDropIn }, directory: true},
		{name: "systemd transient unit", path: func(f *webTUIRetirementFixture) string { return f.runtimeUnit }},
		{name: "systemd runtime drop-in", path: func(f *webTUIRetirementFixture) string { return f.runtimeDropIn }, directory: true},
		{name: "OpenRC conf.d override", alpine: true, path: func(f *webTUIRetirementFixture) string { return f.openRCConf }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWebTUIRetirementFixture(t, test.alpine)
			fixture.seedExact(t)
			override := test.path(fixture)
			if test.directory {
				if err := os.MkdirAll(override, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(override, "operator.conf"), []byte("ExecStart=/srv/operator/listener\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.MkdirAll(filepath.Dir(override), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(override, []byte("operator-owned override\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}

			err := retireLegacyWebTUIService(test.alpine)
			if err == nil || !strings.Contains(err.Error(), "manager override") {
				t.Fatalf("manager override retirement error = %v", err)
			}
			if len(fixture.calls) != 0 {
				t.Fatalf("manager override triggered mutating calls: %v", fixture.calls)
			}
			assertFileContent(t, fixture.servicePath, fixture.expectedUnit)
			assertPathExists(t, fixture.enablementPath)
			assertFileContent(t, fixture.pidPath, "123\n")
			assertPathExists(t, override)
		})
	}
}

func TestRetireLegacyWebTUIServiceRejectsUnexpectedLoadedSystemdIdentity(t *testing.T) {
	for _, test := range []struct {
		name      string
		property  string
		value     string
		wantError string
	}{
		{name: "unexpected load state", property: "LoadState", value: "masked", wantError: "not loaded normally"},
		{name: "different fragment", property: "FragmentPath", value: "/run/systemd/system/operator.service", wantError: "unexpected fragment"},
		{name: "loaded drop-in", property: "DropInPaths", value: "/etc/systemd/system/syswarden-webtui.service.d/operator.conf", wantError: "with drop-ins"},
		{name: "additional argument", property: "ExecStart", value: "{ path=/opt/syswarden/bin/syswarden-cli ; argv[]=/opt/syswarden/bin/syswarden-cli web-tui --operator ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }", wantError: "unexpected loaded"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWebTUIRetirementFixture(t, false)
			fixture.seedExact(t)
			readRetirementCommandOutput = func(_ string, args ...string) (string, error) {
				property := strings.TrimPrefix(args[2], "--property=")
				if property == test.property {
					return test.value, nil
				}
				switch property {
				case "LoadState":
					return "loaded", nil
				case "FragmentPath":
					return fixture.servicePath, nil
				case "DropInPaths":
					return "", nil
				case "ExecStart":
					return "{ path=/opt/syswarden/bin/syswarden-cli ; argv[]=/opt/syswarden/bin/syswarden-cli web-tui ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }", nil
				default:
					return "", fmt.Errorf("unexpected property %s", property)
				}
			}

			err := retireLegacyWebTUIService(false)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("loaded identity retirement error = %v", err)
			}
			if len(fixture.calls) != 0 {
				t.Fatalf("unexpected loaded identity triggered mutating calls: %v", fixture.calls)
			}
			assertFileContent(t, fixture.servicePath, fixture.expectedUnit)
			assertPathExists(t, fixture.enablementPath)
			assertFileContent(t, fixture.pidPath, "123\n")
		})
	}
}

func TestRetireLegacyWebTUIServiceRechecksOverridesBeforeStop(t *testing.T) {
	fixture := newWebTUIRetirementFixture(t, false)
	fixture.seedExact(t)
	probeRetiredService = func(bool) (bool, error) {
		if err := os.MkdirAll(fixture.systemdDropIn, 0700); err != nil {
			t.Fatal(err)
		}
		return true, nil
	}

	err := retireLegacyWebTUIService(false)
	if err == nil || !strings.Contains(err.Error(), "manager override") {
		t.Fatalf("raced manager override retirement error = %v", err)
	}
	if len(fixture.calls) != 0 {
		t.Fatalf("raced manager override triggered stop: %v", fixture.calls)
	}
	assertFileContent(t, fixture.servicePath, fixture.expectedUnit)
	assertPathExists(t, fixture.enablementPath)
	assertFileContent(t, fixture.pidPath, "123\n")
}

func TestLegacySystemdExecStartAttestationIsExact(t *testing.T) {
	exact := "{ path=/opt/syswarden/bin/syswarden-cli ; argv[]=/opt/syswarden/bin/syswarden-cli web-tui ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
	for _, test := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "exact", value: exact, want: true},
		{name: "different executable", value: strings.Replace(exact, "/opt/syswarden/bin/syswarden-cli", "/srv/operator/listener", 1)},
		{name: "different argv", value: strings.Replace(exact, " web-tui ;", " web-tui --operator ;", 1)},
		{name: "second command", value: exact + " ; " + exact},
		{name: "extra field", value: strings.Replace(exact, " ; status=", " ; operator=yes ; status=", 1)},
		{name: "embedded newline", value: strings.Replace(exact, "start_time=", "start_time=\n", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := exactLegacySystemdExecStart(test.value); got != test.want {
				t.Fatalf("exactLegacySystemdExecStart() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestRetireLegacyWebTUIServiceRejectsSymlinkedUnit(t *testing.T) {
	fixture := newWebTUIRetirementFixture(t, false)
	operatorUnit := filepath.Join(filepath.Dir(fixture.servicePath), "operator.service")
	if err := os.WriteFile(operatorUnit, []byte(fixture.expectedUnit), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(operatorUnit, fixture.servicePath); err != nil {
		t.Fatal(err)
	}

	err := retireLegacyWebTUIService(false)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlinked unit retirement error = %v", err)
	}
	if len(fixture.calls) != 0 {
		t.Fatalf("symlinked unit triggered manager calls: %v", fixture.calls)
	}
	assertFileContent(t, operatorUnit, fixture.expectedUnit)
}

func TestRetireLegacyWebTUIServiceRejectsUnexpectedUnitOwner(t *testing.T) {
	fixture := newWebTUIRetirementFixture(t, false)
	fixture.seedExact(t)
	legacyWebTUIExpectedOwnerUID ^= 1

	err := retireLegacyWebTUIService(false)
	if err == nil || !strings.Contains(err.Error(), "expected privileged account") {
		t.Fatalf("unexpected unit owner retirement error = %v", err)
	}
	if len(fixture.calls) != 0 {
		t.Fatalf("unexpected unit owner triggered manager calls: %v", fixture.calls)
	}
	assertFileContent(t, fixture.servicePath, fixture.expectedUnit)
	assertPathExists(t, fixture.enablementPath)
	assertFileContent(t, fixture.pidPath, "123\n")
}

func TestLegacyFileSnapshotDetectsOwnershipAndChownMetadataChanges(t *testing.T) {
	baseline := syscall.Stat_t{
		Uid:  0,
		Gid:  0,
		Ctim: syscall.Timespec{Sec: 100, Nsec: 200},
	}
	changedUID := baseline
	changedUID.Uid = 1
	changedGID := baseline
	changedGID.Gid = 1
	changedCTime := baseline
	changedCTime.Ctim.Nsec++
	for name, candidate := range map[string]syscall.Stat_t{
		"uid":   changedUID,
		"gid":   changedGID,
		"ctime": changedCTime,
	} {
		t.Run(name, func(t *testing.T) {
			if sameLegacyStatSnapshot(&baseline, &candidate) {
				t.Fatalf("%s change was accepted as the same ownership snapshot", name)
			}
		})
	}
}

func TestRetireLegacyWebTUIServiceCleansOnlyExactDanglingEnablement(t *testing.T) {
	for _, alpine := range []bool{false, true} {
		t.Run(map[bool]string{false: "systemd", true: "openrc"}[alpine], func(t *testing.T) {
			fixture := newWebTUIRetirementFixture(t, alpine)
			if !alpine {
				if err := os.RemoveAll(fixture.managerRuntime); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(fixture.linkTarget, fixture.enablementPath); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fixture.pidPath, []byte("987\n"), 0600); err != nil {
				t.Fatal(err)
			}

			if err := retireLegacyWebTUIService(alpine); err != nil {
				t.Fatal(err)
			}
			assertRetiredPathsAbsent(t, fixture.servicePath, fixture.pendingPath, fixture.enablementPath, fixture.pidPath)
			if len(fixture.calls) != 0 {
				t.Fatalf("unit-absent cleanup triggered manager calls: %v", fixture.calls)
			}
		})
	}
}

func TestRetireLegacyWebTUIServiceStopsCachedUnitBeforeReload(t *testing.T) {
	fixture := newWebTUIRetirementFixture(t, false)
	if err := os.MkdirAll(fixture.managerRuntime, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fixture.linkTarget, fixture.enablementPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.pidPath, []byte("987\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loadState := "loaded"
	active := true
	readRetirementCommandOutput = func(_ string, args ...string) (string, error) {
		switch strings.TrimPrefix(args[2], "--property=") {
		case "LoadState":
			return loadState, nil
		case "ActiveState":
			if active {
				return "active", nil
			}
			return "inactive", nil
		case "FragmentPath":
			return fixture.servicePath, nil
		case "DropInPaths":
			return "", nil
		case "ExecStart":
			return "{ path=/opt/syswarden/bin/syswarden-cli ; argv[]=/opt/syswarden/bin/syswarden-cli web-tui ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=900 ; code=(null) ; status=0/0 }", nil
		default:
			return "", fmt.Errorf("unexpected manager property %s", args[2])
		}
	}
	runRetirementCommand = func(name string, args ...string) error {
		call := strings.Join(append([]string{name}, args...), " ")
		fixture.calls = append(fixture.calls, call)
		switch call {
		case "systemctl stop syswarden-webtui.service":
			active = false
		case "systemctl daemon-reload":
			if active {
				return errors.New("daemon reload attempted before cached service stop")
			}
			loadState = "not-found"
		default:
			return fmt.Errorf("unexpected manager mutation %s", call)
		}
		return nil
	}

	if err := retireLegacyWebTUIService(false); err != nil {
		t.Fatal(err)
	}
	assertRetiredPathsAbsent(t, fixture.servicePath, fixture.pendingPath, fixture.enablementPath, fixture.pidPath)
	if active || loadState != "not-found" {
		t.Fatalf("cached service final state: active=%t load=%q", active, loadState)
	}
	wantCalls := []string{
		"systemctl stop syswarden-webtui.service",
		"systemctl daemon-reload",
	}
	if strings.Join(fixture.calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("cached service manager calls = %v, want %v", fixture.calls, wantCalls)
	}
}

func TestRetireLegacyWebTUIServiceRejectsAmbiguousCachedUnitWithoutStop(t *testing.T) {
	fixture := newWebTUIRetirementFixture(t, false)
	if err := os.MkdirAll(fixture.managerRuntime, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fixture.linkTarget, fixture.enablementPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.pidPath, []byte("987\n"), 0600); err != nil {
		t.Fatal(err)
	}
	readRetirementCommandOutput = func(_ string, args ...string) (string, error) {
		switch strings.TrimPrefix(args[2], "--property=") {
		case "LoadState":
			return "loaded", nil
		case "FragmentPath":
			return fixture.servicePath, nil
		case "DropInPaths":
			return "", nil
		case "ExecStart":
			return "{ path=/srv/operator/listener ; argv[]=/srv/operator/listener serve ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=900 ; code=(null) ; status=0/0 }", nil
		default:
			return "", fmt.Errorf("unexpected manager property %s", args[2])
		}
	}

	err := retireLegacyWebTUIService(false)
	if err == nil || !strings.Contains(err.Error(), "unexpected loaded") {
		t.Fatalf("ambiguous cached service retirement error = %v", err)
	}
	if len(fixture.calls) != 0 {
		t.Fatalf("ambiguous cached service triggered manager mutation: %v", fixture.calls)
	}
	assertPathExists(t, fixture.enablementPath)
	assertFileContent(t, fixture.pidPath, "987\n")
}

func TestRetireLegacyWebTUIServicePreservesModifiedEnablement(t *testing.T) {
	for _, test := range []struct {
		name        string
		regularFile bool
	}{
		{name: "modified symlink"},
		{name: "regular file", regularFile: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWebTUIRetirementFixture(t, false)
			if test.regularFile {
				if err := os.WriteFile(fixture.enablementPath, []byte("operator-owned\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Symlink("../operator.service", fixture.enablementPath); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fixture.pidPath, []byte("123\n"), 0600); err != nil {
				t.Fatal(err)
			}

			err := retireLegacyWebTUIService(false)
			if err == nil || !strings.Contains(err.Error(), "refusing") {
				t.Fatalf("modified enablement retirement error = %v", err)
			}
			assertPathExists(t, fixture.enablementPath)
			assertFileContent(t, fixture.pidPath, "123\n")
			if len(fixture.calls) != 0 {
				t.Fatalf("modified enablement triggered manager calls: %v", fixture.calls)
			}
		})
	}
}

func TestRetireLegacyWebTUIServiceResumesExactPendingUnit(t *testing.T) {
	fixture := newWebTUIRetirementFixture(t, false)
	if err := os.WriteFile(fixture.pendingPath, []byte(fixture.expectedUnit), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fixture.linkTarget, fixture.enablementPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.pidPath, []byte("123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := retireLegacyWebTUIService(false); err != nil {
		t.Fatal(err)
	}
	assertRetiredPathsAbsent(t, fixture.servicePath, fixture.pendingPath, fixture.enablementPath, fixture.pidPath)
}

func TestRetireLegacyWebTUIServiceFailsClosedOnAmbiguousOrModifiedPendingUnit(t *testing.T) {
	for _, test := range []struct {
		name       string
		activeUnit bool
		pending    string
	}{
		{name: "active and pending", activeUnit: true, pending: legacySystemdWebTUITemplate},
		{name: "modified pending", pending: legacySystemdWebTUITemplate + "ExecStart=/srv/operator/listener\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWebTUIRetirementFixture(t, false)
			if test.activeUnit {
				if err := os.WriteFile(fixture.servicePath, []byte(fixture.expectedUnit), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(fixture.pendingPath, []byte(test.pending), 0600); err != nil {
				t.Fatal(err)
			}

			if err := retireLegacyWebTUIService(false); err == nil {
				t.Fatal("ambiguous or modified pending unit was accepted")
			}
			assertFileContent(t, fixture.pendingPath, test.pending)
			if test.activeUnit {
				assertFileContent(t, fixture.servicePath, fixture.expectedUnit)
			}
			if len(fixture.calls) != 0 {
				t.Fatalf("unsafe pending state triggered manager calls: %v", fixture.calls)
			}
		})
	}
}

func TestRetireLegacyWebTUIServiceRestoresUnitAfterDaemonReloadFailure(t *testing.T) {
	fixture := newWebTUIRetirementFixture(t, false)
	fixture.seedExact(t)
	failReload := true
	runRetirementCommand = func(name string, args ...string) error {
		call := strings.Join(append([]string{name}, args...), " ")
		fixture.calls = append(fixture.calls, call)
		if call == "systemctl daemon-reload" && failReload {
			return errors.New("injected daemon reload failure")
		}
		return nil
	}

	err := retireLegacyWebTUIService(false)
	if err == nil || !strings.Contains(err.Error(), "reload systemd") {
		t.Fatalf("daemon reload failure = %v", err)
	}
	assertFileContent(t, fixture.servicePath, fixture.expectedUnit)
	assertRetiredPathsAbsent(t, fixture.pendingPath, fixture.enablementPath)
	assertFileContent(t, fixture.pidPath, "123\n")

	failReload = false
	if err := retireLegacyWebTUIService(false); err != nil {
		t.Fatalf("retry after restored unit failed: %v", err)
	}
	assertRetiredPathsAbsent(t, fixture.servicePath, fixture.pendingPath, fixture.enablementPath, fixture.pidPath)
}

func TestRetireLegacyWebTUIServiceFailsClosedOnManagerUncertainty(t *testing.T) {
	for _, test := range []struct {
		name      string
		probe     func(bool) (bool, error)
		failCall  string
		wantError string
	}{
		{
			name:      "initial status probe error",
			probe:     func(bool) (bool, error) { return false, errors.New("probe unavailable") },
			wantError: "verify retired service state",
		},
		{
			name:      "stop failure",
			probe:     func(bool) (bool, error) { return true, nil },
			failCall:  "systemctl stop syswarden-webtui.service",
			wantError: "stop retired service",
		},
		{
			name:      "disable failure",
			probe:     func(bool) (bool, error) { return false, nil },
			failCall:  "systemctl disable syswarden-webtui.service",
			wantError: "disable retired service",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWebTUIRetirementFixture(t, false)
			fixture.seedExact(t)
			probeRetiredService = test.probe
			runRetirementCommand = func(name string, args ...string) error {
				call := strings.Join(append([]string{name}, args...), " ")
				fixture.calls = append(fixture.calls, call)
				if call == test.failCall {
					return errors.New("injected manager failure")
				}
				return nil
			}

			err := retireLegacyWebTUIService(false)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("manager uncertainty error = %v", err)
			}
			assertFileContent(t, fixture.servicePath, fixture.expectedUnit)
			assertPathExists(t, fixture.enablementPath)
			assertFileContent(t, fixture.pidPath, "123\n")
		})
	}
}

func TestRetireLegacyWebTUIPIDCleanupFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
		symlink bool
	}{
		{name: "invalid content", content: "12 operator\n"},
		{name: "symlink", content: "456\n", symlink: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWebTUIRetirementFixture(t, false)
			if test.symlink {
				target := filepath.Join(filepath.Dir(fixture.pidPath), "operator.pid")
				if err := os.WriteFile(target, []byte(test.content), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, fixture.pidPath); err != nil {
					t.Fatal(err)
				}
				defer assertFileContent(t, target, test.content)
			} else if err := os.WriteFile(fixture.pidPath, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}

			if err := retireLegacyWebTUIService(false); err == nil {
				t.Fatal("unsafe PID file was accepted")
			}
			assertPathExists(t, fixture.pidPath)
		})
	}
}

func TestReadOwnedLegacyServiceIsBounded(t *testing.T) {
	previousExpectedUID := legacyWebTUIExpectedOwnerUID
	previousExpectedGID := legacyWebTUIExpectedOwnerGID
	t.Cleanup(func() {
		legacyWebTUIExpectedOwnerUID = previousExpectedUID
		legacyWebTUIExpectedOwnerGID = previousExpectedGID
	})
	path := filepath.Join(t.TempDir(), "oversized.service")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maximumLegacyServiceFileSize+1)), 0600); err != nil {
		t.Fatal(err)
	}
	legacyWebTUIExpectedOwnerUID, legacyWebTUIExpectedOwnerGID = testFileOwner(t, path)
	if _, err := readOwnedLegacyService(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized service read error = %v", err)
	}
}

func TestClassifyLegacyWebTUIProcessRequiresExactExecutableAndNULArguments(t *testing.T) {
	fixture := newWebTUIRetirementFixture(t, false)
	exactArguments := []string{legacyWebTUIExecutablePath, "web-tui", "--bind=127.0.0.1:62027"}
	for _, test := range []struct {
		name              string
		executableMatches bool
		executableStatOK  bool
		executableLink    string
		linkOK            bool
		arguments         []string
		argumentsOK       bool
		wantState         legacyProcessState
		wantError         bool
	}{
		{
			name:              "current attested inode",
			executableMatches: true,
			executableStatOK:  true,
			arguments:         []string{"alternate-argv-zero", "web-tui"},
			argumentsOK:       true,
			wantState:         legacyProcessExact,
		},
		{
			name:             "replaced deleted executable",
			executableStatOK: true,
			executableLink:   legacyWebTUIExecutablePath + " (deleted)",
			linkOK:           true,
			arguments:        exactArguments,
			argumentsOK:      true,
			wantState:        legacyProcessExact,
		},
		{
			name:             "replaced renamed executable is ambiguous",
			executableStatOK: true,
			executableLink:   legacyWebTUIExecutablePath + ".operator-backup",
			linkOK:           true,
			arguments:        exactArguments,
			argumentsOK:      true,
			wantError:        true,
		},
		{
			name:           "deleted path without inode is ambiguous",
			executableLink: legacyWebTUIExecutablePath + " (deleted)",
			linkOK:         true,
			arguments:      exactArguments,
			argumentsOK:    true,
			wantError:      true,
		},
		{
			name:              "unreadable arguments on attested inode",
			executableMatches: true,
			executableStatOK:  true,
			wantError:         true,
		},
		{
			name:             "third party unrelated command",
			executableStatOK: true,
			executableLink:   "/srv/operator/listener",
			linkOK:           true,
			arguments:        []string{"/srv/operator/listener", "serve"},
			argumentsOK:      true,
			wantState:        legacyProcessUnrelated,
		},
		{
			name:              "near match subcommand",
			executableMatches: true,
			executableStatOK:  true,
			arguments:         []string{legacyWebTUIExecutablePath, "web-tui-extra"},
			argumentsOK:       true,
			wantState:         legacyProcessUnrelated,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			state, err := classifyLegacyWebTUIProcess(
				test.executableMatches,
				test.executableStatOK,
				test.executableLink,
				test.linkOK,
				test.arguments,
				test.argumentsOK,
			)
			if (err != nil) != test.wantError {
				t.Fatalf("classification error = %v, want error %t", err, test.wantError)
			}
			if !test.wantError && state != test.wantState {
				t.Fatalf("classification state = %d, want %d", state, test.wantState)
			}
		})
	}
	_ = fixture
}

func TestReadLegacyProcessArgumentsRequiresBoundedNULTerminatedArgv(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "cmdline")
	exact := []byte("/opt/syswarden/bin/syswarden-cli\x00web-tui\x00--bind=127.0.0.1:62027\x00")
	if err := os.WriteFile(path, exact, 0600); err != nil {
		t.Fatal(err)
	}
	arguments, err := readLegacyProcessArguments(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(arguments, "|"); got != "/opt/syswarden/bin/syswarden-cli|web-tui|--bind=127.0.0.1:62027" {
		t.Fatalf("decoded NUL arguments = %q", got)
	}

	if err := os.WriteFile(path, exact[:len(exact)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLegacyProcessArguments(path); err == nil || !strings.Contains(err.Error(), "NUL terminated") {
		t.Fatalf("unterminated command line error = %v", err)
	}
	if err := os.WriteFile(path, append(make([]byte, maximumLegacyCmdlineSize), 0), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLegacyProcessArguments(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized command line error = %v", err)
	}
}

func TestDiscoverExactLegacyWebTUIProcessesIgnoresThirdPartyProcess(t *testing.T) {
	fixture := newWebTUIRetirementFixture(t, false)
	seedFakeLegacyProcess(
		t,
		legacyWebTUIProcPath,
		101,
		legacyWebTUIExecutablePath,
		[]byte(legacyWebTUIExecutablePath+"\x00web-tui\x00--bind=127.0.0.1:62027\x00"),
		"777",
	)
	thirdPartyExecutable := filepath.Join(filepath.Dir(legacyWebTUIExecutablePath), "operator-listener")
	if err := os.WriteFile(thirdPartyExecutable, []byte("operator executable\n"), 0600); err != nil {
		t.Fatal(err)
	}
	seedFakeLegacyProcess(
		t,
		legacyWebTUIProcPath,
		202,
		thirdPartyExecutable,
		[]byte(thirdPartyExecutable+"\x00serve\x00"),
		"888",
	)

	processes, err := discoverExactLegacyWebTUIProcesses()
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) != 1 || processes[0].pid != 101 || processes[0].startTime != "777" {
		t.Fatalf("exact process inventory = %+v", processes)
	}
	_ = fixture
}

func TestRetireExactLegacyWebTUIProcessesNeverSignalsAmbiguousExecutable(t *testing.T) {
	fixture := newWebTUIRetirementFixture(t, false)
	thirdPartyExecutable := filepath.Join(filepath.Dir(legacyWebTUIExecutablePath), "operator-listener")
	if err := os.WriteFile(thirdPartyExecutable, []byte("operator executable\n"), 0600); err != nil {
		t.Fatal(err)
	}
	seedFakeLegacyProcess(
		t,
		legacyWebTUIProcPath,
		303,
		thirdPartyExecutable,
		[]byte(legacyWebTUIExecutablePath+"\x00web-tui\x00"),
		"999",
	)
	var signals []syscall.Signal
	signalRetiredProcess = func(_ int, signal syscall.Signal) error {
		signals = append(signals, signal)
		return nil
	}

	err := retireExactLegacyWebTUIProcesses()
	if err == nil || !strings.Contains(err.Error(), "identity is not attestable") {
		t.Fatalf("ambiguous process retirement error = %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("ambiguous process was signalled: %v", signals)
	}
	_ = fixture
}

func TestRetireExactLegacyWebTUIProcessesUsesOnlyRevalidatedPID(t *testing.T) {
	for _, test := range []struct {
		name        string
		recycled    bool
		termExits   bool
		wantSignals []syscall.Signal
	}{
		{name: "TERM exit", termExits: true, wantSignals: []syscall.Signal{syscall.SIGTERM}},
		{name: "bounded KILL", wantSignals: []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}},
		{name: "recycled PID", recycled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWebTUIRetirementFixture(t, false)
			candidate := legacyWebTUIProcess{pid: 404, startTime: "1000"}
			alive := true
			discoveryCount := 0
			discoverRetiredProcesses = func() ([]legacyWebTUIProcess, error) {
				discoveryCount++
				if test.recycled {
					if discoveryCount == 1 {
						return []legacyWebTUIProcess{candidate}, nil
					}
					return nil, nil
				}
				if alive {
					return []legacyWebTUIProcess{candidate}, nil
				}
				return nil, nil
			}
			inspectRetiredProcess = func(pid int) (legacyWebTUIProcess, legacyProcessState, error) {
				if pid != candidate.pid {
					t.Fatalf("inspected unexpected PID %d", pid)
				}
				if test.recycled {
					return legacyWebTUIProcess{pid: pid, startTime: "2000"}, legacyProcessExact, nil
				}
				if !alive {
					return legacyWebTUIProcess{}, legacyProcessVanished, nil
				}
				return candidate, legacyProcessExact, nil
			}
			var signals []syscall.Signal
			signalRetiredProcess = func(pid int, signal syscall.Signal) error {
				if pid != candidate.pid {
					t.Fatalf("signalled unexpected PID %d", pid)
				}
				signals = append(signals, signal)
				if signal == syscall.SIGKILL || (signal == syscall.SIGTERM && test.termExits) {
					alive = false
				}
				return nil
			}
			legacyWebTUITermGrace = 0
			legacyWebTUIKillGrace = 0

			if err := retireExactLegacyWebTUIProcesses(); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(signals) != fmt.Sprint(test.wantSignals) {
				t.Fatalf("signals = %v, want %v", signals, test.wantSignals)
			}
			_ = fixture
		})
	}
}

func TestRetireLegacyWebTUIServiceFailsClosedWhenExecutableIsNotAttestable(t *testing.T) {
	fixture := newWebTUIRetirementFixture(t, false)
	operatorExecutable := legacyWebTUIExecutablePath + ".operator"
	if err := os.WriteFile(operatorExecutable, []byte("operator executable\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(legacyWebTUIExecutablePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(operatorExecutable, legacyWebTUIExecutablePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.pidPath, []byte("123\n"), 0600); err != nil {
		t.Fatal(err)
	}

	err := retireLegacyWebTUIService(false)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("unattestable executable retirement error = %v", err)
	}
	assertFileContent(t, fixture.pidPath, "123\n")
	assertFileContent(t, operatorExecutable, "operator executable\n")
}

func seedFakeLegacyProcess(t *testing.T, procRoot string, pid int, executableTarget string, commandLine []byte, startTime string) {
	t.Helper()
	processRoot := filepath.Join(procRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(processRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executableTarget, filepath.Join(processRoot, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(processRoot, "cmdline"), commandLine, 0600); err != nil {
		t.Fatal(err)
	}
	fields := make([]string, 20)
	for index := range fields {
		fields[index] = "0"
	}
	fields[0] = "S"
	fields[19] = startTime
	stat := fmt.Sprintf("%d (syswarden cli) %s\n", pid, strings.Join(fields, " "))
	if err := os.WriteFile(filepath.Join(processRoot, "stat"), []byte(stat), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRetiredServiceStatusProbeDistinguishesInactiveFromProbeFailure(t *testing.T) {
	previousRunner := runRetirementCommand
	t.Cleanup(func() { runRetirementCommand = previousRunner })

	runRetirementCommand = func(string, ...string) error {
		return exec.Command("/bin/sh", "-c", "exit 3").Run()
	}
	active, err := probeRetiredServiceActive(false)
	if err != nil || active {
		t.Fatalf("inactive systemd status = active %t, error %v", active, err)
	}

	runRetirementCommand = func(string, ...string) error {
		return exec.Command("/bin/sh", "-c", "exit 4").Run()
	}
	active, err = probeRetiredServiceActive(false)
	if err != nil || active {
		t.Fatalf("missing systemd status = active %t, error %v", active, err)
	}
	if _, err := probeRetiredServiceActive(true); err == nil {
		t.Fatal("OpenRC status exit 4 was accepted as inactive")
	}

	runRetirementCommand = func(string, ...string) error {
		return errors.New("manager transport failure")
	}
	if _, err := probeRetiredServiceActive(false); err == nil || !strings.Contains(err.Error(), "manager transport failure") {
		t.Fatalf("status transport failure was not preserved: %v", err)
	}
}

func TestLegacyWebTUIEnablementTargetsAreExact(t *testing.T) {
	for _, test := range []struct {
		kind   string
		target string
		want   bool
	}{
		{kind: "systemd", target: "../syswarden-webtui.service", want: true},
		{kind: "systemd", target: "/etc/systemd/system/syswarden-webtui.service", want: true},
		{kind: "openrc", target: "/etc/init.d/syswarden-webtui", want: true},
		{kind: "openrc", target: "../../init.d/syswarden-webtui", want: true},
		{kind: "systemd", target: "../operator.service"},
		{kind: "openrc", target: "/srv/operator"},
		{kind: "unknown", target: "../syswarden-webtui.service"},
	} {
		if got := legacyEnablementTargetAllowed(test.kind, test.target); got != test.want {
			t.Errorf("legacyEnablementTargetAllowed(%q, %q) = %t, want %t", test.kind, test.target, got, test.want)
		}
	}
}

func TestRetirementCommandRunnerRejectsUnexpectedExecutable(t *testing.T) {
	err := runAllowedRetirementCommand("/srv/operator/manager", "stop")
	if err == nil || !strings.Contains(err.Error(), "refusing unexpected") {
		t.Fatalf("unexpected retirement command error = %v", err)
	}
}

func TestRetiredServiceCleanupContainsNoBroadProcessOrFilesystemOperation(t *testing.T) {
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate retirement test source")
	}
	directory := filepath.Dir(sourcePath)
	for _, file := range []string{"web_tui_retirement_linux.go", "uninstall_linux.go"} {
		content, err := readWebTUITestFile(filepath.Join(directory, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"pkill", "killall", `exec.Command("kill"`} {
			if strings.Contains(string(content), forbidden) {
				t.Fatalf("%s contains broad process operation %q", file, forbidden)
			}
		}
		if file == "web_tui_retirement_linux.go" && strings.Contains(string(content), "RemoveAll") {
			t.Fatalf("%s contains broad filesystem removal", file)
		}
	}
}

func assertRetiredPathsAbsent(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("retired path %s remains: %v", path, err)
		}
	}
}

func assertPathExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("expected path %s to remain: %v", path, err)
	}
}

func assertFileContent(t *testing.T, path, expected string) {
	t.Helper()
	content, err := readWebTUITestFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != expected {
		t.Fatalf("content of %s changed", path)
	}
}

func readWebTUITestFile(path string) ([]byte, error) {
	file, err := openFileWithinParent(path)
	if err != nil {
		return nil, err
	}
	content, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return content, nil
}

func testFileOwner(t *testing.T, path string) (uint32, uint32) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("test file %s has no Linux ownership metadata", path)
	}
	return stat.Uid, stat.Gid
}
