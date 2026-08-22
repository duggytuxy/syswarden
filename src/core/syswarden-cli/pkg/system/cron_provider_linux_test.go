//go:build linux

package system

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testCronProviderExecutable(t *testing.T, directory, name string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil { // #nosec G306 -- executable mode is required for this isolated provider fixture
		t.Fatal(err)
	}
	return path
}

func activeCronProviderRuntime(bool) (serviceManagerState, error) {
	return serviceManagerActive, nil
}

func offlineCronProviderRuntime(bool) (serviceManagerState, error) {
	return serviceManagerOffline, nil
}

func testCronProviderHost(
	t *testing.T,
	alpine bool,
	classify func(bool) (serviceManagerState, error),
	output func(string, ...string) ([]byte, error),
) cronDProviderHost {
	t.Helper()
	directory := t.TempDir()
	paths := make(map[string]string)
	for _, name := range []string{"systemctl", "dpkg-query", "rpm", "apk", "crond", "rc-service", "rc-update"} {
		paths[name] = testCronProviderExecutable(t, directory, name)
	}
	return cronDProviderHost{
		alpine:          alpine,
		classifyRuntime: classify,
		executor: firewallManagerExecutor{
			lookPath: func(name string) (string, error) {
				path, exists := paths[name]
				if !exists {
					return "", errors.New("unexpected executable")
				}
				return path, nil
			},
			validate: func(string) error { return nil },
			output:   output,
		},
		attestDropIns: attestApprovedSystemdServiceDropIns,
		attestPath: func(path string, executable bool) (string, error) {
			return path, nil
		},
		pathExists:       func(string) (bool, error) { return false, nil },
		attestEnablement: func(string, string) error { return nil },
		canonicalizePath: func(path string) (string, error) { return path, nil },
	}
}

func systemdCronProviderOutput(
	loadedCron bool,
	loadedCrond bool,
	propertyOverride map[string]string,
) func(string, ...string) ([]byte, error) {
	return func(path string, arguments ...string) ([]byte, error) {
		name := filepath.Base(path)
		if name == "dpkg-query" {
			switch strings.Join(arguments, " ") {
			case "--show --showformat=${Version}\\n cron":
				return []byte("3.0pl1-200\n"), nil
			case "--listfiles cron":
				return []byte("/vendor/cron.service\n/usr/sbin/cron\n"), nil
			default:
				return nil, errors.New("unexpected dpkg query")
			}
		}
		if name != "systemctl" || len(arguments) != 4 || arguments[0] != "show" || arguments[2] != "--value" {
			return nil, errors.New("unexpected provider command")
		}
		property := strings.TrimPrefix(arguments[1], "--property=")
		unit := arguments[3]
		if value, exists := propertyOverride[unit+":"+property]; exists {
			return []byte(value + "\n"), nil
		}
		if property == "LoadState" {
			loaded := unit == "cron.service" && loadedCron || unit == "crond.service" && loadedCrond
			if loaded {
				return []byte("loaded\n"), nil
			}
			return []byte("not-found\n"), nil
		}
		if unit != "cron.service" {
			return nil, errors.New("unexpected loaded unit")
		}
		switch property {
		case "ActiveState":
			return []byte("active\n"), nil
		case "UnitFileState":
			return []byte("enabled\n"), nil
		case "FragmentPath":
			return []byte("/vendor/cron.service\n"), nil
		case "DropInPaths":
			return []byte("\n"), nil
		case "ExecStart":
			return []byte("{ path=/usr/sbin/cron ; argv[]=/usr/sbin/cron -f ; ignore_errors=no ; }\n"), nil
		default:
			return nil, errors.New("unexpected property")
		}
	}
}

func TestSystemdCronDProviderRequiresSingleCompleteStableProvider(t *testing.T) {
	host := testCronProviderHost(
		t, false, activeCronProviderRuntime,
		systemdCronProviderOutput(true, false, nil),
	)
	evidence, err := host.attest()
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Mode != CronDProviderRuntime || evidence.Manager != "systemd" ||
		evidence.Unit != "cron.service" || len(evidence.Packages) != 1 || evidence.Packages[0] != "cron" {
		t.Fatalf("systemd evidence = %#v", evidence)
	}
}

func TestSystemdCrondProviderRequiresExactRPMProvenance(t *testing.T) {
	host := testCronProviderHost(t, false, activeCronProviderRuntime, func(path string, arguments ...string) ([]byte, error) {
		switch filepath.Base(path) {
		case "rpm":
			if len(arguments) == 5 && arguments[0] == "--query" && arguments[1] == "--file" &&
				arguments[3] == "--queryformat" && arguments[4] == "%{NAME}\\t%{EVR}\\n" {
				return []byte("cronie\t1.7.2-1\n"), nil
			}
		case "systemctl":
			if len(arguments) != 4 {
				return nil, errors.New("unexpected systemctl arguments")
			}
			property := strings.TrimPrefix(arguments[1], "--property=")
			unit := arguments[3]
			if property == "LoadState" {
				if unit == "crond.service" {
					return []byte("loaded\n"), nil
				}
				return []byte("not-found\n"), nil
			}
			switch property {
			case "ActiveState":
				return []byte("active\n"), nil
			case "UnitFileState":
				return []byte("enabled\n"), nil
			case "FragmentPath":
				return []byte("/vendor/crond.service\n"), nil
			case "DropInPaths":
				return []byte("\n"), nil
			case "ExecStart":
				return []byte("{ path=/usr/sbin/crond ; argv[]=/usr/sbin/crond -n ; ignore_errors=no ; }\n"), nil
			}
		}
		return nil, errors.New("unexpected RPM provider command")
	})
	evidence, err := host.attest()
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Unit != "crond.service" || strings.Join(evidence.Packages, ",") != "cronie" {
		t.Fatalf("RPM provider evidence = %#v", evidence)
	}
}

func TestSystemdCrondProviderAcceptsOnlyAttestedVendorDropIn(t *testing.T) {
	const vendorDropIn = "/usr/lib/systemd/system/service.d/10-timeout-abort.conf"
	host := testCronProviderHost(t, false, activeCronProviderRuntime, func(path string, arguments ...string) ([]byte, error) {
		switch filepath.Base(path) {
		case "rpm":
			if len(arguments) == 5 && arguments[0] == "--query" && arguments[1] == "--file" &&
				arguments[3] == "--queryformat" && arguments[4] == "%{NAME}\\t%{EVR}\\n" {
				return []byte("cronie\t1.7.2-16.fc44\n"), nil
			}
		case "systemctl":
			property := strings.TrimPrefix(arguments[1], "--property=")
			unit := arguments[3]
			if property == "LoadState" {
				if unit == "crond.service" {
					return []byte("loaded\n"), nil
				}
				return []byte("not-found\n"), nil
			}
			switch property {
			case "ActiveState":
				return []byte("active\n"), nil
			case "UnitFileState":
				return []byte("enabled\n"), nil
			case "FragmentPath":
				return []byte("/vendor/crond.service\n"), nil
			case "DropInPaths":
				return []byte(vendorDropIn + "\n"), nil
			case "ExecStart":
				return []byte("{ path=/usr/sbin/crond ; argv[]=/usr/sbin/crond -n ; ignore_errors=no ; }\n"), nil
			}
		}
		return nil, errors.New("unexpected provider command")
	})
	attestCalls := 0
	host.attestDropIns = func(_ firewallManagerExecutor, value string) (string, error) {
		attestCalls++
		if value != vendorDropIn {
			return "", errors.New("unexpected drop-in")
		}
		return vendorDropIn + "#attested", nil
	}
	if _, err := host.attest(); err != nil {
		t.Fatal(err)
	}
	if attestCalls != 2 {
		t.Fatalf("vendor drop-in attestation calls = %d, want 2", attestCalls)
	}
}

func TestCroniePackageOwnershipUsesCanonicalRPMArgumentsAndFailsClosed(t *testing.T) {
	const (
		fragment = "/vendor/crond.service"
		daemon   = "/usr/sbin/crond"
		format   = "%{NAME}\\t%{EVR}\\n"
	)
	var calls []string
	host := testCronProviderHost(t, false, activeCronProviderRuntime, func(path string, arguments ...string) ([]byte, error) {
		calls = append(calls, filepath.Base(path)+" "+strings.Join(arguments, " "))
		if len(arguments) != 5 || arguments[0] != "--query" || arguments[1] != "--file" ||
			arguments[3] != "--queryformat" || arguments[4] != format {
			return nil, errors.New("unexpected RPM arguments")
		}
		return []byte("cronie\t1.7.2-1\n"), nil
	})
	if _, err := host.attestSystemPackage("cronie", fragment, daemon); err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{
		"rpm --query --file " + fragment + " --queryformat " + format,
		"rpm --query --file " + daemon + " --queryformat " + format,
	}
	if strings.Join(calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("RPM calls = %#v, want %#v", calls, wantCalls)
	}

	for _, testCase := range []struct {
		name     string
		fragment []byte
		daemon   []byte
		queryErr error
	}{
		{name: "wrong owner", fragment: []byte("operator-package\t1.7.2-1\n"), daemon: []byte("cronie\t1.7.2-1\n")},
		{name: "duplicate owner", fragment: []byte("cronie\t1.7.2-1\ncronie\t1.7.2-1\n"), daemon: []byte("cronie\t1.7.2-1\n")},
		{name: "version drift", fragment: []byte("cronie\t1.7.2-1\n"), daemon: []byte("cronie\t1.7.3-1\n")},
		{name: "query failure", queryErr: errors.New("rpm query failed")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			host := testCronProviderHost(t, false, activeCronProviderRuntime, func(_ string, arguments ...string) ([]byte, error) {
				if testCase.queryErr != nil {
					return nil, testCase.queryErr
				}
				if len(arguments) != 5 || arguments[0] != "--query" || arguments[1] != "--file" ||
					arguments[3] != "--queryformat" || arguments[4] != format {
					return nil, errors.New("unexpected RPM arguments")
				}
				if arguments[2] == fragment {
					return testCase.fragment, nil
				}
				return testCase.daemon, nil
			})
			if _, err := host.attestSystemPackage("cronie", fragment, daemon); err == nil {
				t.Fatal("unattested Cronie package ownership was accepted")
			}
		})
	}
}

func TestSystemdCronDProviderRejectsDoubleProviderAndMutableExecutionSurface(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		loadedCron  bool
		loadedCrond bool
		override    map[string]string
	}{
		{name: "double provider", loadedCron: true, loadedCrond: true},
		{
			name:       "drop-in",
			loadedCron: true,
			override:   map[string]string{"cron.service:DropInPaths": "/etc/systemd/system/cron.service.d/operator.conf"},
		},
		{
			name:       "shell ExecStart",
			loadedCron: true,
			override:   map[string]string{"cron.service:ExecStart": "{ path=/bin/sh ; argv[]=/bin/sh -c cron ; ignore_errors=no ; }"},
		},
		{
			name:       "ignored ExecStart failure",
			loadedCron: true,
			override:   map[string]string{"cron.service:ExecStart": "{ path=/usr/sbin/cron ; argv[]=/usr/sbin/cron -f ; ignore_errors=yes ; }"},
		},
		{
			name:       "transient enablement",
			loadedCron: true,
			override:   map[string]string{"cron.service:UnitFileState": "enabled-runtime"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			host := testCronProviderHost(
				t, false, activeCronProviderRuntime,
				systemdCronProviderOutput(testCase.loadedCron, testCase.loadedCrond, testCase.override),
			)
			if _, err := host.attest(); err == nil {
				t.Fatal("unsafe systemd cron.d provider was accepted")
			}
		})
	}
}

func TestSystemdCronDProviderRejectsCompleteSnapshotDrift(t *testing.T) {
	activeQueries := 0
	base := systemdCronProviderOutput(true, false, nil)
	host := testCronProviderHost(t, false, activeCronProviderRuntime, func(path string, arguments ...string) ([]byte, error) {
		if len(arguments) == 4 && arguments[1] == "--property=ActiveState" {
			activeQueries++
			if activeQueries == 2 {
				return []byte("inactive\n"), nil
			}
		}
		return base(path, arguments...)
	})
	if _, err := host.attest(); err == nil {
		t.Fatal("systemd provider drift was accepted")
	}
}

func alpineProviderOutput(
	wrongOwner bool,
	runlevels string,
	commandLog *[]string,
) func(string, ...string) ([]byte, error) {
	return func(path string, arguments ...string) ([]byte, error) {
		command := filepath.Base(path) + " " + strings.Join(arguments, " ")
		if commandLog != nil {
			*commandLog = append(*commandLog, command)
		}
		switch {
		case command == "apk info --installed cronie", command == "apk info --installed cronie-openrc":
			return nil, nil
		case strings.HasPrefix(command, "apk info --who-owns "):
			ownedPath := strings.TrimPrefix(command, "apk info --who-owns ")
			packageID := "cronie"
			if ownedPath == "/etc/init.d/cronie" {
				packageID = "cronie-openrc"
			}
			if wrongOwner {
				packageID = "operator-package"
			}
			return []byte(ownedPath + " is owned by " + packageID + "-1.7.2-r0\n"), nil
		case command == "rc-service --exists cronie":
			return nil, nil
		case command == "rc-service cronie status":
			return []byte("status: started\n"), nil
		case command == "rc-update show":
			return []byte(runlevels), nil
		default:
			return nil, errors.New("unexpected Alpine provider command")
		}
	}
}

func TestAlpineCronDProviderBindsPackagesInitDaemonAndDefaultRunlevel(t *testing.T) {
	commands := make([]string, 0)
	host := testCronProviderHost(
		t, true, activeCronProviderRuntime,
		alpineProviderOutput(false, "cronie | default\n", &commands),
	)
	evidence, err := host.attest()
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Mode != CronDProviderRuntime || evidence.Manager != "openrc" ||
		evidence.Unit != "cronie" || evidence.Fragment != "/etc/init.d/cronie" || filepath.Base(evidence.Daemon) != "crond" ||
		!evidence.DefaultRunlevel || strings.Join(evidence.Packages, ",") != "cronie,cronie-openrc" {
		t.Fatalf("Alpine evidence = %#v", evidence)
	}
	firstStatus := -1
	firstInitOwnership := -1
	for index, command := range commands {
		if command == "apk info --who-owns /etc/init.d/cronie" && firstInitOwnership < 0 {
			firstInitOwnership = index
		}
		if command == "rc-service cronie status" && firstStatus < 0 {
			firstStatus = index
		}
	}
	if firstInitOwnership < 0 || firstStatus < 0 || firstInitOwnership > firstStatus {
		t.Fatalf("init provenance was not proven before service execution: %v", commands)
	}
}

func TestAlpineCronDProviderRejectsCompleteSnapshotDrift(t *testing.T) {
	statusCalls := 0
	base := alpineProviderOutput(false, "cronie | default\n", nil)
	host := testCronProviderHost(t, true, activeCronProviderRuntime, func(path string, arguments ...string) ([]byte, error) {
		if filepath.Base(path) == "rc-service" && strings.Join(arguments, " ") == "cronie status" {
			statusCalls++
			if statusCalls == 2 {
				return []byte("status: changed\n"), nil
			}
		}
		return base(path, arguments...)
	})
	if _, err := host.attest(); err == nil {
		t.Fatal("Alpine provider snapshot drift was accepted")
	}
}

func TestAlpineCronDProviderRejectsWrongOwnershipAndNonDefaultRunlevel(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		wrongOwner bool
		runlevels  string
	}{
		{name: "wrong package owner", wrongOwner: true, runlevels: "cronie | default\n"},
		{name: "daemon name is not service name", runlevels: "crond | default\n"},
		{name: "extra runlevel", runlevels: "cronie | default boot\n"},
		{name: "duplicate inventory", runlevels: "cronie | default\ncronie | default\n"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			host := testCronProviderHost(
				t, true, activeCronProviderRuntime,
				alpineProviderOutput(testCase.wrongOwner, testCase.runlevels, nil),
			)
			if _, err := host.attest(); err == nil {
				t.Fatal("unsafe Alpine provider was accepted")
			}
		})
	}
}

func TestAlpineCronDProviderRejectsBusyBoxDaemonTarget(t *testing.T) {
	host := testCronProviderHost(
		t, true, activeCronProviderRuntime,
		alpineProviderOutput(false, "cronie | default\n", nil),
	)
	directory := t.TempDir()
	busybox := testCronProviderExecutable(t, directory, "busybox")
	crond := filepath.Join(directory, "crond")
	if err := os.Symlink(busybox, crond); err != nil {
		t.Fatal(err)
	}
	originalLookPath := host.executor.lookPath
	host.executor.lookPath = func(name string) (string, error) {
		if name == "crond" {
			return crond, nil
		}
		return originalLookPath(name)
	}
	if _, err := host.attest(); err == nil {
		t.Fatal("BusyBox daemon target was accepted")
	}
}

func TestOfflineAlpineProviderProvesFilesWithoutRuntimeCommands(t *testing.T) {
	commands := make([]string, 0)
	host := testCronProviderHost(
		t, true, offlineCronProviderRuntime,
		alpineProviderOutput(false, "", &commands),
	)
	enablementCalls := 0
	host.attestEnablement = func(link, target string) error {
		enablementCalls++
		if link != "/etc/runlevels/default/cronie" || target != "/etc/init.d/cronie" {
			return errors.New("unexpected offline enablement")
		}
		return nil
	}
	evidence, err := host.attest()
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Mode != CronDProviderOffline || enablementCalls != 2 {
		t.Fatalf("offline Alpine evidence=%#v enablement-calls=%d", evidence, enablementCalls)
	}
	for _, command := range commands {
		if strings.HasPrefix(command, "rc-service ") || strings.HasPrefix(command, "rc-update ") {
			t.Fatalf("offline Alpine proof executed runtime manager: %s", command)
		}
	}
}

func TestOfflineSystemdProviderProvesOneExactPackageAndEnablement(t *testing.T) {
	systemctlCalls := 0
	base := systemdCronProviderOutput(true, false, nil)
	host := testCronProviderHost(
		t, false, offlineCronProviderRuntime,
		func(path string, arguments ...string) ([]byte, error) {
			if filepath.Base(path) == "systemctl" {
				systemctlCalls++
			}
			return base(path, arguments...)
		},
	)
	host.offlineCandidates = []cronOfflineCandidate{{
		unit:      "cron.service",
		fragment:  "/vendor/cron.service",
		daemon:    "/usr/sbin/cron",
		packageID: "cron",
		wantsLink: "/etc/systemd/system/multi-user.target.wants/cron.service",
	}}
	host.pathExists = func(string) (bool, error) { return true, nil }
	enablementCalls := 0
	host.attestEnablement = func(link, target string) error {
		enablementCalls++
		if target != "/vendor/cron.service" {
			return errors.New("unexpected target")
		}
		return nil
	}
	evidence, err := host.attest()
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Mode != CronDProviderOffline || evidence.Unit != "cron.service" || enablementCalls != 2 {
		t.Fatalf("offline systemd evidence=%#v enablement-calls=%d", evidence, enablementCalls)
	}
	if systemctlCalls != 0 {
		t.Fatalf("offline systemd proof executed %d runtime manager commands", systemctlCalls)
	}
}

func TestOfflineSystemdProviderRejectsPartialAndDoubleProviders(t *testing.T) {
	candidates := []cronOfflineCandidate{
		{unit: "cron.service", fragment: "/vendor/cron.service", daemon: "/usr/sbin/cron", packageID: "cron", wantsLink: "/wants/cron.service"},
		{unit: "crond.service", fragment: "/vendor/crond.service", daemon: "/usr/sbin/crond", packageID: "cronie", wantsLink: "/wants/crond.service"},
	}
	for _, testCase := range []struct {
		name    string
		present map[string]bool
	}{
		{name: "partial", present: map[string]bool{"/vendor/cron.service": true}},
		{name: "double", present: map[string]bool{
			"/vendor/cron.service": true, "/usr/sbin/cron": true,
			"/vendor/crond.service": true, "/usr/sbin/crond": true,
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			base := systemdCronProviderOutput(true, false, nil)
			host := testCronProviderHost(
				t, false, offlineCronProviderRuntime,
				func(path string, arguments ...string) ([]byte, error) {
					if filepath.Base(path) == "rpm" && len(arguments) == 5 && arguments[0] == "--query" &&
						arguments[1] == "--file" && arguments[3] == "--queryformat" &&
						arguments[4] == "%{NAME}\\t%{EVR}\\n" {
						return []byte("cronie\t1.7.2-1\n"), nil
					}
					return base(path, arguments...)
				},
			)
			host.offlineCandidates = candidates
			host.pathExists = func(path string) (bool, error) { return testCase.present[path], nil }
			if _, err := host.attest(); err == nil {
				t.Fatal("ambiguous offline systemd provider was accepted")
			}
		})
	}
}

func TestCronProviderDirectoryChainRejectsWritableParent(t *testing.T) {
	if err := attestCronProviderDirectoryChain(string(filepath.Separator)); err != nil {
		t.Fatalf("filesystem root was not attestable: %v", err)
	}
	directory := t.TempDir()
	unsafe := filepath.Join(directory, "unsafe")
	if err := os.Mkdir(unsafe, 0755); err != nil { // #nosec G301 -- fixture models a normal executable parent beneath an unsafe ancestor
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0777); err != nil { // #nosec G302 -- adversarial fixture deliberately proves writable ancestors are rejected
		t.Fatal(err)
	}
	if err := attestCronProviderDirectoryChain(unsafe); err == nil {
		t.Fatal("writable cron provider parent was accepted")
	}
}

func TestCronDProviderRejectsAmbiguousTargetState(t *testing.T) {
	host := testCronProviderHost(
		t, false,
		func(bool) (serviceManagerState, error) { return serviceManagerAmbiguous, nil },
		systemdCronProviderOutput(true, false, nil),
	)
	if _, err := host.attest(); err == nil {
		t.Fatal("ambiguous target state was accepted")
	}
}
