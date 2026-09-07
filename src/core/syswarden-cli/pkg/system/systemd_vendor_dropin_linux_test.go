//go:build linux

package system

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func testApprovedSystemdServiceDropInExecutor(
	t *testing.T,
	path string,
	output func([]string) ([]byte, error),
) firewallManagerExecutor {
	t.Helper()
	rpm := testCronProviderExecutable(t, t.TempDir(), "rpm")
	return firewallManagerExecutor{
		lookPath: func(name string) (string, error) {
			if name != "rpm" {
				return "", errors.New("unexpected executable")
			}
			return rpm, nil
		},
		validate: func(candidate string) error {
			if candidate != rpm {
				return errors.New("unexpected RPM path")
			}
			return nil
		},
		output: func(candidate string, arguments ...string) ([]byte, error) {
			if candidate != rpm {
				return nil, errors.New("unexpected RPM path")
			}
			return output(arguments)
		},
	}
}

func testApprovedSystemdServiceDropIn(t *testing.T) (string, uint32, uint32) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "10-timeout-abort.conf")
	if err := os.WriteFile(path, []byte(approvedSystemdServiceDropInContent), 0644); err != nil { // #nosec G306 -- vendor fixture intentionally models the exact package-owned 0644 mode
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("drop-in fixture stat is unavailable")
	}
	return path, stat.Uid, stat.Gid
}

func testApprovedSystemdServiceDropInArchitecture(t *testing.T) string {
	t.Helper()
	architecture, err := approvedSystemdServiceDropInArchitecture()
	if err != nil {
		t.Skipf("unsupported test architecture %s: %v", runtime.GOARCH, err)
	}
	return architecture
}

func TestApprovedSystemdServiceDropInRequiresExactRPMProvenanceAndStableBytes(t *testing.T) {
	path, uid, gid := testApprovedSystemdServiceDropIn(t)
	architecture := testApprovedSystemdServiceDropInArchitecture(t)
	version := "259.5-1.fc44"
	var calls [][]string
	executor := testApprovedSystemdServiceDropInExecutor(t, path, func(arguments []string) ([]byte, error) {
		calls = append(calls, append([]string(nil), arguments...))
		switch {
		case reflect.DeepEqual(arguments, []string{
			"--query", "--file", path, "--queryformat", approvedSystemdServiceDropInRPMQueryFormat,
		}):
			return []byte("systemd\t" + version + "\t" + architecture + "\t8\n"), nil
		case reflect.DeepEqual(arguments, []string{
			"--query", "--file", path, "--queryformat", approvedSystemdServiceDropInRPMFilesFormat,
		}):
			return []byte(path + "\n"), nil
		case reflect.DeepEqual(arguments, []string{
			"--query", "--file", path, "--queryformat", approvedSystemdServiceDropInRPMDigestsFormat,
		}):
			return []byte(approvedSystemdServiceDropInSHA + "\n"), nil
		default:
			return nil, errors.New("unexpected RPM arguments")
		}
	})
	evidence, err := attestApprovedSystemdServiceDropInsAt(executor, path, path, filepath.Dir(path), uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if evidence != path+"#"+approvedSystemdServiceDropInSHA+"#systemd@"+version+"#"+architecture {
		t.Fatalf("drop-in evidence = %q", evidence)
	}
	if len(calls) != 6 {
		t.Fatalf("RPM attestation calls = %#v", calls)
	}
	if empty, err := attestApprovedSystemdServiceDropInsAt(executor, "", path, filepath.Dir(path), uid, gid); err != nil || empty != "" {
		t.Fatalf("empty drop-in attestation = %q, %v", empty, err)
	}
}

func TestApprovedSystemdServiceDropInRejectsUntrustedParentsAndOwner(t *testing.T) {
	t.Run("writable parent", func(t *testing.T) {
		path, uid, gid := testApprovedSystemdServiceDropIn(t)
		trustedRoot := filepath.Dir(path)
		if err := os.Chmod(trustedRoot, 0770); err != nil { // #nosec G302 -- adversarial fixture intentionally models an unsafe writable parent
			t.Fatal(err)
		}
		executor := testApprovedSystemdServiceDropInExecutor(t, path, func([]string) ([]byte, error) {
			return nil, errors.New("RPM must not run for an untrusted parent")
		})
		if _, err := attestApprovedSystemdServiceDropInsAt(executor, path, path, trustedRoot, uid, gid); err == nil {
			t.Fatal("drop-in below a writable parent was accepted")
		}
	})

	t.Run("symlink parent", func(t *testing.T) {
		trustedRoot := t.TempDir()
		realParent := filepath.Join(trustedRoot, "real")
		if err := os.Mkdir(realParent, 0700); err != nil {
			t.Fatal(err)
		}
		linkedParent := filepath.Join(trustedRoot, "linked")
		if err := os.Symlink(realParent, linkedParent); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(linkedParent, "10-timeout-abort.conf")
		if err := os.WriteFile(path, []byte(approvedSystemdServiceDropInContent), 0644); err != nil { // #nosec G306 -- vendor fixture intentionally models the exact package-owned 0644 mode
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatal("drop-in fixture stat is unavailable")
		}
		executor := testApprovedSystemdServiceDropInExecutor(t, path, func([]string) ([]byte, error) {
			return nil, errors.New("RPM must not run for a symlink parent")
		})
		if _, err := attestApprovedSystemdServiceDropInsAt(executor, path, path, trustedRoot, stat.Uid, stat.Gid); err == nil {
			t.Fatal("drop-in below a symlink parent was accepted")
		}
	})

	t.Run("wrong boundary owner", func(t *testing.T) {
		path, uid, gid := testApprovedSystemdServiceDropIn(t)
		executor := testApprovedSystemdServiceDropInExecutor(t, path, func([]string) ([]byte, error) {
			return nil, errors.New("RPM must not run for the wrong boundary owner")
		})
		if _, err := attestApprovedSystemdServiceDropInsAt(executor, path, path, filepath.Dir(path), uid+1, gid); err == nil {
			t.Fatal("drop-in with the wrong boundary owner was accepted")
		}
	})
}

func TestApprovedSystemdServiceDropInRejectsEveryUnprovenSurface(t *testing.T) {
	architecture := testApprovedSystemdServiceDropInArchitecture(t)
	for _, testCase := range []struct {
		name      string
		dropIns   func(string) string
		mutate    func(*testing.T, string)
		owner     string
		files     func(string) string
		digests   string
		queryErr  error
		queryHook func(*testing.T, string)
	}{
		{name: "different path", dropIns: func(path string) string { return path + " /etc/systemd/system/operator.conf" }},
		{name: "operator path", dropIns: func(string) string { return "/etc/systemd/system/operator.conf" }},
		{name: "modified content", mutate: func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, []byte(strings.Replace(approvedSystemdServiceDropInContent, "abort\n", "terminate\n", 1)), 0644); err != nil { // #nosec G306 -- adversarial vendor fixture intentionally preserves the exact 0644 mode
				t.Fatal(err)
			}
		}},
		{name: "writable mode", mutate: func(t *testing.T, path string) {
			t.Helper()
			if err := os.Chmod(path, 0664); err != nil { // #nosec G302 -- adversarial fixture intentionally models an unsafe writable vendor file
				t.Fatal(err)
			}
		}},
		{name: "special mode", mutate: func(t *testing.T, path string) {
			t.Helper()
			if err := os.Chmod(path, 0644|os.ModeSetgid); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hard link", mutate: func(t *testing.T, path string) {
			t.Helper()
			if err := os.Link(path, path+".operator"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wrong package", owner: "operator-package\t259.5-1.fc44\t" + architecture + "\t8\n"},
		{name: "wrong digest algorithm", owner: "systemd\t259.5-1.fc44\t" + architecture + "\t1\n"},
		{name: "wrong architecture", owner: "systemd\t259.5-1.fc44\toperator\t8\n"},
		{name: "duplicate owner", owner: "systemd\t259.5-1.fc44\t" + architecture + "\t8\nsystemd\t259.5-1.fc44\t" + architecture + "\t8\n"},
		{name: "RPM digest drift", digests: strings.Repeat("0", 64) + "\n"},
		{name: "duplicate RPM filename", files: func(path string) string { return path + "\n" + path + "\n" }, digests: approvedSystemdServiceDropInSHA + "\n" + approvedSystemdServiceDropInSHA + "\n"},
		{name: "RPM metadata error", queryErr: errors.New("RPM metadata query failed")},
		{name: "file drift during RPM query", queryHook: func(t *testing.T, path string) {
			t.Helper()
			replacement := path + ".replacement"
			if err := os.WriteFile(replacement, []byte(approvedSystemdServiceDropInContent), 0644); err != nil { // #nosec G306 -- replacement fixture intentionally models the exact package-owned 0644 mode
				t.Fatal(err)
			}
			if err := os.Rename(replacement, path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path, uid, gid := testApprovedSystemdServiceDropIn(t)
			if testCase.mutate != nil {
				testCase.mutate(t, path)
			}
			dropIns := path
			if testCase.dropIns != nil {
				dropIns = testCase.dropIns(path)
			}
			queryCalls := 0
			executor := testApprovedSystemdServiceDropInExecutor(t, path, func(arguments []string) ([]byte, error) {
				queryCalls++
				if testCase.queryErr != nil {
					return nil, testCase.queryErr
				}
				format := arguments[4]
				switch format {
				case approvedSystemdServiceDropInRPMQueryFormat:
					if testCase.owner != "" {
						return []byte(testCase.owner), nil
					}
					return []byte("systemd\t259.5-1.fc44\t" + architecture + "\t8\n"), nil
				case approvedSystemdServiceDropInRPMFilesFormat:
					if testCase.files != nil {
						return []byte(testCase.files(path)), nil
					}
					return []byte(path + "\n"), nil
				case approvedSystemdServiceDropInRPMDigestsFormat:
					if testCase.queryHook != nil && queryCalls == 3 {
						testCase.queryHook(t, path)
					}
					if testCase.digests != "" {
						return []byte(testCase.digests), nil
					}
					return []byte(approvedSystemdServiceDropInSHA + "\n"), nil
				default:
					return nil, errors.New("unexpected RPM query format")
				}
			})
			if _, err := attestApprovedSystemdServiceDropInsAt(executor, dropIns, path, filepath.Dir(path), uid, gid); err == nil {
				t.Fatal("unproven systemd service drop-in was accepted")
			}
		})
	}
}

func testSysWardenSystemdOrderingFixture(t *testing.T) (string, string, uint32, uint32) {
	t.Helper()
	root := t.TempDir()
	directory := filepath.Join(root, "syswarden-firewall.service.d")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "10-syswarden-wireguard-ordering.conf")
	if err := os.WriteFile(path, []byte(systemdFirewallWireGuardOrderingDropIn), 0644); err != nil { // #nosec G306 -- fixture models the exact package-owned mode
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("ordering fixture stat is unavailable")
	}
	return root, path, metadata.Uid, metadata.Gid
}

func testSysWardenOrderingPackageExecutor(
	t *testing.T,
	path string,
	dpkg bool,
	rpm bool,
	version func(string) string,
) firewallManagerExecutor {
	t.Helper()
	binDirectory := t.TempDir()
	executables := make(map[string]string)
	for name, present := range map[string]bool{"dpkg-query": dpkg, "rpm": rpm} {
		if !present {
			continue
		}
		executables[name] = testCronProviderExecutable(t, binDirectory, name)
	}
	return firewallManagerExecutor{
		lookPath: func(name string) (string, error) {
			candidate, present := executables[name]
			if !present {
				return "", exec.ErrNotFound
			}
			return candidate, nil
		},
		validate: func(candidate string) error {
			for _, expected := range executables {
				if candidate == expected {
					return nil
				}
			}
			return errors.New("unexpected package executable")
		},
		output: func(candidate string, arguments ...string) ([]byte, error) {
			switch filepath.Base(candidate) {
			case "dpkg-query":
				if reflect.DeepEqual(arguments, []string{"--listfiles", "syswarden"}) {
					return []byte("/.\n" + path + "\n"), nil
				}
				if reflect.DeepEqual(arguments, []string{
					"--show", "--showformat=" + syswardenDropInDPKGVersionFormat, "syswarden",
				}) {
					return []byte(version("dpkg") + "\tamd64\n"), nil
				}
			case "rpm":
				if reflect.DeepEqual(arguments, []string{
					"--query", "--file", path, "--queryformat", syswardenDropInRPMOwnerFormat,
				}) {
					return []byte("syswarden\t" + version("rpm") + "\tx86_64\t8\n"), nil
				}
			}
			return nil, errors.New("unexpected package query")
		},
	}
}

func TestSysWardenSystemdOrderingDropInRequiresOneStablePackageAuthority(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		dpkg          bool
		rpm           bool
		wantAuthority string
	}{
		{name: "dpkg", dpkg: true, wantAuthority: "syswarden@4.04.3#amd64#dpkg"},
		{name: "rpm", rpm: true, wantAuthority: "syswarden@4.04.3-1#x86_64#sha256#rpm"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root, path, uid, gid := testSysWardenSystemdOrderingFixture(t)
			executor := testSysWardenOrderingPackageExecutor(t, path, testCase.dpkg, testCase.rpm, func(manager string) string {
				if manager == "dpkg" {
					return "4.04.3"
				}
				return "4.04.3-1"
			})
			evidence, err := attestExactSystemdFirewallOrderingDropInAt(
				executor, path, path, root, uid, gid,
			)
			if err != nil {
				t.Fatal(err)
			}
			want := path + "#8c4b31f25436882197beec8c8bff5a7599389e564593bd7c353aa99ef3854483#" + testCase.wantAuthority
			if evidence != want {
				t.Fatalf("ordering evidence = %q, want %q", evidence, want)
			}
		})
	}
}

func TestSysWardenSystemdOrderingDropInRejectsAmbiguousOrDriftingAuthority(t *testing.T) {
	driftCalls := 0
	driftingVersion := func(string) string {
		driftCalls++
		if driftCalls == 1 {
			return "4.04.3"
		}
		return "4.04.2"
	}
	for _, testCase := range []struct {
		name    string
		dpkg    bool
		rpm     bool
		version func(string) string
	}{
		{name: "no authority", version: func(string) string { return "4.04.3-1" }},
		{name: "dual authority", dpkg: true, rpm: true, version: func(manager string) string {
			if manager == "dpkg" {
				return "4.04.3"
			}
			return "4.04.3-1"
		}},
		{name: "authority drift", dpkg: true, version: driftingVersion},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root, path, uid, gid := testSysWardenSystemdOrderingFixture(t)
			executor := testSysWardenOrderingPackageExecutor(
				t, path, testCase.dpkg, testCase.rpm, testCase.version,
			)
			if _, err := attestExactSystemdFirewallOrderingDropInAt(
				executor, path, path, root, uid, gid,
			); err == nil {
				t.Fatal("ambiguous or drifting package authority was accepted")
			}
		})
	}
}

func TestSysWardenSystemdOrderingPackageMetadataParsersFailClosed(t *testing.T) {
	path := systemdFirewallWireGuardOrderingDropInPath
	validList := []byte("/.\n" + path + "\n")
	if err := attestSysWardenDPKGDropInFileList(validList, path); err != nil {
		t.Fatal(err)
	}
	if got, err := parseSysWardenDPKGDropInOwner([]byte("4.04.3\tamd64\n")); err != nil ||
		got != "syswarden@4.04.3#amd64#dpkg" {
		t.Fatalf("dpkg owner = %q, %v", got, err)
	}
	if got, err := parseSysWardenRPMDropInOwner([]byte("syswarden\t4.04.3-1\tx86_64\t8\n")); err != nil ||
		got != "syswarden@4.04.3-1#x86_64#sha256#rpm" {
		t.Fatalf("RPM owner = %q, %v", got, err)
	}
	for _, invalid := range [][]byte{
		[]byte(path),
		[]byte(path + "\n" + path + "\n"),
		[]byte("relative/path\n"),
		[]byte(path + "\r\n"),
	} {
		if err := attestSysWardenDPKGDropInFileList(invalid, path); err == nil {
			t.Fatalf("invalid dpkg inventory was accepted: %q", invalid)
		}
	}
	for _, invalid := range [][]byte{
		[]byte("4.04.3-1\tarm64\n"),
		[]byte("4.04.3 1\tamd64\n"),
		[]byte("4.04.2\tamd64\n"),
		[]byte("4.04.3-1\tamd64\nextra\n"),
	} {
		if _, err := parseSysWardenDPKGDropInOwner(invalid); err == nil {
			t.Fatalf("invalid dpkg owner was accepted: %q", invalid)
		}
	}
	for _, invalid := range [][]byte{
		[]byte("operator\t4.04.3-1\tx86_64\t8\n"),
		[]byte("syswarden\t4.04.3-1\taarch64\t8\n"),
		[]byte("syswarden\t4.04.3 1\tx86_64\t8\n"),
		[]byte("syswarden\t4.04.3-1\tx86_64\t1\n"),
	} {
		if _, err := parseSysWardenRPMDropInOwner(invalid); err == nil {
			t.Fatalf("invalid RPM owner was accepted: %q", invalid)
		}
	}
}

func TestSysWardenRPMDropInOwnershipBoundsPackageTransactionOverlap(t *testing.T) {
	current := "syswarden\t4.04.3-1\tx86_64\t8\n"
	old := "syswarden\t4.04.2-1\tx86_64\t8\n"
	wantCurrent := "syswarden@4.04.3-1#x86_64#sha256#rpm"
	for _, testCase := range []struct {
		name   string
		output string
		want   string
	}{
		{name: "fresh", output: current, want: wantCurrent},
		{
			name:   "upgrade",
			output: old + current,
			want:   "syswarden@4.04.2-1#x86_64#sha256#rpm," + wantCurrent,
		},
		{
			name:   "reinstall",
			output: current + current,
			want:   wantCurrent + "," + wantCurrent,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := parseSysWardenRPMDropInOwners([]byte(testCase.output), true)
			if err != nil {
				t.Fatal(err)
			}
			if got != testCase.want {
				t.Fatalf("transaction ownership = %q, want %q", got, testCase.want)
			}
		})
	}

	for _, invalid := range []string{
		old,
		current + current + current,
		"operator\t4.04.3-1\tx86_64\t8\n" + current,
		"syswarden\t4.04.3-1\taarch64\t8\n" + current,
		"syswarden\t4.04.3-1\tx86_64\t1\n" + current,
	} {
		if _, err := parseSysWardenRPMDropInOwners([]byte(invalid), true); err == nil {
			t.Fatalf("invalid transaction ownership was accepted: %q", invalid)
		}
	}
	if _, err := parseSysWardenRPMDropInOwners([]byte(old+current), false); err == nil {
		t.Fatal("multi-owner RPM state was accepted outside a package transaction")
	}
}

func testInstalledSysWardenPackageExecutor(
	t *testing.T,
	dpkgOutput []byte,
	dpkgErr error,
	rpmOutput []byte,
	rpmErr error,
) firewallManagerExecutor {
	t.Helper()
	binDirectory := t.TempDir()
	executables := map[string]string{}
	if dpkgOutput != nil || dpkgErr != nil {
		executables["dpkg-query"] = testCronProviderExecutable(t, binDirectory, "dpkg-query")
	}
	if rpmOutput != nil || rpmErr != nil {
		executables["rpm"] = testCronProviderExecutable(t, binDirectory, "rpm")
	}
	return firewallManagerExecutor{
		lookPath: func(name string) (string, error) {
			path, present := executables[name]
			if !present {
				return "", exec.ErrNotFound
			}
			return path, nil
		},
		validate: func(candidate string) error {
			for _, path := range executables {
				if candidate == path {
					return nil
				}
			}
			return errors.New("unexpected package executable")
		},
		output: func(candidate string, arguments ...string) ([]byte, error) {
			switch filepath.Base(candidate) {
			case "dpkg-query":
				if !reflect.DeepEqual(arguments, []string{
					"--show", "--showformat=" + syswardenDropInDPKGInstalledFormat, "syswarden",
				}) {
					return nil, errors.New("unexpected dpkg query")
				}
				return dpkgOutput, dpkgErr
			case "rpm":
				if !reflect.DeepEqual(arguments, []string{
					"--query", "syswarden", "--queryformat", syswardenDropInRPMOwnerFormat,
				}) {
					return nil, errors.New("unexpected RPM query")
				}
				return rpmOutput, rpmErr
			default:
				return nil, errors.New("unexpected package query")
			}
		},
	}
}

func TestSystemdOrderingAbsenceDistinguishesSourceAndPackagedInstall(t *testing.T) {
	absentPath := filepath.Join(t.TempDir(), "10-syswarden-wireguard-ordering.conf")
	queryFailure := errors.New("package is absent")
	for _, testCase := range []struct {
		name               string
		executor           firewallManagerExecutor
		packageTransaction bool
		wantError          bool
	}{
		{
			name:     "source without package managers",
			executor: testInstalledSysWardenPackageExecutor(t, nil, nil, nil, nil),
		},
		{
			name: "source with exact absent package evidence",
			executor: testInstalledSysWardenPackageExecutor(
				t,
				[]byte(syswardenDropInDPKGAbsentEvidence), queryFailure,
				[]byte(syswardenDropInRPMAbsentEvidence), queryFailure,
			),
		},
		{
			name: "dpkg managed",
			executor: testInstalledSysWardenPackageExecutor(
				t, []byte("install ok installed\tamd64\t4.04.3\n"), nil, nil, nil,
			),
			wantError: true,
		},
		{
			name: "RPM managed",
			executor: testInstalledSysWardenPackageExecutor(
				t, nil, nil, []byte("syswarden\t4.04.3-1\tx86_64\t8\n"), nil,
			),
			wantError: true,
		},
		{
			name: "ambiguous package query failure",
			executor: testInstalledSysWardenPackageExecutor(
				t, []byte("database failure\n"), queryFailure, nil, nil,
			),
			wantError: true,
		},
		{
			name:               "package transaction",
			executor:           testInstalledSysWardenPackageExecutor(t, nil, nil, nil, nil),
			packageTransaction: true,
			wantError:          true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := attestAbsentSystemdFirewallOrderingDropIn(
				testCase.executor, absentPath, testCase.packageTransaction,
			)
			if (err != nil) != testCase.wantError {
				t.Fatalf("absence attestation error = %v, want error %t", err, testCase.wantError)
			}
		})
	}
}

func TestInstalledSysWardenDPKGStateRequiresRunningRelease(t *testing.T) {
	for _, valid := range []string{"install ok installed\tamd64\t4.04.3\n"} {
		if _, err := parseInstalledSysWardenDPKG([]byte(valid)); err != nil {
			t.Fatalf("valid dpkg package state rejected: %q: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"deinstall ok config-files\tamd64\t4.04.3\n",
		"install ok installed\tarm64\t4.04.3\n",
		"install ok installed\tamd64\t4.04.2\n",
		"install ok installed\tamd64\t4.04.3-1\n",
		"install ok installed\tamd64\t4.04.3\nextra\n",
	} {
		if _, err := parseInstalledSysWardenDPKG([]byte(invalid)); err == nil {
			t.Fatalf("invalid dpkg package state accepted: %q", invalid)
		}
	}
}
