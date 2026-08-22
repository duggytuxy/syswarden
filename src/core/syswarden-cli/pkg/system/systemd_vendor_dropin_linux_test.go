//go:build linux

package system

import (
	"errors"
	"os"
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
