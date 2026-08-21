//go:build linux

package system

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func newSSHConfigurationFixture(t *testing.T, content string) (string, uint32) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("fixture ownership is unavailable")
	}
	return path, stat.Uid
}

func readSSHConfigurationFixture(t *testing.T, path string) string {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	file, openErr := root.Open(filepath.Base(path))
	if openErr != nil {
		_ = root.Close()
		t.Fatal(openErr)
	}
	content, readErr := io.ReadAll(file)
	fileCloseErr := file.Close()
	rootCloseErr := root.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if fileCloseErr != nil {
		t.Fatal(fileCloseErr)
	}
	if rootCloseErr != nil {
		t.Fatal(rootCloseErr)
	}
	return string(content)
}

func systemdSSHTestOutput(t *testing.T, activeUnit string, effective []byte) func(string, ...string) ([]byte, error) {
	t.Helper()
	return func(name string, args ...string) ([]byte, error) {
		if name == "sshd" {
			return effective, nil
		}
		call := strings.Join(append([]string{name}, args...), " ")
		if len(args) == 4 && name == "systemctl" && args[0] == "show" && args[1] == "--property=LoadState" && args[2] == "--value" {
			if args[3] == activeUnit {
				return []byte("loaded\n"), nil
			}
			return []byte("not-found\n"), nil
		}
		t.Fatalf("unexpected output command: %s", call)
		return nil, nil
	}
}

func successfulSSHExecutor(t *testing.T, expectedPort, activeUnit string, calls *[]string) sshCommandExecutor {
	t.Helper()
	output := systemdSSHTestOutput(t, activeUnit, []byte("allowtcpforwarding no\nport "+expectedPort+"\n"))
	return sshCommandExecutor{
		run: func(name string, args ...string) error {
			*calls = append(*calls, strings.Join(append([]string{name}, args...), " "))
			return nil
		},
		output: func(name string, args ...string) ([]byte, error) {
			*calls = append(*calls, strings.Join(append([]string{name}, args...), " "))
			return output(name, args...)
		},
	}
}

func TestSSHConfigurationApplicabilitySkipsOnlyACompletelyAbsentDaemon(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sshd_config")
	signalPath := filepath.Join(root, "sshd")
	rootInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("fixture ownership is unavailable")
	}
	expectedOwnerUID := rootStat.Uid

	notFound := func(string) (string, error) { return "", exec.ErrNotFound }
	applicable, err := sshConfigurationApplicable(configPath, "", []string{signalPath}, notFound, expectedOwnerUID)
	if err != nil || applicable {
		t.Fatalf("absent SSH daemon applicability = %t, %v; want false, nil", applicable, err)
	}

	if err := os.WriteFile(configPath, []byte("Port 22\n"), 0600); err != nil {
		t.Fatal(err)
	}
	applicable, err = sshConfigurationApplicable(configPath, "", []string{signalPath}, notFound, expectedOwnerUID)
	if err != nil || !applicable {
		t.Fatalf("present SSH configuration applicability = %t, %v; want true, nil", applicable, err)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}

	if _, err := sshConfigurationApplicable(configPath, "2222", []string{signalPath}, notFound, expectedOwnerUID); err == nil {
		t.Fatal("configured SSH port was accepted without an SSH configuration")
	}
	if err := os.WriteFile(signalPath, []byte("daemon marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := sshConfigurationApplicable(configPath, "", []string{signalPath}, notFound, expectedOwnerUID); err == nil {
		t.Fatal("SSH daemon component was accepted without an SSH configuration")
	}
	if err := os.Remove(signalPath); err != nil {
		t.Fatal(err)
	}
	if _, err := sshConfigurationApplicable(
		configPath,
		"",
		[]string{signalPath},
		func(string) (string, error) { return "/opt/custom/sbin/sshd", nil },
		expectedOwnerUID,
	); err == nil {
		t.Fatal("discoverable SSH daemon was accepted without an SSH configuration")
	}
	probeFailure := errors.New("PATH probe failed")
	if _, err := sshConfigurationApplicable(
		configPath,
		"",
		[]string{signalPath},
		func(string) (string, error) { return "", probeFailure },
		expectedOwnerUID,
	); !errors.Is(err, probeFailure) {
		t.Fatalf("executable probe failure = %v, want %v", err, probeFailure)
	}

	linkedParent := filepath.Join(root, "linked-ssh")
	if err := os.Symlink(root, linkedParent); err != nil {
		t.Fatal(err)
	}
	if _, err := sshConfigurationApplicable(
		filepath.Join(linkedParent, "sshd_config"),
		"",
		[]string{signalPath},
		notFound,
		expectedOwnerUID,
	); err == nil {
		t.Fatal("symlinked SSH configuration parent was accepted as absent")
	}
}

func TestSSHConfigurationApplicabilityAllowsOnlyATrustedEmptyDropInDirectory(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sshd_config")
	dropInPath := filepath.Join(root, "sshd_config.d")
	if err := os.Mkdir(dropInPath, 0700); err != nil {
		t.Fatal(err)
	}
	dropInInfo, err := os.Lstat(dropInPath)
	if err != nil {
		t.Fatal(err)
	}
	dropInStat, ok := dropInInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("fixture ownership is unavailable")
	}
	notFound := func(string) (string, error) { return "", exec.ErrNotFound }

	applicable, err := sshConfigurationApplicable(configPath, "", []string{dropInPath}, notFound, dropInStat.Uid)
	if err != nil || applicable {
		t.Fatalf("trusted empty drop-in applicability = %t, %v; want false, nil", applicable, err)
	}

	tests := []struct {
		name        string
		prepare     func(t *testing.T)
		expectedUID uint32
	}{
		{
			name: "entry",
			prepare: func(t *testing.T) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dropInPath, "policy.conf"), []byte("Port 22\n"), 0600); err != nil {
					t.Fatal(err)
				}
			},
			expectedUID: dropInStat.Uid,
		},
		{
			name: "symlink",
			prepare: func(t *testing.T) {
				t.Helper()
				if err := os.Remove(dropInPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(root, dropInPath); err != nil {
					t.Fatal(err)
				}
			},
			expectedUID: dropInStat.Uid,
		},
		{
			name: "non-directory",
			prepare: func(t *testing.T) {
				t.Helper()
				if err := os.Remove(dropInPath); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dropInPath, nil, 0600); err != nil {
					t.Fatal(err)
				}
			},
			expectedUID: dropInStat.Uid,
		},
		{
			name: "unexpected owner",
			prepare: func(t *testing.T) {
				t.Helper()
			},
			expectedUID: dropInStat.Uid ^ 1,
		},
		{
			name: "group writable",
			prepare: func(t *testing.T) {
				t.Helper()
				mustChmodTestPath(t, dropInPath, 0775)
			},
			expectedUID: dropInStat.Uid,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := os.RemoveAll(dropInPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dropInPath, 0700); err != nil {
				t.Fatal(err)
			}
			test.prepare(t)
			if _, err := sshConfigurationApplicable(configPath, "", []string{dropInPath}, notFound, test.expectedUID); err == nil {
				t.Fatal("partial SSH state was accepted as not applicable")
			}
		})
	}
}

func TestConfigureSSHFileNormalizesForwardingFormsAndRestartsExactManager(t *testing.T) {
	tests := []struct {
		name    string
		content string
		alpine  bool
		unit    string
		wantEnd string
	}{
		{
			name:    "directive absent",
			content: "Port 2222\nPasswordAuthentication no\n",
			unit:    "ssh.service",
			wantEnd: "systemctl restart ssh.service",
		},
		{
			name:    "indented yes",
			content: "  AllowTcpForwarding yes\nPort 2222\n",
			unit:    "ssh.service",
			wantEnd: "systemctl restart ssh.service",
		},
		{
			name:    "local equals form",
			content: "AllowTcpForwarding = local\nPort 2222\n",
			unit:    "ssh.service",
			wantEnd: "systemctl restart ssh.service",
		},
		{
			name:    "include and match",
			content: "Include /etc/ssh/sshd_config.d/*.conf\nMatch User backup\n  AllowTcpForwarding local\n",
			alpine:  true,
			wantEnd: "rc-service sshd restart",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, uid := newSSHConfigurationFixture(t, test.content)
			calls := make([]string, 0, 3)
			port, err := configureSSHFile(path, "2222", uid, test.alpine, serviceManagerActive, successfulSSHExecutor(t, "2222", test.unit, &calls))
			if err != nil {
				t.Fatal(err)
			}
			if port != "2222" {
				t.Fatalf("unexpected port %q", port)
			}
			content := readSSHConfigurationFixture(t, path)
			if strings.Count(content, "AllowTcpForwarding no") != 1 {
				t.Fatalf("configuration has no unique forwarding policy:\n%s", content)
			}
			include := strings.Index(content, "Include ")
			match := strings.Index(content, "Match ")
			policy := strings.Index(content, "AllowTcpForwarding no")
			if (include >= 0 && policy > include) || (match >= 0 && policy > match) {
				t.Fatalf("global forwarding policy follows Include or Match:\n%s", content)
			}
			wantCalls := make([]string, 0, 5)
			if !test.alpine {
				wantCalls = append(wantCalls,
					"systemctl show --property=LoadState --value ssh.service",
					"systemctl show --property=LoadState --value sshd.service",
				)
			}
			wantCalls = append(wantCalls, "sshd -t -f "+path, "sshd -T -f "+path, test.wantEnd)
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("unexpected calls: got %v, want %v", calls, wantCalls)
			}
		})
	}
}

func TestConfigureSSHFileOfflinePersistsAndValidatesWithoutServiceManager(t *testing.T) {
	path, uid := newSSHConfigurationFixture(t, "AllowTcpForwarding yes\nPort 2222\n")
	calls := make([]string, 0, 2)
	executor := sshCommandExecutor{
		run: func(name string, args ...string) error {
			call := strings.Join(append([]string{name}, args...), " ")
			calls = append(calls, call)
			if name != "sshd" {
				t.Fatalf("service manager invoked offline: %s", call)
			}
			return nil
		},
		output: func(name string, args ...string) ([]byte, error) {
			call := strings.Join(append([]string{name}, args...), " ")
			calls = append(calls, call)
			if name != "sshd" {
				t.Fatalf("service manager queried offline: %s", call)
			}
			return []byte("allowtcpforwarding no\nport 2222\n"), nil
		},
	}

	port, err := configureSSHFile(path, "2222", uid, false, serviceManagerOffline, executor)
	if err != nil {
		t.Fatal(err)
	}
	if port != "2222" {
		t.Fatalf("offline port = %q, want 2222", port)
	}
	if got := readSSHConfigurationFixture(t, path); !strings.Contains(got, "AllowTcpForwarding no") {
		t.Fatalf("offline configuration was not persisted:\n%s", got)
	}
	want := []string{"sshd -t -f " + path, "sshd -T -f " + path}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("offline calls = %v, want %v", calls, want)
	}
}

func TestConfigureSSHFileRejectsAmbiguousManagerBeforeMutation(t *testing.T) {
	original := "AllowTcpForwarding yes\nPort 2222\n"
	path, uid := newSSHConfigurationFixture(t, original)
	commandCalls := 0
	executor := sshCommandExecutor{
		run: func(string, ...string) error { commandCalls++; return nil },
		output: func(string, ...string) ([]byte, error) {
			commandCalls++
			return nil, nil
		},
	}
	if _, err := configureSSHFile(path, "2222", uid, false, serviceManagerAmbiguous, executor); err == nil {
		t.Fatal("ambiguous service-manager state was accepted")
	}
	if commandCalls != 0 {
		t.Fatalf("commands executed for ambiguous manager: %d", commandCalls)
	}
	if got := readSSHConfigurationFixture(t, path); got != original {
		t.Fatalf("configuration changed for ambiguous manager:\n%s", got)
	}
}

func TestConfigureSSHFileDiscoversAndAttestsEffectivePort(t *testing.T) {
	path, uid := newSSHConfigurationFixture(t, "Port 2200\n")
	outputCalls := 0
	systemdOutput := systemdSSHTestOutput(t, "ssh.service", nil)
	executor := sshCommandExecutor{
		run: func(string, ...string) error { return nil },
		output: func(name string, args ...string) ([]byte, error) {
			if name == "sshd" {
				outputCalls++
				if outputCalls == 1 {
					return []byte("allowtcpforwarding yes\nport 2200\n"), nil
				}
				return []byte("allowtcpforwarding no\nport 2200\n"), nil
			}
			return systemdOutput(name, args...)
		},
	}
	port, err := configureSSHFile(path, "", uid, false, serviceManagerActive, executor)
	if err != nil {
		t.Fatal(err)
	}
	if port != "2200" || outputCalls != 2 {
		t.Fatalf("port=%q outputCalls=%d, want 2200 and 2", port, outputCalls)
	}
}

func TestResolveSSHRestartTargetSupportsDebianRPMAndAliases(t *testing.T) {
	tests := []struct {
		name      string
		responses map[string]string
		want      sshRestartTarget
		wantErr   bool
	}{
		{
			name: "Debian ssh service",
			responses: map[string]string{
				"systemctl show --property=LoadState --value ssh.service":  "loaded\n",
				"systemctl show --property=LoadState --value sshd.service": "not-found\n",
			},
			want: sshRestartTarget{name: "systemctl", args: []string{"restart", "ssh.service"}},
		},
		{
			name: "RPM sshd service",
			responses: map[string]string{
				"systemctl show --property=LoadState --value ssh.service":  "not-found\n",
				"systemctl show --property=LoadState --value sshd.service": "loaded\n",
			},
			want: sshRestartTarget{name: "systemctl", args: []string{"restart", "sshd.service"}},
		},
		{
			name: "same underlying Debian unit aliases",
			responses: map[string]string{
				"systemctl show --property=LoadState --value ssh.service":  "loaded\n",
				"systemctl show --property=LoadState --value sshd.service": "loaded\n",
				"systemctl show --property=Id --value ssh.service":         "ssh.service\n",
				"systemctl show --property=Id --value sshd.service":        "ssh.service\n",
			},
			want: sshRestartTarget{name: "systemctl", args: []string{"restart", "ssh.service"}},
		},
		{
			name: "no loaded unit",
			responses: map[string]string{
				"systemctl show --property=LoadState --value ssh.service":  "not-found\n",
				"systemctl show --property=LoadState --value sshd.service": "not-found\n",
			},
			wantErr: true,
		},
		{
			name: "ambiguous distinct units",
			responses: map[string]string{
				"systemctl show --property=LoadState --value ssh.service":  "loaded\n",
				"systemctl show --property=LoadState --value sshd.service": "loaded\n",
				"systemctl show --property=Id --value ssh.service":         "ssh.service\n",
				"systemctl show --property=Id --value sshd.service":        "sshd.service\n",
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := sshCommandExecutor{
				run: func(string, ...string) error { return nil },
				output: func(name string, args ...string) ([]byte, error) {
					call := strings.Join(append([]string{name}, args...), " ")
					response, ok := test.responses[call]
					if !ok {
						t.Fatalf("unexpected query: %s", call)
					}
					return []byte(response), nil
				},
			}
			got, err := resolveSSHRestartTarget(false, executor)
			if test.wantErr {
				if err == nil {
					t.Fatalf("unsafe systemd unit state was accepted: %#v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("target=%#v, want %#v", got, test.want)
			}
		})
	}
}

func TestConfigureSSHFileRollsBackInvalidMutation(t *testing.T) {
	original := "AllowTcpForwarding yes\nPort 2222\n"
	path, uid := newSSHConfigurationFixture(t, original)
	failure := errors.New("injected sshd syntax failure")
	systemdOutput := systemdSSHTestOutput(t, "ssh.service", nil)
	executor := sshCommandExecutor{
		run: func(name string, args ...string) error {
			if name == "sshd" && len(args) > 0 && args[0] == "-t" {
				return failure
			}
			return nil
		},
		output: func(name string, args ...string) ([]byte, error) {
			if name == "sshd" {
				t.Fatal("effective configuration queried after syntax failure")
			}
			return systemdOutput(name, args...)
		},
	}
	if _, err := configureSSHFile(path, "2222", uid, false, serviceManagerActive, executor); !errors.Is(err, failure) {
		t.Fatalf("expected syntax failure, got %v", err)
	}
	if got := readSSHConfigurationFixture(t, path); got != original {
		t.Fatalf("configuration was not rolled back:\n%s", got)
	}
}

func TestConfigureSSHFileRollsBackWhenEffectivePolicyDoesNotMatch(t *testing.T) {
	original := "AllowTcpForwarding local\nPort 2222\n"
	path, uid := newSSHConfigurationFixture(t, original)
	systemdOutput := systemdSSHTestOutput(t, "ssh.service", nil)
	executor := sshCommandExecutor{
		run: func(string, ...string) error { return nil },
		output: func(name string, args ...string) ([]byte, error) {
			if name == "sshd" {
				return []byte("allowtcpforwarding local\nport 2222\n"), nil
			}
			return systemdOutput(name, args...)
		},
	}
	if _, err := configureSSHFile(path, "2222", uid, false, serviceManagerActive, executor); err == nil || !strings.Contains(err.Error(), "allowtcpforwarding no") {
		t.Fatalf("unexpected effective-policy result: %v", err)
	}
	if got := readSSHConfigurationFixture(t, path); got != original {
		t.Fatalf("configuration was not rolled back:\n%s", got)
	}
}

func TestConfigureSSHFileRollsBackAndRestartsAfterRestartFailure(t *testing.T) {
	original := "AllowTcpForwarding yes\nPort 2222\n"
	path, uid := newSSHConfigurationFixture(t, original)
	failure := errors.New("injected restart failure")
	restartCalls := 0
	calls := make([]string, 0, 5)
	systemdOutput := systemdSSHTestOutput(t, "ssh.service", []byte("allowtcpforwarding no\nport 2222\n"))
	executor := sshCommandExecutor{
		run: func(name string, args ...string) error {
			call := strings.Join(append([]string{name}, args...), " ")
			calls = append(calls, call)
			if call == "systemctl restart ssh.service" {
				restartCalls++
				if restartCalls == 1 {
					return failure
				}
			}
			return nil
		},
		output: func(name string, args ...string) ([]byte, error) {
			return systemdOutput(name, args...)
		},
	}
	if _, err := configureSSHFile(path, "2222", uid, false, serviceManagerActive, executor); !errors.Is(err, failure) {
		t.Fatalf("expected restart failure, got %v", err)
	}
	if got := readSSHConfigurationFixture(t, path); got != original {
		t.Fatalf("configuration was not rolled back:\n%s", got)
	}
	wantCalls := []string{
		"sshd -t -f " + path,
		"systemctl restart ssh.service",
		"sshd -t -f " + path,
		"systemctl restart ssh.service",
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("unexpected commands: got %v, want %v", calls, wantCalls)
	}
}

func TestConfigureSSHFileRejectsInvalidPortBeforeMutation(t *testing.T) {
	original := "AllowTcpForwarding yes\n"
	path, uid := newSSHConfigurationFixture(t, original)
	commandCalls := 0
	executor := sshCommandExecutor{
		run: func(string, ...string) error { commandCalls++; return nil },
		output: func(string, ...string) ([]byte, error) {
			commandCalls++
			return nil, nil
		},
	}
	if _, err := configureSSHFile(path, "022", uid, false, serviceManagerActive, executor); err == nil {
		t.Fatal("non-canonical SSH port was accepted")
	}
	if commandCalls != 0 {
		t.Fatalf("commands executed for invalid port: %d", commandCalls)
	}
	if got := readSSHConfigurationFixture(t, path); got != original {
		t.Fatalf("configuration changed for invalid port:\n%s", got)
	}
}

func TestConfigureSSHFileDoesNotMutateWhenSystemdUnitResolutionFails(t *testing.T) {
	original := "AllowTcpForwarding yes\nPort 2222\n"
	path, uid := newSSHConfigurationFixture(t, original)
	runCalls := 0
	executor := sshCommandExecutor{
		run: func(string, ...string) error { runCalls++; return nil },
		output: func(name string, args ...string) ([]byte, error) {
			if name != "systemctl" || len(args) != 4 || args[1] != "--property=LoadState" {
				t.Fatalf("unexpected output command: %s %v", name, args)
			}
			return []byte("not-found\n"), nil
		},
	}
	if _, err := configureSSHFile(path, "2222", uid, false, serviceManagerActive, executor); err == nil || !strings.Contains(err.Error(), "no loaded") {
		t.Fatalf("unexpected unit-resolution result: %v", err)
	}
	if runCalls != 0 {
		t.Fatalf("commands ran after failed unit resolution: %d", runCalls)
	}
	if got := readSSHConfigurationFixture(t, path); got != original {
		t.Fatalf("configuration changed after failed unit resolution:\n%s", got)
	}
}

func TestBeginSSHConfigurationTransactionRejectsUnsafeFiles(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target")
		path := filepath.Join(directory, "sshd_config")
		if err := os.WriteFile(target, []byte("Port 22\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := beginSSHConfigurationTransaction(path, sshConfigurationOwnerUID(t, target)); err == nil {
			t.Fatal("symlink SSH configuration was accepted")
		}
	})

	t.Run("hard link", func(t *testing.T) {
		path, uid := newSSHConfigurationFixture(t, "Port 22\n")
		if err := os.Link(path, path+".backup"); err != nil {
			t.Fatal(err)
		}
		if _, err := beginSSHConfigurationTransaction(path, uid); err == nil {
			t.Fatal("hard-linked SSH configuration was accepted")
		}
	})

	t.Run("group writable", func(t *testing.T) {
		path, uid := newSSHConfigurationFixture(t, "Port 22\n")
		root, err := os.OpenRoot(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Chmod(filepath.Base(path), 0620); err != nil {
			_ = root.Close()
			t.Fatal(err)
		}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := beginSSHConfigurationTransaction(path, uid); err == nil {
			t.Fatal("group-writable SSH configuration was accepted")
		}
	})
}

func sshConfigurationOwnerUID(t *testing.T, path string) uint32 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("fixture ownership is unavailable")
	}
	return stat.Uid
}
