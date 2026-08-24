//go:build linux

package integration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPrivateSELinuxPolicyWorkspaceUsesPrivateUniqueDirectory(t *testing.T) {
	parent := t.TempDir()
	var workspace string
	err := withPrivateSELinuxPolicyWorkspace(parent, func(privateWorkspace string) error {
		workspace = privateWorkspace
		tePath := filepath.Join(workspace, "syswarden_rsyslog.te")
		modulePath := filepath.Join(workspace, "syswarden_rsyslog.mod")
		packagePath := filepath.Join(workspace, "syswarden_rsyslog.pp")
		for _, path := range []string{tePath, modulePath, packagePath} {
			relative, err := filepath.Rel(parent, path)
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
				t.Fatalf("policy path escaped private parent: %q", path)
			}
			if filepath.Dir(path) != workspace {
				t.Fatalf("policy artifacts do not share one workspace: %q", path)
			}
		}
		info, err := os.Stat(tePath)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("SELinux source mode = %v, want regular 0600", info.Mode())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withPrivateSELinuxPolicyWorkspace() error = %v", err)
	}
	if workspace == "" || !strings.HasPrefix(filepath.Base(workspace), "syswarden-rsyslog-") {
		t.Fatalf("unexpected private workspace %q", workspace)
	}
	if _, err := os.Stat(workspace); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private workspace was not removed: %v", err)
	}
}

func TestPrivateSELinuxPolicyWorkspaceCleansUpAfterFailure(t *testing.T) {
	parent := t.TempDir()
	sentinel := errors.New("synthetic policy failure")
	err := withPrivateSELinuxPolicyWorkspace(parent, func(workspace string) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("workspace error = %v, want sentinel", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed policy action left temporary artifacts: %#v", entries)
	}
}

func TestBoundedCombinedOutputRetainsAVisibleHardLimit(t *testing.T) {
	var output boundedCombinedOutput
	payload := []byte(strings.Repeat("x", managedServiceOutputLimit*2))
	if written, err := output.Write(payload); err != nil || written != len(payload) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", written, err, len(payload))
	}
	result := output.Bytes()
	if len(result) != managedServiceOutputLimit {
		t.Fatalf("bounded output size = %d, want %d", len(result), managedServiceOutputLimit)
	}
	if !strings.HasSuffix(string(result), "\n[output truncated]") {
		t.Fatalf("bounded output lacks truncation marker: %q", result[len(result)-32:])
	}
}

type trustedPathTestEntry struct {
	metadata trustedPathMetadata
	target   string
}

func validateTrustedTestPath(path string, entries map[string]trustedPathTestEntry) error {
	return validateTrustedExecutableUsing(
		path,
		func(path string) (trustedPathMetadata, error) {
			entry, ok := entries[path]
			if !ok {
				return trustedPathMetadata{}, os.ErrNotExist
			}
			return entry.metadata, nil
		},
		func(path string) (string, error) {
			entry, ok := entries[path]
			if !ok || entry.metadata.mode&os.ModeSymlink == 0 {
				return "", os.ErrInvalid
			}
			return entry.target, nil
		},
	)
}

func secureDirectTrustedPath() map[string]trustedPathTestEntry {
	return map[string]trustedPathTestEntry{
		"/":             {metadata: trustedPathMetadata{uid: 0, mode: os.ModeDir | 0755}},
		"/usr":          {metadata: trustedPathMetadata{uid: 0, mode: os.ModeDir | 0755}},
		"/usr/bin":      {metadata: trustedPathMetadata{uid: 0, mode: os.ModeDir | 0755}},
		"/usr/bin/tool": {metadata: trustedPathMetadata{uid: 0, mode: 0755}},
	}
}

func secureUsrmergeTrustedPath() map[string]trustedPathTestEntry {
	return map[string]trustedPathTestEntry{
		"/":             {metadata: trustedPathMetadata{uid: 0, mode: os.ModeDir | 0755}},
		"/sbin":         {metadata: trustedPathMetadata{uid: 0, mode: os.ModeSymlink | 0777}, target: "usr/sbin"},
		"/usr":          {metadata: trustedPathMetadata{uid: 0, mode: os.ModeDir | 0755}},
		"/usr/sbin":     {metadata: trustedPathMetadata{uid: 0, mode: os.ModeSymlink | 0777}, target: "bin"},
		"/usr/bin":      {metadata: trustedPathMetadata{uid: 0, mode: os.ModeDir | 0755}},
		"/usr/bin/tool": {metadata: trustedPathMetadata{uid: 0, mode: 0755}},
	}
}

func TestValidateTrustedExecutableRequiresRootOwnedImmutableMetadata(t *testing.T) {
	if err := validateTrustedTestPath("/usr/bin/tool", secureDirectTrustedPath()); err != nil {
		t.Fatalf("secure direct executable rejected: %v", err)
	}

	tests := []struct {
		name string
		edit func(map[string]trustedPathTestEntry)
		want string
	}{
		{
			name: "non-root owner",
			edit: func(entries map[string]trustedPathTestEntry) {
				entry := entries["/usr/bin/tool"]
				entry.metadata.uid = 1000
				entries["/usr/bin/tool"] = entry
			},
			want: "not root-owned",
		},
		{
			name: "0020 group-writable executable",
			edit: func(entries map[string]trustedPathTestEntry) {
				entry := entries["/usr/bin/tool"]
				entry.metadata.mode |= 0020
				entries["/usr/bin/tool"] = entry
			},
			want: "group/world writable",
		},
		{
			name: "0002 world-writable ancestor",
			edit: func(entries map[string]trustedPathTestEntry) {
				entry := entries["/usr/bin"]
				entry.metadata.mode |= 0002
				entries["/usr/bin"] = entry
			},
			want: "group/world writable",
		},
		{
			name: "non-regular executable",
			edit: func(entries map[string]trustedPathTestEntry) {
				entry := entries["/usr/bin/tool"]
				entry.metadata.mode = os.ModeDir | 0755
				entries["/usr/bin/tool"] = entry
			},
			want: "not a regular file",
		},
		{
			name: "non-executable regular file",
			edit: func(entries map[string]trustedPathTestEntry) {
				entry := entries["/usr/bin/tool"]
				entry.metadata.mode = 0644
				entries["/usr/bin/tool"] = entry
			},
			want: "not executable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := secureDirectTrustedPath()
			test.edit(entries)
			if err := validateTrustedTestPath("/usr/bin/tool", entries); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("metadata validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateTrustedExecutableAllowsSecureUsrmergeAndRejectsUnsafeTargets(t *testing.T) {
	if err := validateTrustedTestPath("/sbin/tool", secureUsrmergeTrustedPath()); err != nil {
		t.Fatalf("secure root-owned usrmerge chain rejected: %v", err)
	}

	tests := []struct {
		name string
		path string
		edit func(map[string]trustedPathTestEntry)
		want string
	}{
		{
			name: "non-root symlink",
			path: "/sbin",
			edit: func(entries map[string]trustedPathTestEntry) {
				entry := entries["/sbin"]
				entry.metadata.uid = 1000
				entries["/sbin"] = entry
			},
			want: "not root-owned",
		},
		{
			name: "non-root symlink target",
			path: "/usr/bin/tool",
			edit: func(entries map[string]trustedPathTestEntry) {
				entry := entries["/usr/bin/tool"]
				entry.metadata.uid = 1000
				entries["/usr/bin/tool"] = entry
			},
			want: "not root-owned",
		},
		{
			name: "mutable symlink target",
			path: "/usr/bin/tool",
			edit: func(entries map[string]trustedPathTestEntry) {
				entry := entries["/usr/bin/tool"]
				entry.metadata.mode |= 0020
				entries["/usr/bin/tool"] = entry
			},
			want: "group/world writable",
		},
		{
			name: "mutable resolved ancestor",
			path: "/usr/bin",
			edit: func(entries map[string]trustedPathTestEntry) {
				entry := entries["/usr/bin"]
				entry.metadata.mode |= 0002
				entries["/usr/bin"] = entry
			},
			want: "group/world writable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := secureUsrmergeTrustedPath()
			test.edit(entries)
			err := validateTrustedTestPath("/sbin/tool", entries)
			if err == nil || !strings.Contains(err.Error(), test.want) || !strings.Contains(err.Error(), test.path) {
				t.Fatalf("usrmerge validation error = %v, want %q at %s", err, test.want, test.path)
			}
		})
	}
}

func TestDetectSELinuxRuntimeDistinguishesDisabledActiveAndIndeterminate(t *testing.T) {
	readFailure := errors.New("synthetic SELinux read failure")
	tests := []struct {
		name      string
		value     string
		readErr   error
		wantState selinuxRuntimeState
		wantErr   error
	}{
		{name: "missing enforcement file is disabled", readErr: os.ErrNotExist, wantState: selinuxRuntimeDisabled},
		{name: "permissive runtime is active", value: "0\n", wantState: selinuxRuntimeActive},
		{name: "enforcing runtime is active", value: "1\n", wantState: selinuxRuntimeActive},
		{name: "read failure is indeterminate", readErr: readFailure, wantState: selinuxRuntimeIndeterminate, wantErr: readFailure},
		{name: "unexpected content is indeterminate", value: "unknown", wantState: selinuxRuntimeIndeterminate},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, err := detectSELinuxRuntimeUsing(func(path string) ([]byte, error) {
				if path != selinuxRuntimeEnforcement {
					t.Fatalf("SELinux probe path = %q, want %q", path, selinuxRuntimeEnforcement)
				}
				return []byte(test.value), test.readErr
			})
			if state != test.wantState {
				t.Fatalf("SELinux state = %d, want %d", state, test.wantState)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("SELinux detection error = %v, want wrapped %v", err, test.wantErr)
			}
			if test.wantState == selinuxRuntimeIndeterminate && err == nil {
				t.Fatal("indeterminate SELinux state lacks an error")
			}
			if test.wantState != selinuxRuntimeIndeterminate && err != nil {
				t.Fatalf("determinate SELinux state error = %v", err)
			}
		})
	}
}

func TestRsyslogSELinuxPolicyGateFailsClosedForEveryMissingTool(t *testing.T) {
	for _, state := range []selinuxRuntimeState{selinuxRuntimeActive, selinuxRuntimeIndeterminate} {
		for _, missing := range trustedSELinuxPolicyTools {
			t.Run(strconv.Itoa(int(state))+"/"+filepath.Base(missing), func(t *testing.T) {
				toolFailure := errors.New("synthetic missing SELinux tool")
				detectionFailure := errors.New("synthetic indeterminate detection")
				var detectionErr error
				if state == selinuxRuntimeIndeterminate {
					detectionErr = detectionFailure
				}
				configure, err := shouldConfigureRsyslogSELinuxPolicy(
					state,
					detectionErr,
					func(path string) error {
						if path == missing {
							return toolFailure
						}
						return nil
					},
				)
				if configure || !errors.Is(err, toolFailure) || !strings.Contains(err.Error(), missing) {
					t.Fatalf("SELinux policy gate = (%t, %v), want fail-closed missing %s", configure, err, missing)
				}
				if detectionErr != nil && !errors.Is(err, detectionFailure) {
					t.Fatalf("SELinux policy gate lost detection cause: %v", err)
				}
			})
		}
	}
}

func TestRsyslogSELinuxPolicyGateSkipsDisabledAndDefendsIndeterminate(t *testing.T) {
	validations := 0
	configure, err := shouldConfigureRsyslogSELinuxPolicy(
		selinuxRuntimeDisabled,
		nil,
		func(string) error {
			validations++
			return errors.New("must not run")
		},
	)
	if err != nil || configure || validations != 0 {
		t.Fatalf("disabled SELinux gate = (%t, %v, %d validations), want (false, nil, 0)", configure, err, validations)
	}

	configure, err = shouldConfigureRsyslogSELinuxPolicy(
		selinuxRuntimeIndeterminate,
		errors.New("synthetic detection failure"),
		func(string) error { return nil },
	)
	if err != nil || !configure {
		t.Fatalf("indeterminate SELinux with complete toolchain = (%t, %v), want defensive policy work", configure, err)
	}
}

func TestTrustedCommandIgnoresHostilePATHAndSanitizesEnvironment(t *testing.T) {
	hostilePath := t.TempDir()
	t.Setenv("PATH", hostilePath)
	t.Setenv("SYSWARDEN_TEST_SECRET", "must-not-be-inherited")
	command := newTrustedCommand(context.Background(), trustedSystemctlPath, "is-active", "rsyslog")
	if command.Path != trustedSystemctlPath {
		t.Fatalf("trusted command path = %q, want %q", command.Path, trustedSystemctlPath)
	}
	wantEnv := strings.Join([]string{"LANG=C", "LC_ALL=C", "PATH=" + trustedCommandPath}, "\n")
	if got := strings.Join(command.Env, "\n"); got != wantEnv {
		t.Fatalf("trusted command environment = %q, want %q", got, wantEnv)
	}
	if strings.Contains(strings.Join(command.Env, "\n"), hostilePath) {
		t.Fatal("trusted command inherited hostile PATH")
	}
}

func TestManagedServiceCommandPropagatesDeadlineAndCausesWithoutWaiting(t *testing.T) {
	parent, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	sentinel := errors.New("synthetic executor failure")
	typed := &os.PathError{Op: "exec", Path: trustedSystemctlPath, Err: sentinel}
	deadlineObserved := false
	_, err := runManagedServiceCommandUsing(
		parent,
		managedServiceCommandTimeout,
		func(string) error { return nil },
		func(ctx context.Context, name string, args ...string) ([]byte, error) {
			_, deadlineObserved = ctx.Deadline()
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatalf("executor context error = %v, want deadline exceeded", ctx.Err())
			}
			return nil, typed
		},
		trustedSystemctlPath,
		"restart", "rsyslog",
	)
	var pathErr *os.PathError
	if !deadlineObserved || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, sentinel) || !errors.As(err, &pathErr) {
		t.Fatalf("deadline/cause propagation error = %v", err)
	}
}

func TestManagedServiceDiagnosticCapsPostEscapingAndPreservesTypedCause(t *testing.T) {
	sentinel := errors.New("synthetic diagnostic failure")
	typed := &os.PathError{Op: "journal", Path: trustedJournalctlPath, Err: sentinel}
	escaped := strconv.QuoteToASCII(strings.Repeat("\x1b", managedServiceDiagnosticLimit*2))
	err := newManagedServiceDiagnosticError("journal="+escaped, typed)
	if len(err.Error()) != managedServiceDiagnosticLimit || !strings.HasSuffix(err.Error(), "[diagnostic truncated]") {
		t.Fatalf("bounded diagnostic size/suffix = (%d, %q)", len(err.Error()), err.Error()[len(err.Error())-32:])
	}
	if strings.ContainsRune(err.Error(), '\x1b') {
		t.Fatal("bounded diagnostic contains an unescaped terminal control byte")
	}
	var pathErr *os.PathError
	if !errors.Is(err, sentinel) || !errors.As(err, &pathErr) {
		t.Fatalf("bounded diagnostic lost typed cause: %v", err)
	}
}

func TestRestartManagedServiceUsesOpenRCNodepsRestartForRsyslog_SW_PKG_001(t *testing.T) {
	var calls []string
	err := restartManagedServiceUsing(
		"rsyslog",
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return true },
		func(name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("restartManagedServiceUsing() error = %v", err)
	}
	want := strings.Join([]string{
		"/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf",
		"/sbin/rc-service --ifnotstarted rsyslog start",
		"/sbin/rc-service rsyslog status",
		"/sbin/rc-service --nodeps rsyslog restart",
		"/sbin/rc-service rsyslog status",
	}, "\n")
	if got := strings.Join(calls, "\n"); got != want {
		t.Fatalf("service-manager calls = %q, want %q", got, want)
	}
}

func TestRestartManagedServiceKeepsOpenRCRestartForOtherServices_SW_PKG_001(t *testing.T) {
	var calls []string
	err := restartManagedServiceUsing(
		"wazuh-agent",
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return true },
		func(name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("restartManagedServiceUsing() error = %v", err)
	}
	if got, want := strings.Join(calls, "\n"), "/sbin/rc-service wazuh-agent restart"; got != want {
		t.Fatalf("service-manager calls = %q, want %q", got, want)
	}
}

func TestRestartManagedServiceValidatesAndAttestsSystemdRsyslog_SW_PKG_001(t *testing.T) {
	var calls []string
	err := restartManagedServiceUsing(
		"rsyslog",
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return false },
		func(name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("restartManagedServiceUsing() error = %v", err)
	}
	want := strings.Join([]string{
		"/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf",
		"/usr/bin/systemctl restart rsyslog",
		"/usr/bin/systemctl is-active --quiet rsyslog",
	}, "\n")
	if got := strings.Join(calls, "\n"); got != want {
		t.Fatalf("service-manager calls = %q, want %q", got, want)
	}
}

func TestRestartManagedServiceRetriesSystemdRsyslogExactlyOnce_SW_PKG_001(t *testing.T) {
	sentinel := errors.New("synthetic first restart failure")
	var calls []string
	err := restartManagedServiceUsing(
		"rsyslog",
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return false },
		func(name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			switch len(calls) {
			case 2:
				return []byte("first restart output"), sentinel
			case 3:
				return []byte("failed\n"), sentinel
			default:
				return nil, nil
			}
		},
	)
	if err != nil {
		t.Fatalf("restartManagedServiceUsing() recovery error = %v", err)
	}
	want := strings.Join([]string{
		"/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf",
		"/usr/bin/systemctl restart rsyslog",
		"/usr/bin/systemctl is-active --quiet rsyslog",
		"/usr/bin/systemctl reset-failed rsyslog",
		"/usr/bin/systemctl restart rsyslog",
		"/usr/bin/systemctl is-active --quiet rsyslog",
	}, "\n")
	if got := strings.Join(calls, "\n"); got != want {
		t.Fatalf("recovery calls = %q, want %q", got, want)
	}
}

func TestRestartManagedServiceRejectsInvalidSystemdRsyslogConfig_SW_PKG_001(t *testing.T) {
	sentinel := errors.New("synthetic validation failure")
	var calls []string
	err := restartManagedServiceUsing(
		"rsyslog",
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return false },
		func(name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			return []byte("invalid\x1bconfig"), sentinel
		},
	)
	if err == nil || !strings.Contains(err.Error(), "validate complete rsyslog configuration") {
		t.Fatalf("validation error = %v", err)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("validation diagnostic lost command cause: %v", err)
	}
	if strings.ContainsRune(err.Error(), '\x1b') || !strings.Contains(err.Error(), `\x1b`) {
		t.Fatalf("validation evidence is not safely escaped: %q", err.Error())
	}
	if got, want := strings.Join(calls, "\n"), "/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf"; got != want {
		t.Fatalf("validation calls = %q, want %q", got, want)
	}
}

func TestRestartManagedServiceBoundsTerminalSystemdRsyslogEvidence_SW_PKG_001(t *testing.T) {
	sentinel := errors.New("synthetic command failure")
	largeOutput := []byte(strings.Repeat("x", managedServiceOutputLimit*3) + "\x1bsecret")
	var calls []string
	err := restartManagedServiceUsing(
		"rsyslog",
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return false },
		func(name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			if len(calls) == 1 {
				return nil, nil
			}
			return largeOutput, sentinel
		},
	)
	if err == nil || !strings.Contains(err.Error(), "failed after one bounded retry") {
		t.Fatalf("terminal retry error = %v", err)
	}
	want := strings.Join([]string{
		"/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf",
		"/usr/bin/systemctl restart rsyslog",
		"/usr/bin/systemctl is-active --quiet rsyslog",
		"/usr/bin/systemctl reset-failed rsyslog",
		"/usr/bin/systemctl restart rsyslog",
		"/usr/bin/systemctl is-active --quiet rsyslog",
		"/usr/bin/journalctl --no-pager --quiet --boot --unit rsyslog.service --lines=40",
	}, "\n")
	if got := strings.Join(calls, "\n"); got != want {
		t.Fatalf("terminal failure calls = %q, want %q", got, want)
	}
	if !strings.Contains(err.Error(), "[evidence truncated]") {
		t.Fatalf("terminal evidence did not report truncation: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "journal=") {
		t.Fatalf("terminal diagnostic omitted bounded journal evidence: %q", err.Error())
	}
	if len(err.Error()) > managedServiceDiagnosticLimit {
		t.Fatalf("terminal diagnostic size = %d, limit %d", len(err.Error()), managedServiceDiagnosticLimit)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("terminal diagnostic lost command cause: %v", err)
	}
	if strings.Contains(err.Error(), "secret") || strings.ContainsRune(err.Error(), '\x1b') {
		t.Fatalf("terminal evidence escaped its bound: %q", err.Error())
	}
}

func TestRestartManagedServiceKeepsSingleSystemdRestartForOtherServices_SW_PKG_001(t *testing.T) {
	var calls []string
	err := restartManagedServiceUsing(
		"wazuh-agent",
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return false },
		func(name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("restartManagedServiceUsing() error = %v", err)
	}
	if got, want := strings.Join(calls, "\n"), "/usr/bin/systemctl restart wazuh-agent"; got != want {
		t.Fatalf("service-manager calls = %q, want %q", got, want)
	}
}

func TestRestartManagedServiceDefersOfflineWithoutCommand_SW_PKG_001(t *testing.T) {
	called := false
	err := restartManagedServiceUsing(
		"rsyslog",
		func() (string, error) { return "OFFLINE", nil },
		func() bool { return true },
		func(string, ...string) ([]byte, error) {
			called = true
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("restartManagedServiceUsing() error = %v", err)
	}
	if called {
		t.Fatal("offline service-manager state executed a runtime command")
	}
}

func TestRestartManagedServiceFailsClosedOnUnknownStateAndRunnerError_SW_PKG_001(t *testing.T) {
	t.Run("unknown state", func(t *testing.T) {
		called := false
		err := restartManagedServiceUsing(
			"rsyslog",
			func() (string, error) { return "UNKNOWN", nil },
			func() bool { return true },
			func(string, ...string) ([]byte, error) {
				called = true
				return nil, nil
			},
		)
		if err == nil || !strings.Contains(err.Error(), "refusing unrecognized service-manager runtime state") {
			t.Fatalf("unknown-state error = %v", err)
		}
		if called {
			t.Fatal("unknown service-manager state executed a runtime command")
		}
	})

	for _, test := range []struct {
		name          string
		failCall      int
		wantCalls     int
		wantErrorText string
	}{
		{
			name:          "configuration validation failure",
			failCall:      1,
			wantCalls:     1,
			wantErrorText: "validate rsyslog configuration before OpenRC restart",
		},
		{
			name:          "conditional start failure",
			failCall:      2,
			wantCalls:     2,
			wantErrorText: "conditionally start OpenRC service rsyslog with dependencies",
		},
		{
			name:          "pre-restart active-state failure",
			failCall:      3,
			wantCalls:     3,
			wantErrorText: "attest active OpenRC service rsyslog before dependency-bypassing restart",
		},
		{
			name:          "nodeps restart failure",
			failCall:      4,
			wantCalls:     4,
			wantErrorText: "restart OpenRC service rsyslog without dependency traversal",
		},
		{
			name:          "post-restart attestation failure",
			failCall:      5,
			wantCalls:     5,
			wantErrorText: "attest restarted OpenRC service rsyslog",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sentinel := errors.New("synthetic service-manager failure")
			calls := 0
			err := restartManagedServiceUsing(
				"rsyslog",
				func() (string, error) { return "ACTIVE", nil },
				func() bool { return true },
				func(string, ...string) ([]byte, error) {
					calls++
					if calls == test.failCall {
						return nil, sentinel
					}
					return nil, nil
				},
			)
			if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), test.wantErrorText) {
				t.Fatalf("OpenRC activation error = %v", err)
			}
			if calls != test.wantCalls {
				t.Fatalf("runtime commands after failure = %d, want %d", calls, test.wantCalls)
			}
		})
	}
}
