//go:build linux

package integration

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

func wafRsyslogTestOwner(t *testing.T) (uint32, uint32) {
	t.Helper()
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("temporary directory has no Linux stat metadata")
	}
	return stat.Uid, stat.Gid
}

func wafRsyslogTestConfigPath(parent string) string {
	return filepath.Join(parent, wafRsyslogDirectoryName, wafRsyslogConfigName)
}

func readWAFRsyslogTestFile(t *testing.T, parent, name string) []byte {
	t.Helper()
	root, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := root.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	content, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	return content
}

func writeWAFRsyslogTestConfig(t *testing.T, parent string, content []byte, mode os.FileMode) string {
	t.Helper()
	directory := filepath.Join(parent, wafRsyslogDirectoryName)
	if err := os.Mkdir(directory, 0750); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	path := filepath.Join(directory, wafRsyslogConfigName)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertNoWAFRsyslogStagingFiles(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(parent, wafRsyslogDirectoryName))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "."+wafRsyslogConfigName+".syswarden-") {
			t.Fatalf("rsyslog staging file was not cleaned up: %s", entry.Name())
		}
	}
}

func TestReconcileWAFRsyslogConfigPublishesSecurelyAndIsIdempotent(t *testing.T) {
	parent := t.TempDir()
	uid, gid := wafRsyslogTestOwner(t)
	desired := []byte("managed\n")

	changed, err := reconcileWAFRsyslogConfigAt(parent, uid, gid, desired, nil)
	if err != nil {
		t.Fatalf("first reconcileWAFRsyslogConfigAt() error = %v", err)
	}
	if !changed {
		t.Fatal("first reconciliation did not report a configuration change")
	}
	path := wafRsyslogTestConfigPath(parent)
	content := readWAFRsyslogTestFile(
		t,
		parent,
		filepath.Join(wafRsyslogDirectoryName, wafRsyslogConfigName),
	)
	if string(content) != string(desired) {
		t.Fatalf("published configuration = %q, want %q", content, desired)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("published configuration has no Linux stat metadata")
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
		t.Fatalf("published configuration mode = %v, want regular 0600", before.Mode())
	}
	if beforeStat.Uid != uid || beforeStat.Gid != gid {
		t.Fatalf(
			"published configuration owner = %d:%d, want %d:%d",
			beforeStat.Uid, beforeStat.Gid, uid, gid,
		)
	}
	assertNoWAFRsyslogStagingFiles(t, parent)

	changed, err = reconcileWAFRsyslogConfigAt(parent, uid, gid, desired, nil)
	if err != nil {
		t.Fatalf("idempotent reconcileWAFRsyslogConfigAt() error = %v", err)
	}
	if changed {
		t.Fatal("identical configuration was reported as changed")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || beforeStat.Dev != afterStat.Dev || beforeStat.Ino != afterStat.Ino {
		t.Fatal("identical configuration was unexpectedly replaced")
	}
}

func TestReconcileWAFRsyslogConfigRejectsFileSymlinks(t *testing.T) {
	uid, gid := wafRsyslogTestOwner(t)
	for _, test := range []struct {
		name        string
		dangling    bool
		wantOutside string
	}{
		{name: "symlink", wantOutside: "outside\n"},
		{name: "dangling symlink", dangling: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			directory := filepath.Join(parent, wafRsyslogDirectoryName)
			if err := os.Mkdir(directory, 0750); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(parent, "outside.conf")
			if !test.dangling {
				if err := os.WriteFile(outside, []byte(test.wantOutside), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(outside, wafRsyslogTestConfigPath(parent)); err != nil {
				t.Fatal(err)
			}

			if _, err := reconcileWAFRsyslogConfigAt(parent, uid, gid, []byte("managed\n"), nil); err == nil {
				t.Fatal("symlink configuration was accepted")
			}
			info, err := os.Lstat(wafRsyslogTestConfigPath(parent))
			if err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("managed symlink was modified: info=%v error=%v", info, err)
			}
			if !test.dangling {
				content := readWAFRsyslogTestFile(t, parent, "outside.conf")
				if string(content) != test.wantOutside {
					t.Fatalf("symlink target was modified: content=%q", content)
				}
			}
			assertNoWAFRsyslogStagingFiles(t, parent)
		})
	}
}

func TestReconcileWAFRsyslogConfigRejectsSymlinkedOrMutableDirectory(t *testing.T) {
	uid, gid := wafRsyslogTestOwner(t)
	t.Run("symlink", func(t *testing.T) {
		parent := t.TempDir()
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(parent, wafRsyslogDirectoryName)); err != nil {
			t.Fatal(err)
		}
		if _, err := reconcileWAFRsyslogConfigAt(parent, uid, gid, []byte("managed\n"), nil); err == nil {
			t.Fatal("symlinked rsyslog directory was accepted")
		}
		entries, err := os.ReadDir(outside)
		if err != nil || len(entries) != 0 {
			t.Fatalf("symlinked directory was modified: entries=%v error=%v", entries, err)
		}
	})
	t.Run("group/world writable", func(t *testing.T) {
		parent := t.TempDir()
		directory := filepath.Join(parent, wafRsyslogDirectoryName)
		if err := os.Mkdir(directory, 0750); err != nil {
			t.Fatal(err)
		}
		if err := unix.Chmod(directory, 0777); err != nil {
			t.Fatal(err)
		}
		if _, err := reconcileWAFRsyslogConfigAt(parent, uid, gid, []byte("managed\n"), nil); err == nil ||
			!strings.Contains(err.Error(), "group/world writable") {
			t.Fatalf("mutable rsyslog directory error = %v", err)
		}
	})
}

func TestReconcileWAFRsyslogConfigRejectsUnsafeMetadataAndOversize(t *testing.T) {
	uid, gid := wafRsyslogTestOwner(t)
	t.Run("fifo", func(t *testing.T) {
		parent := t.TempDir()
		directory := filepath.Join(parent, wafRsyslogDirectoryName)
		if err := os.Mkdir(directory, 0750); err != nil {
			t.Fatal(err)
		}
		path := wafRsyslogTestConfigPath(parent)
		if err := unix.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := reconcileWAFRsyslogConfigAt(parent, uid, gid, []byte("managed\n"), nil); err == nil ||
			!strings.Contains(err.Error(), "regular file") {
			t.Fatalf("FIFO rsyslog configuration error = %v", err)
		}
	})
	t.Run("mode", func(t *testing.T) {
		parent := t.TempDir()
		writeWAFRsyslogTestConfig(t, parent, []byte("old\n"), 0644)
		if _, err := reconcileWAFRsyslogConfigAt(parent, uid, gid, []byte("managed\n"), nil); err == nil ||
			!strings.Contains(err.Error(), "mode must be 0600") {
			t.Fatalf("unsafe rsyslog mode error = %v", err)
		}
		content := readWAFRsyslogTestFile(
			t,
			parent,
			filepath.Join(wafRsyslogDirectoryName, wafRsyslogConfigName),
		)
		if string(content) != "old\n" {
			t.Fatalf("unsafe-mode file was modified: content=%q", content)
		}
	})
	t.Run("owner", func(t *testing.T) {
		parent := t.TempDir()
		writeWAFRsyslogTestConfig(t, parent, []byte("old\n"), 0600)
		root, err := os.OpenRoot(parent)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		directory, err := root.Open(wafRsyslogDirectoryName)
		if err != nil {
			t.Fatal(err)
		}
		defer directory.Close()
		unexpectedUID := uid + 1
		if unexpectedUID == uid {
			unexpectedUID = uid - 1
		}
		if _, _, err := inspectWAFRsyslogConfig(directory, unexpectedUID, gid); err == nil ||
			!strings.Contains(err.Error(), "must be owned") {
			t.Fatalf("unsafe rsyslog owner error = %v", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		parent := t.TempDir()
		path := writeWAFRsyslogTestConfig(
			t,
			parent,
			[]byte(strings.Repeat("x", rsyslogArtifactContentLimit+1)),
			0600,
		)
		if _, err := reconcileWAFRsyslogConfigAt(parent, uid, gid, []byte("managed\n"), nil); err == nil ||
			!strings.Contains(err.Error(), "exceeds limit") {
			t.Fatalf("oversize rsyslog configuration error = %v", err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() != rsyslogArtifactContentLimit+1 {
			t.Fatalf("oversize rsyslog file was modified: info=%v error=%v", info, err)
		}
	})
}

func TestReconcileWAFRsyslogConfigFailureBeforeRenamePreservesDestinationAndCleansStage(t *testing.T) {
	parent := t.TempDir()
	uid, gid := wafRsyslogTestOwner(t)
	path := writeWAFRsyslogTestConfig(t, parent, []byte("old\n"), 0600)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeStat := before.Sys().(*syscall.Stat_t)
	sentinel := errors.New("synthetic pre-publication failure")
	stagingObserved := false

	changed, err := reconcileWAFRsyslogConfigAt(parent, uid, gid, []byte("new\n"), func() error {
		entries, readErr := os.ReadDir(filepath.Join(parent, wafRsyslogDirectoryName))
		if readErr != nil {
			return readErr
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), "."+wafRsyslogConfigName+".syswarden-") {
				continue
			}
			stagingObserved = true
			info, statErr := entry.Info()
			if statErr != nil {
				return statErr
			}
			stat := info.Sys().(*syscall.Stat_t)
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != uid || stat.Gid != gid {
				t.Fatalf("staging metadata = mode %v owner %d:%d, want regular 0600 %d:%d", info.Mode(), stat.Uid, stat.Gid, uid, gid)
			}
		}
		return sentinel
	})
	if !changed || !errors.Is(err, sentinel) {
		t.Fatalf("pre-publication result = changed %v error %v, want true and sentinel", changed, err)
	}
	if !stagingObserved {
		t.Fatal("pre-publication hook did not observe a staging file")
	}
	content := readWAFRsyslogTestFile(
		t,
		parent,
		filepath.Join(wafRsyslogDirectoryName, wafRsyslogConfigName),
	)
	if string(content) != "old\n" {
		t.Fatalf("destination was truncated before rename: content=%q", content)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	afterStat := after.Sys().(*syscall.Stat_t)
	if beforeStat.Dev != afterStat.Dev || beforeStat.Ino != afterStat.Ino {
		t.Fatal("destination inode changed before atomic publication")
	}
	assertNoWAFRsyslogStagingFiles(t, parent)
}

func TestReconcileWAFRsyslogConfigDetectsDestinationReplacementBeforeRename(t *testing.T) {
	parent := t.TempDir()
	uid, gid := wafRsyslogTestOwner(t)
	path := writeWAFRsyslogTestConfig(t, parent, []byte("old\n"), 0600)
	replacement := filepath.Join(parent, "replacement.conf")
	if err := os.WriteFile(replacement, []byte("replacement\n"), 0600); err != nil {
		t.Fatal(err)
	}

	changed, err := reconcileWAFRsyslogConfigAt(parent, uid, gid, []byte("new\n"), func() error {
		return os.Rename(replacement, path)
	})
	if !changed || err == nil || !strings.Contains(err.Error(), "changed before publication") {
		t.Fatalf("replacement race result = changed %v error %v", changed, err)
	}
	content := readWAFRsyslogTestFile(
		t,
		parent,
		filepath.Join(wafRsyslogDirectoryName, wafRsyslogConfigName),
	)
	if string(content) != "replacement\n" {
		t.Fatalf("replacement race overwrote current destination: content=%q", content)
	}
	assertNoWAFRsyslogStagingFiles(t, parent)
}

func TestWAFRsyslogDirectorySyncFailureIsRetriedForExactContent(t *testing.T) {
	parent := t.TempDir()
	uid, gid := wafRsyslogTestOwner(t)
	sentinel := errors.New("synthetic directory sync failure")
	desired := []byte("managed\n")
	syncCalls := 0
	syncDirectory := func(*os.File) error {
		syncCalls++
		if syncCalls <= 2 {
			return sentinel
		}
		return nil
	}

	changed, firstErr := reconcileWAFRsyslogConfigAtUsing(
		parent,
		uid,
		gid,
		desired,
		nil,
		syncDirectory,
	)
	var durabilityErr *wafRsyslogPublicationDurabilityError
	if !changed || syncCalls != 1 || !errors.Is(firstErr, sentinel) || !errors.As(firstErr, &durabilityErr) {
		t.Fatalf("post-rename sync result = changed %v calls %d error %v", changed, syncCalls, firstErr)
	}
	content := readWAFRsyslogTestFile(
		t,
		parent,
		filepath.Join(wafRsyslogDirectoryName, wafRsyslogConfigName),
	)
	if string(content) != string(desired) {
		t.Fatalf("configuration was not atomically published before sync failure: content=%q", content)
	}
	before, err := os.Stat(wafRsyslogTestConfigPath(parent))
	if err != nil {
		t.Fatal(err)
	}
	beforeStat := before.Sys().(*syscall.Stat_t)

	changed, retryErr := reconcileWAFRsyslogConfigAtUsing(
		parent,
		uid,
		gid,
		desired,
		nil,
		syncDirectory,
	)
	durabilityErr = nil
	if changed || syncCalls != 2 || !errors.Is(retryErr, sentinel) || !errors.As(retryErr, &durabilityErr) {
		t.Fatalf("exact-content retry result = changed %v calls %d error %v", changed, syncCalls, retryErr)
	}

	activationCalled := false
	err = finishWAFRsyslogSetup(changed, retryErr, func(gotChanged bool) error {
		activationCalled = true
		if gotChanged {
			t.Fatal("exact-content recovery unexpectedly reported a replacement")
		}
		return nil
	})
	if !activationCalled || !errors.Is(err, sentinel) {
		t.Fatalf("exact-content durability activation result = called %v error %v", activationCalled, err)
	}

	changed, err = reconcileWAFRsyslogConfigAtUsing(
		parent,
		uid,
		gid,
		desired,
		nil,
		syncDirectory,
	)
	if changed || err != nil || syncCalls != 3 {
		t.Fatalf("successful durability retry = changed %v calls %d error %v", changed, syncCalls, err)
	}
	after, err := os.Stat(wafRsyslogTestConfigPath(parent))
	if err != nil {
		t.Fatal(err)
	}
	afterStat := after.Sys().(*syscall.Stat_t)
	if beforeStat.Dev != afterStat.Dev || beforeStat.Ino != afterStat.Ino {
		t.Fatal("exact-content durability retries unexpectedly replaced the target")
	}
	assertNoWAFRsyslogStagingFiles(t, parent)
}

func TestWAFRsyslogExactContentRetryActivatesAfterInterruptedPublication(t *testing.T) {
	parent := t.TempDir()
	uid, gid := wafRsyslogTestOwner(t)
	desired := []byte("managed\n")

	changed, err := reconcileWAFRsyslogConfigAt(parent, uid, gid, desired, nil)
	if !changed || err != nil {
		t.Fatalf("initial publication = changed %v error %v", changed, err)
	}
	// Simulate termination after durable Renameat but before finishWAFRsyslogSetup.
	changed, err = reconcileWAFRsyslogConfigAt(parent, uid, gid, desired, nil)
	if changed || err != nil {
		t.Fatalf("exact-content recovery = changed %v error %v", changed, err)
	}

	var calls []string
	err = finishWAFRsyslogSetup(changed, err, func(gotChanged bool) error {
		if gotChanged {
			t.Fatal("exact-content recovery unexpectedly reported a replacement")
		}
		return restartManagedServiceUsingConfigState(
			"rsyslog",
			gotChanged,
			func() (string, error) { return "ACTIVE", nil },
			func() bool { return false },
			func(name string, args ...string) ([]byte, error) {
				calls = append(calls, strings.Join(append([]string{name}, args...), " "))
				return nil, nil
			},
		)
	})
	if err != nil {
		t.Fatalf("exact-content recovery activation error = %v", err)
	}
	want := strings.Join([]string{
		"/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf",
		"/usr/bin/systemctl is-active --quiet rsyslog",
		"/usr/bin/systemctl reload rsyslog",
		"/usr/bin/systemctl is-active --quiet rsyslog",
	}, "\n")
	if got := strings.Join(calls, "\n"); got != want {
		t.Fatalf("interrupted-publication recovery calls = %q, want %q", got, want)
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

func TestRestartManagedServiceRestartsExactContentOpenRCRsyslogAfterInterruptedSetup_SW_PKG_001(t *testing.T) {
	var calls []string
	err := restartManagedServiceUsingConfigState(
		"rsyslog",
		false,
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return true },
		func(name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("restartManagedServiceUsingConfigState() error = %v", err)
	}
	want := strings.Join([]string{
		"/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf",
		"/sbin/rc-service --ifnotstarted rsyslog start",
		"/sbin/rc-service rsyslog status",
		"/sbin/rc-service --nodeps rsyslog restart",
		"/sbin/rc-service rsyslog status",
	}, "\n")
	if got := strings.Join(calls, "\n"); got != want {
		t.Fatalf("exact-content OpenRC recovery calls = %q, want %q", got, want)
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

func TestRestartManagedServiceReloadsAndAttestsActiveSystemdRsyslog_SW_PKG_001(t *testing.T) {
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
		"/usr/bin/systemctl is-active --quiet rsyslog",
		"/usr/bin/systemctl reload rsyslog",
		"/usr/bin/systemctl is-active --quiet rsyslog",
	}, "\n")
	if got := strings.Join(calls, "\n"); got != want {
		t.Fatalf("service-manager calls = %q, want %q", got, want)
	}
}

func TestRestartManagedServiceReloadsExactContentSystemdRsyslogAfterInterruptedSetup_SW_PKG_001(t *testing.T) {
	var calls []string
	err := restartManagedServiceUsingConfigState(
		"rsyslog",
		false,
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return false },
		func(name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("restartManagedServiceUsingConfigState() error = %v", err)
	}
	want := strings.Join([]string{
		"/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf",
		"/usr/bin/systemctl is-active --quiet rsyslog",
		"/usr/bin/systemctl reload rsyslog",
		"/usr/bin/systemctl is-active --quiet rsyslog",
	}, "\n")
	if got := strings.Join(calls, "\n"); got != want {
		t.Fatalf("exact-content systemd recovery calls = %q, want %q", got, want)
	}
}

func TestRestartManagedServiceActivatesUnchangedInactiveSystemdRsyslog_SW_PKG_001(t *testing.T) {
	sentinel := errors.New("synthetic inactive state")
	var calls []string
	err := restartManagedServiceUsingConfigState(
		"rsyslog",
		false,
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return false },
		func(name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			if len(calls) == 2 {
				return []byte("inactive\n"), sentinel
			}
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("restartManagedServiceUsingConfigState() activation error = %v", err)
	}
	want := strings.Join([]string{
		"/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf",
		"/usr/bin/systemctl is-active --quiet rsyslog",
		"/usr/bin/systemctl restart rsyslog",
		"/usr/bin/systemctl is-active --quiet rsyslog",
	}, "\n")
	if got := strings.Join(calls, "\n"); got != want {
		t.Fatalf("inactive-service calls = %q, want %q", got, want)
	}
}

func TestRestartManagedServiceFallsBackAfterSystemdRsyslogReloadOrAttestationFailure_SW_PKG_001(t *testing.T) {
	want := strings.Join([]string{
		"/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf",
		"/usr/bin/systemctl is-active --quiet rsyslog",
		"/usr/bin/systemctl reload rsyslog",
		"/usr/bin/systemctl is-active --quiet rsyslog",
		"/usr/bin/systemctl restart rsyslog",
		"/usr/bin/systemctl is-active --quiet rsyslog",
	}, "\n")
	for _, tt := range []struct {
		name        string
		failureCall int
	}{
		{name: "reload failure", failureCall: 3},
		{name: "active attestation failure", failureCall: 4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sentinel := errors.New("synthetic reload activation failure")
			var calls []string
			err := restartManagedServiceUsing(
				"rsyslog",
				func() (string, error) { return "ACTIVE", nil },
				func() bool { return false },
				func(name string, args ...string) ([]byte, error) {
					calls = append(calls, strings.Join(append([]string{name}, args...), " "))
					if len(calls) == tt.failureCall {
						return []byte("activation failed"), sentinel
					}
					return nil, nil
				},
			)
			if err != nil {
				t.Fatalf("restartManagedServiceUsing() fallback error = %v", err)
			}
			if got := strings.Join(calls, "\n"); got != want {
				t.Fatalf("reload-fallback calls = %q, want %q", got, want)
			}
		})
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
				return []byte("inactive\n"), sentinel
			case 3:
				return []byte("first restart output"), sentinel
			case 4:
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
		"/usr/bin/systemctl is-active --quiet rsyslog",
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
		"/usr/bin/systemctl is-active --quiet rsyslog",
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

func TestPackageRemovalRsyslogRestartForcesAndAttestsSystemdProcessReplacement_SW2_PKG_001(t *testing.T) {
	want := []string{
		"/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf",
		"/usr/bin/systemctl show --property=MainPID --value rsyslog",
		"/usr/bin/systemctl show --property=ActiveEnterTimestampMonotonic --value rsyslog",
		"/usr/bin/systemctl restart rsyslog",
		"/usr/bin/systemctl is-active --quiet rsyslog",
		"/usr/bin/systemctl show --property=MainPID --value rsyslog",
		"/usr/bin/systemctl show --property=ActiveEnterTimestampMonotonic --value rsyslog",
	}
	outputs := [][]byte{
		nil,
		[]byte("1056\n"),
		[]byte("100\n"),
		nil,
		[]byte("active\n"),
		[]byte("2048\n"),
		[]byte("200\n"),
	}
	var calls []string
	err := restartRsyslogForPackageRemovalUsing(
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return false },
		func(name string, args ...string) ([]byte, error) {
			call := strings.Join(append([]string{name}, args...), " ")
			calls = append(calls, call)
			index := len(calls) - 1
			if index >= len(outputs) {
				t.Fatalf("unexpected package-removal command %q", call)
			}
			return outputs[index], nil
		},
	)
	if err != nil {
		t.Fatalf("attested package-removal restart: %v", err)
	}
	if got := strings.Join(calls, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("package-removal systemd calls = %q, want %q", got, strings.Join(want, "\n"))
	}
	if strings.Contains(strings.Join(calls, "\n"), " reload ") {
		t.Fatalf("package-removal path used reload: %v", calls)
	}
}

func TestPackageRemovalRsyslogRestartRetriesAfterUnchangedSystemdIdentity_SW2_PKG_001(t *testing.T) {
	responses := []struct {
		output []byte
		err    error
	}{
		{},                         // validate
		{output: []byte("1056\n")}, // first before PID
		{output: []byte("100\n")},  // first before timestamp
		{},                         // first restart
		{output: []byte("active\n")},
		{output: []byte("1056\n")}, // stale PID
		{output: []byte("100\n")},  // stale timestamp
		{},                         // reset-failed
		{output: []byte("1056\n")}, // retry before PID
		{output: []byte("100\n")},  // retry before timestamp
		{},                         // retry restart
		{output: []byte("active\n")},
		{output: []byte("4096\n")}, // retry after PID
		{output: []byte("300\n")},  // retry after timestamp
	}
	var calls []string
	err := restartRsyslogForPackageRemovalUsing(
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return false },
		func(name string, args ...string) ([]byte, error) {
			call := strings.Join(append([]string{name}, args...), " ")
			calls = append(calls, call)
			index := len(calls) - 1
			if index >= len(responses) {
				t.Fatalf("unexpected bounded-retry command %q", call)
			}
			return responses[index].output, responses[index].err
		},
	)
	if err != nil {
		t.Fatalf("bounded package-removal restart retry: %v", err)
	}
	if got := strings.Count(strings.Join(calls, "\n"), "/usr/bin/systemctl restart rsyslog"); got != 2 {
		t.Fatalf("package-removal restart count = %d, calls %v", got, calls)
	}
	if got := strings.Count(strings.Join(calls, "\n"), " reload "); got != 0 {
		t.Fatalf("package-removal reload count = %d, calls %v", got, calls)
	}
}

func TestPackageRemovalRsyslogRestartRejectsUnchangedSystemdIdentity_SW2_PKG_001(t *testing.T) {
	responses := [][]byte{
		[]byte("1056\n"),
		[]byte("100\n"),
		nil,
		[]byte("active\n"),
		[]byte("1056\n"),
		[]byte("100\n"),
	}
	calls := 0
	err := attemptAttestedSystemdRsyslogRestartForPackageRemovalUsing(
		func(string, ...string) ([]byte, error) {
			if calls >= len(responses) {
				t.Fatal("unexpected identity-attestation command")
			}
			output := responses[calls]
			calls++
			return output, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "MainPID remained 1056") ||
		!strings.Contains(err.Error(), "did not advance from 100 to 100") {
		t.Fatalf("unchanged systemd identity error = %v", err)
	}
}

func TestPackageRemovalRsyslogRestartFailsClosedOfflineWithoutCommand_SW2_PKG_001(t *testing.T) {
	called := false
	err := restartRsyslogForPackageRemovalUsing(
		func() (string, error) { return "OFFLINE", nil },
		func() bool { return false },
		func(string, ...string) ([]byte, error) {
			called = true
			return nil, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "producer quiescence cannot be attested") {
		t.Fatalf("offline package-removal error = %v", err)
	}
	if called {
		t.Fatal("offline package-removal path executed a service command")
	}
}

func TestPackageRemovalRsyslogRestartUsesOpenRCNodepsRestart_SW2_PKG_001(t *testing.T) {
	var calls []string
	err := restartRsyslogForPackageRemovalUsing(
		func() (string, error) { return "ACTIVE", nil },
		func() bool { return true },
		func(name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("OpenRC package-removal restart: %v", err)
	}
	want := strings.Join([]string{
		"/usr/sbin/rsyslogd -N1 -f /etc/rsyslog.conf",
		"/sbin/rc-service --ifnotstarted rsyslog start",
		"/sbin/rc-service rsyslog status",
		"/sbin/rc-service --nodeps rsyslog restart",
		"/sbin/rc-service rsyslog status",
	}, "\n")
	if got := strings.Join(calls, "\n"); got != want {
		t.Fatalf("OpenRC package-removal calls = %q, want %q", got, want)
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
			wantErrorText: "validate rsyslog configuration before OpenRC activation",
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
			wantErrorText: "attest active OpenRC service rsyslog before configuration reconciliation",
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
