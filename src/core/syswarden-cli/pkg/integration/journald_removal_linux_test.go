//go:build linux

package integration

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func journaldRemovalFixtureProperties(generation int) string {
	values := map[string]string{
		"Id": "systemd-journald.service", "LoadState": "loaded", "ActiveState": "active", "SubState": "running",
		"ControlPID": "0", "NeedDaemonReload": "no", "DynamicUser": "no", "PassEnvironment": "TERM",
		"MainPID": strconv.Itoa(100 + generation), "InvocationID": fmt.Sprintf("%032x", generation+1),
		"ExecMainStartTimestampMonotonic": strconv.Itoa(1000 + generation),
		"FragmentPath":                    "/usr/lib/systemd/system/systemd-journald.service",
		"ExecStart":                       fmt.Sprintf("{ path=/usr/lib/systemd/systemd-journald ; argv[]=/usr/lib/systemd/systemd-journald ; ignore_errors=no ; start_time=[fixture] ; stop_time=[n/a] ; pid=%d ; code=(null) ; status=0/0 }", 100+generation),
	}
	var out strings.Builder
	for _, key := range strings.Split(journaldRemovalProperties, ",") {
		fmt.Fprintf(&out, "%s=%s\n", key, values[key])
	}
	return out.String()
}

type journaldRemovalFixture struct {
	parent, target       string
	uid, gid             uint32
	generation, restarts int
	operator             []byte
	alterProperties      func(string) string
	beforeRestart        func() error
}

func newJournaldRemovalFixture(t *testing.T) *journaldRemovalFixture {
	t.Helper()
	parent, _, uid, gid := newOwnedArtifactRemovalFixture(t)
	directory := filepath.Join(parent, "journald.conf.d")
	if err := os.Mkdir(directory, 0750); err != nil {
		t.Fatal(err)
	}
	f := &journaldRemovalFixture{parent: parent, target: filepath.Join(directory, "99-syswarden.conf"), uid: uid, gid: gid, operator: []byte("# /etc/systemd/journald.conf\n[Journal]\nStorage=persistent\nSystemMaxUse=128M\n")}
	writeOwnedArtifactFixture(t, f.target, []byte(journaldRemovalContent), 0600)
	return f
}

func (f *journaldRemovalFixture) run(name string, args ...string) ([]byte, error) {
	switch name + " " + strings.Join(args, " ") {
	case trustedSystemctlPath + " show systemd-journald.service --no-pager --property=" + journaldRemovalProperties:
		properties := journaldRemovalFixtureProperties(f.generation)
		if f.alterProperties != nil {
			properties = f.alterProperties(properties)
		}
		return []byte(properties), nil
	case "/usr/bin/systemd-analyze cat-config systemd/journald.conf":
		output := append([]byte(nil), f.operator...)
		root, err := os.OpenRoot(filepath.Dir(f.target))
		if err != nil {
			return nil, err
		}
		defer func() { _ = root.Close() }()
		content, err := root.ReadFile("99-syswarden.conf")
		if errors.Is(err, os.ErrNotExist) {
			return output, nil
		}
		if err != nil {
			return nil, err
		}
		return append(output, []byte("\n# "+journaldRemovalPath+"\n"+string(content))...), nil
	case trustedSystemctlPath + " restart systemd-journald.service":
		f.restarts++
		if f.beforeRestart != nil {
			if err := f.beforeRestart(); err != nil {
				return nil, err
			}
		}
		f.generation++
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected fixture command")
	}
}
func (f *journaldRemovalFixture) apply(options exactOwnedArtifactRemovalOptions) error {
	return removeExactJournaldFragmentAtUsing(f.parent, f.uid, f.gid, options, func() (string, error) { return "ACTIVE", nil }, f.run, func() error { return nil })
}

func TestJournaldRemovalRetainsAdministratorConfigurationAndActivatesBeforeCompletion(t *testing.T) {
	f := newJournaldRemovalFixture(t)
	before := append([]byte(nil), f.operator...)
	if err := f.apply(defaultExactOwnedArtifactRemovalOptions()); err != nil {
		t.Fatal(err)
	}
	if f.restarts != 1 || !bytes.Equal(f.operator, before) {
		t.Fatal("administrator configuration or activation changed unexpectedly")
	}
	if _, err := os.Lstat(f.target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("generated fragment remains", err)
	}
	if err := f.apply(defaultExactOwnedArtifactRemovalOptions()); err != nil {
		t.Fatal("completed retry", err)
	}
	if f.restarts != 1 {
		t.Fatal("absent fragment restarted shared logging")
	}
}

func TestJournaldRemovalRestoresOriginalOnActivationFailure(t *testing.T) {
	f := newJournaldRemovalFixture(t)
	original, err := os.Lstat(f.target)
	if err != nil {
		t.Fatal(err)
	}
	f.beforeRestart = func() error {
		if f.restarts == 1 {
			return errors.New("synthetic restart failure")
		}
		return nil
	}
	if err := f.apply(defaultExactOwnedArtifactRemovalOptions()); err == nil {
		t.Fatal("activation failure accepted")
	}
	after, err := os.Lstat(f.target)
	if err != nil || !os.SameFile(original, after) || f.restarts != 2 {
		t.Fatal("original source and logging were not restored", err, f.restarts)
	}
}

func TestJournaldRemovalRecoversQuarantineAfterInterruption(t *testing.T) {
	for _, point := range []string{"after-rename:99-syswarden.conf", "after-before-commit:99-syswarden.conf"} {
		t.Run(point, func(t *testing.T) {
			f := newJournaldRemovalFixture(t)
			options := defaultExactOwnedArtifactRemovalOptions()
			options.faultPoint = func(actual string) {
				if actual == point {
					panic("synthetic interruption")
				}
			}
			panicked := false
			func() { defer func() { panicked = recover() != nil }(); _ = f.apply(options) }()
			if !panicked {
				t.Fatal("interruption not reached")
			}
			if err := f.apply(defaultExactOwnedArtifactRemovalOptions()); err != nil {
				t.Fatal("pending retry failed", err)
			}
			if _, err := os.Lstat(f.target); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("fragment remains", err)
			}
		})
	}
}

func TestJournaldRemovalRefusesAmbiguousSourceAndOfflineConsumer(t *testing.T) {
	for _, change := range []string{"content", "mode", "symlink", "offline", "changed-service"} {
		t.Run(change, func(t *testing.T) {
			f := newJournaldRemovalFixture(t)
			switch change {
			case "content":
				writeOwnedArtifactFixture(t, f.target, []byte("[Journal]\nStorage=persistent\n"), 0600)
			case "mode":
				if err := os.Chmod(f.target, 0644); err != nil { // #nosec G302 -- deliberately unsafe mode in the private refusal fixture
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(f.target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("operator.conf", f.target); err != nil {
					t.Fatal(err)
				}
			case "changed-service":
				f.alterProperties = func(s string) string {
					return strings.Replace(s, "RootImage=\n", "RootImage=/private/alternate.raw\n", 1)
				}
			}
			before, err := os.Lstat(f.target)
			if err != nil {
				t.Fatal(err)
			}
			classify := func() (string, error) {
				if change == "offline" {
					return "OFFLINE", nil
				}
				return "ACTIVE", nil
			}
			err = removeExactJournaldFragmentAtUsing(f.parent, f.uid, f.gid, defaultExactOwnedArtifactRemovalOptions(), classify, f.run, func() error { return nil })
			after, statErr := os.Lstat(f.target)
			if err == nil || statErr != nil || !os.SameFile(before, after) || f.restarts != 0 {
				t.Fatal("ambiguous source or inactive manager caused mutation", err, statErr)
			}
		})
	}
}

func TestJournaldRemovalRejectsConcurrentAdministratorChange(t *testing.T) {
	f := newJournaldRemovalFixture(t)
	options := defaultExactOwnedArtifactRemovalOptions()
	changed := []byte("# /etc/systemd/journald.conf\n[Journal]\nStorage=volatile\n")
	options.faultPoint = func(point string) {
		if point == "after-rename:99-syswarden.conf" {
			f.operator = append([]byte(nil), changed...)
		}
	}
	if err := f.apply(options); err == nil {
		t.Fatal("changed administrator configuration was accepted")
	}
	if !bytes.Equal(changed, f.operator) || f.restarts != 0 {
		t.Fatal("administrator change was overwritten or activated unexpectedly")
	}
	if _, err := os.Lstat(f.target); err != nil {
		t.Fatal("original generated source was not retained", err)
	}
}

func TestJournaldRemovalConfigurationProjectionRejectsForgedOrIncompleteBlocks(t *testing.T) {
	base := []byte("# /etc/systemd/journald.conf\n[Journal]\nStorage=persistent\n")
	block := []byte("\n# " + journaldRemovalPath + "\n" + journaldRemovalContent)
	after := []byte("\n# /etc/systemd/journald.conf.d/zz-operator.conf\n[Journal]\nForwardToSyslog=no\n")
	before := append(append(append([]byte(nil), base...), block...), after...)
	got, err := journaldConfigurationWithoutOwnedFragment(before, true)
	if err != nil || !bytes.Equal(got, append(append([]byte(nil), base...), after...)) {
		t.Fatal("projection changed administrator blocks", err)
	}
	for _, input := range [][]byte{base, append(append([]byte(nil), before...), block...), append(append([]byte(nil), base...), append(block, []byte("unexpected\n")...)...)} {
		if _, err := journaldConfigurationWithoutOwnedFragment(input, true); err == nil {
			t.Fatal("ambiguous block accepted")
		}
	}
	if _, err := journaldConfigurationWithoutOwnedFragment(before, false); err == nil {
		t.Fatal("absent file still advertised as an effective source")
	}
}

func TestJournaldRemovalRejectsUnsafeServiceProperties(t *testing.T) {
	for key, value := range map[string]string{"ActiveState": "inactive", "ControlPID": "4", "Environment": "SYSTEMD_LOG_LEVEL=debug", "EnvironmentFiles": "/etc/custom.env", "PassEnvironment": "LD_PRELOAD", "ExecStop": "custom command", "InvocationID": "invalid", "MainPID": "0", "NeedDaemonReload": "yes", "BindPaths": "/alternate:/etc", "ExecStart": "/unsupported/launcher"} {
		t.Run(key, func(t *testing.T) {
			f := newJournaldRemovalFixture(t)
			f.alterProperties = func(s string) string {
				lines := strings.Split(s, "\n")
				for i, line := range lines {
					if strings.HasPrefix(line, key+"=") {
						lines[i] = key + "=" + value
					}
				}
				return strings.Join(lines, "\n")
			}
			if _, err := inspectJournaldRemovalService(f.run); err == nil {
				t.Fatal("unsupported consumer accepted")
			}
		})
	}
}

func TestJournaldRemovalProjectionMatchesInstalledConfigurationReader(t *testing.T) {
	if _, err := os.Stat("/usr/bin/systemd-analyze"); errors.Is(err, os.ErrNotExist) {
		t.Skip("systemd configuration reader is unavailable")
	}
	fixture := t.TempDir()
	root, err := os.OpenRoot(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.MkdirAll("etc/systemd/journald.conf.d", 0700); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("etc/systemd/journald.conf", []byte("[Journal]\nStorage=persistent\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("etc/systemd/journald.conf.d/99-syswarden.conf", []byte(journaldRemovalContent), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("etc/systemd/journald.conf.d/zz-operator.conf", []byte("[Journal]\nForwardToSyslog=no\n"), 0600); err != nil {
		t.Fatal(err)
	}
	read := func() []byte {
		content, err := runManagedServiceCommand("/usr/bin/systemd-analyze", "--root="+fixture, "cat-config", "systemd/journald.conf")
		if err != nil {
			t.Fatal(err)
		}
		return bytes.ReplaceAll(content, []byte(fixture+"/etc/"), []byte("/etc/"))
	}
	before := read()
	expected, err := journaldConfigurationWithoutOwnedFragment(before, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Remove("etc/systemd/journald.conf.d/99-syswarden.conf"); err != nil {
		t.Fatal(err)
	}
	if actual := read(); !bytes.Equal(actual, expected) {
		t.Fatal("projection differs from the installed systemd reader")
	}
}

func TestJournaldRemovalNativeReadOnly(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_JOURNALD_NATIVE") != "1" {
		t.Skip("native read-only inspection was not requested")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native read-only inspection requires root")
	}
	if _, err := inspectJournaldRemovalService(runManagedServiceCommand); err != nil {
		t.Fatal(err)
	}
	if _, err := readJournaldRemovalConfiguration(runManagedServiceCommand); err != nil {
		t.Fatal(err)
	}
}

func TestJournaldRemovalPendingRetryRestoresLoggingAfterActivationFailure(t *testing.T) {
	f := newJournaldRemovalFixture(t)
	quarantine := filepath.Join(filepath.Dir(f.target), exactArtifactQuarantineName(filepath.Base(f.target)))
	if err := os.Rename(f.target, quarantine); err != nil {
		t.Fatal(err)
	}
	f.beforeRestart = func() error {
		if f.restarts == 1 {
			return errors.New("synthetic pending restart failure")
		}
		return nil
	}
	if err := f.apply(defaultExactOwnedArtifactRemovalOptions()); err == nil {
		t.Fatal("pending restart failure accepted")
	}
	if _, err := os.Lstat(f.target); err != nil || f.restarts != 2 {
		t.Fatal("pending failure did not restore source and reactivate logging", err, f.restarts)
	}
}
