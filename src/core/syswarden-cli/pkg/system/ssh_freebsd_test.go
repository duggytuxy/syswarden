//go:build freebsd

package system

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func prepareFreeBSDSSHTest(t *testing.T, content string) string {
	t.Helper()
	directory := t.TempDir()
	configPath := filepath.Join(directory, "sshd_config")
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	originalDirectory := freeBSDSSHDirectory
	originalRename := freeBSDSSHRename
	originalRestart := freeBSDSSHRestart
	originalValidate := freeBSDSSHValidate
	originalWritePrivateFile := freeBSDSSHWritePrivateFile
	originalSyncDirectory := freeBSDSSHSyncDirectory
	originalOwner := freeBSDSSHExpectedOwner
	freeBSDSSHDirectory = directory
	freeBSDSSHRename = func(root *os.Root, oldName, newName string) error {
		return root.Rename(oldName, newName)
	}
	freeBSDSSHRestart = func() error { return nil }
	freeBSDSSHValidate = func() error { return nil }
	freeBSDSSHWritePrivateFile = writePrivateSSHFile
	freeBSDSSHSyncDirectory = syncSSHDirectory
	freeBSDSSHExpectedOwner = os.Geteuid
	t.Cleanup(func() {
		freeBSDSSHDirectory = originalDirectory
		freeBSDSSHRename = originalRename
		freeBSDSSHRestart = originalRestart
		freeBSDSSHValidate = originalValidate
		freeBSDSSHWritePrivateFile = originalWritePrivateFile
		freeBSDSSHSyncDirectory = originalSyncDirectory
		freeBSDSSHExpectedOwner = originalOwner
	})
	return directory
}

func readSSHTestSnapshot(t *testing.T, directory string) freeBSDSSHConfigSnapshot {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	snapshot, err := readSafeFreeBSDSSHFile(root, freeBSDSSHConfig)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertSSHTestArtifactsAbsent(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != freeBSDSSHConfig {
		t.Fatalf("unexpected SSH transaction artifacts: %#v", entries)
	}
}

func TestConfigureFreeBSDSSHDirectivesByteExactNoOp(t *testing.T) {
	original := "PasswordAuthentication yes\nAllowTcpForwarding no\nX11Forwarding no\nMatch User backup\n"
	directory := prepareFreeBSDSSHTest(t, original)
	before := readSSHTestSnapshot(t, directory)
	events := make([]string, 0, 7)
	freeBSDSSHWritePrivateFile = func(root *os.Root, name string, content []byte, mode os.FileMode, uid, gid int) error {
		events = append(events, "write:"+name)
		return writePrivateSSHFile(root, name, content, mode, uid, gid)
	}
	freeBSDSSHValidate = func() error {
		events = append(events, "validate")
		return nil
	}
	freeBSDSSHRename = func(root *os.Root, oldName, newName string) error {
		events = append(events, "rename")
		return root.Rename(oldName, newName)
	}
	freeBSDSSHSyncDirectory = func(root *os.Root) error {
		events = append(events, "sync")
		return syncSSHDirectory(root)
	}
	freeBSDSSHRestart = func() error {
		events = append(events, "restart")
		return nil
	}

	if err := ConfigureFreeBSDSSHDirectives(map[string]string{
		"AllowTcpForwarding": "no",
		"X11Forwarding":      "no",
	}); err != nil {
		t.Fatal(err)
	}
	after := readSSHTestSnapshot(t, directory)
	if !sameFreeBSDSSHConfig(before, after) || string(after.content) != original {
		t.Fatal("byte-exact SSH configuration no-op changed content or metadata")
	}
	if len(events) != 0 {
		t.Fatalf("byte-exact SSH configuration no-op caused side effects: %v", events)
	}
	assertSSHTestArtifactsAbsent(t, directory)
}

func TestConfigureFreeBSDSSHDirectivesChangedContentKeepsTransaction(t *testing.T) {
	original := "PasswordAuthentication yes\nAllowTcpForwarding yes\n"
	directory := prepareFreeBSDSSHTest(t, original)
	testRoot, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := testRoot.Chmod(freeBSDSSHConfig, 0640); err != nil {
		_ = testRoot.Close()
		t.Fatal(err)
	}
	if err := testRoot.Close(); err != nil {
		t.Fatal(err)
	}
	before := readSSHTestSnapshot(t, directory)
	events := make([]string, 0, 7)
	freeBSDSSHWritePrivateFile = func(root *os.Root, name string, content []byte, mode os.FileMode, uid, gid int) error {
		events = append(events, "write:"+name)
		return writePrivateSSHFile(root, name, content, mode, uid, gid)
	}
	freeBSDSSHValidate = func() error {
		events = append(events, "validate")
		return nil
	}
	freeBSDSSHRename = func(root *os.Root, oldName, newName string) error {
		events = append(events, "rename")
		return root.Rename(oldName, newName)
	}
	freeBSDSSHSyncDirectory = func(root *os.Root) error {
		events = append(events, "sync")
		return syncSSHDirectory(root)
	}
	freeBSDSSHRestart = func() error {
		events = append(events, "restart")
		return nil
	}

	directives := map[string]string{"AllowTcpForwarding": "no"}
	want, err := normalizeSSHDirectives(original, directives)
	if err != nil {
		t.Fatal(err)
	}
	if err := ConfigureFreeBSDSSHDirectives(directives); err != nil {
		t.Fatal(err)
	}
	after := readSSHTestSnapshot(t, directory)
	if string(after.content) != want || string(after.content) == original {
		t.Fatalf("SSH transaction did not install normalized content:\n%s", after.content)
	}
	if after.mode != before.mode || after.uid != before.uid || after.gid != before.gid {
		t.Fatalf(
			"SSH transaction changed metadata: before=%o:%d:%d after=%o:%d:%d",
			before.mode, before.uid, before.gid, after.mode, after.uid, after.gid,
		)
	}
	wantEvents := []string{
		"write:" + freeBSDSSHBackup,
		"write:" + freeBSDSSHConfigTmp,
		"validate",
		"rename",
		"sync",
		"restart",
		"sync",
	}
	if strings.Join(events, ",") != strings.Join(wantEvents, ",") {
		t.Fatalf("SSH transaction sequence changed: got %v want %v", events, wantEvents)
	}
	assertSSHTestArtifactsAbsent(t, directory)
}

func readSSHTestFile(t *testing.T, directory, name string) string {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func TestConfigureFreeBSDSSHDirectivesRollsBackRestartFailure(t *testing.T) {
	original := "PasswordAuthentication yes\nMatch User backup\nX11Forwarding yes\n"
	directory := prepareFreeBSDSSHTest(t, original)
	freeBSDSSHRestart = func() error { return errors.New("restart failed") }
	if err := ConfigureFreeBSDSSHDirectives(map[string]string{
		"AllowTcpForwarding": "no",
		"X11Forwarding":      "no",
	}); err == nil {
		t.Fatal("restart failure was ignored")
	}
	if got := readSSHTestFile(t, directory, freeBSDSSHConfig); got != original {
		t.Fatalf("restart failure did not restore the original config:\n%s", got)
	}
}

func TestConfigureFreeBSDSSHDirectivesReportsRollbackRestartFailure(t *testing.T) {
	original := "PasswordAuthentication yes\n"
	directory := prepareFreeBSDSSHTest(t, original)
	restarts := 0
	freeBSDSSHRestart = func() error {
		restarts++
		if restarts == 1 {
			return errors.New("candidate restart failed")
		}
		return errors.New("rollback restart failed")
	}
	err := ConfigureFreeBSDSSHDirectives(map[string]string{"AllowTcpForwarding": "no"})
	if err == nil || !strings.Contains(err.Error(), "candidate restart failed") ||
		!strings.Contains(err.Error(), "restart sshd after rollback") ||
		!strings.Contains(err.Error(), "rollback restart failed") {
		t.Fatalf("rollback restart failure was not fully reported: %v", err)
	}
	if got := readSSHTestFile(t, directory, freeBSDSSHConfig); got != original {
		t.Fatalf("rollback restart failure did not restore the original config:\n%s", got)
	}
}

func TestConfigureFreeBSDSSHDirectivesRejectsConcurrentEditBeforeRename(t *testing.T) {
	directory := prepareFreeBSDSSHTest(t, "PasswordAuthentication yes\n")
	freeBSDSSHValidate = func() error {
		return os.WriteFile(
			filepath.Join(directory, freeBSDSSHConfig),
			[]byte("# operator edit during validation\n"),
			0600,
		)
	}
	err := ConfigureFreeBSDSSHDirectives(map[string]string{"AllowTcpForwarding": "no"})
	if err == nil || !strings.Contains(err.Error(), "changed before atomic replacement") {
		t.Fatalf("pre-rename concurrent edit was not rejected: %v", err)
	}
	if got := readSSHTestFile(t, directory, freeBSDSSHConfig); got != "# operator edit during validation\n" {
		t.Fatalf("pre-rename concurrent edit was overwritten:\n%s", got)
	}
}

func TestConfigureFreeBSDSSHDirectivesPreservesRollbackOnConcurrentEdit(t *testing.T) {
	directory := prepareFreeBSDSSHTest(t, "PasswordAuthentication yes\n")
	concurrent := "PasswordAuthentication no\n# operator concurrent edit\n"
	freeBSDSSHRestart = func() error {
		if err := os.WriteFile(filepath.Join(directory, freeBSDSSHConfig), []byte(concurrent), 0600); err != nil {
			t.Fatal(err)
		}
		return errors.New("restart failed")
	}
	err := ConfigureFreeBSDSSHDirectives(map[string]string{"AllowTcpForwarding": "no"})
	if err == nil || !strings.Contains(err.Error(), "concurrent sshd_config edit") {
		t.Fatalf("concurrent edit was not detected: %v", err)
	}
	if got := readSSHTestFile(t, directory, freeBSDSSHConfig); got != concurrent {
		t.Fatalf("concurrent edit was overwritten:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(directory, freeBSDSSHBackup)); err != nil {
		t.Fatalf("rollback snapshot was not preserved: %v", err)
	}
}

func TestConfigureFreeBSDSSHDirectivesPreservesBackupWhenRollbackRenameFails(t *testing.T) {
	directory := prepareFreeBSDSSHTest(t, "PasswordAuthentication yes\n")
	freeBSDSSHRestart = func() error { return errors.New("restart failed") }
	freeBSDSSHRename = func(root *os.Root, oldName, newName string) error {
		if oldName == freeBSDSSHBackup {
			return errors.New("injected rollback rename failure")
		}
		return root.Rename(oldName, newName)
	}
	err := ConfigureFreeBSDSSHDirectives(map[string]string{"AllowTcpForwarding": "no"})
	if err == nil || !strings.Contains(err.Error(), "snapshot was preserved") {
		t.Fatalf("rollback rename failure was not propagated: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, freeBSDSSHBackup)); err != nil {
		t.Fatalf("rollback snapshot was deleted after rollback failure: %v", err)
	}
}
