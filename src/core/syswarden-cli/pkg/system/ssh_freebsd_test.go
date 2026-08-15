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
	originalOwner := freeBSDSSHExpectedOwner
	freeBSDSSHDirectory = directory
	freeBSDSSHRename = func(root *os.Root, oldName, newName string) error {
		return root.Rename(oldName, newName)
	}
	freeBSDSSHRestart = func() error { return nil }
	freeBSDSSHValidate = func() error { return nil }
	freeBSDSSHExpectedOwner = os.Geteuid
	t.Cleanup(func() {
		freeBSDSSHDirectory = originalDirectory
		freeBSDSSHRename = originalRename
		freeBSDSSHRestart = originalRestart
		freeBSDSSHValidate = originalValidate
		freeBSDSSHExpectedOwner = originalOwner
	})
	return directory
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
