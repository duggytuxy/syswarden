package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditFilePermissionsRefusesWrongOwnerAndUnsafeFileIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(path, []byte("diagnostic fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	uid := uint64(os.Geteuid()) // #nosec G115 -- kernel effective UID is nonnegative
	if err := inspectAuditFilePermissions(path, []string{"600", "640"}, uid); err != nil {
		t.Fatal(err)
	}
	if err := inspectAuditFilePermissions(path, []string{"600", "640"}, uid+1); err == nil {
		t.Fatal("audit accepted the wrong authentication writer")
	}
	link := filepath.Join(filepath.Dir(path), "alias.log")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := inspectAuditFilePermissions(link, []string{"600"}, uid); err == nil {
		t.Fatal("audit followed a symbolic link")
	}
	hardlink := filepath.Join(filepath.Dir(path), "hardlink.log")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if err := inspectAuditFilePermissions(path, []string{"600"}, uid); err == nil {
		t.Fatal("audit accepted a log with multiple links")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil { // #nosec G302 -- intentionally unsafe temporary fixture must be rejected
		t.Fatal(err)
	}
	if err := inspectAuditFilePermissions(path, []string{"600", "640"}, uid); err == nil {
		t.Fatal("audit accepted a writable authentication log")
	}
}
