//go:build linux

package system

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLinuxAuditAndUninstallUseExactFailClosedCronContract(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	auditSource, err := root.ReadFile("audit_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`inspectManagedFeedCron(exec.Command("crontab", "-l"))`,
		`Cron Orchestration FAILED: cannot read root crontab`,
	} {
		if !strings.Contains(string(auditSource), required) {
			t.Fatalf("Linux audit lacks %q", required)
		}
	}
	if strings.Contains(string(auditSource), `strings.Count(string(out), "syswarden-cli update-feeds")`) ||
		strings.Contains(string(auditSource), `out, _ := exec.Command("crontab", "-l").Output()`) {
		t.Fatal("Linux audit still accepts substring matches or ignores crontab read errors")
	}

	uninstallSource, err := root.ReadFile("uninstall_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`removeManagedRootCron(`,
		`exec.Command("crontab", "-l")`,
		`exec.Command("crontab", "-")`,
		`return fmt.Errorf("clean root crontab: %w", err)`,
	} {
		if !strings.Contains(string(uninstallSource), required) {
			t.Fatalf("Linux uninstall lacks %q", required)
		}
	}
	if strings.Contains(string(uninstallSource), `strings.Contains(line, "syswarden-cli")`) ||
		strings.Contains(string(uninstallSource), `out, _ := exec.Command("crontab", "-l").Output()`) {
		t.Fatal("Linux uninstall still broadens cron deletion or ignores read errors")
	}
}
