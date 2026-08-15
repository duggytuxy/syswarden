package system

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFreeBSDAuditVerifiesOwnerAndExactManagedCron_SW_PKG_001(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile("audit_freebsd.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	for _, required := range []string{
		`info.Sys().(*syscall.Stat_t)`,
		`stat.Uid == expectedUID`,
		`platformpaths.IsManagedCronLine(line)`,
		`fields[6] == "update-feeds"`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FreeBSD audit lacks %q", required)
		}
	}
	if strings.Contains(source, `strings.Count(string(out), "syswarden-cli update-feeds")`) {
		t.Fatal("FreeBSD audit still counts substring matches as managed cron entries")
	}
}
