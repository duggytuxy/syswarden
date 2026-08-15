package system

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFreeBSDUninstallIsFailClosedAndUsesCapturedPFRestore(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile("uninstall_freebsd.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	for _, required := range []string{
		`"/usr/local/syswarden/bin/syswarden-cli",`,
		`"package-restore-pf",`,
		`exec.Command("service", "syswarden", "onestop")`,
		`exec.Command("service", "syswardenwebtui", "onestop")`,
		`"/var/lib/syswarden",`,
		`"/usr/home"`,
		`".cshrc"`,
		`clearFreeBSDSystemImmutable("/etc/syslog.conf")`,
		`errors.Join(failures...)`,
		`platformpaths.IsManagedCronLine(line)`,
		`RestoreFreeBSDPackageHostState()`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FreeBSD uninstall lacks %q", required)
		}
	}
	if strings.Contains(source, `exec.Command("pfctl", "-t"`) ||
		strings.Contains(source, `strings.Contains(line, "syswarden-cli")`) ||
		strings.Contains(source, `"/var/cron/allow",`) ||
		strings.Contains(source, `removeFreeBSDPath("/usr/local/etc/wireguard`) {
		t.Fatal("FreeBSD uninstall bypasses the locked PF restore or broadens cron deletion")
	}
}
