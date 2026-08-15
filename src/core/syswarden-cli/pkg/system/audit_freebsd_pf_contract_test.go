package system

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFreeBSDAuditUsesNativePFAndLoggingServices(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve audit source")
	}
	root, err := os.OpenRoot(filepath.Dir(current))
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
		`exec.Command("service", "rsyslogd", "onestatus")`,
		`exec.Command("service", "syslogd", "onestatus")`,
		`exec.Command("service", "syswarden", "onestatus")`,
		`default:`,
		`return false`,
		`isServiceActive("rsyslogd")`,
		`/var/db/syswarden/pf-policy-snapshot.json`,
		`exec.Command("pfctl", "-s", "info")`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FreeBSD audit lacks %q", required)
		}
	}
	for _, forbidden := range []string{"nft", "syswarden.nft"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("FreeBSD audit contains Linux-only token %q", forbidden)
		}
	}
}
