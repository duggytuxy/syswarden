package system

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFreeBSDAuditUsesPackagedRCServiceName_SW_PKG_001(t *testing.T) {
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
	if strings.Count(source, `isServiceActive("syswarden")`) < 2 {
		t.Fatal("FreeBSD audit must probe the packaged syswarden rc.d service")
	}
	if strings.Contains(source, `isServiceActive("syswarden-core")`) {
		t.Fatal("FreeBSD audit must not probe the Linux-only syswarden-core service name")
	}
}
