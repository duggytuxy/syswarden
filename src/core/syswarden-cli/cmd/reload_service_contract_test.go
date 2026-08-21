package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReloadServiceUsesLinuxServiceManager_SW_PKG_001(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile("reload_service_default.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`coreServiceRestartCommand(system.IsAlpine()).Run()`,
		`exec.Command("rc-service", "syswarden-core", "restart")`,
		`exec.Command("systemctl", "restart", "syswarden-core.service")`,
	} {
		if !strings.Contains(string(content), required) {
			t.Fatalf("Linux reload service implementation lacks %q", required)
		}
	}
	reloadSource, err := root.ReadFile("reload.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"RunE:", "errors.Join(failures...)", "return fmt.Errorf"} {
		if !strings.Contains(string(reloadSource), required) {
			t.Fatalf("reload command lacks fail-closed contract %q", required)
		}
	}
}
