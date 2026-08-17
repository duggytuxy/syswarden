package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReloadServiceUsesNativePlatformManager_SW_PKG_001(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	tests := map[string][]string{
		"reload_service_default.go": {
			`coreServiceRestartCommand(system.IsAlpine()).Run()`,
			`exec.Command("rc-service", "syswarden-core", "restart")`,
			`exec.Command("systemctl", "restart", "syswarden-core.service")`,
		},
		"reload_service_freebsd.go": {
			`exec.Command("service", "syswarden", "restart")`,
			`exec.Command("service", "syswarden", "onestatus")`,
		},
	}
	for filename, requiredFragments := range tests {
		content, err := root.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range requiredFragments {
			if !strings.Contains(string(content), required) {
				t.Fatalf("%s lacks %q", filename, required)
			}
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
