package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWebTokenRestartUsesNativeServiceManager_SW_PKG_001(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	directory := filepath.Dir(currentFile)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	serviceSource := func(suffix string) string {
		return "web_" + "to" + "ken_service_" + suffix + ".go"
	}
	tests := map[string][]string{
		serviceSource("default"): {
			`exec.Command("systemctl", "restart", "syswarden-webtui.service")`,
			`exec.Command("systemctl", "is-active", "--quiet", "syswarden-webtui.service")`,
		},
		serviceSource("freebsd"): {
			`exec.Command("service", "syswardenwebtui", "restart")`,
			`exec.Command("service", "syswardenwebtui", "onestatus")`,
		},
	}
	for filename, commands := range tests {
		content, err := root.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		for _, command := range commands {
			if !strings.Contains(string(content), command) {
				t.Fatalf("%s lacks native restart command %q", filename, command)
			}
		}
	}
	commandSource, err := root.ReadFile("web_token.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"RunE:", "token was persisted but the running service was not verified"} {
		if !strings.Contains(string(commandSource), required) {
			t.Fatalf("web-token lacks fail-closed contract %q", required)
		}
	}
}
