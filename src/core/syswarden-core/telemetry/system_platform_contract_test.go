package telemetry

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPlatformTelemetryUsesNativeFreeBSDAndPreservesLinuxCollectors_SW_PKG_001(t *testing.T) {
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
		"system_linux.go": {
			`os.OpenRoot("/proc")`,
			`exec.Command("systemctl", "is-active", "syswarden-core")`,
			`exec.Command("rc-service", "syswarden-firewall", "status")`,
			`exec.Command("ss", "-tuln")`,
		},
		"system_freebsd.go": {
			`exec.CommandContext(ctx, "tail", "-F"`,
			`exec.Command("service", "syswarden", "onestatus")`,
			`exec.Command("service", "syswardenwebtui", "onestatus")`,
			`exec.Command("sockstat", "-46l")`,
			`exec.Command("sysctl", "-n", "hw.physmem")`,
		},
	}
	for filename, required := range tests {
		content, err := root.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range required {
			if !strings.Contains(string(content), fragment) {
				t.Fatalf("%s lacks %q", filename, fragment)
			}
		}
		if filename == "system_freebsd.go" && strings.Contains(string(content), `"bash"`) {
			t.Fatal("FreeBSD telemetry must not depend on non-base bash")
		}
	}
}
