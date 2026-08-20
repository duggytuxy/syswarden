package firewall

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAutoWhitelistUsesLinuxNativeDiscovery(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	linux, err := root.ReadFile("auto_whitelist_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"ip -4 route show default", "ip -4 addr show"} {
		if !strings.Contains(string(linux), command) {
			t.Fatalf("Linux auto-whitelist lost %q", command)
		}
	}
}
