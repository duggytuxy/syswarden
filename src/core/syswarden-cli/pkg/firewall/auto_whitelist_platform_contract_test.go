package firewall

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAutoWhitelistUsesPlatformNativeDiscovery(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	freeBSD, err := root.ReadFile("auto_whitelist_freebsd.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(freeBSD), "ip -4") ||
		!strings.Contains(string(freeBSD), `exec.Command("route", "-n", "get", "default")`) ||
		!strings.Contains(string(freeBSD), "net.Interfaces") {
		t.Fatal("FreeBSD auto-whitelist does not use bounded native route and interface discovery")
	}
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
