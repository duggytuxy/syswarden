package platformpaths

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestPlatformPathsUseLinuxPackagePrefix(t *testing.T) {
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
	content, err := root.ReadFile("paths_default.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		`InstallRoot  = "/opt/syswarden"`,
		`CLI          = InstallRoot + "/bin/syswarden-cli"`,
		`TUI          = InstallRoot + "/bin/syswarden-tui"`,
	} {
		if !strings.Contains(string(content), fragment) {
			t.Fatalf("Linux platform paths lack %q", fragment)
		}
	}
}

func TestWhitelistCommandRejectsNonCanonicalOrUnsafeTargets_SW_PKG_001(t *testing.T) {
	for _, target := range []string{"192.0.2.9", "2001:db8::9", "192.0.2.0/29", "2001:db8::/64"} {
		cmd, err := WhitelistCommand(target, "62026")
		if err != nil {
			t.Fatalf("WhitelistCommand(%q): %v", target, err)
		}
		if cmd.Path != CLI {
			t.Fatalf("WhitelistCommand(%q) path = %q", target, cmd.Path)
		}
		if want := []string{CLI, "whitelist", target, "--port", "62026"}; !reflect.DeepEqual(cmd.Args, want) {
			t.Fatalf("WhitelistCommand(%q) args = %q, want %q", target, cmd.Args, want)
		}
	}
	for _, target := range []string{
		"192.0.2.1/29",
		"2001:0db8::9",
		"127.0.0.1;id",
		"fe80::1%em0",
		"::ffff:192.0.2.9",
		"--port=22",
		"192.0.2.9 22",
		"",
	} {
		if cmd, err := WhitelistCommand(target, "62026"); err == nil || cmd != nil {
			t.Fatalf("WhitelistCommand accepted unsafe target %q", target)
		}
	}
}

func TestWhitelistCommandRequiresOneCanonicalTCPPort_SW_HA_001(t *testing.T) {
	for _, port := range []string{"1", "8443", "62026", "65535"} {
		cmd, err := WhitelistCommand("192.0.2.9", port)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{CLI, "whitelist", "192.0.2.9", "--port", port}
		if cmd.Path != CLI || !reflect.DeepEqual(cmd.Args, want) {
			t.Fatalf("port %q command = %q %q, want %q", port, cmd.Path, cmd.Args, want)
		}
	}
	for _, port := range []string{"", "0", "65536", "-1", "+22", "062026", " 22", "22 ", "22;id", "22,80", "22\n80"} {
		if cmd, err := WhitelistCommand("192.0.2.9", port); err == nil || cmd != nil {
			t.Fatalf("unsafe or unscoped port %q produced a command", port)
		}
	}
}
