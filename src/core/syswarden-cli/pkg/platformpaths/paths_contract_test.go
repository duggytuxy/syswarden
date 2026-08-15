package platformpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPlatformPathsPreserveLinuxAndUseNativeFreeBSDPrefix(t *testing.T) {
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
	tests := map[string][]string{
		"paths_default.go": {
			`InstallRoot  = "/opt/syswarden"`,
			`CLI          = InstallRoot + "/bin/syswarden-cli"`,
			`TUI          = InstallRoot + "/bin/syswarden-tui"`,
			`/opt/syswarden/bin/syswarden-cli whitelist "$SYSWARDEN_PEER"`,
		},
		"paths_freebsd.go": {
			`InstallRoot  = "/usr/local/syswarden"`,
			`CLI          = InstallRoot + "/bin/syswarden-cli"`,
			`TUI          = InstallRoot + "/bin/syswarden-tui"`,
			`/usr/local/syswarden/bin/syswarden-cli whitelist "$SYSWARDEN_PEER"`,
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
	}
}

func TestWhitelistCommandRejectsNonCanonicalOrUnsafeTargets_SW_PKG_001(t *testing.T) {
	for _, target := range []string{"192.0.2.9", "2001:db8::9", "192.0.2.0/29"} {
		cmd, err := WhitelistCommand(target)
		if err != nil {
			t.Fatalf("WhitelistCommand(%q): %v", target, err)
		}
		if cmd.Path != "/bin/sh" {
			t.Fatalf("WhitelistCommand(%q) path = %q", target, cmd.Path)
		}
		if !strings.Contains(strings.Join(cmd.Env, "\n"), "SYSWARDEN_PEER="+target) {
			t.Fatalf("WhitelistCommand(%q) lacks exact validated environment", target)
		}
	}
	for _, target := range []string{
		"192.0.2.1/29",
		"2001:0db8::9",
		"127.0.0.1;id",
		"fe80::1%em0",
		"",
	} {
		if _, err := WhitelistCommand(target); err == nil {
			t.Fatalf("WhitelistCommand accepted unsafe target %q", target)
		}
	}
}

func TestFreeBSDManagedCronPathsIncludeExactHistoricalTransition_SW_PKG_001(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile("paths_freebsd.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `managedCronCLIPaths = [...]string{CLI, "/opt/syswarden/bin/syswarden-cli"}`) {
		t.Fatal("FreeBSD cron cleanup lacks the exact v4.02.8 binary path")
	}
}
