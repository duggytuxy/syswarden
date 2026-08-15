package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunSyswardenIPActionRejectsUntrustedInputs(t *testing.T) {
	for _, test := range []struct {
		action string
		target string
	}{
		{action: "unblock", target: "127.0.0.1; id"},
		{action: "block", target: "fe80::1%em0"},
		{action: "unknown", target: "192.0.2.1"},
	} {
		if err := runSyswardenIPAction(test.action, test.target); err == nil {
			t.Fatalf("untrusted action accepted: %#v", test)
		}
	}
}

func TestFreeBSDActionsUseNativePackagedCLI_SW_PKG_001(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile("platform_freebsd.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	if strings.Count(source, "/usr/local/syswarden/bin/syswarden-cli") != 3 {
		t.Fatal("each FreeBSD action must execute the native packaged CLI path")
	}
	if strings.Contains(source, "/opt/syswarden") {
		t.Fatal("FreeBSD TUI actions must not use the Linux installation prefix")
	}
}

func TestWhitelistActionsUseTheExactCLIArguments(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	for _, sourceName := range []string{"platform_default.go", "platform_freebsd.go"} {
		content, err := root.ReadFile(sourceName)
		if err != nil {
			t.Fatal(err)
		}
		source := string(content)
		if strings.Contains(source, `whitelist add "$SYSWARDEN_TARGET"`) ||
			!strings.Contains(source, `whitelist "$SYSWARDEN_TARGET"`) {
			t.Fatalf("%s uses an invalid whitelist command shape", sourceName)
		}
	}
}
