package runtimepaths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallRootUsesLinuxPackagePrefix_SW_PKG_001(t *testing.T) {
	t.Parallel()
	if got := InstallRoot(); got != "/opt/syswarden" {
		t.Fatalf("InstallRoot() = %q, want Linux package prefix", got)
	}
}

func TestRootedReadCannotEscapeInstallPrefix_SW_PKG_001(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "signatures.json"), []byte("fixed"), 0600); err != nil {
		t.Fatal(err)
	}
	content, err := readFileAtRoot(directory, "signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "fixed" {
		t.Fatalf("unexpected rooted content %q", content)
	}
	if _, err := readFileAtRoot(directory, "../signatures.json"); err == nil {
		t.Fatal("rooted signature read escaped its fixed package prefix")
	}
}

func TestComplianceAuditUsesPackagedNativeCLI_SW_PKG_001(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile("compliance_default.go")
	if err != nil {
		t.Fatal(err)
	}
	const packagedCLI = `/opt/syswarden/bin/syswarden-cli`
	if !strings.Contains(string(content), packagedCLI) {
		t.Fatalf("Linux compliance implementation lacks packaged CLI path %q", packagedCLI)
	}
}
