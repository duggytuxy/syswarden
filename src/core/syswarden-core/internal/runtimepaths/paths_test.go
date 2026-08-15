package runtimepaths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstallRootForUsesNativePackagePrefixes_SW_PKG_001(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"linux":   "/opt/syswarden",
		"freebsd": "/usr/local/syswarden",
	}
	for goos, want := range tests {
		goos, want := goos, want
		t.Run(goos, func(t *testing.T) {
			t.Parallel()
			if got := InstallRootFor(goos); got != want {
				t.Fatalf("InstallRootFor(%q) = %q, want %q", goos, got, want)
			}
		})
	}
}

func TestUnknownTargetKeepsLinuxCompatibility_SW_PKG_001(t *testing.T) {
	t.Parallel()
	if got := InstallRootFor("unknown"); got != "/opt/syswarden" {
		t.Fatalf("InstallRootFor(unknown) = %q, want Linux-compatible prefix", got)
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
	tests := map[string]string{
		"compliance_default.go": `/opt/syswarden/bin/syswarden-cli`,
		"compliance_freebsd.go": `/usr/local/syswarden/bin/syswarden-cli`,
	}
	for filename, packagedCLI := range tests {
		content, err := root.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(content), packagedCLI) {
			t.Fatalf("%s lacks packaged CLI path %q", filename, packagedCLI)
		}
	}
}
