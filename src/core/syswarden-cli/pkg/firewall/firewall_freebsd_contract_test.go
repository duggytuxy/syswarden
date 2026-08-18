package firewall

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFreeBSDPFSyntaxContract_SW_QA_001(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	packageDirectory := filepath.Dir(currentFile)
	repositoryDirectory := filepath.Clean(filepath.Join(
		packageDirectory,
		"..", "..", "..", "..", "..",
	))
	repository, err := os.OpenRoot(repositoryDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repository.Close() }()
	paths := []string{
		"src/core/syswarden-cli/pkg/firewall/firewall_freebsd.go",
		"testdata/firewall/pf-v4.02.8.conf",
	}
	const pluralRule = "block drop in quick all fragments"
	const singularRule = "block drop in quick all fragment"
	const invalidZeroFlagsRule = "flags NONE/"
	const zeroFlagsRule = "flags /WEUAPRSF"
	const unsupportedLengthPredicate = "length > 512"
	for _, path := range paths {
		content, err := repository.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", filepath.Base(path), err)
		}
		text := string(content)
		for _, invalid := range []string{
			pluralRule,
			invalidZeroFlagsRule,
			unsupportedLengthPredicate,
		} {
			if strings.Contains(text, invalid) {
				t.Fatalf("%s contains invalid FreeBSD PF syntax %q", filepath.Base(path), invalid)
			}
		}
		if strings.Count(text, singularRule) != 1 {
			t.Fatalf("%s must contain exactly one %q rule", filepath.Base(path), singularRule)
		}
		if strings.Count(text, zeroFlagsRule) != 1 {
			t.Fatalf("%s must contain exactly one %q rule", filepath.Base(path), zeroFlagsRule)
		}
	}
}
