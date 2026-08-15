package security

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFreeBSDCISCronDirectoryKeepsTraversalBits(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile("cis_freebsd.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	if !strings.Contains(source, `const ownerTraverse = os.FileMode(0100)`) ||
		!strings.Contains(source, `os.Chmod("/var/cron/tabs", os.FileMode(0600)|ownerTraverse)`) {
		t.Fatal("FreeBSD cron spool directory is not owner-traversable")
	}
	if !strings.Contains(source, `os.Chmod("/etc/crontab", 0600)`) {
		t.Fatal("FreeBSD crontab file does not retain its private file mode")
	}
}
