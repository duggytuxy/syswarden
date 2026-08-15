package system

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFreeBSDSSHUsesNativeAtomicConfiguration_SW_PKG_001(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile("ssh_freebsd.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	for _, required := range []string{
		`os.OpenRoot(freeBSDSSHDirectory)`,
		`exec.Command("sshd", "-t", "-f"`,
		`exec.Command("service", "sshd", "restart")`,
		`freeBSDSSHRename(root, freeBSDSSHBackup, freeBSDSSHConfig)`,
		`sameFreeBSDSSHConfig(original, current)`,
		`sameFreeBSDSSHConfig(installed, current)`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FreeBSD SSH implementation lacks %q", required)
		}
	}
	if strings.Contains(source, `exec.Command("sed"`) || strings.Contains(source, `exec.Command("systemctl"`) {
		t.Fatal("FreeBSD SSH implementation must not invoke GNU sed or systemctl")
	}
}
