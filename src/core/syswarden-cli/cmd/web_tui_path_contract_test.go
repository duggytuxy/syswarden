package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWebTUIProductionCommandHasNoPATHFallback(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile("web_tui.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	if strings.Contains(source, `tuiPath = "syswarden-tui"`) ||
		strings.Contains(source, `exec.Command(tuiPath)`) ||
		!strings.Contains(source, `webTUICommand = platformpaths.TUICommand`) {
		t.Fatal("production Web-TUI can fall back to a PATH-resolved executable")
	}
}
