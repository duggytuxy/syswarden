package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigEditorExposesBunkerWebIntegrationModule_SW_CFG_002(t *testing.T) {
	if target := configEditorTarget(5); target != "40-integrations.toml" {
		t.Fatalf("integration editor target = %q, want 40-integrations.toml", target)
	}
}

func TestConfigCommandReturnsErrorWhenModulesAreUnavailable_SW_CFG_001(t *testing.T) {
	previousRoot := configEditorRoot
	configEditorRoot = filepath.Join(t.TempDir(), "missing-config")
	t.Cleanup(func() { configEditorRoot = previousRoot })
	var output bytes.Buffer
	configCmd.SetIn(strings.NewReader("0\n"))
	configCmd.SetOut(&output)
	if err := configCmd.RunE(configCmd, nil); err == nil {
		t.Fatal("config command reported success without a modules directory")
	}
	if strings.Contains(output.String(), "updated successfully") {
		t.Fatalf("missing modules emitted false success: %s", output.String())
	}
}

func TestConfigCommandPropagatesEditorFailureAndUsesExactIntegrationPath_SW_CFG_001(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := os.MkdirAll(filepath.Join(root, "modules"), 0750); err != nil {
		t.Fatal(err)
	}
	previousRoot := configEditorRoot
	previousLauncher := launchConfigEditor
	previousEditor, editorWasSet := os.LookupEnv("EDITOR")
	configEditorRoot = root
	if err := os.Setenv("EDITOR", "/test/failing-editor"); err != nil {
		t.Fatal(err)
	}
	var openedPath string
	launchConfigEditor = func(editor, targetPath string, stdin io.Reader, stdout, stderr io.Writer) error {
		openedPath = targetPath
		return errors.New("injected editor failure")
	}
	t.Cleanup(func() {
		configEditorRoot = previousRoot
		launchConfigEditor = previousLauncher
		if editorWasSet {
			_ = os.Setenv("EDITOR", previousEditor)
		} else {
			_ = os.Unsetenv("EDITOR")
		}
	})
	var output bytes.Buffer
	configCmd.SetIn(strings.NewReader("5\n"))
	configCmd.SetOut(&output)
	configCmd.SetErr(&output)
	err := configCmd.RunE(configCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "injected editor failure") {
		t.Fatalf("config editor error = %v", err)
	}
	want := filepath.Join(root, "modules", "40-integrations.toml")
	if openedPath != want {
		t.Fatalf("integration editor path = %q, want %q", openedPath, want)
	}
	if strings.Contains(output.String(), "updated successfully") {
		t.Fatalf("failed editor emitted false success: %s", output.String())
	}
}
