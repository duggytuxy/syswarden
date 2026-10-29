package integration

import (
	"os"
	"path/filepath"
	"strings"
	"syswarden-cli/config"
	"testing"
)

func TestWazuhPrerequisiteSelectionPreservesIndependentAgent(t *testing.T) {
	root := t.TempDir()
	absent := filepath.Join(root, "absent")
	if err := preflightWazuh(&config.Config{}, absent); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(absent); !os.IsNotExist(err) {
		t.Fatalf("disabled integration created agent state: %v", err)
	}
	c := &config.Config{EnableWazuh: true, WazuhIP: "192.0.2.1"}
	if err := preflightWazuh(c, absent); err == nil || !strings.Contains(err.Error(), "administrator-installed") {
		t.Fatalf("missing selected agent accepted: %v", err)
	}
	path := filepath.Join(root, wazuhConfigName)
	original := []byte("<ossec_config><client>operator configuration</client></ossec_config>\n")
	// #nosec G306 -- Deliberate group-readable administrator configuration fixture in t.TempDir.
	if err := os.WriteFile(path, original, 0640); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	if err := preflightWazuh(c, root); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	data, err := os.ReadFile(path) // #nosec G304 -- Fixed fixture name under t.TempDir; never an operator-selected path.
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(original) || !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("prerequisite inspection changed administrator state")
	}
	linkDir := t.TempDir()
	if err := os.Symlink(path, filepath.Join(linkDir, wazuhConfigName)); err != nil {
		t.Fatal(err)
	}
	if err := preflightWazuh(c, linkDir); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := preflightWazuh(nil, root); err == nil {
		t.Fatal("unknown selection accepted")
	}
	c.WazuhIP = ""
	if err := preflightWazuh(c, root); err == nil {
		t.Fatal("selected integration without manager accepted")
	}
}
