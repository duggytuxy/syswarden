//go:build linux

package integration

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateSELinuxPolicyWorkspaceUsesPrivateUniqueDirectory(t *testing.T) {
	parent := t.TempDir()
	var workspace string
	err := withPrivateSELinuxPolicyWorkspace(parent, func(privateWorkspace string) error {
		workspace = privateWorkspace
		tePath := filepath.Join(workspace, "syswarden_rsyslog.te")
		modulePath := filepath.Join(workspace, "syswarden_rsyslog.mod")
		packagePath := filepath.Join(workspace, "syswarden_rsyslog.pp")
		for _, path := range []string{tePath, modulePath, packagePath} {
			relative, err := filepath.Rel(parent, path)
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
				t.Fatalf("policy path escaped private parent: %q", path)
			}
			if filepath.Dir(path) != workspace {
				t.Fatalf("policy artifacts do not share one workspace: %q", path)
			}
		}
		info, err := os.Stat(tePath)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("SELinux source mode = %v, want regular 0600", info.Mode())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withPrivateSELinuxPolicyWorkspace() error = %v", err)
	}
	if workspace == "" || !strings.HasPrefix(filepath.Base(workspace), "syswarden-rsyslog-") {
		t.Fatalf("unexpected private workspace %q", workspace)
	}
	if _, err := os.Stat(workspace); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private workspace was not removed: %v", err)
	}
}

func TestPrivateSELinuxPolicyWorkspaceCleansUpAfterFailure(t *testing.T) {
	parent := t.TempDir()
	sentinel := errors.New("synthetic policy failure")
	err := withPrivateSELinuxPolicyWorkspace(parent, func(workspace string) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("workspace error = %v, want sentinel", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed policy action left temporary artifacts: %#v", entries)
	}
}
