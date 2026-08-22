//go:build linux

package system

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPreparedServiceEnablementRemovalIsExactAndPreservesLookalikes_SW2_FWBACKEND_001(t *testing.T) {
	root := t.TempDir()
	serviceDirectory := filepath.Join(root, "system")
	wantsDirectory := filepath.Join(serviceDirectory, "multi-user.target.wants")
	if err := os.MkdirAll(wantsDirectory, 0755); err != nil {
		t.Fatal(err)
	}
	servicePath := filepath.Join(serviceDirectory, "syswarden-core.service")
	if err := os.WriteFile(servicePath, []byte(systemdCoreService), 0600); err != nil {
		t.Fatal(err)
	}
	enablementPath := filepath.Join(wantsDirectory, "syswarden-core.service")
	if err := os.Symlink("../syswarden-core.service", enablementPath); err != nil {
		t.Fatal(err)
	}
	if err := removePreparedServiceEnablement(
		enablementPath,
		servicePath,
		systemdCoreService,
		0600,
		"../syswarden-core.service",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(enablementPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact enablement remains: %v", err)
	}

	if err := os.Symlink("../operator.service", enablementPath); err != nil {
		t.Fatal(err)
	}
	if err := removePreparedServiceEnablement(
		enablementPath,
		servicePath,
		systemdCoreService,
		0600,
		"../syswarden-core.service",
	); err == nil {
		t.Fatal("operator enablement target was removed")
	}
	if target, err := os.Readlink(enablementPath); err != nil || target != "../operator.service" {
		t.Fatalf("operator enablement changed: target=%q error=%v", target, err)
	}
}
