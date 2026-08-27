package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecureRegularFileReadRejectsMutationAfterOpenedStat_SW_OPPOL_003(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, userModuleName)
	if err := os.WriteFile(path, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	_, _, err = readSecureRegularFileSnapshotBoundedWithHook(
		root,
		userModuleName,
		path,
		maximumUserModuleSize,
		func() error {
			return os.WriteFile(path, []byte("changed-after-opened-stat\n"), 0o600)
		},
	)
	if err == nil || !strings.Contains(err.Error(), "changed while reading") {
		t.Fatalf("concurrent read-boundary mutation error = %v, want changed-while-reading refusal", err)
	}
}

func TestSecureRegularFileReadRejectsSameSizeMutationWithRestoredMtime_SW_OPPOL_003(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, userModuleName)
	if err := os.WriteFile(path, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	_, _, err = readSecureRegularFileSnapshotBoundedWithHook(
		root,
		userModuleName,
		path,
		maximumUserModuleSize,
		func() error {
			if err := os.WriteFile(path, []byte("after!\n"), 0o600); err != nil {
				return err
			}
			return os.Chtimes(path, before.ModTime(), before.ModTime())
		},
	)
	if err == nil || !strings.Contains(err.Error(), "changed while reading") {
		t.Fatalf("same-size concurrent mutation error = %v, want changed-while-reading refusal", err)
	}
}
