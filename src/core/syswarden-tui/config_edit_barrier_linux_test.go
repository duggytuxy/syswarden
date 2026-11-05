package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func createTUIIntentFixture(t *testing.T, path, kind string) {
	t.Helper()
	var err error
	switch kind {
	case "directory":
		err = os.Mkdir(path, 0700)
	case "symlink":
		err = os.Symlink("absent-private-target", path)
	case "fifo":
		err = unix.Mkfifo(path, 0600)
	default:
		raw := []byte(`{"phase":"` + kind + `","private":"private-value"}`)
		if kind == "malformed" {
			raw = []byte("private-value: invalid JSON")
		}
		mode := os.FileMode(0600)
		if kind == "unreadable" {
			mode = 0
		}
		err = os.WriteFile(path, raw, mode)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func createTUIBarrierFixture(t *testing.T) (string, string) {
	t.Helper()
	parent := t.TempDir()
	root := filepath.Join(parent, "config")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	raw := `[integrations.ha]
enabled = true
peer_ips = ["192.0.2.10"]
peer_port = "62026"
token = "private-test-token"
`
	if err := os.WriteFile(filepath.Join(root, "config.toml"), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(parent, "legacy.conf")
	if err := os.WriteFile(legacy, []byte("SYSWARDEN_HA_ENABLED=y\nSYSWARDEN_HA_PEER_IP=192.0.2.20\nSYSWARDEN_HA_TOKEN=legacy-test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return root, legacy
}

func TestTUIHARefusesPendingEditBeforeReading(t *testing.T) {
	for _, kind := range []string{"prepared", "committed", "rolled_back", "malformed", "unreadable", "directory", "symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			root, legacy := createTUIBarrierFixture(t)
			path := filepath.Join(root, tuiPendingModuleEditName)
			createTUIIntentFixture(t, path, kind)
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			reads := 0
			cfg, err := loadTUIHAConfigWithRead(root, legacy, func(string) ([]byte, error) { reads++; return nil, nil })
			if err == nil || !strings.Contains(err.Error(), "explicit recovery") || strings.Contains(err.Error(), "private-value") {
				t.Fatalf("pending edit error = %v", err)
			}
			if reads != 0 || !reflect.DeepEqual(cfg, tuiHAConfig{}) {
				t.Fatal("pending edit read credentials, selected peers or used legacy fallback")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
				t.Fatal("barrier changed pending evidence")
			}
		})
	}
}

func TestTUIHARefusesIntentOrRootChangeAfterReading(t *testing.T) {
	for _, change := range []string{"intent", "root-replaced", "root-symlink", "root-writable", "root-missing"} {
		t.Run(change, func(t *testing.T) {
			root, legacy := createTUIBarrierFixture(t)
			reads := 0
			cfg, err := loadTUIHAConfigWithRead(root, legacy, func(path string) ([]byte, error) {
				raw, err := readTUIConfigFile(path)
				if err != nil {
					return nil, err
				}
				reads++
				switch change {
				case "intent":
					createTUIIntentFixture(t, filepath.Join(root, tuiPendingModuleEditName), "prepared")
				case "root-writable":
					handle, err := os.OpenRoot(root)
					if err != nil {
						t.Fatal(err)
					}
					directory, err := handle.Open(".")
					if err != nil {
						t.Fatal(err)
					}
					err = directory.Chmod(0777)
					_ = directory.Close()
					_ = handle.Close()
					if err != nil {
						t.Fatal(err)
					}
				default:
					saved := root + "-saved"
					if err := os.Rename(root, saved); err != nil {
						t.Fatal(err)
					}
					if change == "root-replaced" {
						if err := os.Mkdir(root, 0700); err != nil {
							t.Fatal(err)
						}
					}
					if change == "root-symlink" {
						if err := os.Symlink(saved, root); err != nil {
							t.Fatal(err)
						}
					}
				}
				return raw, nil
			})
			if err == nil || reads != 1 || !reflect.DeepEqual(cfg, tuiHAConfig{}) {
				t.Fatalf("late edit/root change selected HA configuration: reads=%d err=%v", reads, err)
			}
		})
	}
}

func TestTUIHALegacyReadRefusesNewModularConfiguration(t *testing.T) {
	root, legacy := createTUIBarrierFixture(t)
	if err := os.Rename(root, root+"-saved"); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadTUIHAConfigWithRead(root, legacy, func(path string) ([]byte, error) {
		raw, err := readTUIConfigFile(path)
		if err != nil {
			return nil, err
		}
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
		createTUIIntentFixture(t, filepath.Join(root, tuiPendingModuleEditName), "prepared")
		return raw, nil
	})
	if err == nil || !reflect.DeepEqual(cfg, tuiHAConfig{}) {
		t.Fatal("legacy fallback bypassed a new modular edit")
	}
}

func TestTUIHAResumesOnlyAfterIntentIsAbsent(t *testing.T) {
	root, legacy := createTUIBarrierFixture(t)
	createTUIIntentFixture(t, filepath.Join(root, tuiPendingModuleEditName), "committed")
	if _, err := loadTUIHAConfig(root, legacy); err == nil {
		t.Fatal("terminal intent was accepted as recovered")
	}
	// Fixture cleanup models completed recovery, not production recovery authority.
	if err := os.Remove(filepath.Join(root, tuiPendingModuleEditName)); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadTUIHAConfig(root, legacy)
	if err != nil || !cfg.Enabled || cfg.Token != "private-test-token" {
		t.Fatal("ordinary modular read did not resume")
	}
}
