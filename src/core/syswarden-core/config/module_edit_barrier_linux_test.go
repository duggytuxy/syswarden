package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
)

func TestRuntimeConfigRefusesPendingEditBeforeReading(t *testing.T) {
	for _, kind := range []string{"prepared", "committed", "rolled_back", "malformed", "unreadable", "directory", "symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			initial := writeConfigFixture(t, validMaster("schema_version = 1"), nil)
			if _, err := LoadConfigDirectory(initial); err != nil {
				t.Fatal(err)
			}
			prior := viper.AllSettings()
			candidate := writeConfigFixture(t, strings.Replace(validMaster("schema_version = 1"), `log_level = "INFO"`, `log_level = "DEBUG"`, 1), nil)
			path := filepath.Join(candidate, pendingModuleEditName)
			createRuntimeIntentFixture(t, path, kind)
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			reads := 0
			_, err = loadConfigDirectory(candidate, func(*os.Root, string, string) ([]byte, error) { reads++; return nil, nil })
			if err == nil || !strings.Contains(err.Error(), "explicit recovery") || strings.Contains(err.Error(), "private-value") {
				t.Fatalf("pending edit error = %v", err)
			}
			if reads != 0 || !reflect.DeepEqual(viper.AllSettings(), prior) {
				t.Fatal("pending edit read candidate data or replaced the prior runtime configuration")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
				t.Fatal("barrier changed pending evidence")
			}
		})
	}
}

func createRuntimeIntentFixture(t *testing.T, path, kind string) {
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

func TestRuntimeConfigRefusesIntentOrRootChangeAfterReading(t *testing.T) {
	for _, change := range []string{"intent", "root-replaced", "root-symlink", "root-writable", "root-missing"} {
		t.Run(change, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			initial := writeConfigFixture(t, validMaster("schema_version = 1"), nil)
			if _, err := LoadConfigDirectory(initial); err != nil {
				t.Fatal(err)
			}
			prior := viper.AllSettings()
			parent := t.TempDir()
			candidate := filepath.Join(parent, "candidate")
			if err := os.Mkdir(candidate, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(candidate, "config.toml"), []byte(validMaster("schema_version = 1")), 0600); err != nil {
				t.Fatal(err)
			}
			reads := 0
			_, err := loadConfigDirectory(candidate, func(root *os.Root, name, display string) ([]byte, error) {
				raw, err := readSecureRegularFile(root, name, display)
				if err != nil {
					return nil, err
				}
				reads++
				switch change {
				case "intent":
					createRuntimeIntentFixture(t, filepath.Join(candidate, pendingModuleEditName), "prepared")
				case "root-writable":
					handle, err := root.Open(".")
					if err != nil {
						t.Fatal(err)
					}
					err = handle.Chmod(0777)
					_ = handle.Close()
					if err != nil {
						t.Fatal(err)
					}
				default:
					saved := filepath.Join(parent, "saved")
					if err := os.Rename(candidate, saved); err != nil {
						t.Fatal(err)
					}
					if change == "root-replaced" {
						if err := os.Mkdir(candidate, 0700); err != nil {
							t.Fatal(err)
						}
					}
					if change == "root-symlink" {
						if err := os.Symlink(saved, candidate); err != nil {
							t.Fatal(err)
						}
					}
				}
				return raw, nil
			})
			if err == nil || reads != 1 || !reflect.DeepEqual(viper.AllSettings(), prior) {
				t.Fatalf("late edit/root change published candidate: reads=%d err=%v", reads, err)
			}
		})
	}
}

func TestRuntimeConfigResumesOnlyAfterIntentIsAbsent(t *testing.T) {
	t.Cleanup(viper.Reset)
	root := writeConfigFixture(t, validMaster("schema_version = 1"), nil)
	createRuntimeIntentFixture(t, filepath.Join(root, pendingModuleEditName), "committed")
	if _, err := LoadConfigDirectory(root); err == nil {
		t.Fatal("terminal intent was accepted as recovered")
	}
	// Fixture cleanup models completed recovery, not production recovery authority.
	if err := os.Remove(filepath.Join(root, pendingModuleEditName)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigDirectory(root); err != nil {
		t.Fatal(err)
	}
}
